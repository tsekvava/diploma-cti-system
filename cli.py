#!/usr/bin/env python3
"""
CTI Pipeline CLI — единая точка входа для системы анализа киберугроз.

Команды:
  analyze   — полный анализ отчёта (7-этапный пайплайн)
  enrich    — обогащение запроса из MITRE ATT&CK БД
  export    — экспорт результатов в OpenCTI (API или STIX Bundle)
  benchmark — запуск бенчмарка моделей
  intel-sync — импорт internal intel из OpenCTI STIX JSON
  mitre-db  — пересоздание базы MITRE ATT&CK

Примеры:
  python3 cli.py analyze -f report.txt
  python3 cli.py analyze -f report.txt --model gemma2:9b --export stix_bundle.json
  python3 cli.py enrich T1059
  python3 cli.py enrich "Lazarus Group"
  python3 cli.py enrich G0032 --json
  python3 cli.py export -i result.json --dry-run
  python3 cli.py export -i result.json --stix-bundle output.json
  python3 cli.py benchmark --models "gemma2:9b,qwen2.5:14b"
  python3 cli.py intel-sync --stix opencti_bundle.json
  python3 cli.py mitre-db
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

# Корень проекта
ROOT = Path(__file__).parent


def _build_ollama_url(host: str, port: "int | None") -> str:
    """Собирает URL Ollama из host/port."""
    raw = host.strip()
    if "://" not in raw:
        raw = f"http://{raw}"

    parsed = urlparse(raw)
    scheme = parsed.scheme or "http"
    hostname = parsed.hostname or parsed.path
    if not hostname:
        raise ValueError(f"Некорректный --ollama-host: {host}")

    final_port = port if port is not None else (parsed.port or 11434)
    return f"{scheme}://{hostname}:{final_port}"


def _configure_ollama(args) -> "str | None":
    """Настраивает endpoint Ollama через OLLAMA_HOST."""
    host = getattr(args, "ollama_host", None) or os.getenv("CTI_OLLAMA_HOST")
    port = getattr(args, "ollama_port", None)
    if port is None:
        env_port = os.getenv("CTI_OLLAMA_PORT")
        if env_port:
            try:
                port = int(env_port)
            except ValueError:
                raise ValueError(f"Некорректный CTI_OLLAMA_PORT: {env_port}")

    if not host:
        return None

    url = _build_ollama_url(host, port)
    os.environ["OLLAMA_HOST"] = url
    print(f"Ollama endpoint: {url}")
    return url


def cmd_analyze(args):
    """Полный 7-этапный анализ отчёта."""
    _configure_ollama(args)
    from summarizer.report_summarizer import ReportSummarizer
    from summarizer.input_loader import load_report_file, InputLoadError

    input_metadata = {}
    # Чтение текста
    if args.file:
        if not Path(args.file).exists():
            print(f"Файл не найден: {args.file}")
            return 1
        try:
            loaded = load_report_file(
                args.file,
                ocr_mode=args.ocr,
                ocr_lang=args.ocr_lang,
            )
        except InputLoadError as e:
            print(f"Ошибка парсинга файла: {e}")
            return 1
        text = loaded.text
        source = loaded.source
        input_metadata = {
            "input_format": loaded.input_format,
            "pages": loaded.pages,
            "ocr_used": loaded.ocr_used,
            "parse_warnings": loaded.parse_warnings,
        }
    elif args.text:
        text = args.text
        source = "cli-input"
        input_metadata = {
            "input_format": "text",
            "pages": 1,
            "ocr_used": False,
            "parse_warnings": [],
        }
    else:
        # Читаем из stdin
        print("Введите текст отчёта (Ctrl+D для завершения):")
        text = sys.stdin.read()
        source = "stdin"
        input_metadata = {
            "input_format": "stdin",
            "pages": 1,
            "ocr_used": False,
            "parse_warnings": [],
        }

    if not text.strip():
        print("Пустой текст. Нечего анализировать.")
        return 1

    print(f"\n{'=' * 60}")
    print(f"CTI PIPELINE — Анализ отчёта")
    print(f"Источник: {source}")
    print(f"Модель:   {args.model}")
    print(f"Формат:   {input_metadata.get('input_format', 'text')}")
    print(f"OCR:      {'ON' if input_metadata.get('ocr_used') else 'OFF'}")
    print(f"Длина:    {len(text)} символов")
    print(f"{'=' * 60}\n")

    if input_metadata.get("parse_warnings"):
        print("⚠️  Предупреждения парсинга:")
        for w in input_metadata["parse_warnings"]:
            print(f"   - {w}")
        print()

    # RAG: поиск похожих отчётов
    rag_context = ""
    if getattr(args, "rag", False):
        try:
            from rag_engine import RAGSystem
            rag = RAGSystem()
            if rag.count > 0:
                rag_context = rag.build_context(text)
                if rag_context:
                    print(f"RAG: найден контекст из {rag.count} отчётов в базе")
                else:
                    print(f"RAG: база содержит {rag.count} отчётов, но релевантных не найдено")
            else:
                print("RAG: база пуста. Используйте 'rag-index' для индексации отчётов.")
        except ImportError as e:
            print(f"RAG: не удалось загрузить (установите chromadb, sentence-transformers): {e}")

    summarizer = ReportSummarizer(model_name=args.model)

    # Запуск пайплайна
    result = summarizer.process(text, source=source, input_metadata=input_metadata, rag_context=rag_context)

    # Вывод
    if args.json_output:
        # JSON на stdout
        print(json.dumps(result["json"], indent=2, ensure_ascii=False))
    else:
        # Форматированный вывод
        _print_analysis_result(result)

    # Сохранение JSON
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result["json"], f, indent=2, ensure_ascii=False)
        print(f"\nJSON сохранён: {args.output}")

    # RAG: индексируем проанализированный отчёт
    if getattr(args, "rag", False) and rag_context is not None:
        try:
            from rag_engine import RAGSystem
            rag = RAGSystem()
            rag.index_report(text, result, source=source)
            print(f"RAG: отчёт '{source}' проиндексирован (всего в базе: {rag.count})")
        except Exception:
            pass

    # Автоматический STIX Bundle экспорт
    if args.export:
        from opencti_exporter import OpenCTIExporter
        exporter = OpenCTIExporter(tlp=args.tlp, dry_run=True)
        exporter.export_stix_bundle(result["json"], output_path=args.export)

    return 0


def cmd_rag_index(args):
    """Индексация отчётов в RAG-базу (ChromaDB)."""
    from rag_engine import RAGSystem

    rag = RAGSystem()
    print(f"RAG база: {rag.count} документов")
    print(f"Индексация из: {args.dir} (паттерн: {args.pattern})")

    count = rag.index_directory(args.dir, args.pattern)
    print(f"Добавлено: {count} отчётов")
    print(f"Всего в базе: {rag.count}")
    return 0


def cmd_nvd(args):
    """Управление локальной базой NVD CVE."""
    from knowledge_base.nvd_db import NVDDatabase

    db = NVDDatabase()

    if args.stats:
        print(f"NVD база: {db.count} CVE записей")
        if db.count > 0:
            row = db.conn.execute(
                "SELECT AVG(cvss3_score), MAX(cvss3_score) FROM cve WHERE cvss3_score IS NOT NULL"
            ).fetchone()
            if row[0]:
                print(f"  Средний CVSS: {row[0]:.1f}")
                print(f"  Макс CVSS:    {row[1]}")

    elif args.fetch:
        print(f"Загрузка {len(args.fetch)} CVE из NVD API...")
        count = db.fetch_batch(args.fetch)
        print(f"Загружено: {count} новых CVE")
        print(f"Всего в базе: {db.count}")

    elif args.update:
        print(f"Загрузка CVE за последние {args.days} дней из NVD API...")
        count = db.fetch_recent(days=args.days)
        print(f"Загружено: {count} CVE")
        print(f"Всего в базе: {db.count}")

    elif args.lookup:
        result = db.lookup(args.lookup)
        if result:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print(f"{args.lookup} не найден в локальной базе")
            print(f"Используйте: python3 cli.py nvd --fetch {args.lookup}")

    db.close()
    return 0


def cmd_analyze_batch(args):
    """Пакетный анализ отчётов из директории."""
    _configure_ollama(args)
    from summarizer.report_summarizer import ReportSummarizer
    from summarizer.input_loader import load_report_file, InputLoadError

    dir_path = Path(args.dir)
    if not dir_path.is_dir():
        print(f"Директория не найдена: {args.dir}")
        return 1

    # Сбор файлов
    extensions = ("*.txt", "*.md", "*.html", "*.pdf", "*.docx", "*.log")
    files = []
    for ext in extensions:
        files.extend(sorted(dir_path.glob(ext)))
    files = sorted(set(files), key=lambda f: f.name)

    if not files:
        print(f"Нет файлов для анализа в {args.dir}")
        return 1

    print(f"\n{'=' * 60}")
    print(f"CTI PIPELINE — Пакетный анализ")
    print(f"Директория: {dir_path}")
    print(f"Файлов:     {len(files)}")
    print(f"Модель:     {args.model}")
    print(f"{'=' * 60}\n")

    summarizer = ReportSummarizer(model_name=args.model)

    # RAG
    rag = None
    if getattr(args, "rag", False):
        try:
            from rag_engine import RAGSystem
            rag = RAGSystem()
            print(f"RAG: база содержит {rag.count} отчётов\n")
        except ImportError:
            print("RAG: chromadb/sentence-transformers не установлены\n")

    results = []
    total_iocs = {"ipv4": set(), "domain": set(), "hash": set(), "email": set()}
    all_actors = set()
    all_malware = set()
    all_techniques = set()
    errors = []

    for idx, fpath in enumerate(files, 1):
        print(f"[{idx}/{len(files)}] {fpath.name}...", end=" ", flush=True)
        try:
            loaded = load_report_file(str(fpath))
            text = loaded.text
        except InputLoadError as e:
            print(f"SKIP ({e})")
            errors.append({"file": fpath.name, "error": str(e)})
            continue

        if len(text.strip()) < 100:
            print("SKIP (слишком короткий)")
            continue

        input_metadata = {
            "input_format": loaded.input_format,
            "pages": loaded.pages,
            "ocr_used": loaded.ocr_used,
            "parse_warnings": loaded.parse_warnings,
        }

        # RAG context
        rag_context = ""
        if rag and rag.count > 0:
            rag_context = rag.build_context(text)

        try:
            t0 = time.time()
            result = summarizer.process(
                text, source=fpath.name,
                input_metadata=input_metadata,
                rag_context=rag_context,
            )
            elapsed = time.time() - t0
            print(f"OK ({elapsed:.1f}с)")
        except Exception as e:
            print(f"ERROR ({e})")
            errors.append({"file": fpath.name, "error": str(e)})
            continue

        # Сохранение индивидуального JSON
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{fpath.stem}_analysis.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(result["json"], f, indent=2, ensure_ascii=False)

        # RAG: индексация
        if rag:
            try:
                rag.index_report(text, result, source=fpath.name)
            except Exception:
                pass

        # Агрегация статистики
        data = result["json"]
        for ioc_type in total_iocs:
            items = data.get("indicators", {}).get(ioc_type, [])
            total_iocs[ioc_type].update(items)

        for a in data.get("threat_actors", []):
            all_actors.add(a.get("name", "?"))
        for m in data.get("malware", []):
            all_malware.add(m.get("name", "?"))
        for phase in data.get("kill_chain", []):
            for t in phase.get("techniques", []):
                all_techniques.add(f"{t.get('id', '?')} {t.get('name_en', '')}")

        results.append({
            "file": fpath.name,
            "actors": [a.get("name", "?") for a in data.get("threat_actors", [])],
            "malware": [m.get("name", "?") for m in data.get("malware", [])],
            "ioc_count": sum(len(data.get("indicators", {}).get(t, [])) for t in total_iocs),
            "techniques_count": sum(len(p.get("techniques", [])) for p in data.get("kill_chain", [])),
            "confidence": data.get("overall_confidence", 0),
            "time_sec": elapsed,
        })

    print(f"\n{'=' * 60}")
    print("СВОДНЫЙ ОТЧЁТ")
    print(f"{'=' * 60}")
    print(f"Обработано:    {len(results)} из {len(files)} файлов")
    if errors:
        print(f"Ошибки:        {len(errors)}")
    print(f"Всего IoC:     {sum(len(v) for v in total_iocs.values())} уникальных")
    for ioc_type, items in total_iocs.items():
        if items:
            print(f"  {ioc_type}: {len(items)}")
    if all_actors:
        print(f"Акторы ({len(all_actors)}):  {', '.join(sorted(all_actors))}")
    if all_malware:
        print(f"Malware ({len(all_malware)}): {', '.join(sorted(all_malware))}")
    print(f"Техники:       {len(all_techniques)} уникальных")

    # Средние метрики
    if results:
        avg_time = sum(r["time_sec"] for r in results) / len(results)
        avg_conf = sum(r["confidence"] for r in results) / len(results)
        print(f"Ср. время:     {avg_time:.1f}с")
        print(f"Ср. confidence: {avg_conf:.0f}%")

    # Сохранение сводки
    summary = {
        "total_files": len(files),
        "processed": len(results),
        "errors": errors,
        "unique_iocs": {k: len(v) for k, v in total_iocs.items()},
        "unique_actors": sorted(all_actors),
        "unique_malware": sorted(all_malware),
        "unique_techniques": sorted(all_techniques),
        "per_file": results,
    }
    summary_path = Path(args.output_dir) / "batch_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"\nРезультаты: {args.output_dir}/")
    print(f"Сводка:     {summary_path}")

    return 0


def _print_analysis_result(result):
    """Красивый вывод результатов анализа."""
    data = result["json"]
    meta = data.get("metadata", {})

    print(f"\n{'─' * 60}")
    print("РЕЗУЛЬТАТ АНАЛИЗА")
    print(f"{'─' * 60}")

    # Metadata
    print(f"  Модель:  {meta.get('model', '?')}")
    print(f"  Время:   {result.get('processing_time', 0):.1f}с")
    print(f"  Формат:  {meta.get('input_format', 'text')}")
    print(f"  Страниц: {meta.get('pages', 1)}")
    print(f"  OCR:     {'ON' if meta.get('ocr_used') else 'OFF'}")

    warnings = meta.get("warnings", []) or []
    if warnings:
        print(f"\n  Warnings ({len(warnings)}):")
        for w in warnings[:8]:
            print(f"    - {w}")
        if len(warnings) > 8:
            print(f"    ... ещё {len(warnings) - 8}")

    # Classification
    cls = data.get("classification", {})
    if cls:
        label = cls.get("label", "?")
        severity = cls.get("severity", "?")
        print(f"  Класс:   {label} (severity: {severity})")

    # Threat Actors
    actors = data.get("threat_actors", [])
    if actors:
        print(f"\n  Threat Actors ({len(actors)}):")
        for a in actors:
            mid = f" [{a.get('mitre_id', '')}]" if a.get("mitre_id") else ""
            print(f"    - {a['name']}{mid} (conf: {a.get('confidence', '?')})")

    # Malware
    malware = data.get("malware", [])
    if malware:
        print(f"\n  Malware ({len(malware)}):")
        for m in malware:
            mid = f" [{m.get('mitre_id', '')}]" if m.get("mitre_id") else ""
            print(f"    - {m['name']}{mid} (conf: {m.get('confidence', '?')})")

    # Tools
    tools = data.get("tools", [])
    if tools:
        print(f"\n  Tools ({len(tools)}):")
        for t in tools:
            mid = f" [{t.get('mitre_id', '')}]" if t.get("mitre_id") else ""
            print(f"    - {t['name']}{mid} (conf: {t.get('confidence', '?')})")

    # Kill Chain
    kc = data.get("kill_chain", [])
    if kc:
        print(f"\n  Kill Chain ({sum(len(p.get('techniques', [])) for p in kc)} techniques):")
        for phase in kc:
            tactic = phase.get("tactic_name", phase.get("tactic_id", "?"))
            print(f"    [{phase.get('tactic_id', '')}] {tactic}:")
            for t in phase.get("techniques", []):
                print(f"      - {t['id']} {t.get('name_en', '')} (conf: {t.get('confidence', '?')})")

    # Vulnerabilities
    vulns = data.get("vulnerabilities", [])
    if vulns:
        print(f"\n  Vulnerabilities ({len(vulns)}):")
        for v in vulns:
            vid = v if isinstance(v, str) else v.get("id", "?")
            print(f"    - {vid}")

    # Indicators
    indicators = data.get("indicators", {})
    total_ioc = sum(len(v) for v in indicators.values())
    if total_ioc:
        print(f"\n  Indicators ({total_ioc}):")
        for ioc_type, values in indicators.items():
            if values:
                print(f"    {ioc_type} ({len(values)}):")
                for v in values[:5]:
                    print(f"      - {v}")
                if len(values) > 5:
                    print(f"      ... ещё {len(values) - 5}")

    # Summary (EN)
    if result.get("summary_en"):
        print(f"\n  Summary (EN):")
        for line in result["summary_en"].split("\n"):
            print(f"    {line}")

    # Note (RU)
    if result.get("note_ru"):
        print(f"\n  Аналитическая записка (RU):")
        for line in result["note_ru"].split("\n"):
            print(f"    {line}")

    print(f"\n{'─' * 60}")


def cmd_enrich(args):
    """Обогащение запроса из MITRE ATT&CK."""
    from knowledge_base.query_enricher import QueryEnricher

    query = " ".join(args.query)
    if not query.strip():
        print("Пустой запрос.")
        return 1

    enricher = QueryEnricher()
    result = enricher.enrich(query)

    if args.json_output:
        # Только JSON
        output = {
            "query": result["query"],
            "detected": result["detected"],
            "enrichments": result["enrichments"],
        }
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        # Человекочитаемый формат
        print(result["context_for_llm"])

    enricher.close()
    return 0


def cmd_export(args):
    """Экспорт в OpenCTI."""
    from opencti_exporter import OpenCTIExporter

    if not Path(args.input).exists():
        print(f"Файл не найден: {args.input}")
        return 1

    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)

    exporter = OpenCTIExporter(
        url=args.url,
        token=args.token,
        tlp=args.tlp,
        dry_run=args.dry_run or bool(args.stix_bundle),
    )

    if args.stix_bundle:
        exporter.export_stix_bundle(data, output_path=args.stix_bundle)
    else:
        exporter.export(data)

    return 0


def cmd_benchmark(args):
    """Запуск бенчмарка моделей."""
    sys.path.insert(0, str(ROOT / "benchmark"))
    import subprocess

    cmd = [
        sys.executable, "-u",
        str(ROOT / "benchmark" / "benchmark_multi_model.py"),
        "--models", args.models,
    ]
    if args.skip_baselines:
        cmd.append("--skip-baselines")
    if args.output:
        cmd.extend(["--output", args.output])

    env = os.environ.copy()
    ollama_url = _configure_ollama(args)
    if ollama_url:
        env["OLLAMA_HOST"] = ollama_url

    print(f"Запуск: {' '.join(cmd)}\n")
    return subprocess.call(cmd, env=env)


def cmd_profile(args):
    """Генерация профиля APT-группы или ПО."""
    _configure_ollama(args)
    from summarizer.profiler import Profiler

    query = " ".join(args.query)
    if not query.strip():
        print("Пустой запрос.")
        return 1

    profiler = Profiler(model_name=args.model)

    if args.type == "group":
        result = profiler.profile_group(query)
    elif args.type == "software":
        result = profiler.profile_software(query)
    else:
        result = profiler.profile(query)

    if "error" in result:
        print(f"Ошибка: {result['error']}")
        return 1

    if args.json_output:
        # JSON (без data для компактности)
        output = {k: v for k, v in result.items() if k != "data"}
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        # Человекочитаемый формат
        print(f"\n{'=' * 60}")
        print(f"ПРОФИЛЬ: {result.get('entity_name', '?')} ({result.get('entity_id', '?')})")
        print(f"Тип: {result.get('entity_type', '?')}")
        if result.get("aliases"):
            print(f"Алиасы: {', '.join(result['aliases'][:10])}")
        if result.get("techniques_count"):
            print(f"Техник: {result['techniques_count']}")
        print(f"{'=' * 60}\n")

        if result.get("profile_en"):
            print("─── PROFILE (EN) ───\n")
            print(result["profile_en"])

        if result.get("profile_ru"):
            print("\n─── ПРОФИЛЬ (RU) ───\n")
            print(result["profile_ru"])

    # Сохранение
    if args.output:
        output = {k: v for k, v in result.items() if k != "data"}
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        print(f"\nСохранено: {args.output}")

    return 0


def cmd_mitre_db(args):
    """Пересоздание базы MITRE ATT&CK."""
    from knowledge_base.mitre_catalog import build_catalog

    print("Пересоздание базы MITRE ATT&CK...")
    build_catalog(include_stix=True)
    print("Готово.")
    return 0


def cmd_intel_sync(args):
    """Импорт корпоративной базы знаний из STIX JSON (OpenCTI export)."""
    from knowledge_base.intel_sync import InternalIntelSync

    mode = "replace" if args.replace_source else "append"
    source = args.source or "opencti"

    syncer = InternalIntelSync()
    try:
        stats = syncer.import_stix(args.stix, mode=mode, source=source)
    finally:
        syncer.close()

    print("\nINTEL SYNC — RESULT")
    print(f"  Source:   {stats.get('source')}")
    print(f"  Mode:     {stats.get('mode')}")
    print(f"  Objects:  {stats.get('objects_scanned', 0)}")
    print(f"  Groups:   {stats.get('groups_upserted', 0)}")
    print(f"  Software: {stats.get('software_upserted', 0)}")
    print(f"  G→T links:{stats.get('group_tech_links_upserted', 0)}")
    print(f"  S→T links:{stats.get('software_tech_links_upserted', 0)}")
    return 0


def cmd_survey(args):
    """Анализ ответов опроса SOC-аналитиков."""
    sys.path.insert(0, str(ROOT / "data" / "soc_survey"))
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "analyze_survey",
        ROOT / "data" / "soc_survey" / "analyze_survey.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    if args.demo:
        sys.argv = ["analyze_survey.py", "--demo"]
    elif args.input:
        argv = ["analyze_survey.py", args.input]
        if args.test_enrichment:
            argv.append("--test-enrichment")
        sys.argv = argv
    else:
        sys.argv = ["analyze_survey.py", "--demo"]

    mod.main()
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="cti-pipeline",
        description="CTI Pipeline — система анализа киберугроз для SOC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  %(prog)s analyze -f report.txt
  %(prog)s analyze -f report.pdf --ocr auto --ocr-lang rus+eng
  %(prog)s analyze -f report.txt --model gemma2:9b --export bundle.json
  %(prog)s enrich T1059
  %(prog)s enrich "Lazarus Group" --json
  %(prog)s profile "APT28"
  %(prog)s profile "Cobalt Strike" --type software
  %(prog)s export -i result.json --dry-run
  %(prog)s export -i result.json --stix-bundle output.json
  %(prog)s benchmark --models "gemma2:9b,qwen2.5:14b"
  %(prog)s intel-sync --stix opencti_bundle.json --append
        """,
    )
    subparsers = parser.add_subparsers(dest="command", help="Доступные команды")

    p_analyze = subparsers.add_parser("analyze", help="Полный анализ CTI-отчёта")
    input_group = p_analyze.add_mutually_exclusive_group()
    input_group.add_argument(
        "-f", "--file",
        help="Путь к файлу отчёта (txt/md/log/html/docx/pdf/png/jpg/jpeg/bmp)",
    )
    input_group.add_argument("-t", "--text", help="Текст отчёта напрямую")
    p_analyze.add_argument("--model", default="gemma2:9b", help="Ollama модель (default: gemma2:9b)")
    p_analyze.add_argument("--ollama-host", help="Хост Ollama (например 127.0.0.1 или ollama.local)")
    p_analyze.add_argument("--ollama-port", type=int, help="Порт Ollama (default: 11434)")
    p_analyze.add_argument("-o", "--output", help="Сохранить JSON результат в файл")
    p_analyze.add_argument("--json", dest="json_output", action="store_true", help="Вывести только JSON")
    p_analyze.add_argument("--export", metavar="FILE", help="Автоматически экспортировать STIX Bundle")
    p_analyze.add_argument("--tlp", default="TLP:AMBER", help="TLP-маркировка (default: TLP:AMBER)")
    p_analyze.add_argument("--ocr", choices=["auto", "on", "off"], default="auto",
                           help="OCR режим для PDF/изображений и встроенных картинок в html/docx (default: auto)")
    p_analyze.add_argument("--ocr-lang", default="rus+eng",
                           help="Языки OCR для tesseract (default: rus+eng)")
    p_analyze.add_argument("--rag", action="store_true",
                           help="Использовать RAG (поиск похожих отчётов из ChromaDB)")

    p_batch = subparsers.add_parser("analyze-batch", help="Пакетный анализ отчётов из директории")
    p_batch.add_argument("-d", "--dir", required=True, help="Директория с отчётами")
    p_batch.add_argument("--model", default="gemma2:9b", help="Ollama модель (default: gemma2:9b)")
    p_batch.add_argument("--ollama-host", help="Хост Ollama")
    p_batch.add_argument("--ollama-port", type=int, help="Порт Ollama (default: 11434)")
    p_batch.add_argument("-o", "--output-dir", default="batch_results", help="Директория для результатов")
    p_batch.add_argument("--rag", action="store_true", help="Использовать RAG")

    p_rag = subparsers.add_parser("rag-index", help="Индексировать отчёты в RAG-базу (ChromaDB)")
    p_rag.add_argument("-d", "--dir", required=True, help="Директория с текстовыми отчётами")
    p_rag.add_argument("--pattern", default="*.txt", help="Glob-паттерн файлов (default: *.txt)")

    p_enrich = subparsers.add_parser("enrich", help="Обогащение запроса из MITRE ATT&CK")
    p_enrich.add_argument("query", nargs="+", help="Запрос: T1059, G0032, 'Cobalt Strike', CVE-2024-38063")
    p_enrich.add_argument("--json", dest="json_output", action="store_true", help="Вывод в JSON формате")

    p_export = subparsers.add_parser("export", help="Экспорт результатов в OpenCTI")
    p_export.add_argument("-i", "--input", required=True, help="JSON-файл результатов анализа")
    p_export.add_argument("--dry-run", action="store_true", help="Показать что будет создано без подключения")
    p_export.add_argument("--stix-bundle", "-s", metavar="FILE", help="Экспорт как STIX 2.1 Bundle JSON")
    p_export.add_argument("--tlp", default="TLP:AMBER", help="TLP-маркировка (default: TLP:AMBER)")
    p_export.add_argument("--url", default=None, help="OpenCTI URL")
    p_export.add_argument("--token", default=None, help="OpenCTI API token")

    p_bench = subparsers.add_parser("benchmark", help="Бенчмарк LLM-моделей")
    p_bench.add_argument("--models", default="gemma2:9b,qwen2.5:14b",
                         help="Модели через запятую (default: gemma2:9b,qwen2.5:14b)")
    p_bench.add_argument("--ollama-host", help="Хост Ollama для бенчмарка")
    p_bench.add_argument("--ollama-port", type=int, help="Порт Ollama (default: 11434)")
    p_bench.add_argument("--skip-baselines", action="store_true", default=True,
                         help="Пропустить baseline-модели")
    p_bench.add_argument("-o", "--output", default="benchmark_results.csv", help="Файл результатов")

    p_profile = subparsers.add_parser("profile", help="Профилирование APT-группы или ПО")
    p_profile.add_argument("query", nargs="+", help="Запрос: G0032, 'APT28', S0154, 'Cobalt Strike'")
    p_profile.add_argument("--type", choices=["auto", "group", "software"], default="auto",
                           help="Тип сущности (default: auto)")
    p_profile.add_argument("--model", default="gemma2:9b", help="Ollama модель (default: gemma2:9b)")
    p_profile.add_argument("--ollama-host", help="Хост Ollama (например 10.0.0.5)")
    p_profile.add_argument("--ollama-port", type=int, help="Порт Ollama (default: 11434)")
    p_profile.add_argument("--json", dest="json_output", action="store_true", help="Вывод в JSON формате")
    p_profile.add_argument("-o", "--output", help="Сохранить результат в файл")

    p_mitre = subparsers.add_parser("mitre-db", help="Пересоздать базу MITRE ATT&CK SQLite")

    p_sync = subparsers.add_parser("intel-sync", help="Импорт internal intel из STIX JSON (OpenCTI)")
    p_sync.add_argument("--stix", required=True, help="Путь к STIX JSON/BUNDLE файлу")
    mode_group = p_sync.add_mutually_exclusive_group()
    mode_group.add_argument("--replace-source", action="store_true",
                            help="Перед импортом очистить предыдущий слой этого source")
    mode_group.add_argument("--append", action="store_true",
                            help="Добавить/обновить записи (по умолчанию)")
    p_sync.add_argument("--source", default="opencti", help="Имя источника (default: opencti)")

    p_nvd = subparsers.add_parser("nvd", help="Управление локальной базой NVD CVE")
    nvd_group = p_nvd.add_mutually_exclusive_group(required=True)
    nvd_group.add_argument("--fetch", nargs="+", metavar="CVE", help="Загрузить конкретные CVE")
    nvd_group.add_argument("--update", action="store_true", help="Загрузить последние CVE (30 дней)")
    nvd_group.add_argument("--lookup", metavar="CVE", help="Поиск CVE в локальной базе")
    nvd_group.add_argument("--stats", action="store_true", help="Статистика базы")
    p_nvd.add_argument("--days", type=int, default=30, help="Количество дней для --update")

    p_survey = subparsers.add_parser("survey", help="Анализ ответов опроса SOC-аналитиков")
    p_survey.add_argument("-i", "--input", help="JSON-файл с ответами опроса")
    p_survey.add_argument("--demo", action="store_true", help="Запуск с демо-данными")
    p_survey.add_argument("--test-enrichment", action="store_true", help="Проверить покрытие системой")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 0

    commands = {
        "analyze": cmd_analyze,
        "enrich": cmd_enrich,
        "export": cmd_export,
        "profile": cmd_profile,
        "benchmark": cmd_benchmark,
        "mitre-db": cmd_mitre_db,
        "intel-sync": cmd_intel_sync,
        "rag-index": cmd_rag_index,
        "analyze-batch": cmd_analyze_batch,
        "nvd": cmd_nvd,
        "survey": cmd_survey,
    }

    try:
        return commands[args.command](args)
    except KeyboardInterrupt:
        print("\nПрервано пользователем.")
        return 130
    except Exception as e:
        print(f"\nОшибка: {e}", file=sys.stderr)
        if "--debug" in sys.argv:
            raise
        return 1


if __name__ == "__main__":
    sys.exit(main() or 0)
