#!/usr/bin/env python3
"""
CTI Pipeline CLI — единая точка входа для системы анализа киберугроз.

Команды:
  analyze   — полный анализ отчёта (7-этапный пайплайн)
  enrich    — обогащение запроса из MITRE ATT&CK БД
  export    — экспорт результатов в OpenCTI (API или STIX Bundle)
  benchmark — запуск бенчмарка моделей
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
  python3 cli.py mitre-db
"""

import argparse
import json
import sys
import time
from pathlib import Path

# Корень проекта
ROOT = Path(__file__).parent


def cmd_analyze(args):
    """Полный 7-этапный анализ отчёта."""
    from summarizer.report_summarizer import ReportSummarizer

    # Чтение текста
    if args.file:
        if not Path(args.file).exists():
            print(f"Файл не найден: {args.file}")
            return 1
        with open(args.file, "r", encoding="utf-8") as f:
            text = f.read()
        source = Path(args.file).name
    elif args.text:
        text = args.text
        source = "cli-input"
    else:
        # Читаем из stdin
        print("Введите текст отчёта (Ctrl+D для завершения):")
        text = sys.stdin.read()
        source = "stdin"

    if not text.strip():
        print("Пустой текст. Нечего анализировать.")
        return 1

    print(f"\n{'=' * 60}")
    print(f"CTI PIPELINE — Анализ отчёта")
    print(f"Источник: {source}")
    print(f"Модель:   {args.model}")
    print(f"Длина:    {len(text)} символов")
    print(f"{'=' * 60}\n")

    # Инициализация
    summarizer = ReportSummarizer(model_name=args.model)

    # Запуск пайплайна
    result = summarizer.process(text, source=source)

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

    # Автоматический STIX Bundle экспорт
    if args.export:
        from opencti_exporter import OpenCTIExporter
        exporter = OpenCTIExporter(tlp=args.tlp, dry_run=True)
        exporter.export_stix_bundle(result["json"], output_path=args.export)

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

    print(f"Запуск: {' '.join(cmd)}\n")
    return subprocess.call(cmd)


def cmd_profile(args):
    """Генерация профиля APT-группы или ПО."""
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
  %(prog)s analyze -f report.txt --model gemma2:9b --export bundle.json
  %(prog)s enrich T1059
  %(prog)s enrich "Lazarus Group" --json
  %(prog)s profile "APT28"
  %(prog)s profile "Cobalt Strike" --type software
  %(prog)s export -i result.json --dry-run
  %(prog)s export -i result.json --stix-bundle output.json
  %(prog)s benchmark --models "gemma2:9b,qwen2.5:14b"
        """,
    )
    subparsers = parser.add_subparsers(dest="command", help="Доступные команды")

    # ── analyze ──
    p_analyze = subparsers.add_parser("analyze", help="Полный анализ CTI-отчёта")
    input_group = p_analyze.add_mutually_exclusive_group()
    input_group.add_argument("-f", "--file", help="Путь к текстовому файлу отчёта")
    input_group.add_argument("-t", "--text", help="Текст отчёта напрямую")
    p_analyze.add_argument("--model", default="gemma2:9b", help="Ollama модель (default: gemma2:9b)")
    p_analyze.add_argument("-o", "--output", help="Сохранить JSON результат в файл")
    p_analyze.add_argument("--json", dest="json_output", action="store_true", help="Вывести только JSON")
    p_analyze.add_argument("--export", metavar="FILE", help="Автоматически экспортировать STIX Bundle")
    p_analyze.add_argument("--tlp", default="TLP:AMBER", help="TLP-маркировка (default: TLP:AMBER)")

    # ── enrich ──
    p_enrich = subparsers.add_parser("enrich", help="Обогащение запроса из MITRE ATT&CK")
    p_enrich.add_argument("query", nargs="+", help="Запрос: T1059, G0032, 'Cobalt Strike', CVE-2024-38063")
    p_enrich.add_argument("--json", dest="json_output", action="store_true", help="Вывод в JSON формате")

    # ── export ──
    p_export = subparsers.add_parser("export", help="Экспорт результатов в OpenCTI")
    p_export.add_argument("-i", "--input", required=True, help="JSON-файл результатов анализа")
    p_export.add_argument("--dry-run", action="store_true", help="Показать что будет создано без подключения")
    p_export.add_argument("--stix-bundle", "-s", metavar="FILE", help="Экспорт как STIX 2.1 Bundle JSON")
    p_export.add_argument("--tlp", default="TLP:AMBER", help="TLP-маркировка (default: TLP:AMBER)")
    p_export.add_argument("--url", default=None, help="OpenCTI URL")
    p_export.add_argument("--token", default=None, help="OpenCTI API token")

    # ── benchmark ──
    p_bench = subparsers.add_parser("benchmark", help="Бенчмарк LLM-моделей")
    p_bench.add_argument("--models", default="gemma2:9b,qwen2.5:14b",
                         help="Модели через запятую (default: gemma2:9b,qwen2.5:14b)")
    p_bench.add_argument("--skip-baselines", action="store_true", default=True,
                         help="Пропустить baseline-модели")
    p_bench.add_argument("-o", "--output", default="benchmark_results.csv", help="Файл результатов")

    # ── profile ──
    p_profile = subparsers.add_parser("profile", help="Профилирование APT-группы или ПО")
    p_profile.add_argument("query", nargs="+", help="Запрос: G0032, 'APT28', S0154, 'Cobalt Strike'")
    p_profile.add_argument("--type", choices=["auto", "group", "software"], default="auto",
                           help="Тип сущности (default: auto)")
    p_profile.add_argument("--model", default="gemma2:9b", help="Ollama модель (default: gemma2:9b)")
    p_profile.add_argument("--json", dest="json_output", action="store_true", help="Вывод в JSON формате")
    p_profile.add_argument("-o", "--output", help="Сохранить результат в файл")

    # ── mitre-db ──
    p_mitre = subparsers.add_parser("mitre-db", help="Пересоздать базу MITRE ATT&CK SQLite")

    # ── survey ──
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
