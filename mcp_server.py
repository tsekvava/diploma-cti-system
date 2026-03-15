"""
CTI Pipeline MCP Server — единый MCP-интерфейс для системы анализа киберугроз.

Предоставляет все возможности системы через MCP-протокол,
подключаемый к любому LLM-клиенту (Claude Desktop, Open WebUI, custom agent).

Tools:
  - summarize_report   — полный 7-этапный анализ CTI-отчёта
  - enrich_query       — обогащение запроса из MITRE ATT&CK
  - profile_entity     — профилирование APT-группы или ПО
  - export_stix        — экспорт результатов в STIX 2.1 Bundle
  - search_mitre       — поиск по базе MITRE ATT&CK
  - list_tactics       — список всех тактик Kill Chain
  - list_groups        — список APT-групп из базы

Resources:
  - mitre://stats       — статистика базы MITRE ATT&CK

Запуск:
    python3 mcp_server.py                     # stdio (для Claude Desktop)
    python3 mcp_server.py --transport sse     # SSE (для веб-клиентов)
"""

import json
import os
import sys
import sqlite3
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

# --- Пути ---
PROJECT_ROOT = Path(__file__).parent
DB_PATH = PROJECT_ROOT / "knowledge_base" / "mitre.db"

# --- Инициализация MCP ---
mcp = FastMCP(
    "CTI Pipeline",
    instructions="Automated Cyber Threat Intelligence analysis system for SOC. "
                 "Analyzes threat reports, enriches queries from MITRE ATT&CK, "
                 "profiles APT groups, and exports to OpenCTI/STIX. v1.0.0",
)

# --- Ленивая инициализация компонентов ---
_components = {}


def _build_ollama_url(host: str, port: int | None) -> str:
    raw = host.strip()
    if "://" not in raw:
        raw = f"http://{raw}"

    parsed = urlparse(raw)
    scheme = parsed.scheme or "http"
    hostname = parsed.hostname or parsed.path
    if not hostname:
        raise ValueError(f"Invalid Ollama host: {host}")

    final_port = port if port is not None else (parsed.port or 11434)
    return f"{scheme}://{hostname}:{final_port}"


def _configure_ollama(host: str | None, port: int | None):
    env_host = host or os.getenv("CTI_OLLAMA_HOST")
    env_port = port
    if env_port is None:
        raw_port = os.getenv("CTI_OLLAMA_PORT")
        if raw_port:
            try:
                env_port = int(raw_port)
            except ValueError:
                raise ValueError(f"Invalid CTI_OLLAMA_PORT: {raw_port}")

    if not env_host:
        return

    url = _build_ollama_url(env_host, env_port)
    os.environ["OLLAMA_HOST"] = url
    print(f"Ollama endpoint: {url}")


def _get_enricher():
    """Ленивая инициализация QueryEnricher."""
    if "enricher" not in _components:
        from knowledge_base.query_enricher import QueryEnricher
        _components["enricher"] = QueryEnricher()
    return _components["enricher"]


def _get_summarizer(model_name: str = "gemma2:9b"):
    """Ленивая инициализация ReportSummarizer."""
    key = f"summarizer_{model_name}"
    if key not in _components:
        from summarizer.report_summarizer import ReportSummarizer
        _components[key] = ReportSummarizer(model_name=model_name)
    return _components[key]


def _get_profiler(model_name: str = "gemma2:9b"):
    """Ленивая инициализация Profiler."""
    key = f"profiler_{model_name}"
    if key not in _components:
        from summarizer.profiler import Profiler
        _components[key] = Profiler(model_name=model_name)
    return _components[key]


def _get_db():
    """Прямое подключение к SQLite для лёгких запросов."""
    if "db" not in _components:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        _components["db"] = conn
    return _components["db"]


# ================================================================
#  TOOLS
# ================================================================


@mcp.tool()
def summarize_report(
    text: str,
    model: str = "gemma2:9b",
    source: str = "mcp-input",
) -> str:
    """Полный анализ CTI-отчёта: извлечение сущностей, нормализация,
    Kill Chain маппинг, генерация аналитической записки на русском.

    Принимает неструктурированный текст отчёта об угрозах и возвращает:
    - Threat Actors с MITRE ID и confidence
    - Malware и Tools с нормализованными именами
    - Kill Chain маппинг с привязкой к ATT&CK
    - IoC (IP, домены, хеши, CVE, email)
    - Аналитическую записку на русском языке

    Args:
        text: Текст CTI-отчёта для анализа
        model: Ollama модель (default: gemma2:9b)
        source: Имя источника для метаданных
    """
    input_metadata = {}
    candidate_path = Path(str(text).strip()).expanduser()
    if candidate_path.exists() and candidate_path.is_file():
        try:
            from summarizer.input_loader import load_report_file
            loaded = load_report_file(candidate_path)
            text = loaded.text
            if source == "mcp-input":
                source = loaded.source
            input_metadata = {
                "input_format": loaded.input_format,
                "pages": loaded.pages,
                "ocr_used": loaded.ocr_used,
                "parse_warnings": loaded.parse_warnings,
            }
        except Exception as e:
            return json.dumps({"status": "error", "error": f"Failed to parse input file: {e}"})

    summarizer = _get_summarizer(model)
    result = summarizer.process(text, source=source, input_metadata=input_metadata)

    # Формируем ответ
    output = {
        "status": "success",
        "processing_time": round(result.get("processing_time", 0), 1),
        "analysis": result["json"],
    }

    # Добавляем текстовые результаты
    if result.get("summary_en"):
        output["summary_en"] = result["summary_en"]
    if result.get("note_ru"):
        output["note_ru"] = result["note_ru"]

    return json.dumps(output, indent=2, ensure_ascii=False)


@mcp.tool()
def enrich_query(query: str) -> str:
    """Обогащение CTI-запроса данными из локальной базы MITRE ATT&CK.

    Определяет тип сущности (техника, тактика, APT-группа, ПО, CVE)
    и возвращает полный контекст из верифицированной БД.

    Поддерживаемые форматы:
    - MITRE Technique: T1059, T1059.001
    - MITRE Tactic: TA0002
    - APT Group: G0032, "APT28", "Lazarus Group"
    - Software: S0154, "Cobalt Strike"
    - Mitigation: M1036
    - Data Source: DS0026
    - CVE: CVE-2024-38063

    Args:
        query: Идентификатор или имя сущности
    """
    enricher = _get_enricher()
    result = enricher.enrich(query)

    output = {
        "query": result["query"],
        "detected": result["detected"],
        "enrichments_count": len(result["enrichments"]),
        "enrichments": result["enrichments"],
        "context": result["context_for_llm"],
    }

    return json.dumps(output, indent=2, ensure_ascii=False)


@mcp.tool()
def profile_entity(
    query: str,
    entity_type: str = "auto",
    model: str = "gemma2:9b",
) -> str:
    """Генерация полного профиля APT-группы или вредоносного ПО.

    Создаёт детальный аналитический профиль на основе MITRE ATT&CK:
    - Executive Summary
    - Attribution & Aliases
    - Target Profile (для групп)
    - Tactics & Techniques Summary
    - Detection Recommendations
    - Mitigation Priorities
    - Версия на русском языке

    Args:
        query: Имя или ID сущности (APT28, G0032, Cobalt Strike, S0154)
        entity_type: Тип: "auto", "group", "software"
        model: Ollama модель (default: gemma2:9b)
    """
    profiler = _get_profiler(model)

    if entity_type == "group":
        result = profiler.profile_group(query)
    elif entity_type == "software":
        result = profiler.profile_software(query)
    else:
        result = profiler.profile(query)

    if "error" in result:
        return json.dumps({"status": "error", "error": result["error"]})

    # Убираем сырые данные для компактности
    output = {k: v for k, v in result.items() if k != "data"}
    output["status"] = "success"

    return json.dumps(output, indent=2, ensure_ascii=False)


@mcp.tool()
def export_stix(
    analysis_json: str,
    tlp: str = "TLP:AMBER",
) -> str:
    """Экспорт результатов анализа в STIX 2.1 Bundle (JSON).

    Создаёт полный STIX Bundle из результата анализа, пригодный
    для импорта в OpenCTI или другие STIX-совместимые платформы.

    Объекты: Intrusion Sets, Malware, Tools, Attack Patterns,
    Vulnerabilities, Indicators, Relationships, TLP Marking.

    Args:
        analysis_json: JSON-строка с результатом анализа (от summarize_report)
        tlp: TLP-маркировка (TLP:WHITE, TLP:GREEN, TLP:AMBER, TLP:RED)
    """
    from opencti_exporter import OpenCTIExporter

    try:
        data = json.loads(analysis_json)
    except json.JSONDecodeError as e:
        return json.dumps({"status": "error", "error": f"Invalid JSON: {e}"})

    exporter = OpenCTIExporter(tlp=tlp, dry_run=True)
    bundle = exporter.export_stix_bundle(data)

    return json.dumps({
        "status": "success",
        "bundle_type": bundle.get("type", "bundle"),
        "objects_count": len(bundle.get("objects", [])),
        "stix_bundle": bundle,
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def search_mitre(
    query: str,
    category: str = "all",
    limit: int = 10,
) -> str:
    """Поиск по базе MITRE ATT&CK (техники, тактики, группы, ПО).

    Выполняет текстовый поиск по локальной SQLite базе и возвращает
    совпадающие записи с ID, именами и описаниями.

    Args:
        query: Поисковый запрос (текст или часть названия)
        category: Категория поиска: "all", "techniques", "groups", "software", "tactics"
        limit: Максимум результатов (default: 10)
    """
    db = _get_db()
    cur = db.cursor()
    q = f"%{query.lower().strip()}%"
    results = []

    if category in ("all", "techniques"):
        cur.execute(
            "SELECT id, name_en, name_ru, tactic_id FROM techniques "
            "WHERE LOWER(name_en) LIKE ? OR LOWER(name_ru) LIKE ? OR id LIKE ? "
            "ORDER BY id LIMIT ?",
            (q, q, q, limit),
        )
        for r in cur.fetchall():
            results.append({
                "category": "technique",
                "id": r["id"],
                "name_en": r["name_en"],
                "name_ru": r["name_ru"] or "",
                "tactic_id": r["tactic_id"] or "",
            })

    if category in ("all", "groups"):
        cur.execute(
            "SELECT id, name, aliases, country FROM groups "
            "WHERE LOWER(name) LIKE ? OR LOWER(aliases) LIKE ? OR id LIKE ? "
            "ORDER BY id LIMIT ?",
            (q, q, q, limit),
        )
        for r in cur.fetchall():
            results.append({
                "category": "group",
                "id": r["id"],
                "name": r["name"],
                "aliases": json.loads(r["aliases"]) if r["aliases"] else [],
                "country": r["country"] or "",
            })

    if category in ("all", "software"):
        cur.execute(
            "SELECT id, name, type, aliases FROM software "
            "WHERE LOWER(name) LIKE ? OR LOWER(aliases) LIKE ? OR id LIKE ? "
            "ORDER BY id LIMIT ?",
            (q, q, q, limit),
        )
        for r in cur.fetchall():
            results.append({
                "category": "software",
                "id": r["id"],
                "name": r["name"],
                "type": r["type"],
                "aliases": json.loads(r["aliases"]) if r["aliases"] else [],
            })

    if category in ("all", "tactics"):
        cur.execute(
            "SELECT id, name_en, name_ru, kill_chain_order FROM tactics "
            "WHERE LOWER(name_en) LIKE ? OR LOWER(name_ru) LIKE ? OR id LIKE ? "
            "ORDER BY kill_chain_order LIMIT ?",
            (q, q, q, limit),
        )
        for r in cur.fetchall():
            results.append({
                "category": "tactic",
                "id": r["id"],
                "name_en": r["name_en"],
                "name_ru": r["name_ru"] or "",
                "kill_chain_order": r["kill_chain_order"],
            })

    return json.dumps({
        "query": query,
        "category": category,
        "results_count": len(results),
        "results": results[:limit],
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def list_tactics() -> str:
    """Список всех 14 тактик MITRE ATT&CK Kill Chain.

    Возвращает полный список тактик в порядке Kill Chain
    с русскими и английскими названиями, количеством техник.
    """
    db = _get_db()
    cur = db.cursor()

    cur.execute(
        "SELECT id, name_en, name_ru, kill_chain_order FROM tactics "
        "ORDER BY kill_chain_order"
    )
    tactics = []
    for r in cur.fetchall():
        # Подсчёт техник
        cur2 = db.cursor()
        cur2.execute(
            "SELECT COUNT(*) as cnt FROM techniques WHERE tactic_id = ? AND is_subtechnique = 0",
            (r["id"],),
        )
        count = cur2.fetchone()["cnt"]

        tactics.append({
            "id": r["id"],
            "name_en": r["name_en"],
            "name_ru": r["name_ru"] or "",
            "order": r["kill_chain_order"],
            "techniques_count": count,
        })

    return json.dumps({
        "total": len(tactics),
        "tactics": tactics,
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def list_groups(
    country: str = "",
    limit: int = 20,
) -> str:
    """Список APT-групп из базы MITRE ATT&CK.

    Возвращает APT-группы с именами, алиасами, страной
    и количеством связанных техник.

    Args:
        country: Фильтр по стране (пустой = все)
        limit: Максимум результатов (default: 20)
    """
    db = _get_db()
    cur = db.cursor()

    if country:
        cur.execute(
            "SELECT id, name, aliases, country FROM groups "
            "WHERE LOWER(country) LIKE ? ORDER BY name LIMIT ?",
            (f"%{country.lower()}%", limit),
        )
    else:
        cur.execute(
            "SELECT id, name, aliases, country FROM groups ORDER BY name LIMIT ?",
            (limit,),
        )

    groups = []
    for r in cur.fetchall():
        # Подсчёт техник
        cur2 = db.cursor()
        cur2.execute(
            "SELECT COUNT(*) as cnt FROM group_techniques WHERE group_id = ?",
            (r["id"],),
        )
        tech_count = cur2.fetchone()["cnt"]

        groups.append({
            "id": r["id"],
            "name": r["name"],
            "aliases": json.loads(r["aliases"]) if r["aliases"] else [],
            "country": r["country"] or "",
            "techniques_count": tech_count,
        })

    return json.dumps({
        "total": len(groups),
        "filter_country": country or "all",
        "groups": groups,
    }, indent=2, ensure_ascii=False)


# ================================================================
#  RESOURCES
# ================================================================


@mcp.resource("mitre://stats")
def mitre_stats() -> str:
    """Статистика базы MITRE ATT&CK: количество техник, групп, ПО, тактик."""
    db = _get_db()
    cur = db.cursor()

    stats = {}
    for table, label in [
        ("techniques", "techniques_total"),
        ("tactics", "tactics"),
        ("groups", "groups"),
        ("software", "software"),
        ("mitigations", "mitigations"),
        ("data_sources", "data_sources"),
    ]:
        try:
            cur.execute(f"SELECT COUNT(*) as cnt FROM {table}")
            stats[label] = cur.fetchone()["cnt"]
        except Exception:
            stats[label] = 0

    # Подтехники
    try:
        cur.execute("SELECT COUNT(*) as cnt FROM techniques WHERE is_subtechnique = 1")
        stats["subtechniques"] = cur.fetchone()["cnt"]
        stats["base_techniques"] = stats["techniques_total"] - stats["subtechniques"]
    except Exception:
        pass

    # Software breakdown
    try:
        cur.execute("SELECT type, COUNT(*) as cnt FROM software GROUP BY type")
        for r in cur.fetchall():
            stats[f"software_{r['type']}"] = r["cnt"]
    except Exception:
        pass

    return json.dumps(stats, indent=2)


# ================================================================
#  PROMPTS
# ================================================================


@mcp.prompt()
def analyze_threat_report(report_text: str) -> str:
    """Шаблон промпта для анализа CTI-отчёта с использованием инструментов."""
    return (
        "You are a senior Cyber Threat Intelligence analyst. "
        "Analyze the following threat report and use the available tools:\n\n"
        "1. Use `summarize_report` to extract all entities, map Kill Chain, and generate analysis\n"
        "2. Use `enrich_query` to get additional context on identified techniques/groups\n"
        "3. Use `profile_entity` to generate profiles for notable threat actors\n"
        "4. Use `export_stix` to create a STIX Bundle for OpenCTI import\n\n"
        f"Report text:\n{report_text}"
    )


@mcp.prompt()
def investigate_actor(actor_name: str) -> str:
    """Шаблон промпта для расследования APT-группы."""
    return (
        f"Investigate the threat actor '{actor_name}' using available tools:\n\n"
        f"1. Use `enrich_query` with '{actor_name}' to find the MITRE ID\n"
        f"2. Use `profile_entity` to generate a full profile\n"
        f"3. Use `search_mitre` to find related techniques and software\n"
        f"4. Summarize findings in Russian for SOC analysts"
    )


@mcp.prompt()
def enrich_technique(technique_id: str) -> str:
    """Шаблон промпта для обогащения информации о технике ATT&CK."""
    return (
        f"Enrich information about MITRE ATT&CK technique {technique_id}:\n\n"
        f"1. Use `enrich_query` with '{technique_id}' to get full context\n"
        f"2. Use `search_mitre` to find related groups using this technique\n"
        f"3. Provide detection recommendations and mitigations in Russian"
    )


# ================================================================
#  ENTRY POINT
# ================================================================


def main():
    import argparse

    parser = argparse.ArgumentParser(description="CTI Pipeline MCP Server")
    parser.add_argument(
        "--transport", choices=["stdio", "sse"], default="stdio",
        help="Transport: stdio (Claude Desktop) or sse (web clients)",
    )
    parser.add_argument("--port", type=int, default=8000, help="Port for SSE transport")
    parser.add_argument("--ollama-host", help="Ollama host (e.g. 127.0.0.1 or ollama.internal)")
    parser.add_argument("--ollama-port", type=int, help="Ollama port (default: 11434)")
    args = parser.parse_args()

    _configure_ollama(args.ollama_host, args.ollama_port)

    if args.transport == "sse":
        mcp.run(transport="sse", port=args.port)
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
