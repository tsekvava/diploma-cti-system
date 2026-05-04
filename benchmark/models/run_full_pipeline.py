"""
Full Pipeline экстрактор для бенчмарка.

В отличие от run_llm_generic.py (только Regex + LLM), использует
полный пайплайн ReportSummarizer:
  1. Regex IoC
  2. LLM Entity Extraction
  3. EntityNormalizer (3-уровневый: exact → alias → fuzzy)
  4. AttackMapper (2-этапный Kill Chain: tactics → techniques)
  5. Confidence Scoring

Использование:
    from models.run_full_pipeline import extract_full_pipeline
    result = extract_full_pipeline(text, model_name="qwen2.5:14b")
"""

import re
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def extract_full_pipeline(text: str, model_name: str = "qwen2.5:14b",
                          skip_normalize: bool = False,
                          skip_kill_chain: bool = False,
                          skip_confidence: bool = False,
                          no_chunk: bool = False,
                          ollama_host: str = "localhost",
                          ollama_port: int = 11434) -> dict:
    """
    Полная экстракция через ReportSummarizer.

    Args:
        text: Текст отчёта
        model_name: Имя модели в Ollama
        skip_normalize: Пропустить EntityNormalizer (для ablation)
        skip_kill_chain: Пропустить AttackMapper (для ablation)
        skip_confidence: Пропустить Confidence Scoring (для ablation)
        no_chunk: Не разбивать на чанки (для ablation)

    Returns:
        dict совместимый с benchmark evaluate:
        {threat_actor, malware, tools, attack_patterns, indicators}
    """
    from summarizer.report_summarizer import ReportSummarizer

    summarizer = ReportSummarizer(
        model_name=model_name,
    )

    # Для ablation: patch настроек
    if no_chunk:
        summarizer.chunk_size = 100000
        summarizer.overlap = 0

    # Этап 1: Regex IoC
    ioc = summarizer._extract_ioc_regex(text)

    # Этап 2: LLM Entity Extraction
    llm_data = summarizer._extract_entities_llm(text)
    raw_confidence = llm_data.get("_raw_with_confidence", {})

    # Объединяем regex + LLM
    combined = {
        "threat_actor": llm_data["threat_actor"],
        "malware": llm_data["malware"],
        "tools": llm_data["tools"],
        "targeted_countries": llm_data.get("targeted_countries", []),
        "indicators": ioc["indicators"],
        "vulnerabilities": ioc.get("vulnerabilities", []),
    }

    # Этап 3: Нормализация
    if skip_normalize:
        # Без нормализации — оставляем как есть, но в формате normalizer output
        normalized = {
            "threat_actor": [{"name": a, "original": a, "normalized": False, "match_type": "none"}
                             for a in combined.get("threat_actor", [])],
            "malware": [{"name": m, "original": m, "normalized": False, "match_type": "none"}
                        for m in combined.get("malware", [])],
            "tools": [{"name": t, "original": t, "normalized": False, "match_type": "none"}
                      for t in combined.get("tools", [])],
            "indicators": combined.get("indicators", {}),
            "vulnerabilities": combined.get("vulnerabilities", []),
        }
    else:
        normalized = summarizer._normalize_entities(combined)

    # Этап 4: Kill Chain
    if skip_kill_chain:
        kill_chain = {"kill_chain_phases": []}
    else:
        try:
            kill_chain = summarizer._map_kill_chain(text)
        except Exception as e:
            print(f"    [!] Kill Chain failed: {e}")
            kill_chain = {"kill_chain_phases": []}

    # Этап 5: Confidence
    if not skip_confidence:
        summarizer._apply_confidence(normalized, raw_confidence, kill_chain)

    # Конвертируем в формат бенчмарка
    result = {
        "threat_actor": [a["name"] if isinstance(a, dict) else a
                         for a in normalized.get("threat_actor", [])],
        "malware": [m["name"] if isinstance(m, dict) else m
                    for m in normalized.get("malware", [])],
        "tools": [t["name"] if isinstance(t, dict) else t
                  for t in normalized.get("tools", [])],
        "attack_patterns": [],
        "indicators": {},
    }

    # Attack patterns из Kill Chain
    for phase in kill_chain.get("kill_chain_phases", []):
        for tech in phase.get("techniques", []):
            tech_id = tech.get("id", "")
            tech_name = tech.get("name_en", tech.get("name", ""))
            if tech_id:
                result["attack_patterns"].append(f"{tech_name} ({tech_id})")
            elif tech_name:
                result["attack_patterns"].append(tech_name)

    # Добавляем T-коды из regex (если AttackMapper их не нашёл)
    existing_ids = set(re.findall(r"T\d{4}(?:\.\d{3})?", " ".join(result["attack_patterns"])))
    for pattern in ioc.get("attack_patterns", []):
        t_ids = re.findall(r"T\d{4}(?:\.\d{3})?", str(pattern))
        for tid in t_ids:
            if tid not in existing_ids:
                result["attack_patterns"].append(tid)
                existing_ids.add(tid)

    # IoC
    indicators = normalized.get("indicators", {})
    result["indicators"] = {
        "ipv4": list(indicators.get("ipv4", [])),
        "domain": list(indicators.get("domain", [])),
        "hash": list(indicators.get("hash", [])),
    }

    return result
