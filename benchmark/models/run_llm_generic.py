"""
Универсальный LLM-экстрактор для бенчмарка.

Использует тот же гибридный подход (Regex + LLM),
но позволяет подставить любую модель через Ollama.

Использование:
    from models.run_llm_generic import extract_with_model
    result = extract_with_model(text, model_name="qwen2.5:14b")
"""

import re
import json
import sys
import ollama
from pathlib import Path

CHUNK_SIZE = 4000
OVERLAP = 500

REGEX_PATTERNS = {
    "ipv4": r"\b(?!127\.|10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.)(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    "domain": r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b",
    "hash": r"\b[a-fA-F0-9]{32,64}\b",
    "mitre": r"\bT\d{4}(?:\.\d{3})?\b",
    "cve": r"CVE-\d{4}-\d{4,7}",
}

IGNORE_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".png", ".jpg", ".js", ".html", ".json", ".css",
    ".msi", ".hta", ".crt", ".log", ".txt", ".reg", ".bat", ".ps1", ".vbs",
    ".xml", ".yml", ".yaml", ".ini", ".cfg", ".php", ".jpeg", ".gif",
    ".svg", ".woff", ".ttf",
}

# Оптимизированный промпт из prompts/extract_entities.txt
SYSTEM_PROMPT = """You are a Cyber Threat Intelligence (CTI) analyst. Extract structured threat intelligence entities from the provided text.

Guidelines:
- Extract ONLY entities that are explicitly mentioned or strongly implied in the text
- Do NOT extract IPs, domains, hashes, emails, or CVE numbers (these are extracted separately by regex)
- Focus on semantic entities: threat actors, malware families, tools, and targeted countries
- For EACH entity, provide a confidence score (0-100)
- Use standardized names when possible (e.g., "Lazarus Group" not "Lazarus")
- Respond ONLY with valid JSON, no additional text

Output format:
{"threat_actor": [{"name": "...", "confidence": N}], "malware": [{"name": "...", "confidence": N}], "tools": [{"name": "...", "confidence": N}], "targeted_countries": [{"name": "...", "confidence": N}]}"""


def _chunk_text(text: str) -> list[str]:
    chunks = []
    start = 0
    while start < len(text):
        chunks.append(text[start : start + CHUNK_SIZE])
        start += CHUNK_SIZE - OVERLAP
    return chunks


def _extract_regex(text: str) -> dict:
    """Regex-фаза: IoC + MITRE ID."""
    results = {
        "indicators": {"ipv4": set(), "domain": set(), "hash": set()},
        "attack_patterns": set(),
    }

    results["indicators"]["ipv4"].update(re.findall(REGEX_PATTERNS["ipv4"], text))

    sha256 = set(h for h in re.findall(r"\b[a-fA-F0-9]{64}\b", text))
    sha1 = set(h for h in re.findall(r"\b[a-fA-F0-9]{40}\b", text)) - sha256
    md5 = set(h for h in re.findall(r"\b[a-fA-F0-9]{32}\b", text)) - sha256 - sha1
    results["indicators"]["hash"] = sha256 | sha1 | md5

    results["attack_patterns"].update(re.findall(REGEX_PATTERNS["mitre"], text))

    raw_domains = re.finditer(REGEX_PATTERNS["domain"], text)
    for m in raw_domains:
        d = m.group(0).lower()
        if not any(d.endswith(x) for x in IGNORE_EXTENSIONS):
            results["indicators"]["domain"].add(d)

    return results


def _flatten_names(items) -> list[str]:
    """Рекурсивно извлекает строковые имена из любой структуры LLM-ответа."""
    result = []
    if isinstance(items, str):
        result.append(items)
    elif isinstance(items, dict):
        name = items.get("name", "")
        if isinstance(name, list):
            for n in name:
                result.extend(_flatten_names(n))
        elif isinstance(name, str) and name:
            result.append(name)
    elif isinstance(items, list):
        for item in items:
            result.extend(_flatten_names(item))
    return result


def _extract_llm(text: str, model_name: str) -> dict:
    """LLM-фаза: семантические сущности."""
    chunks = _chunk_text(text)

    all_actors = []
    all_malware = []
    all_tools = []

    for chunk in chunks:
        try:
            resp = ollama.chat(
                model=model_name,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": f"Extract entities from this text:\n\n{chunk}"},
                ],
                format="json",
                options={"temperature": 0.0, "num_ctx": 4096},
            )

            data = json.loads(resp["message"]["content"])

            all_actors.extend(_flatten_names(data.get("threat_actor", [])))
            all_malware.extend(_flatten_names(data.get("malware", [])))
            all_tools.extend(_flatten_names(data.get("tools", [])))

        except Exception as e:
            print(f"      [LLM Warning] {model_name}: {e}", file=sys.stderr)

    return {
        "threat_actor": list(set(all_actors)),
        "malware": list(set(all_malware)),
        "tools": list(set(all_tools)),
    }


def extract_with_model(text: str, model_name: str = "qwen2.5:14b") -> dict:
    """
    Полная гибридная экстракция: Regex + LLM.

    Args:
        text: Текст отчёта
        model_name: Имя модели в Ollama

    Returns:
        dict с ключами: threat_actor, malware, tools, attack_patterns, indicators
    """
    # Regex
    regex_results = _extract_regex(text)

    # LLM
    llm_results = _extract_llm(text, model_name)

    # Объединяем
    return {
        "threat_actor": llm_results["threat_actor"],
        "malware": llm_results["malware"],
        "tools": llm_results["tools"],
        "attack_patterns": list(regex_results["attack_patterns"]),
        "indicators": {
            k: list(v) for k, v in regex_results["indicators"].items()
        },
    }
