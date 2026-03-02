"""
ReportSummarizer — полный пайплайн суммаризации CTI-отчётов.

Оркестрирует все компоненты:
  1. Regex-экстракция IoC (IP, домены, хеши, CVE, email)
  2. LLM-экстракция семантических сущностей (actors, malware, tools)
  3. Нормализация к MITRE ATT&CK (EntityNormalizer)
  4. Kill Chain маппинг (AttackMapper)
  5. Confidence Score (post-processing с бонусами нормализации)
  6. LLM-суммаризация (EN)
  7. Перевод EN→RU (Translator)
  8. Генерация аналитической записки (два формата: JSON + текст)

Два выходных формата:
  - JSON: для OpenCTI и машинной обработки
  - Аналитическая записка: для SOC-аналитика на русском языке

Использование:
    from summarizer.report_summarizer import ReportSummarizer
    summarizer = ReportSummarizer()
    result = summarizer.process("text of threat report...")
    print(result["note_ru"])  # Аналитическая записка
"""

import json
import re
import time
import ollama
from datetime import datetime
from pathlib import Path
from typing import Optional

from knowledge_base.normalizer import EntityNormalizer
from knowledge_base.attack_mapper import AttackMapper
from summarizer.translator import Translator

PROJECT_ROOT = Path(__file__).parent.parent
DEFAULT_MODEL = "qwen2.5:14b"

# --- Regex-паттерны для IoC ---
REGEX_PATTERNS = {
    "ipv4": r"\b(?!127\.|10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.)(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    "domain": r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b",
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "sha1": r"\b[a-fA-F0-9]{40}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "cve": r"CVE-\d{4}-\d{4,7}",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
}

IGNORE_EXTENSIONS = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif",
    ".svg", ".woff", ".ttf", ".html", ".php",
}
IGNORE_DOMAINS = {
    "sophos.com", "google.com", "microsoft.com", "schema.org",
    "w3.org", "twitter.com", "linkedin.com", "github.com",
    "wikipedia.org", "example.com",
}

CHUNK_SIZE = 5000
OVERLAP = 500


class ReportSummarizer:
    """Полный пайплайн суммаризации CTI-отчёта."""

    def __init__(
        self,
        model_name: str = DEFAULT_MODEL,
        normalizer: Optional[EntityNormalizer] = None,
        mapper: Optional[AttackMapper] = None,
        translator: Optional[Translator] = None,
    ):
        self.model_name = model_name
        print(f"[ReportSummarizer] Инициализация (модель: {model_name})...")

        self.normalizer = normalizer or EntityNormalizer()
        self.mapper = mapper or AttackMapper(model_name=model_name, normalizer=self.normalizer)
        self.translator = translator or Translator(model_name=model_name)

        self._load_prompts()
        print("[ReportSummarizer] Готов к работе.\n")

    def _load_prompts(self):
        """Загружает промпты из файлов."""
        prompts_dir = PROJECT_ROOT / "prompts"

        def load(name: str, fallback: str) -> str:
            path = prompts_dir / name
            if path.exists():
                return path.read_text(encoding="utf-8")
            return fallback

        self._extract_prompt = load(
            "extract_entities.txt",
            "Extract threat_actor, malware, tools, targeted_countries from this text. "
            "Return JSON.\n\n{text}",
        )
        self._summarize_prompt = load(
            "summarize.txt",
            "Write a concise analytical summary of this threat report.\n\n{text}",
        )

    # ──────────────────────────────────────────────
    #  ЭТАП 1: Regex-экстракция IoC
    # ──────────────────────────────────────────────

    def _extract_ioc_regex(self, text: str) -> dict:
        """Фаза 1: детерминированная экстракция IoC."""
        print("   [1/7] Regex-экстракция IoC...")

        indicators = {"ipv4": [], "domain": [], "hash": [], "email": []}

        # IP
        ips = list(set(re.findall(REGEX_PATTERNS["ipv4"], text)))
        indicators["ipv4"] = sorted(ips)

        # Хеши (дедупликация: sha256 содержит sha1, sha1 содержит md5)
        sha256 = set(re.findall(REGEX_PATTERNS["sha256"], text))
        sha1 = set(re.findall(REGEX_PATTERNS["sha1"], text)) - sha256
        md5 = set(re.findall(REGEX_PATTERNS["md5"], text)) - sha256 - sha1
        indicators["hash"] = sorted(sha256 | sha1 | md5)

        # CVE
        cves = sorted(set(re.findall(REGEX_PATTERNS["cve"], text)))

        # Домены (с фильтрацией)
        domains = set()
        for match in re.finditer(REGEX_PATTERNS["domain"], text):
            domain = match.group(0).lower()
            if any(domain.endswith(ext) for ext in IGNORE_EXTENSIONS):
                continue
            if domain in IGNORE_DOMAINS:
                continue
            # Фильтруем слишком короткие (< 4 символов до TLD)
            parts = domain.split(".")
            if len(parts) >= 2 and len(parts[-2]) >= 2:
                domains.add(domain)
        indicators["domain"] = sorted(domains)

        # Email
        emails = sorted(set(re.findall(REGEX_PATTERNS["email"], text)))
        indicators["email"] = emails

        total_ioc = sum(len(v) for v in indicators.values()) + len(cves)
        print(f"         Найдено: {len(ips)} IP, {len(indicators['hash'])} хешей, "
              f"{len(domains)} доменов, {len(cves)} CVE, {len(emails)} email "
              f"(итого IoC: {total_ioc})")

        return {"indicators": indicators, "vulnerabilities": cves}

    # ──────────────────────────────────────────────
    #  ЭТАП 2: LLM-экстракция сущностей
    # ──────────────────────────────────────────────

    def _extract_entities_llm(self, text: str) -> dict:
        """Фаза 2: LLM извлекает семантические сущности с confidence."""
        print("   [2/7] LLM-экстракция сущностей...")

        chunks = self._chunk_text(text)
        print(f"         Текст разделён на {len(chunks)} чанков")

        all_actors = []
        all_malware = []
        all_tools = []
        all_countries = []

        for i, chunk in enumerate(chunks):
            print(f"         Чанк {i + 1}/{len(chunks)}...")
            prompt = self._extract_prompt.replace("{text}", chunk)

            try:
                response = ollama.chat(
                    model=self.model_name,
                    messages=[
                        {
                            "role": "system",
                            "content": (
                                "You are a Cyber Threat Intelligence expert. "
                                "Respond ONLY with valid JSON."
                            ),
                        },
                        {"role": "user", "content": prompt},
                    ],
                    format="json",
                    options={"temperature": 0.1, "num_ctx": 8192},
                )
                data = json.loads(response["message"]["content"])

                # Каждый элемент: {"name": "...", "confidence": N}
                all_actors.extend(data.get("threat_actor", []))
                all_malware.extend(data.get("malware", []))
                all_tools.extend(data.get("tools", []))
                all_countries.extend(data.get("targeted_countries", []))

            except Exception as e:
                print(f"         [!] Ошибка чанка {i + 1}: {e}")

        # Дедупликация по имени (берём максимальный confidence)
        actors = self._dedup_entities(all_actors)
        malware = self._dedup_entities(all_malware)
        tools = self._dedup_entities(all_tools)
        countries = self._dedup_entities(all_countries)

        print(f"         Найдено: {len(actors)} actors, {len(malware)} malware, "
              f"{len(tools)} tools, {len(countries)} countries")

        return {
            "threat_actor": [e["name"] for e in actors],
            "malware": [e["name"] for e in malware],
            "tools": [e["name"] for e in tools],
            "targeted_countries": [e["name"] for e in countries],
            "_raw_with_confidence": {
                "threat_actor": actors,
                "malware": malware,
                "tools": tools,
                "targeted_countries": countries,
            },
        }

    @staticmethod
    def _dedup_entities(entities: list) -> list:
        """Дедупликация: берём максимальный confidence при совпадении имени."""
        seen = {}
        for ent in entities:
            if isinstance(ent, str):
                name = ent
                conf = 75  # default
            elif isinstance(ent, dict):
                name = ent.get("name", "")
                conf = ent.get("confidence", 75)
            else:
                continue

            key = name.strip().lower()
            if not key:
                continue

            if key not in seen or conf > seen[key]["confidence"]:
                seen[key] = {"name": name.strip(), "confidence": conf}

        return sorted(seen.values(), key=lambda x: -x["confidence"])

    # ──────────────────────────────────────────────
    #  ЭТАП 3: Нормализация к MITRE ATT&CK
    # ──────────────────────────────────────────────

    def _normalize_entities(self, raw: dict) -> dict:
        """Фаза 3: нормализация всех сущностей через EntityNormalizer."""
        print("   [3/7] Нормализация сущностей к MITRE ATT&CK...")
        normalized = self.normalizer.normalize_all(raw)

        n_actors = sum(1 for a in normalized.get("threat_actor", []) if a.get("normalized"))
        n_sw = sum(1 for s in normalized.get("malware", []) + normalized.get("tools", []) if s.get("normalized"))
        print(f"         Нормализовано: {n_actors} actors, {n_sw} software")

        return normalized

    # ──────────────────────────────────────────────
    #  ЭТАП 4: Kill Chain маппинг
    # ──────────────────────────────────────────────

    def _map_kill_chain(self, text: str) -> dict:
        """Фаза 4: маппинг текста на MITRE ATT&CK Kill Chain."""
        print("   [4/7] Kill Chain маппинг...")
        return self.mapper.map_text(text)

    # ──────────────────────────────────────────────
    #  ЭТАП 5: Confidence Score (post-processing)
    # ──────────────────────────────────────────────

    def _apply_confidence(self, normalized: dict, raw_confidence: dict, kill_chain: dict) -> dict:
        """
        Фаза 5: корректировка confidence на основе верификации.

        Правила:
          - IoC (regex): confidence = 100 (детерминированно)
          - Нормализация exact match: +10
          - Нормализация alias match: +5
          - Нормализация fuzzy match: +0
          - Не нормализовано: -10
          - Kill Chain техника валидирована: +5 к технике
          - Kill Chain техника не валидирована: -20 к технике
        """
        print("   [5/7] Корректировка Confidence Score...")

        # Confidence для actors
        for actor in normalized.get("threat_actor", []):
            base = self._get_base_confidence(actor["original"], raw_confidence.get("threat_actor", []))
            bonus = actor.get("confidence_bonus", 0)
            actor["confidence"] = self._clamp(base + bonus)

        # Confidence для malware
        for mal in normalized.get("malware", []):
            base = self._get_base_confidence(mal["original"], raw_confidence.get("malware", []))
            bonus = mal.get("confidence_bonus", 0)
            mal["confidence"] = self._clamp(base + bonus)

        # Confidence для tools
        for tool in normalized.get("tools", []):
            base = self._get_base_confidence(tool["original"], raw_confidence.get("tools", []))
            bonus = tool.get("confidence_bonus", 0)
            tool["confidence"] = self._clamp(base + bonus)

        # IoC: confidence = 100 (regex, детерминированно)
        indicators_conf = {}
        for ioc_type, ioc_list in normalized.get("indicators", {}).items():
            indicators_conf[ioc_type] = [
                {"value": ioc, "confidence": 100, "source": "regex"}
                for ioc in ioc_list
            ]
        normalized["indicators_with_confidence"] = indicators_conf

        # CVE: confidence = 100
        vuln_conf = [
            {"id": cve, "confidence": 100, "source": "regex"}
            for cve in normalized.get("vulnerabilities", [])
        ]
        normalized["vulnerabilities_with_confidence"] = vuln_conf

        # Kill Chain techniques: confidence уже встроен в маппер
        # Добавляем +5 за validated=True
        for phase in kill_chain.get("kill_chain_phases", []):
            for tech in phase.get("techniques", []):
                if tech.get("validated"):
                    tech["confidence"] = self._clamp(tech.get("confidence", 50) + 5)

        # Overall confidence
        all_conf = []
        for actor in normalized.get("threat_actor", []):
            all_conf.append(actor.get("confidence", 50))
        for mal in normalized.get("malware", []):
            all_conf.append(mal.get("confidence", 50))
        for tool in normalized.get("tools", []):
            all_conf.append(tool.get("confidence", 50))
        for phase in kill_chain.get("kill_chain_phases", []):
            for tech in phase.get("techniques", []):
                all_conf.append(tech.get("confidence", 50))

        overall = round(sum(all_conf) / len(all_conf)) if all_conf else 0
        print(f"         Overall confidence: {overall}/100")

        return {"overall_confidence": overall}

    @staticmethod
    def _get_base_confidence(name: str, raw_list: list) -> int:
        """Ищет базовый confidence от LLM для данной сущности."""
        name_lower = name.strip().lower()
        for item in raw_list:
            if isinstance(item, dict):
                if item.get("name", "").strip().lower() == name_lower:
                    return item.get("confidence", 75)
            elif isinstance(item, str) and item.strip().lower() == name_lower:
                return 75
        return 75  # default

    @staticmethod
    def _clamp(value: int) -> int:
        return min(100, max(0, value))

    # ──────────────────────────────────────────────
    #  ЭТАП 6: LLM-суммаризация
    # ──────────────────────────────────────────────

    def _generate_summary(self, text: str) -> str:
        """Фаза 6: генерация краткого саммари на английском."""
        print("   [6/7] Генерация аналитического саммари (EN)...")

        truncated = text[:6000] if len(text) > 6000 else text
        prompt = self._summarize_prompt.replace("{text}", truncated)

        try:
            response = ollama.chat(
                model=self.model_name,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a senior CTI analyst. Write concise, actionable summaries. "
                            "Focus on WHO, WHAT, HOW, WHERE, and IMPACT."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                options={"temperature": 0.3, "num_ctx": 8192},
            )
            summary = response["message"]["content"].strip()
            print(f"         Саммари: {len(summary)} символов")
            return summary
        except Exception as e:
            print(f"         [!] Ошибка суммаризации: {e}")
            return ""

    # ──────────────────────────────────────────────
    #  ЭТАП 7: Перевод и формирование записки
    # ──────────────────────────────────────────────

    def _translate_and_format(self, summary_en: str, normalized: dict,
                               kill_chain: dict, overall_conf: int,
                               source: str) -> str:
        """Фаза 7: перевод саммари на RU + формирование аналитической записки."""
        print("   [7/7] Перевод EN→RU и формирование записки...")

        summary_ru = self.translator.translate_summary_block(summary_en, normalized)

        # Формируем записку
        conf_level = self._confidence_level(overall_conf)
        now = datetime.now().strftime("%d.%m.%Y %H:%M")

        lines = [
            "=" * 56,
            "АНАЛИТИЧЕСКАЯ ЗАПИСКА",
            "=" * 56,
            f"Дата анализа:  {now}",
            f"Источник:      {source}",
            f"Достоверность: {overall_conf}/100 ({conf_level})",
            "",
            "─── КРАТКОЕ РЕЗЮМЕ ───",
            summary_ru,
            "",
        ]

        # Kill Chain
        phases = kill_chain.get("kill_chain_phases", [])
        if phases:
            lines.append("─── ЭТАПЫ АТАКИ (Kill Chain) ───")
            for i, phase in enumerate(phases, 1):
                lines.append(
                    f"{i}. {phase['tactic_name_ru']} ({phase['tactic_name_en']})"
                )
                for tech in phase.get("techniques", []):
                    name = tech.get("name_ru") or tech.get("name_en", "")
                    lines.append(
                        f"   {tech['id']} {name} — [confidence: {tech.get('confidence', '?')}]"
                    )
                    if tech.get("evidence"):
                        lines.append(f"   → {tech['evidence']}")
            lines.append("")

        # Угрозы
        actors = normalized.get("threat_actor", [])
        if actors:
            lines.append("─── СУБЪЕКТЫ УГРОЗЫ ───")
            for a in actors:
                mitre = f" ({a['mitre_id']})" if a.get("mitre_id") else ""
                aliases = ", ".join(a.get("aliases", [])[:3])
                alias_str = f" [aliases: {aliases}]" if aliases else ""
                lines.append(
                    f"• {a['name']}{mitre}{alias_str} — confidence: {a.get('confidence', '?')}"
                )
            lines.append("")

        # Малварь и инструменты
        malware = normalized.get("malware", [])
        tools = normalized.get("tools", [])
        if malware or tools:
            lines.append("─── ВРЕДОНОСНОЕ ПО И ИНСТРУМЕНТЫ ───")
            for m in malware:
                mitre = f" ({m['mitre_id']})" if m.get("mitre_id") else ""
                lines.append(f"• [malware] {m['name']}{mitre} — confidence: {m.get('confidence', '?')}")
            for t in tools:
                mitre = f" ({t['mitre_id']})" if t.get("mitre_id") else ""
                lines.append(f"• [tool] {t['name']}{mitre} — confidence: {t.get('confidence', '?')}")
            lines.append("")

        # IoC
        indicators = normalized.get("indicators", {})
        total_ioc = sum(len(v) for v in indicators.values())
        if total_ioc > 0:
            lines.append("─── ИНДИКАТОРЫ КОМПРОМЕТАЦИИ (IoC) ───")
            for ioc_type, ioc_list in indicators.items():
                if ioc_list:
                    label = {"ipv4": "IP", "domain": "Домены", "hash": "Хеши", "email": "Email"}.get(ioc_type, ioc_type)
                    lines.append(f"  [{label}]")
                    for ioc in ioc_list[:10]:  # Макс 10 на тип
                        lines.append(f"    {ioc}")
                    if len(ioc_list) > 10:
                        lines.append(f"    ... и ещё {len(ioc_list) - 10}")
            lines.append("")

        # CVE
        vulns = normalized.get("vulnerabilities", [])
        if vulns:
            lines.append("─── УЯЗВИМОСТИ ───")
            for cve in vulns:
                lines.append(f"  {cve}")
            lines.append("")

        lines.append("=" * 56)

        return "\n".join(lines)

    @staticmethod
    def _confidence_level(score: int) -> str:
        if score >= 95:
            return "Very High"
        elif score >= 85:
            return "High"
        elif score >= 70:
            return "Medium"
        elif score >= 50:
            return "Low"
        else:
            return "Very Low"

    # ──────────────────────────────────────────────
    #  JSON-формат (для OpenCTI)
    # ──────────────────────────────────────────────

    def _build_json_output(self, normalized: dict, kill_chain: dict,
                            overall_conf: int, summary_en: str,
                            source: str, processing_time: float) -> dict:
        """Формирует JSON-выход для OpenCTI."""

        # Threat actors
        actors_json = []
        for a in normalized.get("threat_actor", []):
            actors_json.append({
                "name": a["name"],
                "mitre_id": a.get("mitre_id"),
                "aliases": a.get("aliases", []),
                "confidence": a.get("confidence", 0),
                "normalized": a.get("normalized", False),
            })

        # Malware
        malware_json = []
        for m in normalized.get("malware", []):
            malware_json.append({
                "name": m["name"],
                "mitre_id": m.get("mitre_id"),
                "type": m.get("type", "malware"),
                "confidence": m.get("confidence", 0),
                "normalized": m.get("normalized", False),
            })

        # Tools
        tools_json = []
        for t in normalized.get("tools", []):
            tools_json.append({
                "name": t["name"],
                "mitre_id": t.get("mitre_id"),
                "confidence": t.get("confidence", 0),
                "normalized": t.get("normalized", False),
            })

        # IoC
        indicators = normalized.get("indicators", {})

        # CVE
        vulns = [{"id": cve, "confidence": 100, "source": "regex"}
                 for cve in normalized.get("vulnerabilities", [])]

        return {
            "metadata": {
                "source": source,
                "analysis_date": datetime.now().isoformat(),
                "model": self.model_name,
                "processing_time_sec": round(processing_time, 2),
            },
            "summary": summary_en,
            "threat_actors": actors_json,
            "malware": malware_json,
            "tools": tools_json,
            "indicators": indicators,
            "vulnerabilities": vulns,
            "kill_chain": kill_chain.get("kill_chain_phases", []),
            "overall_confidence": overall_conf,
            "targeted_countries": normalized.get("targeted_countries", []),
        }

    # ──────────────────────────────────────────────
    #  ОСНОВНОЙ МЕТОД
    # ──────────────────────────────────────────────

    def process(self, text: str, source: str = "unknown") -> dict:
        """
        Полный пайплайн обработки CTI-отчёта.

        Args:
            text: Текст отчёта (plain text, уже очищенный от HTML)
            source: Имя файла/источника (для метаданных)

        Returns:
            {
                "json": dict,        # Структурированный JSON (для OpenCTI)
                "note_ru": str,      # Аналитическая записка (RU)
                "summary_en": str,   # Краткое саммари (EN)
                "processing_time": float
            }
        """
        print(f"\n{'=' * 60}")
        print(f"АНАЛИЗ ОТЧЁТА: {source}")
        print(f"Длина текста: {len(text)} символов")
        print(f"Модель: {self.model_name}")
        print(f"{'=' * 60}\n")

        start_time = time.time()

        # Этап 1: Regex IoC
        ioc_data = self._extract_ioc_regex(text)

        # Этап 2: LLM-экстракция
        llm_data = self._extract_entities_llm(text)

        # Объединяем regex + LLM
        combined = {
            "threat_actor": llm_data["threat_actor"],
            "malware": llm_data["malware"],
            "tools": llm_data["tools"],
            "targeted_countries": llm_data.get("targeted_countries", []),
            "indicators": ioc_data["indicators"],
            "vulnerabilities": ioc_data["vulnerabilities"],
        }

        # Этап 3: Нормализация
        normalized = self._normalize_entities(combined)

        # Этап 4: Kill Chain
        kill_chain = self._map_kill_chain(text)

        # Этап 5: Confidence
        raw_conf = llm_data.get("_raw_with_confidence", {})
        conf_result = self._apply_confidence(normalized, raw_conf, kill_chain)
        overall_conf = conf_result["overall_confidence"]

        # Этап 6: Суммаризация
        summary_en = self._generate_summary(text)

        # Этап 7: Перевод + записка
        note_ru = self._translate_and_format(
            summary_en, normalized, kill_chain, overall_conf, source
        )

        processing_time = time.time() - start_time
        print(f"\n   Общее время обработки: {processing_time:.1f} сек")

        # JSON-выход
        json_output = self._build_json_output(
            normalized, kill_chain, overall_conf,
            summary_en, source, processing_time,
        )

        return {
            "json": json_output,
            "note_ru": note_ru,
            "summary_en": summary_en,
            "processing_time": processing_time,
        }

    # ──────────────────────────────────────────────
    #  Утилиты
    # ──────────────────────────────────────────────

    @staticmethod
    def _chunk_text(text: str) -> list[str]:
        """Разбивает текст на чанки с перекрытием."""
        chunks = []
        start = 0
        while start < len(text):
            end = start + CHUNK_SIZE
            chunks.append(text[start:end])
            start += CHUNK_SIZE - OVERLAP
        return chunks


if __name__ == "__main__":
    print("=" * 60)
    print("ТЕСТ ReportSummarizer")
    print("=" * 60)

    test_text = """
    The threat actor group known as Lazarus Group (also referred to as HIDDEN COBRA)
    has been observed conducting a sophisticated campaign targeting financial institutions
    in South Korea and Japan.

    The attack begins with spearphishing emails containing malicious Microsoft Word documents.
    When opened, the documents execute embedded macros that launch PowerShell commands
    to download a Cobalt Strike beacon from the command and control server at 185.220.101.45.

    The attackers used Mimikatz to dump credentials from LSASS memory, enabling lateral
    movement through the network via Remote Desktop Protocol (RDP). They also deployed
    a custom backdoor communicating with the domain evil-c2.darkweb.to.

    File hashes observed:
    - e99a18c428cb38d5f260853678922e03 (dropper)
    - 5d41402abc4b2a76b9719d911017c592fa7e0a3b (payload stage 1)

    The campaign exploits CVE-2025-55182, a critical vulnerability in document processing.
    Data was exfiltrated to an external cloud storage service using encrypted channels.
    """

    summarizer = ReportSummarizer()
    result = summarizer.process(test_text, source="test_lazarus_report.txt")

    print("\n\n")
    print(result["note_ru"])
    print("\n\n--- JSON OUTPUT ---")
    print(json.dumps(result["json"], indent=2, ensure_ascii=False))
