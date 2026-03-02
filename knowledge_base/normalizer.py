"""
Entity Normalizer — нормализация извлечённых сущностей к стандартам MITRE ATT&CK.

Три уровня сопоставления:
  1. Exact match (case-insensitive) — "Lazarus Group" → G0032
  2. Alias match — "HIDDEN COBRA" → G0032 (через алиасы из STIX)
  3. Fuzzy match (rapidfuzz) — "Lazarus Grp" → G0032 (порог 85%)

Поддерживает нормализацию:
  - APT-групп (threat_actors) → таблица groups
  - Малвари и инструментов (malware, tools) → таблица software
  - Техник MITRE (technique IDs) → таблица techniques

Использование:
    from knowledge_base.normalizer import EntityNormalizer
    norm = EntityNormalizer()
    result = norm.normalize_threat_actor("HIDDEN COBRA")
    # → {"name": "Lazarus Group", "mitre_id": "G0032", "aliases": [...], ...}
"""

import sqlite3
import json
from pathlib import Path
from typing import Optional

from rapidfuzz import fuzz, process

PROJECT_ROOT = Path(__file__).parent.parent
DB_PATH = PROJECT_ROOT / "knowledge_base" / "mitre.db"

FUZZY_THRESHOLD = 85  # Минимальный score для fuzzy match


class EntityNormalizer:
    """Нормализует извлечённые сущности к каталогу MITRE ATT&CK."""

    def __init__(self, db_path: Path = DB_PATH):
        if not db_path.exists():
            raise FileNotFoundError(
                f"База MITRE не найдена: {db_path}\n"
                "Запусти: python3 -m knowledge_base.mitre_catalog --stix"
            )
        self.db_path = db_path
        self._load_lookup_tables()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _load_lookup_tables(self):
        """Загружает справочники в память для быстрого поиска."""
        conn = self._get_conn()
        try:
            # --- APT-группы ---
            self._groups = {}           # name_lower → {id, name, aliases, ...}
            self._group_aliases = {}    # alias_lower → group_id
            self._group_names = []      # для fuzzy search

            for row in conn.execute("SELECT id, name, aliases, description, country FROM groups"):
                name = row["name"]
                group_id = row["id"]
                aliases = json.loads(row["aliases"]) if row["aliases"] else []

                entry = {
                    "mitre_id": group_id,
                    "name": name,
                    "aliases": aliases,
                    "description": (row["description"] or "")[:500],
                    "country": row["country"] or "",
                }

                self._groups[name.lower()] = entry
                self._group_names.append(name)

                # Алиасы
                for alias in aliases:
                    self._group_aliases[alias.lower()] = group_id
                # Сам MITRE ID тоже как алиас
                self._group_aliases[group_id.lower()] = group_id

            # --- Software (malware + tools) ---
            self._software = {}         # name_lower → {id, name, type, aliases, ...}
            self._software_aliases = {} # alias_lower → software_id
            self._software_names = []   # для fuzzy search

            for row in conn.execute("SELECT id, name, type, aliases, description FROM software"):
                name = row["name"]
                sw_id = row["id"]
                aliases = json.loads(row["aliases"]) if row["aliases"] else []

                entry = {
                    "mitre_id": sw_id,
                    "name": name,
                    "type": row["type"],
                    "aliases": aliases,
                    "description": (row["description"] or "")[:500],
                }

                self._software[name.lower()] = entry
                self._software_names.append(name)

                for alias in aliases:
                    self._software_aliases[alias.lower()] = sw_id
                self._software_aliases[sw_id.lower()] = sw_id

            # --- Техники ---
            self._techniques = {}  # id → {name_ru, name_en, tactic_id, ...}

            for row in conn.execute(
                "SELECT t.id, t.name_en, t.name_ru, t.description_ru, t.tactic_id, "
                "t.is_subtechnique, t.parent_technique_id, tac.name_en as tactic_en, tac.name_ru as tactic_ru "
                "FROM techniques t LEFT JOIN tactics tac ON t.tactic_id = tac.id"
            ):
                self._techniques[row["id"]] = {
                    "id": row["id"],
                    "name_en": row["name_en"] or "",
                    "name_ru": row["name_ru"] or "",
                    "description_ru": (row["description_ru"] or "")[:500],
                    "tactic_id": row["tactic_id"] or "",
                    "tactic_en": row["tactic_en"] or "",
                    "tactic_ru": row["tactic_ru"] or "",
                    "is_subtechnique": bool(row["is_subtechnique"]),
                    "parent_technique_id": row["parent_technique_id"] or "",
                }

        finally:
            conn.close()

        stats = (
            f"EntityNormalizer загружен: "
            f"{len(self._groups)} групп, "
            f"{len(self._software)} software, "
            f"{len(self._techniques)} техник"
        )
        print(f"   [{stats}]")

    def normalize_threat_actor(self, name: str) -> dict:
        """
        Нормализует имя APT-группы к каталогу MITRE.

        Returns:
            {
                "name": "Lazarus Group",      # Стандартное имя из MITRE
                "mitre_id": "G0032",           # MITRE ID
                "aliases": ["HIDDEN COBRA", ...],
                "confidence_bonus": 10,        # Бонус к confidence
                "normalized": True,
                "match_type": "exact"|"alias"|"fuzzy",
                "match_score": 100,            # Для fuzzy — score; для exact/alias — 100
                "original": "HIDDEN COBRA"     # Что было на входе
            }
        """
        original = name.strip()
        name_lower = original.lower()

        # Уровень 1: Exact match
        if name_lower in self._groups:
            entry = self._groups[name_lower]
            return self._make_result(entry, original, "exact", 100, confidence_bonus=10)

        # Уровень 2: Alias match
        if name_lower in self._group_aliases:
            group_id = self._group_aliases[name_lower]
            # Найти entry по ID
            for entry in self._groups.values():
                if entry["mitre_id"] == group_id:
                    return self._make_result(entry, original, "alias", 100, confidence_bonus=5)

        # Уровень 3: Fuzzy match
        if self._group_names:
            match = process.extractOne(
                original, self._group_names,
                scorer=fuzz.token_sort_ratio,
                score_cutoff=FUZZY_THRESHOLD
            )
            if match:
                matched_name, score, _ = match
                entry = self._groups[matched_name.lower()]
                return self._make_result(entry, original, "fuzzy", score, confidence_bonus=0)

        # Не найдено
        return {
            "name": original,
            "mitre_id": None,
            "aliases": [],
            "confidence_bonus": -10,
            "normalized": False,
            "match_type": "none",
            "match_score": 0,
            "original": original,
        }

    def normalize_software(self, name: str) -> dict:
        """
        Нормализует имя малвари или инструмента к каталогу MITRE Software.
        Логика аналогична normalize_threat_actor.
        """
        original = name.strip()
        name_lower = original.lower()

        # Exact match
        if name_lower in self._software:
            entry = self._software[name_lower]
            return self._make_sw_result(entry, original, "exact", 100, confidence_bonus=10)

        # Alias match
        if name_lower in self._software_aliases:
            sw_id = self._software_aliases[name_lower]
            for entry in self._software.values():
                if entry["mitre_id"] == sw_id:
                    return self._make_sw_result(entry, original, "alias", 100, confidence_bonus=5)

        # Fuzzy match
        if self._software_names:
            match = process.extractOne(
                original, self._software_names,
                scorer=fuzz.token_sort_ratio,
                score_cutoff=FUZZY_THRESHOLD
            )
            if match:
                matched_name, score, _ = match
                entry = self._software[matched_name.lower()]
                return self._make_sw_result(entry, original, "fuzzy", score, confidence_bonus=0)

        return {
            "name": original,
            "mitre_id": None,
            "type": "unknown",
            "aliases": [],
            "confidence_bonus": -10,
            "normalized": False,
            "match_type": "none",
            "match_score": 0,
            "original": original,
        }

    def validate_technique_id(self, technique_id: str) -> Optional[dict]:
        """
        Проверяет существование technique ID в справочнике.
        Возвращает полную информацию о технике или None если не найдена.
        """
        tid = technique_id.strip().upper()
        if tid in self._techniques:
            return self._techniques[tid]
        return None

    def get_techniques_for_tactic(self, tactic_id: str) -> list[dict]:
        """Возвращает все техники для данной тактики (для Kill Chain Mapper)."""
        result = []
        for tech in self._techniques.values():
            if tech["tactic_id"] == tactic_id:
                result.append(tech)
        return sorted(result, key=lambda x: x["id"])

    def get_group_techniques(self, group_id: str) -> list[str]:
        """Возвращает список technique IDs, используемых группой."""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT technique_id FROM group_techniques WHERE group_id = ?",
                (group_id,)
            ).fetchall()
            return [row["technique_id"] for row in rows]
        finally:
            conn.close()

    def get_software_techniques(self, software_id: str) -> list[str]:
        """Возвращает список technique IDs для software."""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT technique_id FROM software_techniques WHERE software_id = ?",
                (software_id,)
            ).fetchall()
            return [row["technique_id"] for row in rows]
        finally:
            conn.close()

    def normalize_all(self, extraction_result: dict) -> dict:
        """
        Нормализует все сущности в результате экстракции.

        Input:  {"threat_actor": ["HIDDEN COBRA", "Lazarus"], "malware": ["CobaltStrike"], ...}
        Output: {"threat_actor": [{name, mitre_id, normalized, ...}], ...}
        """
        result = {}

        # Threat actors
        actors = []
        seen_ids = set()
        for actor_name in extraction_result.get("threat_actor", []):
            normalized = self.normalize_threat_actor(actor_name)
            # Дедупликация по mitre_id
            key = normalized["mitre_id"] or normalized["name"].lower()
            if key not in seen_ids:
                seen_ids.add(key)
                actors.append(normalized)
        result["threat_actor"] = actors

        # Malware
        malware = []
        seen_ids = set()
        for name in extraction_result.get("malware", []):
            normalized = self.normalize_software(name)
            key = normalized["mitre_id"] or normalized["name"].lower()
            if key not in seen_ids:
                seen_ids.add(key)
                if normalized.get("type") != "tool":  # Фильтруем tools
                    malware.append(normalized)
        result["malware"] = malware

        # Tools
        tools = []
        seen_ids = set()
        for name in extraction_result.get("tools", []):
            normalized = self.normalize_software(name)
            key = normalized["mitre_id"] or normalized["name"].lower()
            if key not in seen_ids:
                seen_ids.add(key)
                tools.append(normalized)
        result["tools"] = tools

        # IoC и CVE — пропускаем без нормализации (regex уже точный)
        if "indicators" in extraction_result:
            result["indicators"] = extraction_result["indicators"]
        if "vulnerabilities" in extraction_result:
            result["vulnerabilities"] = extraction_result["vulnerabilities"]
        if "targeted_countries" in extraction_result:
            result["targeted_countries"] = extraction_result.get("targeted_countries", [])

        return result

    @staticmethod
    def _make_result(entry: dict, original: str, match_type: str,
                     score: float, confidence_bonus: int) -> dict:
        return {
            "name": entry["name"],
            "mitre_id": entry["mitre_id"],
            "aliases": entry["aliases"],
            "confidence_bonus": confidence_bonus,
            "normalized": True,
            "match_type": match_type,
            "match_score": round(score, 1),
            "original": original,
        }

    @staticmethod
    def _make_sw_result(entry: dict, original: str, match_type: str,
                        score: float, confidence_bonus: int) -> dict:
        return {
            "name": entry["name"],
            "mitre_id": entry["mitre_id"],
            "type": entry["type"],
            "aliases": entry["aliases"],
            "confidence_bonus": confidence_bonus,
            "normalized": True,
            "match_type": match_type,
            "match_score": round(score, 1),
            "original": original,
        }


# --- CLI тестирование ---
if __name__ == "__main__":
    print("Загрузка EntityNormalizer...\n")
    norm = EntityNormalizer()

    print("=" * 60)
    print("ТЕСТ НОРМАЛИЗАЦИИ APT-ГРУПП")
    print("=" * 60)

    test_actors = [
        "Lazarus Group",     # exact match
        "HIDDEN COBRA",      # alias match
        "lazarus group",     # case-insensitive exact
        "Lazarus Grp",       # fuzzy match
        "G0032",             # MITRE ID
        "APT28",             # alias (Fancy Bear)
        "Fancy Bear",        # alias → APT28
        "SuperNewAPT9000",   # не найдётся
    ]

    for actor in test_actors:
        result = norm.normalize_threat_actor(actor)
        status = "OK" if result["normalized"] else "NOT FOUND"
        mitre = result["mitre_id"] or "—"
        print(f"  '{actor}' → {result['name']} [{mitre}] "
              f"({result['match_type']}, score={result['match_score']}) [{status}]")

    print("\n" + "=" * 60)
    print("ТЕСТ НОРМАЛИЗАЦИИ SOFTWARE")
    print("=" * 60)

    test_software = [
        "Cobalt Strike",     # exact
        "CobaltStrike",      # fuzzy
        "Mimikatz",          # exact
        "mimikatz",          # case-insensitive
        "S0154",             # MITRE ID
        "NotARealMalware",   # не найдётся
    ]

    for name in test_software:
        result = norm.normalize_software(name)
        status = "OK" if result["normalized"] else "NOT FOUND"
        mitre = result["mitre_id"] or "—"
        print(f"  '{name}' → {result['name']} [{mitre}] "
              f"({result['match_type']}, type={result.get('type','?')}) [{status}]")

    print("\n" + "=" * 60)
    print("ТЕСТ ВАЛИДАЦИИ TECHNIQUE ID")
    print("=" * 60)

    test_techniques = ["T1059", "T1059.001", "T9999", "T1566.001"]
    for tid in test_techniques:
        info = norm.validate_technique_id(tid)
        if info:
            print(f"  {tid} → {info['name_ru']} (tactic: {info['tactic_ru']})")
        else:
            print(f"  {tid} → НЕ СУЩЕСТВУЕТ (галлюцинация LLM)")
