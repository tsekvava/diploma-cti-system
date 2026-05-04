"""
Query Enrichment — обогащение коротких запросов из MITRE ATT&CK БД.

SOC-оператор вводит короткий запрос (T1059, APT28, CVE-2024-38063),
и система возвращает полный контекст из локальной SQLite.

Поддерживаемые типы запросов:
  - MITRE Technique:   T1059, T1059.001
  - MITRE Tactic:      TA0002
  - MITRE Group:       G0032, "APT28", "Lazarus Group"
  - MITRE Software:    S0154, "Cobalt Strike"
  - MITRE Mitigation:  M1036
  - MITRE Data Source: DS0026
  - CVE:               CVE-2024-38063

Использование:
    from knowledge_base.query_enricher import QueryEnricher
    enricher = QueryEnricher()
    result = enricher.enrich("T1059")
    # result = {
    #   "query_type": "technique",
    #   "query": "T1059",
    #   "data": { ... полный контекст ... },
    #   "context_for_llm": "... текст для подстановки в промпт ..."
    # }
"""

import re
import json
import sqlite3
from pathlib import Path
from typing import Optional

DB_PATH = Path(__file__).parent / "mitre.db"

# --- Regex-паттерны для определения типа запроса ---
QUERY_PATTERNS = [
    ("technique",    r"\b(T\d{4}(?:\.\d{3})?)\b"),
    ("tactic",       r"\b(TA\d{4})\b"),
    ("group_id",     r"\b(G\d{4}|XG-[A-F0-9]{12})\b"),
    ("software_id",  r"\b(S\d{4}|XS-[A-F0-9]{12})\b"),
    ("mitigation",   r"\b(M\d{4})\b"),
    ("data_source",  r"\b(DS\d{4})\b"),
    ("cve",          r"\b(CVE-\d{4}-\d{4,7})\b"),
]


class QueryEnricher:
    """Обогащает короткие CTI-запросы контекстом из MITRE ATT&CK."""

    def __init__(self, db_path: str = None):
        self.db_path = db_path or str(DB_PATH)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self._has_intel_groups = self._table_exists("intel_groups")
        self._has_intel_software = self._table_exists("intel_software")
        self._has_intel_group_tech = self._table_exists("intel_group_techniques")
        self._has_intel_sw_tech = self._table_exists("intel_software_techniques")

    def _table_exists(self, table_name: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?",
            (table_name,),
        ).fetchone()
        return row is not None

    def close(self):
        self.conn.close()

    def __del__(self):
        try:
            self.conn.close()
        except Exception:
            pass

    #  Определение типа запроса

    def detect_query_type(self, query: str) -> list[dict]:
        """
        Определяет типы идентификаторов в запросе.

        Returns:
            Список найденных: [{"type": "technique", "id": "T1059"}, ...]
        """
        found = []
        for qtype, pattern in QUERY_PATTERNS:
            for match in re.finditer(pattern, query, re.IGNORECASE):
                found.append({
                    "type": qtype,
                    "id": match.group(1).upper() if qtype != "cve" else match.group(1),
                })

        # Если не нашли по ID — ищем по имени
        if not found:
            found = self._search_by_name(query)

        return found

    def _search_by_name(self, query: str) -> list[dict]:
        """Поиск сущности по имени — сначала полный запрос, затем отдельные слова."""
        found = []
        seen_ids = set()

        # Пробуем полный запрос и подстроки (2+ слов, затем отдельные слова)
        query_lower = query.lower().strip()
        search_terms = [query_lower]

        # Добавляем отдельные слова >= 3 символов (для "Что делает APT28?" → ["apt28"])
        words = [w for w in re.split(r'[\s,;:?!.]+', query_lower) if len(w) >= 3]
        # Также пробуем пары соседних слов ("cobalt strike" из "analyse cobalt strike beacon")
        for i in range(len(words) - 1):
            bigram = f"{words[i]} {words[i+1]}"
            if bigram != query_lower:
                search_terms.append(bigram)
        search_terms.extend(w for w in words if w != query_lower)

        cur = self.conn.cursor()

        for term in search_terms:
            if len(found) >= 10:
                break

            # Ищем в группах
            cur.execute(
                "SELECT id, name FROM groups WHERE LOWER(name) LIKE ? OR LOWER(aliases) LIKE ?",
                (f"%{term}%", f"%{term}%"),
            )
            for row in cur.fetchall():
                if row["id"] not in seen_ids:
                    found.append({"type": "group_id", "id": row["id"], "name": row["name"]})
                    seen_ids.add(row["id"])

            if self._has_intel_groups:
                cur.execute(
                    "SELECT id, name FROM intel_groups WHERE LOWER(name) LIKE ? OR LOWER(aliases) LIKE ?",
                    (f"%{term}%", f"%{term}%"),
                )
                for row in cur.fetchall():
                    if row["id"] not in seen_ids:
                        found.append({"type": "group_id", "id": row["id"], "name": row["name"]})
                        seen_ids.add(row["id"])

            # Ищем в software
            cur.execute(
                "SELECT id, name FROM software WHERE LOWER(name) LIKE ? OR LOWER(aliases) LIKE ?",
                (f"%{term}%", f"%{term}%"),
            )
            for row in cur.fetchall():
                if row["id"] not in seen_ids:
                    found.append({"type": "software_id", "id": row["id"], "name": row["name"]})
                    seen_ids.add(row["id"])

            if self._has_intel_software:
                cur.execute(
                    "SELECT id, name FROM intel_software WHERE LOWER(name) LIKE ? OR LOWER(aliases) LIKE ?",
                    (f"%{term}%", f"%{term}%"),
                )
                for row in cur.fetchall():
                    if row["id"] not in seen_ids:
                        found.append({"type": "software_id", "id": row["id"], "name": row["name"]})
                        seen_ids.add(row["id"])

            # Ищем в техниках (только для конкретных терминов, не стоп-слов)
            if len(term) >= 5:
                cur.execute(
                    "SELECT id, name_en, name_ru FROM techniques WHERE LOWER(name_en) LIKE ? OR LOWER(name_ru) LIKE ?",
                    (f"%{term}%", f"%{term}%"),
                )
                for row in cur.fetchall():
                    if row["id"] not in seen_ids:
                        found.append({"type": "technique", "id": row["id"], "name": row["name_en"]})
                        seen_ids.add(row["id"])

        return found[:10]

    #  Обогащение по типам

    def enrich(self, query: str) -> dict:
        """
        Основной метод обогащения.

        Args:
            query: Короткий запрос (T1059, APT28, CVE-2024-38063, и т.д.)

        Returns:
            {
                "query": str,
                "detected": [{"type": ..., "id": ...}],
                "enrichments": [ ... обогащённые данные ... ],
                "context_for_llm": str  # Текст для подстановки в промпт LLM
            }
        """
        detected = self.detect_query_type(query)

        if not detected:
            return {
                "query": query,
                "detected": [],
                "enrichments": [],
                "context_for_llm": f"No known MITRE/CVE identifiers found in query: {query}",
            }

        enrichments = []
        for item in detected:
            qtype = item["type"]
            qid = item["id"]

            if qtype == "technique":
                enrichments.append(self._enrich_technique(qid))
            elif qtype == "tactic":
                enrichments.append(self._enrich_tactic(qid))
            elif qtype == "group_id":
                enrichments.append(self._enrich_group(qid))
            elif qtype == "software_id":
                enrichments.append(self._enrich_software(qid))
            elif qtype == "mitigation":
                enrichments.append(self._enrich_mitigation(qid))
            elif qtype == "data_source":
                enrichments.append(self._enrich_data_source(qid))
            elif qtype == "cve":
                enrichments.append(self._enrich_cve(qid))

        # Формируем контекст для LLM
        context = self._build_llm_context(enrichments)

        return {
            "query": query,
            "detected": detected,
            "enrichments": enrichments,
            "context_for_llm": context,
        }

    def _enrich_technique(self, tech_id: str) -> dict:
        """Обогащение MITRE Technique."""
        cur = self.conn.cursor()

        # Основная информация
        cur.execute(
            "SELECT * FROM techniques WHERE id = ?", (tech_id,)
        )
        row = cur.fetchone()
        if not row:
            return {"type": "technique", "id": tech_id, "found": False}

        data = {
            "type": "technique",
            "id": tech_id,
            "found": True,
            "name_en": row["name_en"],
            "name_ru": row["name_ru"] or "",
            "description_ru": row["description_ru"] or "",
            "tactic_id": row["tactic_id"] or "",
            "is_subtechnique": bool(row["is_subtechnique"]),
            "parent_technique_id": row["parent_technique_id"] or "",
        }

        # Тактика
        if data["tactic_id"]:
            cur.execute("SELECT name_en, name_ru FROM tactics WHERE id = ?", (data["tactic_id"],))
            tactic = cur.fetchone()
            if tactic:
                data["tactic_name_en"] = tactic["name_en"]
                data["tactic_name_ru"] = tactic["name_ru"] or ""

        # Сабтехники (если это родительская)
        if not data["is_subtechnique"]:
            cur.execute(
                "SELECT id, name_en, name_ru FROM techniques WHERE parent_technique_id = ?",
                (tech_id,),
            )
            data["subtechniques"] = [
                {"id": r["id"], "name_en": r["name_en"], "name_ru": r["name_ru"] or ""}
                for r in cur.fetchall()
            ]

        # Группы, использующие технику
        cur.execute("""
            SELECT g.id, g.name FROM groups g
            JOIN group_techniques gt ON g.id = gt.group_id
            WHERE gt.technique_id = ?
            ORDER BY g.name
        """, (tech_id,))
        data["used_by_groups"] = [
            {"id": r["id"], "name": r["name"]} for r in cur.fetchall()
        ]

        # Software, использующий технику
        cur.execute("""
            SELECT s.id, s.name, s.type FROM software s
            JOIN software_techniques st ON s.id = st.software_id
            WHERE st.technique_id = ?
            ORDER BY s.name
        """, (tech_id,))
        data["used_by_software"] = [
            {"id": r["id"], "name": r["name"], "type": r["type"]} for r in cur.fetchall()
        ]

        # Mitigations
        cur.execute(
            "SELECT id, name_en, name_ru FROM mitigations WHERE techniques_covered LIKE ?",
            (f"%{tech_id}%",),
        )
        data["mitigations"] = [
            {"id": r["id"], "name_en": r["name_en"], "name_ru": r["name_ru"] or ""}
            for r in cur.fetchall()
        ]

        return data

    def _enrich_tactic(self, tactic_id: str) -> dict:
        """Обогащение MITRE Tactic."""
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM tactics WHERE id = ?", (tactic_id,))
        row = cur.fetchone()
        if not row:
            return {"type": "tactic", "id": tactic_id, "found": False}

        data = {
            "type": "tactic",
            "id": tactic_id,
            "found": True,
            "name_en": row["name_en"],
            "name_ru": row["name_ru"] or "",
            "description_ru": row["description_ru"] or "",
            "kill_chain_order": row["kill_chain_order"],
        }

        # Техники в этой тактике
        cur.execute(
            "SELECT id, name_en, name_ru FROM techniques WHERE tactic_id = ? AND is_subtechnique = 0 ORDER BY id",
            (tactic_id,),
        )
        data["techniques"] = [
            {"id": r["id"], "name_en": r["name_en"], "name_ru": r["name_ru"] or ""}
            for r in cur.fetchall()
        ]

        return data

    def _enrich_group(self, group_id: str) -> dict:
        """Обогащение MITRE Group (APT)."""
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM groups WHERE id = ?", (group_id,))
        row = cur.fetchone()
        if not row:
            return self._enrich_group_internal(group_id)

        aliases = json.loads(row["aliases"]) if row["aliases"] else []

        data = {
            "type": "group",
            "id": group_id,
            "found": True,
            "source": "mitre",
            "name": row["name"],
            "description": row["description"] or "",
            "aliases": aliases,
            "country": row["country"] or "",
        }

        # Техники группы
        cur.execute("""
            SELECT t.id, t.name_en, t.tactic_id FROM techniques t
            JOIN group_techniques gt ON t.id = gt.technique_id
            WHERE gt.group_id = ?
            ORDER BY t.id
        """, (group_id,))
        data["techniques"] = [
            {"id": r["id"], "name_en": r["name_en"], "tactic_id": r["tactic_id"] or ""}
            for r in cur.fetchall()
        ]

        # Software группы
        cur.execute("""
            SELECT DISTINCT s.id, s.name, s.type FROM software s
            JOIN software_techniques st ON s.id = st.software_id
            JOIN group_techniques gt ON st.technique_id = gt.technique_id
            WHERE gt.group_id = ?
            ORDER BY s.name
            LIMIT 20
        """, (group_id,))
        data["software"] = [
            {"id": r["id"], "name": r["name"], "type": r["type"]}
            for r in cur.fetchall()
        ]

        return data

    def _enrich_group_internal(self, group_id: str) -> dict:
        if not self._has_intel_groups:
            return {"type": "group", "id": group_id, "found": False}

        cur = self.conn.cursor()
        cur.execute("SELECT * FROM intel_groups WHERE id = ?", (group_id,))
        row = cur.fetchone()
        if not row:
            return {"type": "group", "id": group_id, "found": False}

        aliases = json.loads(row["aliases"]) if row["aliases"] else []
        source = row["source"] or "opencti"

        data = {
            "type": "group",
            "id": row["id"],
            "found": True,
            "source": source,
            "name": row["name"],
            "description": row["description"] or "",
            "aliases": aliases,
            "country": row["country"] or "",
        }

        if self._has_intel_group_tech:
            cur.execute(
                """
                SELECT t.id, t.name_en, t.tactic_id
                FROM techniques t
                JOIN intel_group_techniques gt ON t.id = gt.technique_id
                WHERE gt.group_id = ?
                ORDER BY t.id
                """,
                (row["id"],),
            )
            data["techniques"] = [
                {"id": r["id"], "name_en": r["name_en"], "tactic_id": r["tactic_id"] or ""}
                for r in cur.fetchall()
            ]
        else:
            data["techniques"] = []

        if self._has_intel_sw_tech and self._has_intel_group_tech and self._has_intel_software:
            cur.execute(
                """
                SELECT DISTINCT s.id, s.name, s.type
                FROM intel_software s
                JOIN intel_software_techniques st ON s.id = st.software_id
                JOIN intel_group_techniques gt ON st.technique_id = gt.technique_id
                WHERE gt.group_id = ?
                ORDER BY s.name
                LIMIT 20
                """,
                (row["id"],),
            )
            data["software"] = [
                {"id": r["id"], "name": r["name"], "type": r["type"]}
                for r in cur.fetchall()
            ]
        else:
            data["software"] = []

        return data

    def _enrich_software(self, soft_id: str) -> dict:
        """Обогащение MITRE Software (malware/tool)."""
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM software WHERE id = ?", (soft_id,))
        row = cur.fetchone()
        if not row:
            return self._enrich_software_internal(soft_id)

        aliases = json.loads(row["aliases"]) if row["aliases"] else []

        data = {
            "type": "software",
            "id": soft_id,
            "found": True,
            "source": "mitre",
            "name": row["name"],
            "software_type": row["type"],
            "description": row["description"] or "",
            "aliases": aliases,
        }

        # Техники
        cur.execute("""
            SELECT t.id, t.name_en, t.tactic_id FROM techniques t
            JOIN software_techniques st ON t.id = st.technique_id
            WHERE st.software_id = ?
            ORDER BY t.id
        """, (soft_id,))
        data["techniques"] = [
            {"id": r["id"], "name_en": r["name_en"], "tactic_id": r["tactic_id"] or ""}
            for r in cur.fetchall()
        ]

        # Группы, использующие этот software
        cur.execute("""
            SELECT DISTINCT g.id, g.name FROM groups g
            JOIN group_techniques gt ON g.id = gt.group_id
            JOIN software_techniques st ON gt.technique_id = st.technique_id
            WHERE st.software_id = ?
            ORDER BY g.name
            LIMIT 20
        """, (soft_id,))
        data["used_by_groups"] = [
            {"id": r["id"], "name": r["name"]} for r in cur.fetchall()
        ]

        return data

    def _enrich_software_internal(self, soft_id: str) -> dict:
        if not self._has_intel_software:
            return {"type": "software", "id": soft_id, "found": False}

        cur = self.conn.cursor()
        cur.execute("SELECT * FROM intel_software WHERE id = ?", (soft_id,))
        row = cur.fetchone()
        if not row:
            return {"type": "software", "id": soft_id, "found": False}

        aliases = json.loads(row["aliases"]) if row["aliases"] else []
        source = row["source"] or "opencti"

        data = {
            "type": "software",
            "id": row["id"],
            "found": True,
            "source": source,
            "name": row["name"],
            "software_type": row["type"],
            "description": row["description"] or "",
            "aliases": aliases,
        }

        if self._has_intel_sw_tech:
            cur.execute(
                """
                SELECT t.id, t.name_en, t.tactic_id
                FROM techniques t
                JOIN intel_software_techniques st ON t.id = st.technique_id
                WHERE st.software_id = ?
                ORDER BY t.id
                """,
                (row["id"],),
            )
            data["techniques"] = [
                {"id": r["id"], "name_en": r["name_en"], "tactic_id": r["tactic_id"] or ""}
                for r in cur.fetchall()
            ]
        else:
            data["techniques"] = []

        if self._has_intel_sw_tech and self._has_intel_group_tech and self._has_intel_groups:
            cur.execute(
                """
                SELECT DISTINCT g.id, g.name
                FROM intel_groups g
                JOIN intel_group_techniques gt ON g.id = gt.group_id
                JOIN intel_software_techniques st ON gt.technique_id = st.technique_id
                WHERE st.software_id = ?
                ORDER BY g.name
                LIMIT 20
                """,
                (row["id"],),
            )
            data["used_by_groups"] = [{"id": r["id"], "name": r["name"]} for r in cur.fetchall()]
        else:
            data["used_by_groups"] = []

        return data

    def _enrich_mitigation(self, mit_id: str) -> dict:
        """Обогащение MITRE Mitigation."""
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM mitigations WHERE id = ?", (mit_id,))
        row = cur.fetchone()
        if not row:
            return {"type": "mitigation", "id": mit_id, "found": False}

        techniques = json.loads(row["techniques_covered"]) if row["techniques_covered"] else []

        return {
            "type": "mitigation",
            "id": mit_id,
            "found": True,
            "name_en": row["name_en"],
            "name_ru": row["name_ru"] or "",
            "description_ru": row["description_ru"] or "",
            "techniques_covered": techniques,
        }

    def _enrich_data_source(self, ds_id: str) -> dict:
        """Обогащение MITRE Data Source."""
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM data_sources WHERE id = ?", (ds_id,))
        row = cur.fetchone()
        if not row:
            return {"type": "data_source", "id": ds_id, "found": False}

        components = json.loads(row["components"]) if row["components"] else []

        return {
            "type": "data_source",
            "id": ds_id,
            "found": True,
            "name_en": row["name_en"],
            "name_ru": row["name_ru"] or "",
            "description_ru": row["description_ru"] or "",
            "components": components,
        }

    def _enrich_cve(self, cve_id: str) -> dict:
        """Обогащение CVE из локальной NVD SQLite базы."""
        try:
            from knowledge_base.nvd_db import NVDDatabase
            nvd = NVDDatabase()
            data = nvd.lookup(cve_id)
            nvd.close()
        except Exception:
            data = None

        if not data:
            return {
                "type": "cve",
                "id": cve_id,
                "found": True,
                "description": "",
                "cvss3_score": None,
                "cvss3_severity": None,
                "note": "CVE not found in local NVD database. "
                        "Use 'python3 -m knowledge_base.nvd_db --fetch " + cve_id + "' to download.",
            }

        return {
            "type": "cve",
            "id": cve_id,
            "found": True,
            "description": data.get("description", ""),
            "cvss3_score": data.get("cvss3_score"),
            "cvss3_vector": data.get("cvss3_vector"),
            "cvss3_severity": data.get("cvss3_severity"),
            "cvss2_score": data.get("cvss2_score"),
            "cwe_ids": data.get("cwe_ids", []),
            "affected": data.get("affected", [])[:5],
            "published": data.get("published"),
            "references": data.get("references", [])[:3],
        }

    #  Контекст для LLM

    def _build_llm_context(self, enrichments: list) -> str:
        """Формирует текстовый контекст для подстановки в LLM-промпт."""
        parts = []

        for e in enrichments:
            if not e.get("found", False):
                parts.append(f"[{e.get('type', 'unknown')} {e.get('id', '?')}] — NOT FOUND in database.\n")
                continue

            etype = e["type"]

            if etype == "technique":
                part = self._format_technique_context(e)
            elif etype == "tactic":
                part = self._format_tactic_context(e)
            elif etype == "group":
                part = self._format_group_context(e)
            elif etype == "software":
                part = self._format_software_context(e)
            elif etype == "mitigation":
                part = self._format_mitigation_context(e)
            elif etype == "data_source":
                part = self._format_data_source_context(e)
            elif etype == "cve":
                part = f"CVE: {e['id']}\n"
                if e.get("description"):
                    part += f"Description: {e['description']}\n"
                if e.get("cvss3_score"):
                    part += f"CVSS 3.x: {e['cvss3_score']} ({e.get('cvss3_severity', '')})\n"
                if e.get("cwe_ids"):
                    part += f"CWE: {', '.join(e['cwe_ids'])}\n"
                if e.get("note"):
                    part += f"{e['note']}\n"
            else:
                part = f"[{etype}] {e.get('id', '?')}\n"

            parts.append(part)

        header = "=== ENRICHMENT CONTEXT (MITRE ATT&CK + internal intelligence layer) ===\n\n"
        return header + "\n---\n\n".join(parts)

    def _format_technique_context(self, e: dict) -> str:
        """Форматирует контекст для техники."""
        lines = [
            f"MITRE ATT&CK Technique: {e['id']} — {e['name_en']}",
        ]
        if e.get("name_ru"):
            lines.append(f"Русское название: {e['name_ru']}")
        if e.get("tactic_name_en"):
            lines.append(f"Тактика: {e.get('tactic_id', '')} {e['tactic_name_en']}"
                         + (f" ({e.get('tactic_name_ru', '')})" if e.get("tactic_name_ru") else ""))
        if e.get("description_ru"):
            desc = e["description_ru"][:500]
            lines.append(f"Описание: {desc}")

        # Сабтехники
        subs = e.get("subtechniques", [])
        if subs:
            lines.append(f"\nПодтехники ({len(subs)}):")
            for s in subs:
                lines.append(f"  - {s['id']} {s['name_en']}" + (f" ({s['name_ru']})" if s.get("name_ru") else ""))

        # Группы
        groups = e.get("used_by_groups", [])
        if groups:
            names = ", ".join(f"{g['name']} ({g['id']})" for g in groups[:10])
            lines.append(f"\nГруппы, использующие технику ({len(groups)}): {names}")
            if len(groups) > 10:
                lines.append(f"  ... и ещё {len(groups) - 10}")

        # Software
        soft = e.get("used_by_software", [])
        if soft:
            names = ", ".join(f"{s['name']} ({s['id']}, {s['type']})" for s in soft[:10])
            lines.append(f"\nSoftware ({len(soft)}): {names}")
            if len(soft) > 10:
                lines.append(f"  ... и ещё {len(soft) - 10}")

        # Mitigations
        mits = e.get("mitigations", [])
        if mits:
            lines.append(f"\nМитигации:")
            for m in mits:
                lines.append(f"  - {m['id']} {m['name_en']}" + (f" ({m['name_ru']})" if m.get("name_ru") else ""))

        return "\n".join(lines) + "\n"

    def _format_tactic_context(self, e: dict) -> str:
        """Форматирует контекст для тактики."""
        lines = [
            f"MITRE ATT&CK Tactic: {e['id']} — {e['name_en']}",
        ]
        if e.get("name_ru"):
            lines.append(f"Русское название: {e['name_ru']}")
        lines.append(f"Порядок в Kill Chain: {e.get('kill_chain_order', '?')}")
        if e.get("description_ru"):
            lines.append(f"Описание: {e['description_ru'][:500]}")

        techs = e.get("techniques", [])
        if techs:
            lines.append(f"\nТехники в тактике ({len(techs)}):")
            for t in techs:
                lines.append(f"  - {t['id']} {t['name_en']}" + (f" ({t['name_ru']})" if t.get("name_ru") else ""))

        return "\n".join(lines) + "\n"

    def _format_group_context(self, e: dict) -> str:
        """Форматирует контекст для APT-группы."""
        lines = [
            f"MITRE ATT&CK Group: {e['id']} — {e['name']}",
        ]
        if e.get("source"):
            lines.append(f"Источник: {e['source']}")
        if e.get("aliases"):
            lines.append(f"Алиасы: {', '.join(e['aliases'][:10])}")
        if e.get("country"):
            lines.append(f"Страна: {e['country']}")
        if e.get("description"):
            lines.append(f"Описание: {e['description'][:500]}")

        techs = e.get("techniques", [])
        if techs:
            lines.append(f"\nТехники ({len(techs)}):")
            for t in techs[:20]:
                lines.append(f"  - {t['id']} {t['name_en']} [{t.get('tactic_id', '')}]")
            if len(techs) > 20:
                lines.append(f"  ... и ещё {len(techs) - 20}")

        soft = e.get("software", [])
        if soft:
            lines.append(f"\nИспользуемый software ({len(soft)}):")
            for s in soft:
                lines.append(f"  - {s['id']} {s['name']} ({s['type']})")

        return "\n".join(lines) + "\n"

    def _format_software_context(self, e: dict) -> str:
        """Форматирует контекст для software."""
        lines = [
            f"MITRE ATT&CK Software: {e['id']} — {e['name']} (type: {e.get('software_type', '?')})",
        ]
        if e.get("source"):
            lines.append(f"Источник: {e['source']}")
        if e.get("aliases"):
            lines.append(f"Алиасы: {', '.join(e['aliases'][:10])}")
        if e.get("description"):
            lines.append(f"Описание: {e['description'][:500]}")

        techs = e.get("techniques", [])
        if techs:
            lines.append(f"\nТехники ({len(techs)}):")
            for t in techs[:15]:
                lines.append(f"  - {t['id']} {t['name_en']} [{t.get('tactic_id', '')}]")
            if len(techs) > 15:
                lines.append(f"  ... и ещё {len(techs) - 15}")

        groups = e.get("used_by_groups", [])
        if groups:
            names = ", ".join(f"{g['name']} ({g['id']})" for g in groups)
            lines.append(f"\nИспользуется группами ({len(groups)}): {names}")

        return "\n".join(lines) + "\n"

    def _format_mitigation_context(self, e: dict) -> str:
        """Форматирует контекст для митигации."""
        lines = [
            f"MITRE ATT&CK Mitigation: {e['id']} — {e['name_en']}",
        ]
        if e.get("name_ru"):
            lines.append(f"Русское название: {e['name_ru']}")
        if e.get("description_ru"):
            lines.append(f"Описание: {e['description_ru'][:500]}")

        techs = e.get("techniques_covered", [])
        if techs:
            lines.append(f"\nПокрывает техники ({len(techs)}): {', '.join(techs[:20])}")

        return "\n".join(lines) + "\n"

    def _format_data_source_context(self, e: dict) -> str:
        """Форматирует контекст для Data Source."""
        lines = [
            f"MITRE ATT&CK Data Source: {e['id']} — {e['name_en']}",
        ]
        if e.get("name_ru"):
            lines.append(f"Русское название: {e['name_ru']}")
        if e.get("description_ru"):
            lines.append(f"Описание: {e['description_ru'][:500]}")

        comps = e.get("components", [])
        if comps:
            lines.append(f"\nКомпоненты ({len(comps)}): {', '.join(comps)}")

        return "\n".join(lines) + "\n"


# --- CLI для тестирования ---

def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 query_enricher.py <query>")
        print("Examples:")
        print("  python3 query_enricher.py T1059")
        print("  python3 query_enricher.py TA0002")
        print("  python3 query_enricher.py G0032")
        print("  python3 query_enricher.py 'APT28'")
        print("  python3 query_enricher.py S0154")
        print("  python3 query_enricher.py 'Cobalt Strike'")
        return

    query = " ".join(sys.argv[1:])
    enricher = QueryEnricher()
    result = enricher.enrich(query)

    print(f"Query: {result['query']}")
    print(f"Detected: {result['detected']}")
    print(f"Enrichments: {len(result['enrichments'])}")
    print()
    print(result["context_for_llm"])


if __name__ == "__main__":
    main()
