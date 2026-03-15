"""
Internal intelligence sync from OpenCTI STIX JSON.

Импортирует сущности в отдельный слой БД (intel_*),
не перезаписывая базовые таблицы MITRE.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime
from pathlib import Path

from knowledge_base.normalizer import DB_PATH


GROUP_ID_RE = re.compile(r"^G\d{4}$", re.IGNORECASE)
SOFTWARE_ID_RE = re.compile(r"^S\d{4}$", re.IGNORECASE)
TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)


class InternalIntelSync:
    """Синхронизирует локальный intel-слой из STIX JSON."""

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = Path(db_path)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self.ensure_schema()

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass

    def __del__(self):
        self.close()

    def ensure_schema(self):
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS intel_groups (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                aliases TEXT DEFAULT '[]',
                country TEXT DEFAULT '',
                source TEXT DEFAULT 'opencti',
                updated_at TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS intel_software (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                type TEXT DEFAULT 'malware',
                description TEXT DEFAULT '',
                aliases TEXT DEFAULT '[]',
                source TEXT DEFAULT 'opencti',
                updated_at TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS intel_group_techniques (
                group_id TEXT NOT NULL,
                technique_id TEXT NOT NULL,
                source TEXT DEFAULT 'opencti',
                updated_at TEXT DEFAULT '',
                PRIMARY KEY (group_id, technique_id)
            );

            CREATE TABLE IF NOT EXISTS intel_software_techniques (
                software_id TEXT NOT NULL,
                technique_id TEXT NOT NULL,
                source TEXT DEFAULT 'opencti',
                updated_at TEXT DEFAULT '',
                PRIMARY KEY (software_id, technique_id)
            );

            CREATE INDEX IF NOT EXISTS idx_intel_groups_name ON intel_groups(name);
            CREATE INDEX IF NOT EXISTS idx_intel_software_name ON intel_software(name);
            CREATE INDEX IF NOT EXISTS idx_intel_group_tech_t ON intel_group_techniques(technique_id);
            CREATE INDEX IF NOT EXISTS idx_intel_sw_tech_t ON intel_software_techniques(technique_id);
            """
        )
        self.conn.commit()

    def clear_source(self, source: str = "opencti"):
        cur = self.conn.cursor()
        cur.execute("DELETE FROM intel_group_techniques WHERE source = ?", (source,))
        cur.execute("DELETE FROM intel_software_techniques WHERE source = ?", (source,))
        cur.execute("DELETE FROM intel_groups WHERE source = ?", (source,))
        cur.execute("DELETE FROM intel_software WHERE source = ?", (source,))
        self.conn.commit()

    def import_stix(self, stix_path: str | Path, mode: str = "append", source: str = "opencti") -> dict:
        path = Path(stix_path)
        if not path.exists():
            raise FileNotFoundError(f"STIX file not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        objects = self._extract_objects(data)
        if not objects:
            raise ValueError("STIX payload does not contain objects.")

        if mode == "replace":
            self.clear_source(source=source)

        now = datetime.now().isoformat()
        cur = self.conn.cursor()

        technique_by_stix = {}
        groups_by_stix = {}
        software_by_stix = {}

        for obj in objects:
            otype = obj.get("type")
            stix_id = obj.get("id", "")
            if not stix_id:
                continue

            if otype == "attack-pattern":
                tech_id = self._extract_external_id(obj, matcher=TECHNIQUE_ID_RE)
                if tech_id:
                    technique_by_stix[stix_id] = tech_id
                continue

            if otype == "intrusion-set":
                group_id = self._extract_external_id(obj, matcher=GROUP_ID_RE) or self._make_internal_id("G", stix_id)
                groups_by_stix[stix_id] = {
                    "id": group_id,
                    "name": obj.get("name", group_id),
                    "description": obj.get("description", "") or "",
                    "aliases": self._extract_aliases(obj),
                    "country": self._extract_country(obj),
                }
                continue

            if otype in ("malware", "tool"):
                software_id = self._extract_external_id(obj, matcher=SOFTWARE_ID_RE) or self._make_internal_id("S", stix_id)
                software_by_stix[stix_id] = {
                    "id": software_id,
                    "name": obj.get("name", software_id),
                    "type": "tool" if otype == "tool" else "malware",
                    "description": obj.get("description", "") or "",
                    "aliases": self._extract_aliases(obj),
                }

        for record in groups_by_stix.values():
            cur.execute(
                """
                INSERT INTO intel_groups (id, name, description, aliases, country, source, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name,
                    description=excluded.description,
                    aliases=excluded.aliases,
                    country=excluded.country,
                    source=excluded.source,
                    updated_at=excluded.updated_at
                """,
                (
                    record["id"],
                    record["name"],
                    record["description"],
                    json.dumps(record["aliases"], ensure_ascii=False),
                    record["country"],
                    source,
                    now,
                ),
            )

        for record in software_by_stix.values():
            cur.execute(
                """
                INSERT INTO intel_software (id, name, type, description, aliases, source, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name,
                    type=excluded.type,
                    description=excluded.description,
                    aliases=excluded.aliases,
                    source=excluded.source,
                    updated_at=excluded.updated_at
                """,
                (
                    record["id"],
                    record["name"],
                    record["type"],
                    record["description"],
                    json.dumps(record["aliases"], ensure_ascii=False),
                    source,
                    now,
                ),
            )

        group_links = set()
        software_links = set()

        for obj in objects:
            if obj.get("type") != "relationship":
                continue

            src = obj.get("source_ref", "")
            dst = obj.get("target_ref", "")
            if not src or not dst:
                continue

            src_tech = technique_by_stix.get(src)
            dst_tech = technique_by_stix.get(dst)

            # group -> technique
            if src in groups_by_stix and dst_tech:
                group_links.add((groups_by_stix[src]["id"], dst_tech))
            if dst in groups_by_stix and src_tech:
                group_links.add((groups_by_stix[dst]["id"], src_tech))

            # software -> technique
            if src in software_by_stix and dst_tech:
                software_links.add((software_by_stix[src]["id"], dst_tech))
            if dst in software_by_stix and src_tech:
                software_links.add((software_by_stix[dst]["id"], src_tech))

        for group_id, technique_id in sorted(group_links):
            cur.execute(
                """
                INSERT INTO intel_group_techniques (group_id, technique_id, source, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(group_id, technique_id) DO UPDATE SET
                    source=excluded.source,
                    updated_at=excluded.updated_at
                """,
                (group_id, technique_id, source, now),
            )

        for software_id, technique_id in sorted(software_links):
            cur.execute(
                """
                INSERT INTO intel_software_techniques (software_id, technique_id, source, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(software_id, technique_id) DO UPDATE SET
                    source=excluded.source,
                    updated_at=excluded.updated_at
                """,
                (software_id, technique_id, source, now),
            )

        self.conn.commit()

        return {
            "source": source,
            "mode": mode,
            "objects_scanned": len(objects),
            "groups_upserted": len(groups_by_stix),
            "software_upserted": len(software_by_stix),
            "group_tech_links_upserted": len(group_links),
            "software_tech_links_upserted": len(software_links),
        }

    @staticmethod
    def _extract_objects(data: dict) -> list[dict]:
        if isinstance(data, dict) and isinstance(data.get("objects"), list):
            return data["objects"]
        if isinstance(data, list):
            return data
        return []

    @staticmethod
    def _extract_external_id(obj: dict, matcher: re.Pattern) -> str | None:
        for ref in obj.get("external_references", []) or []:
            ext_id = str(ref.get("external_id", "")).upper().strip()
            if matcher.match(ext_id):
                return ext_id
        return None

    @staticmethod
    def _extract_aliases(obj: dict) -> list[str]:
        aliases = obj.get("aliases") or obj.get("x_opencti_aliases") or []
        if isinstance(aliases, str):
            aliases = [aliases]
        if not isinstance(aliases, list):
            return []
        out = []
        seen = set()
        for item in aliases:
            value = str(item).strip()
            if value and value.lower() not in seen:
                seen.add(value.lower())
                out.append(value)
        return out[:50]

    @staticmethod
    def _extract_country(obj: dict) -> str:
        for key in ("x_opencti_country", "country", "x_mitre_country"):
            value = obj.get(key)
            if value:
                return str(value)
        return ""

    @staticmethod
    def _make_internal_id(prefix: str, stix_id: str) -> str:
        digest = hashlib.sha1(stix_id.encode("utf-8")).hexdigest()[:12].upper()
        return f"X{prefix}-{digest}"


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Sync internal intel from STIX JSON")
    parser.add_argument("--stix", required=True, help="Path to STIX JSON file")
    parser.add_argument("--mode", choices=["append", "replace"], default="append")
    parser.add_argument("--source", default="opencti")
    args = parser.parse_args()

    syncer = InternalIntelSync()
    try:
        stats = syncer.import_stix(args.stix, mode=args.mode, source=args.source)
        print(json.dumps(stats, indent=2, ensure_ascii=False))
    finally:
        syncer.close()


if __name__ == "__main__":
    main()

