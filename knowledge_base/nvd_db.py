"""
NVD (National Vulnerability Database) — локальная SQLite база CVE.

Загружает данные из NVD 2.0 API и сохраняет в SQLite для offline-обогащения.
В air-gapped среде: загрузить базу один раз с интернетом, далее использовать локально.

Использование:
    # Загрузка/обновление базы
    python3 -m knowledge_base.nvd_db --update

    # Поиск CVE
    from knowledge_base.nvd_db import NVDDatabase
    db = NVDDatabase()
    cve = db.lookup("CVE-2024-38063")
    # → {"id": "CVE-2024-38063", "description": "...", "cvss3_score": 9.8, ...}
"""

import json
import sqlite3
import time
import urllib.request
import urllib.error
from pathlib import Path

DB_PATH = str(Path(__file__).parent / "nvd.db")
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDDatabase:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._ensure_schema()

    def _ensure_schema(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS cve (
                cve_id       TEXT PRIMARY KEY,
                description  TEXT,
                cvss3_score  REAL,
                cvss3_vector TEXT,
                cvss3_severity TEXT,
                cvss2_score  REAL,
                cwe_ids      TEXT,   -- JSON array
                refs         TEXT,   -- JSON array of reference URLs
                affected     TEXT,   -- JSON array of CPE strings
                published    TEXT,
                last_modified TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_cve_cvss3 ON cve(cvss3_score);
        """)
        self.conn.commit()

    @property
    def count(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) FROM cve").fetchone()
        return row[0]

    def lookup(self, cve_id: str) -> dict:
        """Ищет CVE в локальной базе. Возвращает dict или None."""
        row = self.conn.execute(
            "SELECT * FROM cve WHERE cve_id = ?", (cve_id.upper(),)
        ).fetchone()
        if not row:
            return None
        return {
            "id": row["cve_id"],
            "description": row["description"],
            "cvss3_score": row["cvss3_score"],
            "cvss3_vector": row["cvss3_vector"],
            "cvss3_severity": row["cvss3_severity"],
            "cvss2_score": row["cvss2_score"],
            "cwe_ids": json.loads(row["cwe_ids"] or "[]"),
            "references": json.loads(row["refs"] or "[]"),
            "affected": json.loads(row["affected"] or "[]"),
            "published": row["published"],
            "last_modified": row["last_modified"],
        }

    def lookup_many(self, cve_ids: list) -> dict:
        """Поиск нескольких CVE. Возвращает {cve_id: data}."""
        result = {}
        for cve_id in cve_ids:
            data = self.lookup(cve_id)
            if data:
                result[cve_id.upper()] = data
        return result

    def upsert(self, cve_data: dict):
        """Вставка/обновление одной CVE записи."""
        self.conn.execute("""
            INSERT OR REPLACE INTO cve
            (cve_id, description, cvss3_score, cvss3_vector, cvss3_severity,
             cvss2_score, cwe_ids, refs, affected, published, last_modified)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cve_data["id"],
            cve_data.get("description", ""),
            cve_data.get("cvss3_score"),
            cve_data.get("cvss3_vector"),
            cve_data.get("cvss3_severity"),
            cve_data.get("cvss2_score"),
            json.dumps(cve_data.get("cwe_ids", [])),
            json.dumps(cve_data.get("references", [])),
            json.dumps(cve_data.get("affected", [])),
            cve_data.get("published"),
            cve_data.get("last_modified"),
        ))

    def _parse_nvd_item(self, vuln: dict) -> dict:
        """Парсит один элемент из NVD API 2.0 ответа."""
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")

        # Description (English)
        descriptions = cve.get("descriptions", [])
        desc_en = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc_en = d.get("value", "")
                break

        # CVSS v3.1
        cvss3_score = None
        cvss3_vector = None
        cvss3_severity = None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30"):
            cvss_list = metrics.get(key, [])
            if cvss_list:
                primary = cvss_list[0].get("cvssData", {})
                cvss3_score = primary.get("baseScore")
                cvss3_vector = primary.get("vectorString")
                cvss3_severity = primary.get("baseSeverity")
                break

        # CVSS v2
        cvss2_score = None
        cvss2_list = metrics.get("cvssMetricV2", [])
        if cvss2_list:
            cvss2_score = cvss2_list[0].get("cvssData", {}).get("baseScore")

        # CWE
        cwe_ids = []
        weaknesses = cve.get("weaknesses", [])
        for w in weaknesses:
            for d in w.get("description", []):
                val = d.get("value", "")
                if val.startswith("CWE-"):
                    cwe_ids.append(val)

        # References
        refs = [r.get("url", "") for r in cve.get("references", [])[:10]]

        # Affected (CPE)
        affected = []
        configurations = cve.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria", "")
                    if cpe:
                        affected.append(cpe)

        return {
            "id": cve_id,
            "description": desc_en,
            "cvss3_score": cvss3_score,
            "cvss3_vector": cvss3_vector,
            "cvss3_severity": cvss3_severity,
            "cvss2_score": cvss2_score,
            "cwe_ids": cwe_ids,
            "references": refs,
            "affected": affected[:20],
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
        }

    def fetch_cve(self, cve_id: str) -> dict:
        """Загружает одну CVE из NVD API 2.0."""
        url = f"{NVD_API_URL}?cveId={cve_id}"
        req = urllib.request.Request(url, headers={"User-Agent": "CTI-Pipeline/1.0"})

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError) as e:
            return None

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None

        parsed = self._parse_nvd_item(vulns[0])
        self.upsert(parsed)
        self.conn.commit()
        return parsed

    def fetch_batch(self, cve_ids: list, delay: float = 0.7) -> int:
        """Загружает список CVE из NVD API (с rate limiting).

        NVD API без ключа: 5 запросов в 30 секунд.
        С API key: 50 запросов в 30 секунд.
        """
        fetched = 0
        for cve_id in cve_ids:
            existing = self.lookup(cve_id)
            if existing:
                continue
            result = self.fetch_cve(cve_id)
            if result:
                fetched += 1
                print(f"  {cve_id}: CVSS {result.get('cvss3_score', '?')} — {result.get('cvss3_severity', '?')}")
            else:
                print(f"  {cve_id}: NOT FOUND in NVD")
            time.sleep(delay)
        return fetched

    def fetch_recent(self, days: int = 30, max_results: int = 500) -> int:
        """Загружает последние CVE за N дней."""
        from datetime import datetime, timedelta
        end = datetime.utcnow()
        start = end - timedelta(days=days)

        start_str = start.strftime("%Y-%m-%dT00:00:00.000")
        end_str = end.strftime("%Y-%m-%dT23:59:59.999")

        fetched = 0
        start_index = 0
        results_per_page = 100

        while fetched < max_results:
            url = (
                f"{NVD_API_URL}?"
                f"pubStartDate={start_str}&pubEndDate={end_str}"
                f"&startIndex={start_index}&resultsPerPage={results_per_page}"
            )
            req = urllib.request.Request(url, headers={"User-Agent": "CTI-Pipeline/1.0"})

            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
            except (urllib.error.URLError, urllib.error.HTTPError):
                break

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break

            for vuln in vulns:
                parsed = self._parse_nvd_item(vuln)
                self.upsert(parsed)
                fetched += 1

            self.conn.commit()
            total_results = data.get("totalResults", 0)
            start_index += results_per_page

            if start_index >= total_results:
                break

            time.sleep(6.5)  # Rate limit without API key

        return fetched

    def close(self):
        self.conn.close()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="NVD CVE Database Manager")
    parser.add_argument("--update", action="store_true", help="Загрузить последние CVE (30 дней)")
    parser.add_argument("--days", type=int, default=30, help="Количество дней для загрузки")
    parser.add_argument("--fetch", nargs="+", help="Загрузить конкретные CVE: CVE-2024-38063 CVE-2021-44228")
    parser.add_argument("--lookup", help="Поиск CVE в локальной базе")
    parser.add_argument("--stats", action="store_true", help="Статистика базы")
    args = parser.parse_args()

    db = NVDDatabase()

    if args.stats:
        print(f"NVD база: {db.count} CVE записей")
        if db.count > 0:
            row = db.conn.execute(
                "SELECT AVG(cvss3_score), MAX(cvss3_score), MIN(published) FROM cve WHERE cvss3_score IS NOT NULL"
            ).fetchone()
            print(f"  Средний CVSS: {row[0]:.1f}" if row[0] else "  CVSS данных нет")
            print(f"  Макс CVSS:    {row[1]}" if row[1] else "")
            print(f"  С:            {row[2]}" if row[2] else "")

    elif args.fetch:
        print(f"Загрузка {len(args.fetch)} CVE из NVD API...")
        count = db.fetch_batch(args.fetch)
        print(f"Загружено: {count} новых CVE")
        print(f"Всего в базе: {db.count}")

    elif args.update:
        print(f"Загрузка CVE за последние {args.days} дней...")
        count = db.fetch_recent(days=args.days)
        print(f"Загружено: {count} CVE")
        print(f"Всего в базе: {db.count}")

    elif args.lookup:
        result = db.lookup(args.lookup)
        if result:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print(f"{args.lookup} не найден в локальной базе")
            print("Используйте --fetch для загрузки из NVD API")

    else:
        parser.print_help()

    db.close()
