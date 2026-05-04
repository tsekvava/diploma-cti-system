"""
OpenCTI Exporter — расширенный экспорт результатов анализа в граф знаний OpenCTI.

Что создаёт (STIX-объекты):
  - Intrusion Sets (APT-группы) — с MITRE ID, алиасами, confidence
  - Malware — с типом, описанием, confidence
  - Tools — с описанием и confidence
  - Attack Patterns (TTP) — MITRE техники с Kill Chain Phase и русским описанием
  - Vulnerabilities (CVE) — из regex-экстракции
  - Indicators (IoC) — IP, домены, хеши, email (STIX pattern)
  - TLP-маркировка на всех объектах

Какие связи создаёт (Knowledge Graph):
  - Intrusion Set → uses → Attack Pattern
  - Intrusion Set → uses → Malware
  - Intrusion Set → uses → Tool
  - Malware → uses → Attack Pattern
  - Malware → exploits → Vulnerability
  - Indicator → indicates → Malware
  - Indicator → indicates → Intrusion Set

Использование:
    from opencti_exporter import OpenCTIExporter
    exporter = OpenCTIExporter()
    exporter.export(summarizer_result["json"])

Или из CLI:
    python3 opencti_exporter.py --input result.json
    python3 opencti_exporter.py --input result.json --tlp AMBER --dry-run

Переменные окружения:
    OPENCTI_URL   — адрес OpenCTI (по умолчанию http://localhost:8080)
    OPENCTI_TOKEN — API-токен
"""

import json
import os
import sys
import argparse
from datetime import datetime
from pathlib import Path

# pycti — импортируется при реальном экспорте, не при dry-run
try:
    from pycti import OpenCTIApiClient
    PYCTI_AVAILABLE = True
except ImportError:
    PYCTI_AVAILABLE = False

# --- TLP Marking Definition IDs (стандартные STIX) ---
TLP_MARKINGS = {
    "TLP:CLEAR": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "TLP:WHITE": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "TLP:GREEN": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "TLP:AMBER": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "TLP:AMBER+STRICT": "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37",
    "TLP:RED": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}

# Kill Chain Phase names для OpenCTI (MITRE ATT&CK)
TACTIC_PHASE_MAP = {
    "TA0043": "reconnaissance",
    "TA0042": "resource-development",
    "TA0001": "initial-access",
    "TA0002": "execution",
    "TA0003": "persistence",
    "TA0004": "privilege-escalation",
    "TA0005": "defense-evasion",
    "TA0006": "credential-access",
    "TA0007": "discovery",
    "TA0008": "lateral-movement",
    "TA0009": "collection",
    "TA0011": "command-and-control",
    "TA0010": "exfiltration",
    "TA0040": "impact",
}


class OpenCTIExporter:
    """Экспортирует результаты CTI-анализа в OpenCTI."""

    def __init__(
        self,
        url: str = None,
        token: str = None,
        tlp: str = "TLP:AMBER",
        dry_run: bool = False,
    ):
        self.url = url or os.getenv("OPENCTI_URL", "http://localhost:8080")
        self.token = token or os.getenv("OPENCTI_TOKEN", "")
        self.tlp = tlp.upper()
        self.dry_run = dry_run
        self.client = None

        self.tlp_id = TLP_MARKINGS.get(self.tlp, TLP_MARKINGS["TLP:AMBER"])

        # Счётчики
        self._stats = {
            "intrusion_sets": 0,
            "malware": 0,
            "tools": 0,
            "attack_patterns": 0,
            "vulnerabilities": 0,
            "indicators": 0,
            "relationships": 0,
            "errors": 0,
        }

        if not dry_run:
            if not PYCTI_AVAILABLE:
                raise ImportError(
                    "pycti не установлен! pip3 install pycti\n"
                    "Или используйте --dry-run для проверки без подключения."
                )
            if not self.token:
                raise ValueError(
                    "OPENCTI_TOKEN не задан!\n"
                    "export OPENCTI_TOKEN=your_token_here"
                )

    def _connect(self):
        """Подключение к OpenCTI."""
        if self.dry_run:
            print(f"[DRY-RUN] OpenCTI URL: {self.url}")
            return

        print(f"Подключение к OpenCTI: {self.url}")
        self.client = OpenCTIApiClient(self.url, self.token)
        print("   Подключено.\n")

    #  Создание STIX-объектов

    def _create_intrusion_set(self, actor: dict) -> str:
        """Создаёт Intrusion Set (APT-группу)."""
        name = actor["name"]
        mitre_id = actor.get("mitre_id", "")
        aliases = actor.get("aliases", [])
        confidence = actor.get("confidence", 50)

        description = f"Threat actor identified by automated CTI analysis."
        if mitre_id:
            description += f" MITRE ATT&CK ID: {mitre_id}."
        if aliases:
            description += f" Known aliases: {', '.join(aliases[:5])}."

        print(f"   [+] Intrusion Set: {name}" + (f" ({mitre_id})" if mitre_id else ""))

        if self.dry_run:
            self._stats["intrusion_sets"] += 1
            return f"dry-run-{name}"

        try:
            result = self.client.intrusion_set.create(
                name=name,
                description=description,
                aliases=aliases[:10] if aliases else None,
                confidence=confidence,
                objectMarking=[self.tlp_id],
                update=True,
            )
            self._stats["intrusion_sets"] += 1
            return result.get("id", "")
        except Exception as e:
            print(f"       [ERROR] {e}")
            self._stats["errors"] += 1
            return ""

    def _create_malware(self, mal: dict) -> str:
        """Создаёт Malware."""
        name = mal["name"]
        mitre_id = mal.get("mitre_id", "")
        confidence = mal.get("confidence", 50)
        mal_type = mal.get("type", "malware")

        description = f"Malware identified by automated CTI analysis."
        if mitre_id:
            description += f" MITRE ATT&CK ID: {mitre_id}."

        print(f"   [+] Malware: {name}" + (f" ({mitre_id})" if mitre_id else ""))

        if self.dry_run:
            self._stats["malware"] += 1
            return f"dry-run-{name}"

        try:
            result = self.client.malware.create(
                name=name,
                is_family=True,
                description=description,
                confidence=confidence,
                objectMarking=[self.tlp_id],
                update=True,
            )
            self._stats["malware"] += 1
            return result.get("id", "")
        except Exception as e:
            print(f"       [ERROR] {e}")
            self._stats["errors"] += 1
            return ""

    def _create_tool(self, tool: dict) -> str:
        """Создаёт Tool."""
        name = tool["name"]
        mitre_id = tool.get("mitre_id", "")
        confidence = tool.get("confidence", 50)

        description = "Tool identified by automated CTI analysis."
        if mitre_id:
            description += f" MITRE ATT&CK ID: {mitre_id}."

        print(f"   [+] Tool: {name}" + (f" ({mitre_id})" if mitre_id else ""))

        if self.dry_run:
            self._stats["tools"] += 1
            return f"dry-run-{name}"

        try:
            result = self.client.tool.create(
                name=name,
                description=description,
                confidence=confidence,
                objectMarking=[self.tlp_id],
                update=True,
            )
            self._stats["tools"] += 1
            return result.get("id", "")
        except Exception as e:
            print(f"       [ERROR] {e}")
            self._stats["errors"] += 1
            return ""

    def _create_attack_pattern(self, technique: dict, tactic_id: str = "") -> str:
        """Создаёт Attack Pattern (MITRE TTP)."""
        tech_id = technique["id"]
        name_en = technique.get("name_en", "")
        name_ru = technique.get("name_ru", "")
        confidence = technique.get("confidence", 50)
        evidence = technique.get("evidence", "")

        display_name = f"{tech_id} - {name_en}"
        description = ""
        if name_ru:
            description += f"Русское название: {name_ru}. "
        if evidence:
            description += f"Evidence: {evidence}. "
        description += "Mapped by automated Kill Chain analysis."

        # Kill Chain Phase
        phase_name = TACTIC_PHASE_MAP.get(tactic_id, "")
        kill_chain = []
        if phase_name:
            kill_chain = [{
                "kill_chain_name": "mitre-attack",
                "phase_name": phase_name,
            }]

        print(f"   [+] Attack Pattern: {display_name} [conf: {confidence}]")

        if self.dry_run:
            self._stats["attack_patterns"] += 1
            return f"dry-run-{tech_id}"

        try:
            result = self.client.attack_pattern.create(
                name=display_name,
                description=description,
                x_mitre_id=tech_id,
                confidence=confidence,
                killChainPhases=kill_chain if kill_chain else None,
                objectMarking=[self.tlp_id],
                update=True,
            )
            self._stats["attack_patterns"] += 1
            return result.get("id", "")
        except Exception as e:
            print(f"       [ERROR] {e}")
            self._stats["errors"] += 1
            return ""

    def _create_vulnerability(self, vuln: dict) -> str:
        """Создаёт Vulnerability (CVE)."""
        cve_id = vuln if isinstance(vuln, str) else vuln.get("id", "")
        confidence = 100 if isinstance(vuln, str) else vuln.get("confidence", 100)

        print(f"   [+] Vulnerability: {cve_id}")

        if self.dry_run:
            self._stats["vulnerabilities"] += 1
            return f"dry-run-{cve_id}"

        try:
            result = self.client.vulnerability.create(
                name=cve_id,
                description=f"Vulnerability {cve_id} extracted from threat report.",
                confidence=confidence,
                objectMarking=[self.tlp_id],
                update=True,
            )
            self._stats["vulnerabilities"] += 1
            return result.get("id", "")
        except Exception as e:
            print(f"       [ERROR] {e}")
            self._stats["errors"] += 1
            return ""

    def _create_indicator(self, ioc_type: str, value: str) -> str:
        """Создаёт Indicator (IoC)."""
        patterns = {
            "ipv4": (f"[ipv4-addr:value = '{value}']", "IPv4-Addr"),
            "domain": (f"[domain-name:value = '{value}']", "Domain-Name"),
            "email": (f"[email-addr:value = '{value}']", "Email-Addr"),
        }

        # Хеши — определяем тип по длине
        if ioc_type == "hash":
            length = len(value)
            if length == 64:
                pattern = f"[file:hashes.'SHA-256' = '{value}']"
            elif length == 40:
                pattern = f"[file:hashes.'SHA-1' = '{value}']"
            elif length == 32:
                pattern = f"[file:hashes.'MD5' = '{value}']"
            else:
                print(f"       [SKIP] Unknown hash length {length}: {value[:16]}...")
                return ""
            observable_type = "StixFile"
        elif ioc_type in patterns:
            pattern, observable_type = patterns[ioc_type]
        else:
            return ""

        if self.dry_run:
            print(f"   [+] Indicator ({ioc_type}): {value}")
            self._stats["indicators"] += 1
            return f"dry-run-{value[:32]}"

        try:
            result = self.client.indicator.create(
                name=value,
                pattern=pattern,
                pattern_type="stix",
                x_opencti_main_observable_type=observable_type,
                confidence=100,
                objectMarking=[self.tlp_id],
                update=True,
            )
            self._stats["indicators"] += 1
            return result.get("id", "")
        except Exception as e:
            print(f"       [ERROR] Indicator {value[:32]}: {e}")
            self._stats["errors"] += 1
            return ""

    #  Создание связей (Relationships)

    def _create_relationship(self, from_id: str, to_id: str,
                              rel_type: str, description: str = ""):
        """Создаёт STIX Relationship."""
        if not from_id or not to_id:
            return

        if self.dry_run:
            self._stats["relationships"] += 1
            return

        try:
            self.client.stix_core_relationship.create(
                fromId=from_id,
                toId=to_id,
                relationship_type=rel_type,
                description=description or "Identified by automated CTI analysis",
                confidence=70,
                objectMarking=[self.tlp_id],
            )
            self._stats["relationships"] += 1
        except Exception as e:
            print(f"       [ERROR] Relationship {rel_type}: {e}")
            self._stats["errors"] += 1

    #  Основной метод экспорта

    def export(self, data: dict) -> dict:
        """
        Экспортирует структурированный JSON в OpenCTI.

        Args:
            data: JSON-выход от ReportSummarizer (result["json"])

        Returns:
            Статистика экспорта
        """
        self._connect()

        print(f"{'=' * 56}")
        print(f"ЭКСПОРТ В OPENCTI")
        print(f"Источник: {data.get('metadata', {}).get('source', 'unknown')}")
        print(f"TLP: {self.tlp}")
        print(f"{'=' * 56}\n")

        # --- 1. Intrusion Sets ---
        print("── Intrusion Sets (APT-группы) ──")
        actor_ids = {}
        for actor in data.get("threat_actors", []):
            obj_id = self._create_intrusion_set(actor)
            if obj_id:
                actor_ids[actor["name"]] = obj_id

        # --- 2. Malware ---
        print("\n── Malware ──")
        malware_ids = {}
        for mal in data.get("malware", []):
            obj_id = self._create_malware(mal)
            if obj_id:
                malware_ids[mal["name"]] = obj_id

        # --- 3. Tools ---
        print("\n── Tools ──")
        tool_ids = {}
        for tool in data.get("tools", []):
            obj_id = self._create_tool(tool)
            if obj_id:
                tool_ids[tool["name"]] = obj_id

        # --- 4. Attack Patterns (Kill Chain) ---
        print("\n── Attack Patterns (TTP) ──")
        attack_pattern_ids = {}
        for phase in data.get("kill_chain", []):
            tactic_id = phase.get("tactic_id", "")
            for technique in phase.get("techniques", []):
                obj_id = self._create_attack_pattern(technique, tactic_id)
                if obj_id:
                    attack_pattern_ids[technique["id"]] = obj_id

        # --- 5. Vulnerabilities (CVE) ---
        print("\n── Vulnerabilities ──")
        vuln_ids = {}
        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln if isinstance(vuln, str) else vuln.get("id", "")
            obj_id = self._create_vulnerability(vuln)
            if obj_id:
                vuln_ids[cve_id] = obj_id

        # --- 6. Indicators (IoC) ---
        print("\n── Indicators (IoC) ──")
        indicator_ids = {}
        indicators = data.get("indicators", {})
        for ioc_type, ioc_list in indicators.items():
            for value in ioc_list:
                obj_id = self._create_indicator(ioc_type, value)
                if obj_id:
                    indicator_ids[value] = obj_id

        ioc_count = sum(len(v) for v in indicators.values())
        print(f"   Итого IoC: {ioc_count}")

        # --- 7. Relationships ---
        print(f"\n── Relationships (связи) ──")

        # Actor → uses → Malware
        for actor_name, actor_id in actor_ids.items():
            for mal_name, mal_id in malware_ids.items():
                print(f"   {actor_name} → uses → {mal_name}")
                self._create_relationship(actor_id, mal_id, "uses")

        # Actor → uses → Tool
        for actor_name, actor_id in actor_ids.items():
            for tool_name, tool_id in tool_ids.items():
                print(f"   {actor_name} → uses → {tool_name}")
                self._create_relationship(actor_id, tool_id, "uses")

        # Actor → uses → Attack Pattern
        for actor_name, actor_id in actor_ids.items():
            for tech_id, ap_id in attack_pattern_ids.items():
                print(f"   {actor_name} → uses → {tech_id}")
                self._create_relationship(actor_id, ap_id, "uses")

        # Malware → uses → Attack Pattern
        for mal_name, mal_id in malware_ids.items():
            for tech_id, ap_id in attack_pattern_ids.items():
                print(f"   {mal_name} → uses → {tech_id}")
                self._create_relationship(mal_id, ap_id, "uses")

        # Malware → exploits → Vulnerability
        for mal_name, mal_id in malware_ids.items():
            for cve_id, vuln_id in vuln_ids.items():
                print(f"   {mal_name} → exploits → {cve_id}")
                self._create_relationship(mal_id, vuln_id, "exploits")

        # Indicator → indicates → Malware (каждый IoC → все malware)
        for ioc_val, ioc_id in indicator_ids.items():
            for mal_name, mal_id in malware_ids.items():
                self._create_relationship(ioc_id, mal_id, "indicates")

        # Indicator → indicates → Intrusion Set (каждый IoC → все actors)
        for ioc_val, ioc_id in indicator_ids.items():
            for actor_name, actor_id in actor_ids.items():
                self._create_relationship(ioc_id, actor_id, "indicates")

        # --- Итог ---
        print(f"\n{'=' * 56}")
        print("РЕЗУЛЬТАТ ЭКСПОРТА:")
        print(f"  Intrusion Sets:  {self._stats['intrusion_sets']}")
        print(f"  Malware:         {self._stats['malware']}")
        print(f"  Tools:           {self._stats['tools']}")
        print(f"  Attack Patterns: {self._stats['attack_patterns']}")
        print(f"  Vulnerabilities: {self._stats['vulnerabilities']}")
        print(f"  Indicators:      {self._stats['indicators']}")
        print(f"  Relationships:   {self._stats['relationships']}")
        print(f"  Errors:          {self._stats['errors']}")
        total = sum(v for k, v in self._stats.items() if k != "errors")
        print(f"  ИТОГО объектов:  {total}")
        print(f"{'=' * 56}")

        return self._stats

    #  STIX Bundle экспорт (для air-gapped среды)

    def export_stix_bundle(self, data: dict, output_path: str = None) -> dict:
        """
        Генерирует STIX 2.1 Bundle как JSON-файл.

        Для air-gapped SOC: файл можно перенести через USB/защищённый канал
        и импортировать в OpenCTI через UI (Data → Import → STIX Bundle).

        Args:
            data: JSON-выход от ReportSummarizer (result["json"])
            output_path: Путь к выходному файлу (по умолчанию: stix_bundle_<timestamp>.json)

        Returns:
            STIX Bundle dict
        """
        import uuid

        from datetime import timezone
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        objects = []

        # Вспомогательная функция для создания STIX ID
        def stix_id(stype: str) -> str:
            return f"{stype}--{uuid.uuid4()}"

        # TLP marking
        objects.append({
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": self.tlp_id,
            "created": "2017-01-20T00:00:00.000Z",
            "definition_type": "tlp",
            "name": self.tlp,
            "definition": {"tlp": self.tlp.replace("TLP:", "").lower()},
        })

        # --- Track IDs for relationships ---
        actor_stix_ids = {}
        malware_stix_ids = {}
        tool_stix_ids = {}
        ap_stix_ids = {}
        vuln_stix_ids = {}
        indicator_stix_ids = {}

        # --- Intrusion Sets ---
        for actor in data.get("threat_actors", []):
            sid = stix_id("intrusion-set")
            actor_stix_ids[actor["name"]] = sid
            obj = {
                "type": "intrusion-set",
                "spec_version": "2.1",
                "id": sid,
                "created": now,
                "modified": now,
                "name": actor["name"],
                "confidence": actor.get("confidence", 50),
                "object_marking_refs": [self.tlp_id],
            }
            if actor.get("mitre_id"):
                obj["external_references"] = [{
                    "source_name": "mitre-attack",
                    "external_id": actor["mitre_id"],
                }]
            if actor.get("aliases"):
                obj["aliases"] = actor["aliases"][:10]
            objects.append(obj)

        # --- Malware ---
        for mal in data.get("malware", []):
            sid = stix_id("malware")
            malware_stix_ids[mal["name"]] = sid
            obj = {
                "type": "malware",
                "spec_version": "2.1",
                "id": sid,
                "created": now,
                "modified": now,
                "name": mal["name"],
                "is_family": True,
                "confidence": mal.get("confidence", 50),
                "object_marking_refs": [self.tlp_id],
            }
            if mal.get("mitre_id"):
                obj["external_references"] = [{
                    "source_name": "mitre-attack",
                    "external_id": mal["mitre_id"],
                }]
            objects.append(obj)

        # --- Tools ---
        for tool in data.get("tools", []):
            sid = stix_id("tool")
            tool_stix_ids[tool["name"]] = sid
            obj = {
                "type": "tool",
                "spec_version": "2.1",
                "id": sid,
                "created": now,
                "modified": now,
                "name": tool["name"],
                "confidence": tool.get("confidence", 50),
                "object_marking_refs": [self.tlp_id],
            }
            if tool.get("mitre_id"):
                obj["external_references"] = [{
                    "source_name": "mitre-attack",
                    "external_id": tool["mitre_id"],
                }]
            objects.append(obj)

        # --- Attack Patterns ---
        for phase in data.get("kill_chain", []):
            tactic_id = phase.get("tactic_id", "")
            phase_name = TACTIC_PHASE_MAP.get(tactic_id, "")
            for tech in phase.get("techniques", []):
                sid = stix_id("attack-pattern")
                ap_stix_ids[tech["id"]] = sid
                obj = {
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": sid,
                    "created": now,
                    "modified": now,
                    "name": f"{tech['id']} - {tech.get('name_en', '')}",
                    "confidence": tech.get("confidence", 50),
                    "external_references": [{
                        "source_name": "mitre-attack",
                        "external_id": tech["id"],
                    }],
                    "object_marking_refs": [self.tlp_id],
                }
                if phase_name:
                    obj["kill_chain_phases"] = [{
                        "kill_chain_name": "mitre-attack",
                        "phase_name": phase_name,
                    }]
                if tech.get("name_ru"):
                    obj["x_opencti_description_ru"] = tech["name_ru"]
                objects.append(obj)

        # --- Vulnerabilities ---
        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln if isinstance(vuln, str) else vuln.get("id", "")
            sid = stix_id("vulnerability")
            vuln_stix_ids[cve_id] = sid
            objects.append({
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": sid,
                "created": now,
                "modified": now,
                "name": cve_id,
                "external_references": [{
                    "source_name": "cve",
                    "external_id": cve_id,
                }],
                "object_marking_refs": [self.tlp_id],
            })

        # --- Indicators ---
        indicators = data.get("indicators", {})
        stix_patterns = {
            "ipv4": lambda v: f"[ipv4-addr:value = '{v}']",
            "domain": lambda v: f"[domain-name:value = '{v}']",
            "email": lambda v: f"[email-addr:value = '{v}']",
        }
        for ioc_type, ioc_list in indicators.items():
            for value in ioc_list:
                if ioc_type == "hash":
                    length = len(value)
                    if length == 64:
                        pattern = f"[file:hashes.'SHA-256' = '{value}']"
                    elif length == 40:
                        pattern = f"[file:hashes.'SHA-1' = '{value}']"
                    elif length == 32:
                        pattern = f"[file:hashes.'MD5' = '{value}']"
                    else:
                        continue
                elif ioc_type in stix_patterns:
                    pattern = stix_patterns[ioc_type](value)
                else:
                    continue

                sid = stix_id("indicator")
                indicator_stix_ids[value] = sid
                objects.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": sid,
                    "created": now,
                    "modified": now,
                    "name": value,
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": now,
                    "confidence": 100,
                    "object_marking_refs": [self.tlp_id],
                })

        # --- Relationships ---
        def add_rel(from_id, to_id, rel_type):
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": stix_id("relationship"),
                "created": now,
                "modified": now,
                "relationship_type": rel_type,
                "source_ref": from_id,
                "target_ref": to_id,
                "confidence": 70,
                "object_marking_refs": [self.tlp_id],
            })

        # Actor → uses → Malware/Tool/Attack Pattern
        for actor_name, actor_id in actor_stix_ids.items():
            for _, mal_id in malware_stix_ids.items():
                add_rel(actor_id, mal_id, "uses")
            for _, tool_id in tool_stix_ids.items():
                add_rel(actor_id, tool_id, "uses")
            for _, ap_id in ap_stix_ids.items():
                add_rel(actor_id, ap_id, "uses")

        # Malware → uses → Attack Pattern, exploits → Vulnerability
        for _, mal_id in malware_stix_ids.items():
            for _, ap_id in ap_stix_ids.items():
                add_rel(mal_id, ap_id, "uses")
            for _, vuln_id in vuln_stix_ids.items():
                add_rel(mal_id, vuln_id, "exploits")

        # Indicator → indicates → Malware/Actor
        for _, ioc_id in indicator_stix_ids.items():
            for _, mal_id in malware_stix_ids.items():
                add_rel(ioc_id, mal_id, "indicates")
            for _, actor_id in actor_stix_ids.items():
                add_rel(ioc_id, actor_id, "indicates")

        # --- Bundle ---
        bundle = {
            "type": "bundle",
            "id": stix_id("bundle"),
            "objects": objects,
        }

        # Сохраняем
        if output_path is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"stix_bundle_{ts}.json"

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2, ensure_ascii=False)

        n_objects = len([o for o in objects if o["type"] != "marking-definition" and o["type"] != "relationship"])
        n_rels = len([o for o in objects if o["type"] == "relationship"])

        print(f"\nSTIX Bundle сохранён: {output_path}")
        print(f"  Объектов: {n_objects}, Связей: {n_rels}, Всего: {len(objects)}")

        return bundle


# --- CLI ---

def main():
    parser = argparse.ArgumentParser(description="Export CTI analysis to OpenCTI")
    parser.add_argument("--input", "-i", required=True, help="JSON file from ReportSummarizer")
    parser.add_argument("--tlp", default="TLP:AMBER", help="TLP marking (default: TLP:AMBER)")
    parser.add_argument("--url", default=None, help="OpenCTI URL (or OPENCTI_URL env)")
    parser.add_argument("--token", default=None, help="OpenCTI token (or OPENCTI_TOKEN env)")
    parser.add_argument("--dry-run", action="store_true", help="Print what would be created without connecting")
    parser.add_argument(
        "--stix-bundle", "-s",
        type=str,
        default=None,
        metavar="FILE",
        help="Export as STIX 2.1 Bundle JSON (for air-gapped import to OpenCTI)",
    )
    args = parser.parse_args()

    if not Path(args.input).exists():
        print(f"Файл не найден: {args.input}")
        return

    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)

    exporter = OpenCTIExporter(
        url=args.url,
        token=args.token,
        tlp=args.tlp,
        dry_run=args.dry_run or bool(args.stix_bundle),  # если bundle — dry_run для API
    )

    if args.stix_bundle:
        # Режим STIX Bundle: генерируем файл для офлайн-импорта
        exporter.export_stix_bundle(data, output_path=args.stix_bundle)
    else:
        # Режим API или dry-run
        exporter.export(data)


if __name__ == "__main__":
    main()
