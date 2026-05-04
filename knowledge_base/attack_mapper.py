"""
Kill Chain Mapper — маппинг текста на MITRE ATT&CK Kill Chain.

Двухэтапный подход:
  Этап 1: LLM определяет тактики (из 14 вариантов)
  Этап 2: LLM выбирает конкретные техники из списка для каждой тактики
  Валидация: проверка каждого T-кода в справочнике SQLite

Использование:
    from knowledge_base.attack_mapper import AttackMapper
    mapper = AttackMapper()
    result = mapper.map_text("The attacker used spearphishing with a malicious docx...")
"""

import json
import ollama
from pathlib import Path
from knowledge_base.normalizer import EntityNormalizer

PROJECT_ROOT = Path(__file__).parent.parent
DEFAULT_MODEL = "qwen2.5:14b"


class AttackMapper:
    """Маппит текст на MITRE ATT&CK Kill Chain."""

    def __init__(self, model_name: str = DEFAULT_MODEL, normalizer: EntityNormalizer = None):
        self.model_name = model_name
        self.normalizer = normalizer or EntityNormalizer()
        self._load_prompts()
        self._build_tactic_reference()

    def _load_prompts(self):
        """Загружает промпты из файлов (рекомендация ASAP RAG_LLM: раздельные файлы)."""
        prompts_dir = PROJECT_ROOT / "prompts"

        def _load(name, fallback):
            path = prompts_dir / name
            return path.read_text(encoding="utf-8") if path.exists() else fallback

        self._tactics_prompt_template = _load(
            "map_killchain_tactics.txt",
            "Identify MITRE ATT&CK tactics in the text.\n{text}",
        )
        self._techniques_prompt_template = _load(
            "map_killchain_techniques.txt",
            "Identify techniques for tactic {tactic_id}.\n{text}",
        )

        # Проверяем только обязательные плейсхолдеры.
        # JSON-скобки внутри шаблонов допускаются и не должны ломать рендер.
        self._validate_template(
            self._tactics_prompt_template,
            required={"tactics_reference", "text"},
            template_name="map_killchain_tactics.txt",
        )
        self._validate_template(
            self._techniques_prompt_template,
            required={"tactic_name", "tactic_id", "techniques_reference", "text"},
            template_name="map_killchain_techniques.txt",
        )

    @staticmethod
    def _validate_template(template: str, required: set[str], template_name: str):
        missing = [key for key in required if f"{{{key}}}" not in template]
        if missing:
            raise ValueError(
                f"Prompt template '{template_name}' missing placeholders: {', '.join(missing)}"
            )

    @staticmethod
    def _render_template(template: str, values: dict[str, str]) -> str:
        """Безопасный рендер плейсхолдеров без str.format."""
        rendered = template
        for key, value in values.items():
            rendered = rendered.replace(f"{{{key}}}", str(value))
        return rendered

    def _build_tactic_reference(self):
        """Строит справочный текст с тактиками для промпта."""
        from knowledge_base.normalizer import DB_PATH
        import sqlite3

        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row

        self._tactics = []
        for row in conn.execute("SELECT * FROM tactics ORDER BY kill_chain_order"):
            self._tactics.append({
                "id": row["id"],
                "name_en": row["name_en"],
                "name_ru": row["name_ru"],
                "order": row["kill_chain_order"],
            })

        conn.close()

        # Текст для промпта Этапа 1
        lines = []
        for t in self._tactics:
            lines.append(f"{t['id']} {t['name_en']} ({t['name_ru']})")
        self._tactics_reference = "\n".join(lines)

    def _build_techniques_reference(self, tactic_id: str) -> str:
        """Строит список техник для конкретной тактики (для Этапа 2)."""
        techniques = self.normalizer.get_techniques_for_tactic(tactic_id)
        if not techniques:
            return ""

        lines = []
        for t in techniques:
            prefix = "  " if t["is_subtechnique"] else ""
            name = t["name_en"] or t["name_ru"]
            lines.append(f"{prefix}{t['id']} - {name}")

        return "\n".join(lines)

    def map_text(self, text: str, max_text_len: int = 6000) -> dict:
        """
        Полный маппинг текста на Kill Chain.

        Returns:
            {
                "kill_chain_phases": [
                    {
                        "tactic_id": "TA0001",
                        "tactic_name_en": "Initial Access",
                        "tactic_name_ru": "Первоначальный доступ",
                        "techniques": [
                            {
                                "id": "T1566.001",
                                "name_en": "Phishing: Spearphishing Attachment",
                                "name_ru": "Целевой фишинг с вложением",
                                "confidence": 85,
                                "evidence": "email with malicious attachment"
                            }
                        ]
                    }
                ]
            }
        """
        warnings = []

        # Обрезаем текст если слишком длинный
        truncated = text[:max_text_len] if len(text) > max_text_len else text

        # Этап 1: Определение тактик
        print("   [Kill Chain] Этап 1: определение тактик...")
        try:
            tactics = self._identify_tactics(truncated)
        except Exception as e:
            msg = f"Kill Chain Stage 1 failed: {e}"
            print(f"   [Kill Chain] {msg}")
            warnings.append(msg)
            return {"kill_chain_phases": [], "warnings": warnings}

        if not tactics:
            print("   [Kill Chain] Тактики не определены")
            return {"kill_chain_phases": [], "warnings": warnings}

        print(f"   [Kill Chain] Найдено тактик: {len(tactics)}")

        # Этап 2: Определение техник для каждой тактики
        phases = []
        for tactic_info in tactics:
            tactic_id = tactic_info.get("tactic_id", "")
            if not tactic_id:
                continue

            # Проверяем что тактика существует
            tactic_data = next((t for t in self._tactics if t["id"] == tactic_id), None)
            if not tactic_data:
                continue

            print(f"   [Kill Chain] Этап 2: техники для {tactic_id} {tactic_data['name_en']}...")
            try:
                techniques = self._identify_techniques(truncated, tactic_id, tactic_data)
            except Exception as e:
                msg = f"Kill Chain Stage 2 failed for {tactic_id}: {e}"
                print(f"   [Kill Chain] {msg}")
                warnings.append(msg)
                techniques = []

            phase = {
                "tactic_id": tactic_id,
                "tactic_name_en": tactic_data["name_en"],
                "tactic_name_ru": tactic_data["name_ru"],
                "techniques": techniques,
            }
            phases.append(phase)

        # Сортировка по Kill Chain order
        tactic_order = {t["id"]: t["order"] for t in self._tactics}
        phases.sort(key=lambda p: tactic_order.get(p["tactic_id"], 99))

        return {"kill_chain_phases": phases, "warnings": warnings}

    def _identify_tactics(self, text: str) -> list[dict]:
        """Этап 1: LLM определяет какие тактики описаны в тексте."""
        prompt = self._render_template(
            self._tactics_prompt_template,
            {
                "tactics_reference": self._tactics_reference,
                "text": text,
            },
        )

        response = ollama.chat(
            model=self.model_name,
            messages=[
                {"role": "system", "content": "You are a MITRE ATT&CK expert. Respond ONLY with valid JSON."},
                {"role": "user", "content": prompt},
            ],
            format="json",
            options={"temperature": 0.1, "num_ctx": 8192},
        )
        data = json.loads(response["message"]["content"])
        tactics = data.get("tactics", [])
        if not isinstance(tactics, list):
            raise ValueError("Invalid JSON schema: 'tactics' must be a list")
        return tactics

    def _identify_techniques(self, text: str, tactic_id: str, tactic_data: dict) -> list[dict]:
        """Этап 2: LLM выбирает конкретные техники из списка для тактики."""
        techniques_ref = self._build_techniques_reference(tactic_id)
        if not techniques_ref:
            return []

        prompt = self._render_template(
            self._techniques_prompt_template,
            {
                "tactic_name": tactic_data["name_en"],
                "tactic_id": tactic_id,
                "techniques_reference": techniques_ref,
                "text": text,
            },
        )

        response = ollama.chat(
            model=self.model_name,
            messages=[
                {"role": "system", "content": "You are a MITRE ATT&CK expert. Respond ONLY with valid JSON."},
                {"role": "user", "content": prompt},
            ],
            format="json",
            options={"temperature": 0.1, "num_ctx": 8192},
        )
        data = json.loads(response["message"]["content"])
        raw_techniques = data.get("techniques", [])
        if not isinstance(raw_techniques, list):
            raise ValueError("Invalid JSON schema: 'techniques' must be a list")

        # Валидация: проверяем каждый ID в справочнике
        validated = []
        for tech in raw_techniques:
            tech_id = tech.get("id", "")
            info = self.normalizer.validate_technique_id(tech_id)

            if info:
                validated.append({
                    "id": tech_id,
                    "name_en": info["name_en"],
                    "name_ru": info["name_ru"],
                    "confidence": min(100, max(0, tech.get("confidence", 50))),
                    "evidence": tech.get("evidence", ""),
                    "validated": True,
                })
            else:
                print(f"   [Kill Chain] ОТБРОШЕНО: {tech_id} (не существует в MITRE)")

        return validated


if __name__ == "__main__":
    print("Загрузка AttackMapper...\n")
    mapper = AttackMapper()

    test_text = """
    The threat actor group sent spearphishing emails with malicious Word documents
    attached. When the victim opened the document, a macro executed PowerShell commands
    that downloaded Cobalt Strike beacon from a command and control server.
    The attackers then used Mimikatz to dump credentials from memory and moved
    laterally through the network using stolen credentials via RDP.
    They eventually exfiltrated sensitive data to an external cloud storage service.
    """

    print("Тестовый текст:")
    print(f"  {test_text.strip()[:100]}...\n")

    result = mapper.map_text(test_text)

    print("\n" + "=" * 60)
    print("РЕЗУЛЬТАТ Kill Chain МАППИНГА:")
    print("=" * 60)
    print(json.dumps(result, indent=2, ensure_ascii=False))
