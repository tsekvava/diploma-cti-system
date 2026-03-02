"""
Translator — двуязычная цепочка EN→RU для аналитических записок.

Обоснование (Лидия Андреевна):
  "Возможно стоит строить цепочку на Английском, а перед выходом
  прогонять через переводчик — на Английском модели работают лучше в инфобезе"

Подход:
  - Все промпты и reasoning на EN (лучшее качество)
  - Финальный перевод на RU с сохранением технических терминов
  - MITRE ID, CVE, IP, хеши, имена малвари — остаются на EN
  - Ключевые термины: "Боковое перемещение (Lateral Movement)"

Использование:
    from summarizer.translator import Translator
    tr = Translator()
    ru_text = tr.translate(en_text)
"""

import json
import ollama
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
DEFAULT_MODEL = "qwen2.5:14b"


class Translator:
    """Переводит аналитические записки EN→RU с сохранением терминологии."""

    def __init__(self, model_name: str = DEFAULT_MODEL):
        self.model_name = model_name
        self._prompt_template = self._load_prompt()

    def _load_prompt(self) -> str:
        prompt_path = PROJECT_ROOT / "prompts" / "translate.txt"
        if prompt_path.exists():
            return prompt_path.read_text(encoding="utf-8")
        # Fallback
        return (
            "### Task:\n"
            "Translate the following cybersecurity text from English to Russian.\n"
            "Keep all technical identifiers (MITRE IDs, CVE, IPs, hashes, malware names) in English.\n"
            "For cybersecurity terms, add English in parentheses on first mention.\n\n"
            "### Text to translate:\n{text}"
        )

    def translate(self, text: str) -> str:
        """
        Переводит английский текст на русский.

        Args:
            text: Английский текст аналитической записки

        Returns:
            Русский текст с сохранёнными техническими терминами
        """
        if not text or not text.strip():
            return ""

        prompt = self._prompt_template.replace("{text}", text)

        try:
            response = ollama.chat(
                model=self.model_name,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a professional cybersecurity translator (EN→RU). "
                            "Translate accurately, preserving all technical identifiers. "
                            "Use established Russian cybersecurity terminology."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                options={"temperature": 0.2, "num_ctx": 8192},
            )
            return response["message"]["content"].strip()
        except Exception as e:
            print(f"   [Translator] Ошибка перевода: {e}")
            return f"[Перевод не выполнен: {e}]\n\n{text}"

    def translate_summary_block(self, summary_en: str, entities: dict) -> str:
        """
        Переводит саммари, добавляя контекст из извлечённых сущностей
        для более точного перевода имён.

        Args:
            summary_en: Английское саммари
            entities: Нормализованные сущности (для контекста)

        Returns:
            Русский текст записки
        """
        # Собираем глоссарий из нормализованных сущностей
        glossary_lines = []

        for actor in entities.get("threat_actor", []):
            if actor.get("mitre_id"):
                glossary_lines.append(
                    f"- {actor['name']} ({actor['mitre_id']}) — keep as-is"
                )

        for mal in entities.get("malware", []):
            if mal.get("mitre_id"):
                glossary_lines.append(
                    f"- {mal['name']} ({mal['mitre_id']}) — keep as-is"
                )

        for tool in entities.get("tools", []):
            if tool.get("mitre_id"):
                glossary_lines.append(
                    f"- {tool['name']} ({tool['mitre_id']}) — keep as-is"
                )

        glossary = "\n".join(glossary_lines) if glossary_lines else "None"

        enhanced_text = (
            f"### Glossary of terms to keep in English:\n{glossary}\n\n"
            f"### Text to translate:\n{summary_en}"
        )

        prompt = self._prompt_template.replace("{text}", enhanced_text)

        try:
            response = ollama.chat(
                model=self.model_name,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a professional cybersecurity translator (EN→RU). "
                            "Translate accurately. Keep ALL items from the glossary in English. "
                            "For cybersecurity terms, add English in parentheses on first mention."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                options={"temperature": 0.2, "num_ctx": 8192},
            )
            return response["message"]["content"].strip()
        except Exception as e:
            print(f"   [Translator] Ошибка перевода с глоссарием: {e}")
            return self.translate(summary_en)


if __name__ == "__main__":
    print("Тест Translator...\n")
    tr = Translator()

    test_text = """
    The Lazarus Group (G0032) conducted a spearphishing campaign targeting
    financial institutions in South Korea. The attackers used Cobalt Strike (S0154)
    beacons for command and control (T1071.001 - Application Layer Protocol: Web Protocols).
    Initial access was gained through T1566.001 (Phishing: Spearphishing Attachment)
    using malicious .docx files exploiting CVE-2025-55182.
    """

    print("EN текст:")
    print(test_text.strip())
    print("\n" + "=" * 60)
    print("RU перевод:")
    result = tr.translate(test_text.strip())
    print(result)
