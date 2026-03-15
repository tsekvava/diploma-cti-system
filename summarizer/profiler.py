"""
APT/Malware Profiler — генерация полных профилей из MITRE ATT&CK + LLM.

User Story: Аналитик вводит "Lazarus" или "G0032" →
система генерирует полный профиль из всех доступных источников.

Pipeline:
    [1] Нормализация → Lazarus Group (G0032)
    [2] Lookup в SQLite → базовая информация
    [3] Lookup связей → техники, ПО
    [4] LLM-генерация → формирование профиля
    [5] Перевод → русский язык

Использование:
    from summarizer.profiler import Profiler
    profiler = Profiler()
    result = profiler.profile_group("Lazarus")
    result = profiler.profile_software("Cobalt Strike")
"""

import json
import ollama
from pathlib import Path
from typing import Optional

from knowledge_base.query_enricher import QueryEnricher
from knowledge_base.normalizer import EntityNormalizer
from summarizer.translator import Translator

DEFAULT_MODEL = "gemma2:9b"
PROJECT_ROOT = Path(__file__).parent.parent


def _load_prompt(filename: str, fallback: str) -> str:
    """Загрузка промпта из файла (рекомендация ASAP RAG_LLM: раздельные файлы)."""
    path = PROJECT_ROOT / "prompts" / filename
    return path.read_text(encoding="utf-8") if path.exists() else fallback


PROFILE_GROUP_PROMPT = _load_prompt(
    "profile_group.txt",
    "Generate a comprehensive threat actor profile.\n\n{context}",
)

PROFILE_SOFTWARE_PROMPT = _load_prompt(
    "profile_software.txt",
    "Generate a comprehensive malware/tool profile.\n\n{context}",
)


class Profiler:
    """Генерирует полные профили APT-групп и ПО."""

    def __init__(
        self,
        model_name: str = DEFAULT_MODEL,
        enricher: Optional[QueryEnricher] = None,
        normalizer: Optional[EntityNormalizer] = None,
        translator: Optional[Translator] = None,
    ):
        self.model_name = model_name
        self.enricher = enricher or QueryEnricher()
        self.normalizer = normalizer or EntityNormalizer()
        self.translator = translator or Translator(model_name=model_name)

    def profile_group(self, query: str) -> dict:
        """
        Генерирует полный профиль APT-группы.

        Args:
            query: Имя группы, MITRE ID (G0032), или алиас (APT28)

        Returns:
            {
                "entity_type": "group",
                "entity_id": "G0032",
                "entity_name": "Lazarus Group",
                "data": { ... enriched data ... },
                "profile_en": str,
                "profile_ru": str,
            }
        """
        print(f"\n[Profiler] Профилирование группы: {query}")

        # [1] Нормализация и определение
        norm_result = self.normalizer.normalize_threat_actor(query)
        if not norm_result.get("normalized"):
            # Попробуем через enricher
            enrichment = self.enricher.enrich(query)
            detected = enrichment.get("detected", [])
            group_items = [d for d in detected if d["type"] in ("group_id",)]
            if not group_items:
                print(f"   [!] Группа не найдена: {query}")
                return {"error": f"Group not found: {query}"}
            group_id = group_items[0]["id"]
        else:
            group_id = norm_result.get("mitre_id", "")

        # [2-3] Lookup в SQLite через enricher
        enrichment = self.enricher.enrich(group_id)
        enrichments = enrichment.get("enrichments", [])
        if not enrichments or not enrichments[0].get("found"):
            print(f"   [!] Данные не найдены для: {group_id}")
            return {"error": f"No data for: {group_id}"}

        data = enrichments[0]
        context = enrichment["context_for_llm"]

        print(f"   [1] Нормализовано: {data['name']} ({data['id']})")
        print(f"   [2] Техник: {len(data.get('techniques', []))}")
        print(f"   [3] Software: {len(data.get('software', []))}")

        # [4] LLM-генерация профиля
        print(f"   [4] Генерация профиля (LLM: {self.model_name})...")
        profile_en = self._generate_profile(context, PROFILE_GROUP_PROMPT)
        print(f"       Профиль: {len(profile_en)} символов")

        # [5] Перевод
        print(f"   [5] Перевод EN→RU...")
        profile_ru = self.translator.translate(profile_en)

        result = {
            "entity_type": "group",
            "entity_id": data["id"],
            "entity_name": data["name"],
            "aliases": data.get("aliases", []),
            "country": data.get("country", ""),
            "techniques_count": len(data.get("techniques", [])),
            "software_count": len(data.get("software", [])),
            "data": data,
            "profile_en": profile_en,
            "profile_ru": profile_ru,
        }

        print(f"   [OK] Профиль готов.\n")
        return result

    def profile_software(self, query: str) -> dict:
        """
        Генерирует полный профиль малвари/инструмента.

        Args:
            query: Имя software, MITRE ID (S0154), или алиас

        Returns:
            {
                "entity_type": "software",
                "entity_id": "S0154",
                "entity_name": "Cobalt Strike",
                "data": { ... enriched data ... },
                "profile_en": str,
                "profile_ru": str,
            }
        """
        print(f"\n[Profiler] Профилирование software: {query}")

        # [1] Нормализация
        norm_result = self.normalizer.normalize_software(query)
        if not norm_result.get("normalized"):
            enrichment = self.enricher.enrich(query)
            detected = enrichment.get("detected", [])
            soft_items = [d for d in detected if d["type"] == "software_id"]
            if not soft_items:
                print(f"   [!] Software не найден: {query}")
                return {"error": f"Software not found: {query}"}
            soft_id = soft_items[0]["id"]
        else:
            soft_id = norm_result.get("mitre_id", "")

        # [2-3] Lookup
        enrichment = self.enricher.enrich(soft_id)
        enrichments = enrichment.get("enrichments", [])
        if not enrichments or not enrichments[0].get("found"):
            print(f"   [!] Данные не найдены для: {soft_id}")
            return {"error": f"No data for: {soft_id}"}

        data = enrichments[0]
        context = enrichment["context_for_llm"]

        print(f"   [1] Нормализовано: {data['name']} ({data['id']})")
        print(f"   [2] Техник: {len(data.get('techniques', []))}")
        print(f"   [3] Используется группами: {len(data.get('used_by_groups', []))}")

        # [4] LLM-генерация
        print(f"   [4] Генерация профиля (LLM: {self.model_name})...")
        profile_en = self._generate_profile(context, PROFILE_SOFTWARE_PROMPT)
        print(f"       Профиль: {len(profile_en)} символов")

        # [5] Перевод
        print(f"   [5] Перевод EN→RU...")
        profile_ru = self.translator.translate(profile_en)

        result = {
            "entity_type": "software",
            "entity_id": data["id"],
            "entity_name": data["name"],
            "software_type": data.get("software_type", ""),
            "aliases": data.get("aliases", []),
            "techniques_count": len(data.get("techniques", [])),
            "used_by_groups_count": len(data.get("used_by_groups", [])),
            "data": data,
            "profile_en": profile_en,
            "profile_ru": profile_ru,
        }

        print(f"   [OK] Профиль готов.\n")
        return result

    def _generate_profile(self, context: str, system_prompt: str) -> str:
        """Генерирует профиль через LLM."""
        try:
            resp = ollama.chat(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Generate a profile based on this data:\n\n{context}"},
                ],
                options={"temperature": 0.3, "num_ctx": 8192},
            )
            return resp["message"]["content"].strip()
        except Exception as e:
            return f"[Error generating profile: {e}]"

    def profile(self, query: str) -> dict:
        """
        Универсальный метод — автоматически определяет тип сущности.

        Args:
            query: Любой идентификатор (G0032, S0154, APT28, Cobalt Strike, T1059)

        Returns:
            Результат профилирования
        """
        detected = self.enricher.detect_query_type(query)

        if not detected:
            return {"error": f"Cannot identify entity: {query}"}

        first = detected[0]
        qtype = first["type"]

        if qtype in ("group_id",):
            return self.profile_group(first["id"])
        elif qtype in ("software_id",):
            return self.profile_software(first["id"])
        elif qtype in ("technique", "tactic", "mitigation", "data_source"):
            # Для техник и тактик просто возвращаем enrichment
            enrichment = self.enricher.enrich(query)
            return {
                "entity_type": qtype,
                "entity_id": first["id"],
                "data": enrichment.get("enrichments", [{}])[0],
                "context": enrichment.get("context_for_llm", ""),
            }
        else:
            return {"error": f"Profiling not supported for type: {qtype}"}
