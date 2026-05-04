"""
RAG Engine — Retrieval-Augmented Generation для CTI Pipeline.

Использует ChromaDB (локальную векторную БД) для хранения и поиска
проанализированных отчётов. При анализе нового отчёта система ищет
похожие ранее проанализированные отчёты и добавляет их контекст в промпт.

Использование:
    # Индексация отчёта после анализа
    rag = RAGSystem()
    rag.index_report(text, analysis_result, source="report.txt")

    # Поиск похожего контекста перед анализом
    context = rag.build_context(text, max_results=3)
"""

import json
import uuid
from pathlib import Path

import chromadb
from sentence_transformers import SentenceTransformer

DEFAULT_DB_PATH = str(Path(__file__).parent / "chroma_db")
EMBEDDING_MODEL = "all-MiniLM-L6-v2"
COLLECTION_NAME = "threat_reports"


class RAGSystem:
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.client = chromadb.PersistentClient(path=db_path)
        self.embedder = SentenceTransformer(EMBEDDING_MODEL)
        self.collection = self.client.get_or_create_collection(name=COLLECTION_NAME)

    @property
    def count(self) -> int:
        return self.collection.count()

    def add_report(self, text: str, metadata: dict) -> str:
        """Добавляет сырой текст отчёта в векторную базу."""
        doc_id = str(uuid.uuid4())
        embedding = self.embedder.encode(text).tolist()
        self.collection.add(
            documents=[text],
            embeddings=[embedding],
            metadatas=[metadata],
            ids=[doc_id],
        )
        return doc_id

    def index_report(self, text: str, analysis_result: dict, source: str = "unknown") -> str:
        """Индексирует проанализированный отчёт: текст + ключевые сущности из результата."""
        json_data = analysis_result.get("json", {})

        actors = [a.get("name", a) if isinstance(a, dict) else str(a)
                  for a in json_data.get("threat_actor", [])]
        malware = [m.get("name", m) if isinstance(m, dict) else str(m)
                   for m in json_data.get("malware", [])]
        tools = [t.get("name", t) if isinstance(t, dict) else str(t)
                 for t in json_data.get("tools", [])]

        summary = analysis_result.get("summary_en", "")

        # Индексируемый документ: summary + сущности + начало текста
        index_text = f"{summary}\n\nActors: {', '.join(actors)}\nMalware: {', '.join(malware)}\nTools: {', '.join(tools)}\n\n{text[:3000]}"

        metadata = {
            "source": source,
            "actors": ", ".join(actors[:10]),
            "malware": ", ".join(malware[:10]),
            "tools": ", ".join(tools[:10]),
            "text_length": len(text),
        }

        doc_id = self.add_report(index_text, metadata)
        return doc_id

    def search(self, query: str, n_results: int = 3) -> list[dict]:
        """Ищет семантически похожие отчёты."""
        if self.count == 0:
            return []

        query_embedding = self.embedder.encode(query).tolist()
        n = min(n_results, self.count)

        results = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=n,
        )

        found = []
        if results["documents"]:
            for i, doc in enumerate(results["documents"][0]):
                found.append({
                    "content": doc[:500],
                    "metadata": results["metadatas"][0][i],
                    "distance": results["distances"][0][i],
                })
        return found

    def build_context(self, text: str, max_results: int = 3, max_distance: float = 1.5) -> str:
        """Строит RAG-контекст для инъекции в промпт.

        Args:
            text: текст нового отчёта (запрос)
            max_results: максимум результатов
            max_distance: порог расстояния (чем меньше — тем строже)

        Returns:
            Форматированная строка контекста или "" если ничего не найдено.
        """
        query = text[:2000]  # Первые 2000 символов как запрос
        hits = self.search(query, n_results=max_results)

        relevant = [h for h in hits if h["distance"] < max_distance]
        if not relevant:
            return ""

        lines = ["Previously analyzed reports with similar content:"]
        for i, hit in enumerate(relevant, 1):
            meta = hit["metadata"]
            source = meta.get("source", "unknown")
            actors = meta.get("actors", "")
            malware = meta.get("malware", "")
            tools = meta.get("tools", "")
            dist = hit["distance"]

            lines.append(f"\n--- Similar report #{i} (source: {source}, similarity: {1 - dist:.2f}) ---")
            if actors:
                lines.append(f"Known actors: {actors}")
            if malware:
                lines.append(f"Known malware: {malware}")
            if tools:
                lines.append(f"Known tools: {tools}")
            # Добавляем начало контента
            content_preview = hit["content"][:300].strip()
            if content_preview:
                lines.append(f"Context: {content_preview}")

        return "\n".join(lines)

    def index_directory(self, directory: str, glob_pattern: str = "*.txt") -> int:
        """Индексирует все текстовые файлы из директории (без анализа)."""
        dir_path = Path(directory)
        count = 0
        for file_path in sorted(dir_path.glob(glob_pattern)):
            text = file_path.read_text(encoding="utf-8", errors="replace")
            if len(text.strip()) < 100:
                continue
            self.add_report(text, {"source": file_path.name, "text_length": len(text)})
            count += 1
        return count


if __name__ == "__main__":
    rag = RAGSystem()

    print(f"ChromaDB: {rag.count} документов в базе")
    print("\nИндексация benchmark/data/...")

    data_dir = Path(__file__).parent / "benchmark" / "data"
    count = rag.index_directory(str(data_dir), "*.txt")
    print(f"Добавлено: {count} отчётов")
    print(f"Всего в базе: {rag.count}")

    print("\nТест поиска: 'APT28 spearphishing webmail'")
    hits = rag.search("APT28 spearphishing webmail")
    for hit in hits:
        print(f"  [{hit['distance']:.3f}] {hit['metadata'].get('source', '?')}")
