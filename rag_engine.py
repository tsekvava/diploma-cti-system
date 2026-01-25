import chromadb
from sentence_transformers import SentenceTransformer
import uuid
import os
import json

class RAGSystem:
    def __init__(self, db_path="./chroma_db"):
        print("🧠 Инициализация RAG (ChromaDB)...")
        self.client = chromadb.PersistentClient(path=db_path)
        
        self.embedder = SentenceTransformer('all-MiniLM-L6-v2')
        
        self.collection = self.client.get_or_create_collection(name="threat_reports")

    def add_report(self, text, metadata):
        """Добавляет отчет в базу знаний"""
        embedding = self.embedder.encode(text).tolist()
        
        self.collection.add(
            documents=[text],
            embeddings=[embedding],
            metadatas=[metadata],
            ids=[str(uuid.uuid4())]
        )
        print(f"   [RAG] Добавлен отчет: {metadata.get('title', 'Unknown')}")

    def search(self, query, n_results=2):
        """Ищет похожие отчеты"""
        query_embedding = self.embedder.encode(query).tolist()
        
        results = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=n_results
        )
        
        found_docs = []
        if results['documents']:
            for i, doc in enumerate(results['documents'][0]):
                meta = results['metadatas'][0][i]
                found_docs.append({
                    "content": doc[:200] + "...",
                    "metadata": meta,
                    "distance": results['distances'][0][i]
                })
        return found_docs

if __name__ == "__main__":
    rag = RAGSystem()
    
    print("\n📥 Загрузка данных в память...")
    
    with open("benchmark/data/gold_salem.txt", "r", encoding="utf-8") as f:
        rag.add_report(f.read(), {"title": "Gold Salem Report", "malware": "Warlock", "year": "2025"})
        
    with open("benchmark/data/frost_beacon.txt", "r", encoding="utf-8") as f:
        rag.add_report(f.read(), {"title": "Frost Beacon Operation", "malware": "Cobalt Strike", "year": "2024"})
    
    with open("benchmark/data/cve.txt", "r", encoding="utf-8") as f:
        rag.add_report(f.read(), {"title": "CVE-2025-55182 Botnet", "malware": "Mirai", "year": "2025"})

    print("\n🔍 ТЕСТ ПОИСКА:")
    user_query = "Any info about Warlock ransomware?"
    print(f"Запрос: {user_query}")
    
    hits = rag.search(user_query)
    for hit in hits:
        print(f"   Найдено: {hit['metadata']['title']} (Score: {hit['distance']:.4f})")