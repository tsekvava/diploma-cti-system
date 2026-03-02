import json
import sys
import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer
from rag_engine import RAGSystem
from benchmark.models.run_hybrid import extract_hybrid

FILTER_MODEL_NAME = "Qwen/Qwen2.5-3B-Instruct"
FILTER_ADAPTER = "finetuning/diploma_filter_adapter"

class CyberPipeline:
    def __init__(self):
        print("🚀 [1/3] Загрузка Фильтра (Qwen-3B + LoRA)...")
        try:
            base = AutoModelForCausalLM.from_pretrained(
                FILTER_MODEL_NAME, torch_dtype=torch.float32, device_map="cpu"
            )
            self.tokenizer = AutoTokenizer.from_pretrained(FILTER_MODEL_NAME)
            self.filter_model = PeftModel.from_pretrained(base, FILTER_ADAPTER)
            self.filter_model.eval()
            print("   ✅ Фильтр готов.")
        except Exception as e:
            print(f"   ❌ Ошибка загрузки фильтра: {e}")
            sys.exit(1)

        print("🧠 [2/3] Инициализация Памяти (RAG)...")
        self.rag = RAGSystem()
        
        print("🕵️ [3/3] Экстрактор (Hybrid) готов к работе.")

    def classify_message(self, text):
        """Быстрый фильтр: это угроза или просто шум."""
        msgs = [
            {"role": "system", "content": "Classify as 'THREAT' or 'SPAM'."},
            {"role": "user", "content": text}
        ]
        prompt = self.tokenizer.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
        inputs = self.tokenizer([prompt], return_tensors="pt")
        
        with torch.no_grad():
            ids = self.filter_model.generate(**inputs, max_new_tokens=5, do_sample=False)
        
        resp = self.tokenizer.batch_decode(ids[:, inputs.input_ids.shape[1]:], skip_special_tokens=True)[0]
        return "THREAT" in resp.upper()

    def process(self, text):
        print("\n" + "="*50)
        print("📨 НОВОЕ СООБЩЕНИЕ:")
        print(f"   {text[:100]}...")
        
        is_threat = self.classify_message(text)
        if not is_threat:
            print("🚫 ВЕРДИКТ: СПАМ/МУСОР. Пропускаем.")
            return None
        
        print("🚨 ВЕРДИКТ: УГРОЗА! Начинаем анализ...")
        
        print("🔍 Поиск похожих инцидентов в базе...")
        similar_cases = self.rag.search(text, n_results=1)
        context_info = ""
        if similar_cases:
            best = similar_cases[0]
            print(f"   Найдено совпадение: {best['metadata'].get('title')} (Score: {best['distance']:.2f})")
            context_info = f"\nRelated Incident: {best['content']}"
        else:
            print("   Совпадений не найдено.")

        enriched_text = text + context_info
        
        print("⛏️  Извлечение сущностей (Hybrid Method)...")
        cti_data = extract_hybrid(enriched_text)
        
        print("\n✅ ГОТОВЫЙ ОТЧЕТ (JSON):")
        print(json.dumps(cti_data, indent=2, ensure_ascii=False))
        return cti_data

if __name__ == "__main__":
    app = CyberPipeline()
    
    messages = [
        "Buy cheap Viagra, delivery worldwide!",
        "Lapsus$ group claims they hacked Microsoft and leaked 50GB of source code.",
        "Warlock ransomware detected on 192.168.1.55. It encrypts files via SMB."
    ]
    
    for msg in messages:
        app.process(msg)
