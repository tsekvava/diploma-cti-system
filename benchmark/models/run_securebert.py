from transformers import AutoTokenizer, AutoModelForTokenClassification
from transformers import pipeline
import sys

MODEL_NAME = "dslim/bert-base-NER"

def extract_securebert(text):
    print("   [SecureBERT] Загрузка модели...", file=sys.stderr)
    try:
        tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
        model = AutoModelForTokenClassification.from_pretrained(MODEL_NAME)
        nlp = pipeline("ner", model=model, tokenizer=tokenizer, aggregation_strategy="simple")
    except Exception as e:
        print(f"Ошибка: {e}")
        return {}

    results = {
        "threat_actor": set(), "malware": set(), "tools": set(),
        "indicators": {"ipv4": set(), "hash": set(), "domain": set()}
    }
    
    chunk_size = 1000 
    print("   [SecureBERT] Обработка...", file=sys.stderr)
    
    for i in range(0, len(text), chunk_size):
        chunk = text[i : i + chunk_size]
        try:
            ner_results = nlp(chunk)
            for entity in ner_results:
                word = entity['word'].strip()
                label = entity['entity_group']
                
                if label == "ORG": results["threat_actor"].add(word)
                elif label == "MISC": results["malware"].add(word)
        except: pass

    return {k: list(v) if isinstance(v, set) else v for k, v in results.items()}