import json
import time
import re
import pandas as pd
from models.run_securebert import extract_securebert
from models.run_gliner import extract_gliner
from models.run_hybrid import extract_hybrid

TASKS = [
    {"text": "data/gold_salem.txt", "truth": "data/ground_truth_gold_salem.json"},
    {"text": "data/frost_beacon.txt", "truth": "data/ground_truth_frost_beacon.json"},
    {"text": "data/cve.txt", "truth": "data/ground_truth_cve.json"}
]

def normalize_entity(text):
    """
    Превращает 'Spearphishing Attachment (T1566.001)' -> 'spearphishing attachment'
    Убирает скобки, ID техник, спецсимволы и приводит к нижнему регистру.
    """
    text = str(text).lower()
    text = re.sub(r'[\(\[]?t\d{4}(\.\d{3})?[\)\]]?', '', text)
    text = text.strip().strip('.,-:')
    return text

def calculate_metrics_smart(pred, truth):
    def get_normalized_set(data):
        s = set()
        keys = ["threat_actor", "malware", "tools", "attack_patterns"]
        for key in keys:
            for item in data.get(key, []):
                norm = normalize_entity(item)
                if len(norm) > 2:
                    s.add(norm)
        
        if "indicators" in data:
            for k, v in data["indicators"].items():
                for item in v:
                    s.add(str(item).lower().strip())
        return s

    pred_set = get_normalized_set(pred)
    truth_set = get_normalized_set(truth)

    if not truth_set: return 0, 0, 0

    tp = len(pred_set.intersection(truth_set))
    fp = len(pred_set - truth_set)
    fn = len(truth_set - pred_set)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    return precision, recall, f1

def main():
    results = []
    print("Запуск Умного Бенчмарка (с нормализацией строк)...")

    for task in TASKS:
        print(f"\n>>> Файл: {task['text']} <<<")
        with open(task["text"], "r", encoding="utf-8") as f: text = f.read()
        with open(task["truth"], "r", encoding="utf-8") as f: truth = json.load(f)

        start = time.time()
        res = extract_hybrid(text)
        dur = time.time() - start
        p, r, f1 = calculate_metrics_smart(res, truth)
        results.append({"Method": "Hybrid (Ours)", "File": task["text"], "Time": dur, "Precision": p, "Recall": r, "F1": f1})
        print(f"Hybrid:     F1={f1:.2f} (P={p:.2f}, R={r:.2f})")

        start = time.time()
        res = extract_securebert(text)
        dur = time.time() - start
        p, r, f1 = calculate_metrics_smart(res, truth)
        results.append({"Method": "SecureBERT", "File": task["text"], "Time": dur, "Precision": p, "Recall": r, "F1": f1})
        print(f"SecureBERT: F1={f1:.2f} (P={p:.2f}, R={r:.2f})")

        start = time.time()
        res = extract_gliner(text)
        dur = time.time() - start
        p, r, f1 = calculate_metrics_smart(res, truth)
        results.append({"Method": "GLiNER", "File": task["text"], "Time": dur, "Precision": p, "Recall": r, "F1": f1})
        print(f"GLiNER:     F1={f1:.2f} (P={p:.2f}, R={r:.2f})")

    df = pd.DataFrame(results)
    df.to_csv("final_benchmark_v2.csv", index=False)
    print("\nРезультаты сохранены в final_benchmark_v2.csv")

if __name__ == "__main__":
    main()