import json
import time
import os
import pandas as pd
from models.run_securebert import extract_securebert
from models.run_gliner import extract_gliner
from models.run_hybrid import extract_hybrid

TASKS = [
    {"text": "data/gold_salem.txt", "truth": "data/ground_truth_gold_salem.json"},
    {"text": "data/frost_beacon.txt", "truth": "data/ground_truth_frost_beacon.json"},
    {"text": "data/cve.txt", "truth": "data/ground_truth_cve.json"}
]

def calculate_f1(pred, truth):
    def get_set(data):
        s = set()
        for key in ["threat_actor", "malware", "tools"]:
            for item in data.get(key, []): s.add(str(item).lower().strip())
        if "indicators" in data:
            for k, v in data["indicators"].items():
                for item in v: s.add(str(item).lower().strip())
        return s

    pred_set = get_set(pred)
    truth_set = get_set(truth)

    if not truth_set: return 0.0, 0.0, 0.0

    tp = len(pred_set.intersection(truth_set))
    fp = len(pred_set - truth_set)
    fn = len(truth_set - pred_set)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    return precision, recall, f1

def main():
    results = []

    for task in TASKS:
        print(f"\n>>> БЕНЧМАРК: {task['text']} <<<")
        
        with open(task["text"], "r", encoding="utf-8") as f: text = f.read()
        with open(task["truth"], "r", encoding="utf-8") as f: truth = json.load(f)

        start = time.time()
        res = extract_hybrid(text)
        dur = time.time() - start
        p, r, f1 = calculate_f1(res, truth)
        results.append({"Method": "Hybrid (Ours)", "File": task["text"], "Time": dur, "Precision": p, "Recall": r, "F1": f1})
        print(f"Hybrid:     F1={f1:.2f} (Time: {dur:.1f}s)")

        start = time.time()
        res = extract_securebert(text)
        dur = time.time() - start
        p, r, f1 = calculate_f1(res, truth)
        results.append({"Method": "SecureBERT", "File": task["text"], "Time": dur, "Precision": p, "Recall": r, "F1": f1})
        print(f"SecureBERT: F1={f1:.2f} (Time: {dur:.1f}s)")

        start = time.time()
        res = extract_gliner(text)
        dur = time.time() - start
        p, r, f1 = calculate_f1(res, truth)
        results.append({"Method": "GLiNER", "File": task["text"], "Time": dur, "Precision": p, "Recall": r, "F1": f1})
        print(f"GLiNER:     F1={f1:.2f} (Time: {dur:.1f}s)")

    df = pd.DataFrame(results)
    print("\n=== ИТОГОВАЯ ТАБЛИЦА ===")
    print(df.groupby("Method")[["Time", "F1"]].mean())
    df.to_csv("final_benchmark.csv", index=False)
    print("\nРезультаты сохранены в final_benchmark.csv")

if __name__ == "__main__":
    main()