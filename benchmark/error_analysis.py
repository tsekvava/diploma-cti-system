"""
Error Analysis — детальный анализ ошибок моделей для ВКР.

Генерирует:
  1. TP/FP/FN разбивка по моделям и категориям (stacked bar)
  2. Топ-10 самых частых False Positives (галлюцинации)
  3. Топ-10 самых частых False Negatives (пропуски)
  4. Hallucination detection: проверка T-кодов в MITRE SQLite
  5. Категорийная матрица ошибок (heatmap)
  6. Сводная таблица для ВКР (CSV + LaTeX)

Использование:
    cd benchmark
    python3 error_analysis.py
"""

import json
import re
import sqlite3
import sys
from collections import Counter, defaultdict
from pathlib import Path

import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

DETAILED_JSON = Path(__file__).parent / "benchmark_full_9models_detailed.json"
MITRE_DB = PROJECT_ROOT / "knowledge_base" / "mitre.db"
OUTPUT_DIR = Path(__file__).parent / "charts"
OUTPUT_DIR.mkdir(exist_ok=True)

plt.rcParams.update({
    "figure.dpi": 150,
    "font.size": 11,
    "axes.titlesize": 13,
    "axes.labelsize": 11,
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,
    "legend.fontsize": 9,
    "figure.figsize": (12, 7),
})

SHORT_NAMES = {
    "qwen2.5:14b": "Qwen2.5-14B",
    "qwen2.5:7b": "Qwen2.5-7B",
    "llama3.1:8b": "Llama3.1-8B",
    "mistral:7b": "Mistral-7B",
    "gemma2:9b": "Gemma2-9B",
    "glm4:9b": "GLM4-9B",
    "deepseek-v2:16b": "DeepSeek-16B",
    "alientelligence/cybersecuritythreatanalysisv2": "AlienCyber",
    "qingmian/qwen2.5-14b-cybersecurity": "QwenCyber-14B",
}

CATEGORIES = ["actors", "malware", "tools", "attack_patterns", "ioc"]




def shorten(name: str) -> str:
    return SHORT_NAMES.get(name, name)


def normalize(text: str) -> str:
    text = str(text).lower().strip()
    text = re.sub(r"[\(\[]?t\d{4}(\.\d{3})?[\)\]]?", "", text)
    text = re.sub(r"[\(\[]?cve-\d{4}-\d+[\)\]]?", "", text)
    text = text.strip().strip(".,-:()")
    text = re.sub(r"\s+", " ", text).strip()
    return text


def get_entity_set(data: dict, keys: list) -> set:
    result = set()
    for key in keys:
        for item in data.get(key, []):
            n = normalize(item)
            if len(n) > 2:
                result.add(n)
    return result


def get_ioc_set(data: dict) -> set:
    result = set()
    indicators = data.get("indicators", {})
    if isinstance(indicators, dict):
        for ioc_type, values in indicators.items():
            for v in values:
                v = str(v).strip().lower()
                if v:
                    result.add(v)
    return result


def extract_mitre_ids(items: list) -> set:
    ids = set()
    for item in items:
        for m in re.finditer(r"T\d{4}(?:\.\d{3})?", str(item), re.IGNORECASE):
            ids.add(m.group(0).upper())
    return ids


def get_sets(entry: dict, truth: dict):
    """Return (pred_set, truth_set) per category."""
    ext = entry["extracted"]
    sets = {}

    # actors
    pred_actors = get_entity_set(ext, ["threat_actor"])
    truth_actors = get_entity_set(truth, ["threat_actor"])
    sets["actors"] = (pred_actors, truth_actors)

    # malware
    pred_mal = get_entity_set(ext, ["malware"])
    truth_mal = get_entity_set(truth, ["malware"])
    sets["malware"] = (pred_mal, truth_mal)

    # tools
    pred_tools = get_entity_set(ext, ["tools"])
    truth_tools = get_entity_set(truth, ["tools"])
    sets["tools"] = (pred_tools, truth_tools)

    # attack_patterns
    pred_ap = extract_mitre_ids(ext.get("attack_patterns", []))
    truth_ap = extract_mitre_ids(truth.get("attack_patterns", []))
    sets["attack_patterns"] = (pred_ap, truth_ap)

    # ioc
    pred_ioc = get_ioc_set(ext)
    truth_ioc = get_ioc_set(truth)
    sets["ioc"] = (pred_ioc, truth_ioc)

    return sets




def load_data():
    with open(DETAILED_JSON) as f:
        entries = json.load(f)

    truths = {}
    data_dir = Path(__file__).parent / "data"
    for gt_file in data_dir.glob("ground_truth_*.json"):
        dataset = gt_file.stem.replace("ground_truth_", "")
        with open(gt_file) as f:
            truths[dataset] = json.load(f)

    return entries, truths




def plot_tp_fp_fn_by_model(entries, truths):
    """Stacked bar chart: TP/FP/FN aggregated per model."""
    model_stats = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})

    for entry in entries:
        dataset = entry["dataset"]
        if dataset not in truths:
            continue
        truth = truths[dataset]
        sets = get_sets(entry, truth)
        model = entry["model"]

        for cat, (pred, gold) in sets.items():
            tp = len(pred & gold)
            fp = len(pred - gold)
            fn = len(gold - pred)
            model_stats[model]["tp"] += tp
            model_stats[model]["fp"] += fp
            model_stats[model]["fn"] += fn

    models = sorted(model_stats.keys(), key=lambda m: model_stats[m]["tp"], reverse=True)
    tp_vals = [model_stats[m]["tp"] for m in models]
    fp_vals = [model_stats[m]["fp"] for m in models]
    fn_vals = [model_stats[m]["fn"] for m in models]
    labels = [shorten(m) for m in models]

    x = np.arange(len(models))
    width = 0.6

    fig, ax = plt.subplots(figsize=(12, 7))
    ax.bar(x, tp_vals, width, label="True Positives", color="#2ecc71")
    ax.bar(x, fp_vals, width, bottom=tp_vals, label="False Positives", color="#e74c3c")
    ax.bar(x, fn_vals, width, bottom=[t + f for t, f in zip(tp_vals, fp_vals)],
           label="False Negatives", color="#f39c12")

    ax.set_ylabel("Количество сущностей")
    ax.set_title("TP / FP / FN по моделям (все категории, все датасеты)")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=30, ha="right")
    ax.legend()
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "07_tp_fp_fn_by_model.png")
    plt.close()
    print("  [+] 07_tp_fp_fn_by_model.png")

    return model_stats




def plot_tp_fp_fn_by_category(entries, truths):
    """Grouped stacked bar: TP/FP/FN per category (averaged across models)."""
    cat_stats = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})

    for entry in entries:
        dataset = entry["dataset"]
        if dataset not in truths:
            continue
        truth = truths[dataset]
        sets = get_sets(entry, truth)

        for cat, (pred, gold) in sets.items():
            cat_stats[cat]["tp"] += len(pred & gold)
            cat_stats[cat]["fp"] += len(pred - gold)
            cat_stats[cat]["fn"] += len(gold - pred)

    cats = CATEGORIES
    tp_vals = [cat_stats[c]["tp"] for c in cats]
    fp_vals = [cat_stats[c]["fp"] for c in cats]
    fn_vals = [cat_stats[c]["fn"] for c in cats]
    cat_labels = ["Actors", "Malware", "Tools", "ATT&CK", "IoC"]

    x = np.arange(len(cats))
    width = 0.6

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(x, tp_vals, width, label="True Positives", color="#2ecc71")
    ax.bar(x, fp_vals, width, bottom=tp_vals, label="False Positives", color="#e74c3c")
    ax.bar(x, fn_vals, width, bottom=[t + f for t, f in zip(tp_vals, fp_vals)],
           label="False Negatives", color="#f39c12")

    ax.set_ylabel("Количество (сумма по всем моделям × датасетам)")
    ax.set_title("TP / FP / FN по категориям")
    ax.set_xticks(x)
    ax.set_xticklabels(cat_labels)
    ax.legend()
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "08_tp_fp_fn_by_category.png")
    plt.close()
    print("  [+] 08_tp_fp_fn_by_category.png")




def analyze_top_errors(entries, truths):
    """Find most common False Positives and False Negatives."""
    fp_counter = Counter()
    fn_counter = Counter()
    fp_by_cat = defaultdict(Counter)
    fn_by_cat = defaultdict(Counter)

    for entry in entries:
        dataset = entry["dataset"]
        if dataset not in truths:
            continue
        truth = truths[dataset]
        sets = get_sets(entry, truth)

        for cat, (pred, gold) in sets.items():
            for item in pred - gold:
                fp_counter[item] += 1
                fp_by_cat[cat][item] += 1
            for item in gold - pred:
                fn_counter[item] += 1
                fn_by_cat[cat][item] += 1

    print("\n  ── Топ-15 False Positives (галлюцинации / лишнее) ──")
    for item, count in fp_counter.most_common(15):
        cats = []
        for cat in CATEGORIES:
            if item in fp_by_cat[cat]:
                cats.append(cat)
        print(f"    {count:3d}x  [{','.join(cats):20s}]  {item}")

    print("\n  ── Топ-15 False Negatives (пропуски) ──")
    for item, count in fn_counter.most_common(15):
        cats = []
        for cat in CATEGORIES:
            if item in fn_by_cat[cat]:
                cats.append(cat)
        print(f"    {count:3d}x  [{','.join(cats):20s}]  {item}")

    # Save to CSV
    fp_df = pd.DataFrame(fp_counter.most_common(30), columns=["entity", "count"])
    fp_df.to_csv(OUTPUT_DIR / "top_false_positives.csv", index=False)
    fn_df = pd.DataFrame(fn_counter.most_common(30), columns=["entity", "count"])
    fn_df.to_csv(OUTPUT_DIR / "top_false_negatives.csv", index=False)
    print("  [+] top_false_positives.csv, top_false_negatives.csv")

    return fp_counter, fn_counter




def detect_hallucinations(entries):
    """Check extracted MITRE T-codes against SQLite DB."""
    if not MITRE_DB.exists():
        print("  [!] mitre.db не найден — пропускаю проверку галлюцинаций")
        return

    conn = sqlite3.connect(str(MITRE_DB))
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM techniques")
    valid_ids = {row[0] for row in cursor.fetchall()}
    conn.close()

    hallucinated = Counter()
    model_hallucinations = defaultdict(int)
    total_t_codes = defaultdict(int)

    for entry in entries:
        model = entry["model"]
        t_codes = extract_mitre_ids(entry["extracted"].get("attack_patterns", []))
        total_t_codes[model] += len(t_codes)

        for t_code in t_codes:
            if t_code not in valid_ids:
                hallucinated[t_code] += 1
                model_hallucinations[model] += 1

    print("\n  ── Hallucination Detection (несуществующие MITRE T-коды) ──")
    if not hallucinated:
        print("    Галлюцинаций не обнаружено!")
    else:
        print(f"    Всего уникальных галлюцинированных ID: {len(hallucinated)}")
        for t_code, count in hallucinated.most_common(20):
            print(f"    {count:3d}x  {t_code}")

    print("\n  ── Hallucination rate по моделям ──")
    all_models = sorted(set(e["model"] for e in entries), key=lambda m: shorten(m))
    for model in all_models:
        total = total_t_codes.get(model, 0)
        hall = model_hallucinations.get(model, 0)
        rate = hall / total * 100 if total > 0 else 0
        print(f"    {shorten(model):20s}  {hall}/{total} = {rate:.1f}%")

    # Save
    rows = []
    all_models = set(e["model"] for e in entries)
    for model in sorted(all_models):
        total = total_t_codes.get(model, 0)
        hall = model_hallucinations.get(model, 0)
        rate = hall / total * 100 if total > 0 else 0
        rows.append({"model": shorten(model), "hallucinated": hall, "total_t_codes": total, "rate_pct": round(rate, 1)})
    pd.DataFrame(rows).to_csv(OUTPUT_DIR / "hallucination_rates.csv", index=False)
    print("  [+] hallucination_rates.csv")




def plot_category_heatmap(entries, truths):
    """Heatmap: F1 per model × category."""
    model_cat_f1 = defaultdict(dict)

    for entry in entries:
        dataset = entry["dataset"]
        if dataset not in truths:
            continue
        model = entry["model"]
        metrics = entry["metrics"]
        for cat in CATEGORIES:
            f1 = metrics.get(cat, {}).get("f1", 0)
            if cat not in model_cat_f1[model]:
                model_cat_f1[model][cat] = []
            model_cat_f1[model][cat].append(f1)

    # Average F1 per model × category
    models = sorted(model_cat_f1.keys(), key=lambda m: shorten(m))
    cat_labels = ["Actors", "Malware", "Tools", "ATT&CK", "IoC"]
    matrix = []
    for model in models:
        row = []
        for cat in CATEGORIES:
            vals = model_cat_f1[model].get(cat, [0])
            row.append(np.mean(vals))
        matrix.append(row)

    matrix = np.array(matrix)
    labels = [shorten(m) for m in models]

    fig, ax = plt.subplots(figsize=(10, 8))
    im = ax.imshow(matrix, cmap="RdYlGn", aspect="auto", vmin=0, vmax=1)

    ax.set_xticks(np.arange(len(cat_labels)))
    ax.set_yticks(np.arange(len(labels)))
    ax.set_xticklabels(cat_labels)
    ax.set_yticklabels(labels)

    for i in range(len(labels)):
        for j in range(len(cat_labels)):
            val = matrix[i, j]
            color = "white" if val < 0.4 else "black"
            ax.text(j, i, f"{val:.2f}", ha="center", va="center", color=color, fontsize=10)

    ax.set_title("F1 по модели × категории (среднее по датасетам)")
    fig.colorbar(im, ax=ax, shrink=0.8)
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "09_category_heatmap.png")
    plt.close()
    print("  [+] 09_category_heatmap.png")




def generate_summary_table(entries, truths, model_stats):
    """Generate summary CSV with TP/FP/FN/F1 per model."""
    rows = []
    for model in sorted(model_stats.keys(), key=lambda m: shorten(m)):
        s = model_stats[model]
        tp, fp, fn = s["tp"], s["fp"], s["fn"]
        p = tp / (tp + fp) if (tp + fp) > 0 else 0
        r = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0
        rows.append({
            "Model": shorten(model),
            "TP": tp,
            "FP": fp,
            "FN": fn,
            "Precision": round(p, 3),
            "Recall": round(r, 3),
            "F1": round(f1, 3),
        })

    df = pd.DataFrame(rows).sort_values("F1", ascending=False)
    df.to_csv(OUTPUT_DIR / "error_analysis_summary.csv", index=False)
    print("\n  ── Сводная таблица ──")
    print(df.to_string(index=False))
    print(f"\n  [+] error_analysis_summary.csv")




def plot_fp_fn_ratio(entries, truths):
    """Per-model FP ratio and FN ratio side by side."""
    model_data = defaultdict(lambda: {"fp": 0, "fn": 0, "tp": 0})

    for entry in entries:
        dataset = entry["dataset"]
        if dataset not in truths:
            continue
        truth = truths[dataset]
        sets = get_sets(entry, truth)

        for cat, (pred, gold) in sets.items():
            m = entry["model"]
            model_data[m]["tp"] += len(pred & gold)
            model_data[m]["fp"] += len(pred - gold)
            model_data[m]["fn"] += len(gold - pred)

    models = sorted(model_data.keys(), key=lambda m: shorten(m))
    labels = [shorten(m) for m in models]

    fp_rates = []
    fn_rates = []
    for m in models:
        d = model_data[m]
        total_pred = d["tp"] + d["fp"]
        total_truth = d["tp"] + d["fn"]
        fp_rates.append(d["fp"] / total_pred * 100 if total_pred else 0)
        fn_rates.append(d["fn"] / total_truth * 100 if total_truth else 0)

    x = np.arange(len(models))
    width = 0.35

    fig, ax = plt.subplots(figsize=(12, 6))
    ax.bar(x - width/2, fp_rates, width, label="FP Rate (% от предсказаний)", color="#e74c3c", alpha=0.8)
    ax.bar(x + width/2, fn_rates, width, label="FN Rate (% от ground truth)", color="#f39c12", alpha=0.8)
    ax.set_ylabel("Процент (%)")
    ax.set_title("False Positive Rate и False Negative Rate по моделям")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=30, ha="right")
    ax.legend()
    ax.set_ylim(0, 100)
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "10_fp_fn_rates.png")
    plt.close()
    print("  [+] 10_fp_fn_rates.png")




def main():
    print("=" * 60)
    print("ERROR ANALYSIS — Детальный анализ ошибок моделей")
    print("=" * 60)

    entries, truths = load_data()
    print(f"\nЗагружено: {len(entries)} записей, {len(truths)} ground truth файлов")
    print(f"Модели: {len(set(e['model'] for e in entries))}")
    print(f"Датасеты в результатах: {sorted(set(e['dataset'] for e in entries))}")

    print("\n── 1. TP/FP/FN по моделям ──")
    model_stats = plot_tp_fp_fn_by_model(entries, truths)

    print("\n── 2. TP/FP/FN по категориям ──")
    plot_tp_fp_fn_by_category(entries, truths)

    print("\n── 3. Анализ ошибок ──")
    analyze_top_errors(entries, truths)

    print("\n── 4. Детекция галлюцинаций ──")
    detect_hallucinations(entries)

    print("\n── 5. Heatmap по категориям ──")
    plot_category_heatmap(entries, truths)

    print("\n── 6. FP/FN Rates ──")
    plot_fp_fn_ratio(entries, truths)

    print("\n── 7. Сводная таблица ──")
    generate_summary_table(entries, truths, model_stats)

    print(f"\n{'=' * 60}")
    print(f"Все результаты сохранены в {OUTPUT_DIR}/")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
