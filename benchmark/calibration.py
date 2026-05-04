"""
Калибровка Confidence Scores CTI-пайплайна.

Анализирует, насколько confidence scores соответствуют реальной точности:
  1. Reliability Diagram (калибровочная кривая)
  2. Expected Calibration Error (ECE)
  3. Maximum Calibration Error (MCE)
  4. Brier Score
  5. Рекалибровка: Isotonic Regression + Platt Scaling
  6. Per-category анализ

Использование:
    cd benchmark
    python3 calibration.py --input calibration_data.json
    python3 calibration.py --generate --model gemma2:9b  # генерация данных
"""

import json
import re
import sys
import argparse
from pathlib import Path

import numpy as np
import matplotlib.pyplot as plt

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

CHARTS_DIR = Path("charts")
CHARTS_DIR.mkdir(exist_ok=True)


# ─────────────────────────────────────────────
#  1. Сбор данных для калибровки
# ─────────────────────────────────────────────

def generate_calibration_data(model_name: str = "gemma2:9b") -> list:
    """Прогоняет pipeline на тестовых отчётах, собирает (confidence, is_correct)."""
    from summarizer.report_summarizer import ReportSummarizer

    data_dir = Path("data")
    tasks = []
    for gt_path in sorted(data_dir.glob("ground_truth_*.json")):
        ds_name = gt_path.stem.replace("ground_truth_", "")
        txt_path = data_dir / f"{ds_name}.txt"
        if txt_path.exists():
            tasks.append({"text": txt_path, "truth": gt_path, "name": ds_name})

    if not tasks:
        print("Нет тестовых данных!")
        return []

    summarizer = ReportSummarizer(model_name=model_name)
    calibration_data = []

    for task in tasks:
        print(f"  Processing {task['name']}...")
        text = task["text"].read_text(encoding="utf-8")
        with open(task["truth"], "r", encoding="utf-8") as f:
            truth = json.load(f)

        # Прогоняем pipeline
        try:
            result = summarizer.process(text)
        except Exception as e:
            print(f"    ERROR: {e}")
            continue

        json_result = result.get("json", {})

        # Собираем confidence + is_correct для семантических сущностей
        for category, truth_key in [("actors", "threat_actor"), ("malware", "malware"), ("tools", "tools")]:
            truth_set = {str(t).lower().strip() for t in truth.get(truth_key, [])}

            items = json_result.get(truth_key, [])
            for item in items:
                if isinstance(item, dict):
                    name = str(item.get("name", "")).lower().strip()
                    conf = item.get("confidence", 50) / 100.0  # Normalize to [0, 1]
                else:
                    name = str(item).lower().strip()
                    conf = 0.5

                # Check if correct (fuzzy match)
                is_correct = 0
                from rapidfuzz import fuzz
                for t in truth_set:
                    if fuzz.token_sort_ratio(name, t) >= 80:
                        is_correct = 1
                        break

                calibration_data.append({
                    "entity": name, "category": category,
                    "confidence": conf, "is_correct": is_correct,
                    "dataset": task["name"],
                })

        # IoC — всегда confidence=1.0
        for ioc_type in ["ipv4", "domain", "hash"]:
            pred_iocs = set()
            indicators = json_result.get("indicators", {})
            if isinstance(indicators, dict):
                for item in indicators.get(ioc_type, []):
                    if isinstance(item, dict):
                        pred_iocs.add(str(item.get("value", "")).lower())
                    else:
                        pred_iocs.add(str(item).lower())

            truth_iocs = {str(t).lower() for t in truth.get("indicators", {}).get(ioc_type, [])}

            for ioc in pred_iocs:
                calibration_data.append({
                    "entity": ioc, "category": f"ioc_{ioc_type}",
                    "confidence": 1.0,
                    "is_correct": 1 if ioc in truth_iocs else 0,
                    "dataset": task["name"],
                })

    return calibration_data


# ─────────────────────────────────────────────
#  2. Метрики калибровки
# ─────────────────────────────────────────────

def compute_calibration_metrics(confidences: np.ndarray, labels: np.ndarray,
                                 n_bins: int = 10) -> dict:
    """ECE, MCE, Brier score, per-bin accuracy."""
    bin_boundaries = np.linspace(0, 1, n_bins + 1)
    bin_accuracies = []
    bin_confidences = []
    bin_counts = []

    for i in range(n_bins):
        mask = (confidences >= bin_boundaries[i]) & (confidences < bin_boundaries[i + 1])
        if i == n_bins - 1:  # Last bin includes right edge
            mask = (confidences >= bin_boundaries[i]) & (confidences <= bin_boundaries[i + 1])

        if mask.sum() == 0:
            bin_accuracies.append(0.0)
            bin_confidences.append((bin_boundaries[i] + bin_boundaries[i + 1]) / 2)
            bin_counts.append(0)
        else:
            bin_accuracies.append(float(labels[mask].mean()))
            bin_confidences.append(float(confidences[mask].mean()))
            bin_counts.append(int(mask.sum()))

    # ECE
    N = len(confidences)
    ece = sum(
        (n_b / N) * abs(acc - conf)
        for acc, conf, n_b in zip(bin_accuracies, bin_confidences, bin_counts)
        if n_b > 0
    )

    # MCE
    mce = max(
        abs(acc - conf)
        for acc, conf, n_b in zip(bin_accuracies, bin_confidences, bin_counts)
        if n_b > 0
    ) if any(n > 0 for n in bin_counts) else 0.0

    # Brier score
    brier = float(np.mean((confidences - labels) ** 2))

    return {
        "ece": float(ece),
        "mce": float(mce),
        "brier": float(brier),
        "bin_accuracies": bin_accuracies,
        "bin_confidences": bin_confidences,
        "bin_counts": bin_counts,
        "bin_boundaries": bin_boundaries.tolist(),
        "n_samples": N,
    }


# ─────────────────────────────────────────────
#  3. Рекалибровка
# ─────────────────────────────────────────────

def recalibrate(confidences: np.ndarray, labels: np.ndarray) -> dict:
    """Isotonic regression + Platt scaling рекалибровка."""
    from sklearn.isotonic import IsotonicRegression
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import train_test_split

    # Split 70/30
    X_train, X_test, y_train, y_test = train_test_split(
        confidences, labels, test_size=0.3, random_state=42
    )

    results = {}

    # Isotonic regression
    iso = IsotonicRegression(y_min=0, y_max=1, out_of_bounds="clip")
    iso.fit(X_train, y_train)
    cal_iso_test = iso.predict(X_test)
    cal_iso_all = iso.predict(confidences)

    metrics_before = compute_calibration_metrics(X_test, y_test)
    metrics_iso = compute_calibration_metrics(cal_iso_test, y_test)
    results["isotonic"] = {
        "ece_before": metrics_before["ece"],
        "ece_after": metrics_iso["ece"],
        "improvement_pct": (1 - metrics_iso["ece"] / metrics_before["ece"]) * 100
        if metrics_before["ece"] > 0 else 0,
        "calibrated_confidences": cal_iso_all.tolist(),
    }

    # Platt scaling (logistic regression)
    platt = LogisticRegression()
    platt.fit(X_train.reshape(-1, 1), y_train)
    cal_platt_test = platt.predict_proba(X_test.reshape(-1, 1))[:, 1]
    cal_platt_all = platt.predict_proba(confidences.reshape(-1, 1))[:, 1]

    metrics_platt = compute_calibration_metrics(cal_platt_test, y_test)
    results["platt"] = {
        "ece_before": metrics_before["ece"],
        "ece_after": metrics_platt["ece"],
        "improvement_pct": (1 - metrics_platt["ece"] / metrics_before["ece"]) * 100
        if metrics_before["ece"] > 0 else 0,
        "calibrated_confidences": cal_platt_all.tolist(),
    }

    return results


# ─────────────────────────────────────────────
#  Визуализации
# ─────────────────────────────────────────────

def plot_reliability_diagram(metrics: dict, title: str = "Overall",
                              output: str = "charts/reliability_diagram.png"):
    """Reliability diagram с гистограммой."""
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(8, 8),
                                     gridspec_kw={"height_ratios": [3, 1]})

    accs = metrics["bin_accuracies"]
    confs = metrics["bin_confidences"]
    counts = metrics["bin_counts"]
    boundaries = metrics["bin_boundaries"]
    n_bins = len(accs)

    # Reliability diagram
    ax1.plot([0, 1], [0, 1], "k--", label="Ideal calibration", alpha=0.5)

    bar_width = 1.0 / n_bins
    for i in range(n_bins):
        if counts[i] > 0:
            color = "steelblue" if abs(accs[i] - confs[i]) < 0.1 else "tomato"
            ax1.bar(confs[i], accs[i], width=bar_width * 0.8,
                    color=color, alpha=0.7, edgecolor="black")

    ax1.set_xlim(0, 1)
    ax1.set_ylim(0, 1)
    ax1.set_xlabel("Mean Predicted Confidence", fontsize=11)
    ax1.set_ylabel("Fraction of Positives (Accuracy)", fontsize=11)
    ax1.set_title(f"Reliability Diagram — {title}\n"
                  f"ECE={metrics['ece']:.4f}, MCE={metrics['mce']:.4f}, "
                  f"Brier={metrics['brier']:.4f}", fontsize=12)
    ax1.legend(fontsize=10)
    ax1.grid(alpha=0.3)

    # Histogram
    bin_centers = [(boundaries[i] + boundaries[i + 1]) / 2 for i in range(n_bins)]
    ax2.bar(bin_centers, counts, width=bar_width * 0.8,
            color="steelblue", alpha=0.7, edgecolor="black")
    ax2.set_xlim(0, 1)
    ax2.set_xlabel("Confidence", fontsize=11)
    ax2.set_ylabel("Count", fontsize=11)
    ax2.set_title("Distribution of Predictions", fontsize=10)

    plt.tight_layout()
    plt.savefig(output, dpi=150)
    plt.close()
    print(f"  Сохранён: {output}")


def plot_recalibration_comparison(before: dict, iso_after: dict, platt_after: dict,
                                   output: str = "charts/recalibration.png"):
    """Сравнение до/после рекалибровки."""
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))

    for ax, metrics, title in zip(axes,
                                    [before, iso_after, platt_after],
                                    ["Before", "After (Isotonic)", "After (Platt)"]):
        ax.plot([0, 1], [0, 1], "k--", alpha=0.5)
        accs = metrics["bin_accuracies"]
        confs = metrics["bin_confidences"]
        counts = metrics["bin_counts"]
        n_bins = len(accs)
        bar_width = 1.0 / n_bins

        for i in range(n_bins):
            if counts[i] > 0:
                ax.bar(confs[i], accs[i], width=bar_width * 0.8,
                       color="steelblue", alpha=0.7, edgecolor="black")

        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.set_title(f"{title}\nECE={metrics['ece']:.4f}", fontsize=11)
        ax.set_xlabel("Confidence")
        ax.set_ylabel("Accuracy")
        ax.grid(alpha=0.3)

    plt.tight_layout()
    plt.savefig(output, dpi=150)
    plt.close()
    print(f"  Сохранён: {output}")


# ─────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Confidence Calibration Analysis")
    parser.add_argument("--input", default="calibration_data.json",
                        help="Input calibration data JSON")
    parser.add_argument("--generate", action="store_true",
                        help="Generate calibration data by running pipeline")
    parser.add_argument("--model", default="gemma2:9b",
                        help="Model for data generation")
    args = parser.parse_args()

    # Генерация или загрузка данных
    if args.generate:
        print("Генерация calibration data...")
        cal_data = generate_calibration_data(args.model)
        with open(args.input, "w", encoding="utf-8") as f:
            json.dump(cal_data, f, indent=2, ensure_ascii=False)
        print(f"Сохранено {len(cal_data)} записей в {args.input}")
    else:
        if not Path(args.input).exists():
            print(f"Файл {args.input} не найден! Используйте --generate для создания.")
            return
        with open(args.input, "r", encoding="utf-8") as f:
            cal_data = json.load(f)

    if not cal_data:
        print("Нет данных для анализа!")
        return

    confidences = np.array([d["confidence"] for d in cal_data])
    labels = np.array([d["is_correct"] for d in cal_data])

    print("=" * 70)
    print("КАЛИБРОВКА CONFIDENCE SCORES")
    print(f"Записей: {len(cal_data)}, Accuracy: {labels.mean():.3f}")
    print("=" * 70)

    # 1. Overall calibration
    print("\n1. Overall Calibration Metrics")
    print("-" * 40)
    metrics = compute_calibration_metrics(confidences, labels)
    print(f"   ECE  = {metrics['ece']:.4f}")
    print(f"   MCE  = {metrics['mce']:.4f}")
    print(f"   Brier = {metrics['brier']:.4f}")
    print(f"   N    = {metrics['n_samples']}")

    plot_reliability_diagram(metrics, "Overall")

    # 2. Per-category
    print("\n2. Per-Category Calibration")
    print("-" * 40)
    categories = set(d["category"] for d in cal_data)
    cat_metrics = {}
    for cat in sorted(categories):
        mask = np.array([d["category"] == cat for d in cal_data])
        if mask.sum() < 5:
            continue
        cat_m = compute_calibration_metrics(confidences[mask], labels[mask])
        cat_metrics[cat] = cat_m
        print(f"   {cat:15s}  ECE={cat_m['ece']:.4f}  Brier={cat_m['brier']:.4f}  n={cat_m['n_samples']}")

        plot_reliability_diagram(cat_m, cat,
                                  output=f"charts/reliability_{cat}.png")

    # 3. Рекалибровка
    print("\n3. Рекалибровка")
    print("-" * 40)
    # Только для сущностей (не IoC — те всегда 1.0)
    sem_mask = np.array([not d["category"].startswith("ioc_") for d in cal_data])
    if sem_mask.sum() >= 10:
        sem_conf = confidences[sem_mask]
        sem_labels = labels[sem_mask]

        recal = recalibrate(sem_conf, sem_labels)

        for method in ["isotonic", "platt"]:
            r = recal[method]
            print(f"   {method.capitalize():10s}  "
                  f"ECE: {r['ece_before']:.4f} → {r['ece_after']:.4f}  "
                  f"({r['improvement_pct']:+.1f}%)")

        # Визуализация — calibrated_confidences уже на sem-only данных
        before_m = compute_calibration_metrics(sem_conf, sem_labels)
        iso_cal = np.array(recal["isotonic"]["calibrated_confidences"])
        platt_cal = np.array(recal["platt"]["calibrated_confidences"])
        iso_m = compute_calibration_metrics(iso_cal, sem_labels)
        platt_m = compute_calibration_metrics(platt_cal, sem_labels)
        plot_recalibration_comparison(before_m, iso_m, platt_m)
    else:
        print("   Недостаточно данных для рекалибровки")

    # Сохраняем результаты
    output = {
        "overall": {k: v for k, v in metrics.items() if k != "bin_boundaries"},
        "per_category": {k: {"ece": v["ece"], "mce": v["mce"], "brier": v["brier"]}
                         for k, v in cat_metrics.items()},
    }
    out_file = "charts/calibration_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False, default=str)
    print(f"\nРезультаты сохранены в {out_file}")


if __name__ == "__main__":
    main()
