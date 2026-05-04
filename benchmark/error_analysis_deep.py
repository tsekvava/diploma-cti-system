"""
Глубокий анализ ошибок CTI-бенчмарка (Error Taxonomy).

Анализирует:
  1. Entity-level TP/FP/FN с классификацией типа ошибки
  2. Корреляция ошибок между моделями (Jaccard similarity)
  3. Category-wise error decomposition (stacked bars, radar charts)
  4. Per-model error profiles

Использование:
    cd benchmark
    python3 error_analysis_deep.py
    python3 error_analysis_deep.py --input benchmark_full_9models_detailed.json
"""

import json
import re
import argparse
from pathlib import Path
from collections import Counter, defaultdict

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

CHARTS_DIR = Path("charts")
CHARTS_DIR.mkdir(exist_ok=True)

# Расширения файлов, ложно определяемые как домены
REGEX_ARTIFACT_EXTENSIONS = {
    ".msi", ".hta", ".crt", ".log", ".txt", ".reg", ".bat", ".ps1",
    ".vbs", ".exe", ".dll", ".sys", ".doc", ".docx", ".xls", ".xlsx",
}


# ─────────────────────────────────────────────
#  Утилиты
# ─────────────────────────────────────────────

def normalize(text: str) -> str:
    """Нормализация для сравнения: lower, strip."""
    text = str(text).lower().strip()
    text = re.sub(r"[\(\[]?t\d{4}(\.\d{3})?[\)\]]?", "", text)
    text = re.sub(r"[\(\[]?cve-\d{4}-\d+[\)\]]?", "", text)
    text = text.strip().strip(".,-:()")
    text = re.sub(r"\s+", " ", text).strip()
    return text


def get_entities(data: dict, keys: list) -> set:
    s = set()
    for key in keys:
        for item in data.get(key, []):
            norm = normalize(item)
            if len(norm) > 2:
                s.add(norm)
    return s


def get_ioc(data: dict) -> set:
    s = set()
    for k, v in data.get("indicators", {}).items():
        for item in v:
            s.add(str(item).lower().strip())
    return s


def get_attack_patterns(data: dict) -> set:
    items = data.get("attack_patterns", [])
    s = set()
    for item in items:
        found = re.findall(r"T\d{4}(?:\.\d{3})?", str(item))
        s.update(f.lower() for f in found)
        if not re.search(r"T\d{4}", str(item)):
            norm = normalize(item)
            if len(norm) > 2:
                s.add(norm)
    return s


# ─────────────────────────────────────────────
#  1. Классификация ошибок
# ─────────────────────────────────────────────

def classify_fp(entity: str, pred_data: dict, truth_data: dict, text: str) -> str:
    """Классифицирует тип ложноположительной ошибки."""
    entity_lower = entity.lower()

    # 1. Regex artifact — файл с расширением ложно определён как домен
    for ext in REGEX_ARTIFACT_EXTENSIONS:
        if entity_lower.endswith(ext):
            return "regex_artifact"

    # 2. Granularity mismatch — частично совпадает с ground truth
    all_truth = set()
    for key in ["threat_actor", "malware", "tools"]:
        for item in truth_data.get(key, []):
            all_truth.add(normalize(item))
    for t in all_truth:
        if entity_lower in t or t in entity_lower:
            return "granularity_mismatch"

    # 3. Category confusion — сущность есть в ground truth, но в другой категории
    all_truth_flat = set()
    for key in ["threat_actor", "malware", "tools"]:
        for item in truth_data.get(key, []):
            all_truth_flat.add(normalize(item))
    # Check if entity matches a truth entity from ANY category
    from rapidfuzz import fuzz
    for t in all_truth_flat:
        if fuzz.token_sort_ratio(entity_lower, t) >= 80:
            return "category_confusion"

    # 4. Over-extraction — entity exists in text but is not CTI-relevant
    if entity_lower in text.lower():
        return "over_extraction"

    # 5. Hallucination — entity doesn't exist in text or MITRE
    return "hallucination"


def classify_fn(entity: str, pred_data: dict, text: str) -> str:
    """Классифицирует причину пропуска (FN)."""
    entity_lower = entity.lower()

    # 1. Not mentioned — ground truth entity not in report text
    if entity_lower not in text.lower():
        return "not_in_text"

    # 2. Check if model extracted something similar (fuzzy match)
    from rapidfuzz import fuzz
    all_pred = set()
    for key in ["threat_actor", "malware", "tools"]:
        for item in pred_data.get(key, []):
            all_pred.add(normalize(item))
    for p in all_pred:
        if fuzz.token_sort_ratio(entity_lower, p) >= 70:
            return "near_miss"

    # 3. Missed by LLM
    return "missed_by_llm"


def analyze_errors(detailed_results: list, report_texts: dict) -> dict:
    """Полный анализ ошибок для всех моделей и датасетов."""
    categories = {
        "actors": (["threat_actor"], ["threat_actor"]),
        "malware": (["malware"], ["malware"]),
        "tools": (["tools"], ["tools"]),
    }

    all_errors = []

    for entry in detailed_results:
        model = entry["model"]
        dataset = entry["dataset"]
        pred = entry["extracted"]
        text = report_texts.get(dataset, "")

        # Загружаем ground truth
        gt_path = Path(f"data/ground_truth_{dataset}.json")
        if not gt_path.exists():
            continue
        with open(gt_path, "r", encoding="utf-8") as f:
            truth = json.load(f)

        # По каждой категории
        for cat_name, (pred_keys, truth_keys) in categories.items():
            pred_set = get_entities(pred, pred_keys)
            truth_set = get_entities(truth, truth_keys)

            tp = pred_set & truth_set
            fp = pred_set - truth_set
            fn = truth_set - pred_set

            for entity in fp:
                error_type = classify_fp(entity, pred, truth, text)
                all_errors.append({
                    "model": model, "dataset": dataset, "category": cat_name,
                    "error_kind": "FP", "entity": entity, "error_type": error_type,
                })

            for entity in fn:
                error_type = classify_fn(entity, pred, text)
                all_errors.append({
                    "model": model, "dataset": dataset, "category": cat_name,
                    "error_kind": "FN", "entity": entity, "error_type": error_type,
                })

            for entity in tp:
                all_errors.append({
                    "model": model, "dataset": dataset, "category": cat_name,
                    "error_kind": "TP", "entity": entity, "error_type": "correct",
                })

        # IoC
        pred_ioc = get_ioc(pred)
        truth_ioc = get_ioc(truth)
        for entity in (pred_ioc - truth_ioc):
            error_type = "regex_artifact" if any(entity.endswith(e) for e in REGEX_ARTIFACT_EXTENSIONS) else "over_extraction"
            all_errors.append({
                "model": model, "dataset": dataset, "category": "ioc",
                "error_kind": "FP", "entity": entity, "error_type": error_type,
            })
        for entity in (truth_ioc - pred_ioc):
            all_errors.append({
                "model": model, "dataset": dataset, "category": "ioc",
                "error_kind": "FN", "entity": entity, "error_type": "missed_by_regex",
            })
        for entity in (pred_ioc & truth_ioc):
            all_errors.append({
                "model": model, "dataset": dataset, "category": "ioc",
                "error_kind": "TP", "entity": entity, "error_type": "correct",
            })

    return all_errors


# ─────────────────────────────────────────────
#  2. Jaccard similarity между моделями
# ─────────────────────────────────────────────

def jaccard_similarity(errors_df: pd.DataFrame, models: list) -> pd.DataFrame:
    """Матрица Jaccard similarity по множествам FP."""
    n = len(models)
    matrix = np.zeros((n, n))

    for i, m1 in enumerate(models):
        fp1 = set(errors_df[(errors_df["model"] == m1) & (errors_df["error_kind"] == "FP")]["entity"])
        for j, m2 in enumerate(models):
            fp2 = set(errors_df[(errors_df["model"] == m2) & (errors_df["error_kind"] == "FP")]["entity"])
            union = fp1 | fp2
            intersection = fp1 & fp2
            matrix[i, j] = len(intersection) / len(union) if union else 1.0

    return pd.DataFrame(matrix, index=models, columns=models)


# ─────────────────────────────────────────────
#  Визуализации
# ─────────────────────────────────────────────

def plot_stacked_bar(errors_df: pd.DataFrame, models: list,
                     output: str = "charts/error_stacked_bar.png"):
    """Stacked bar: TP/FP/FN по моделям."""
    short = [m.split("/")[-1][:12] for m in models]
    tp_counts = [len(errors_df[(errors_df["model"] == m) & (errors_df["error_kind"] == "TP")]) for m in models]
    fp_counts = [len(errors_df[(errors_df["model"] == m) & (errors_df["error_kind"] == "FP")]) for m in models]
    fn_counts = [len(errors_df[(errors_df["model"] == m) & (errors_df["error_kind"] == "FN")]) for m in models]

    x = np.arange(len(models))
    width = 0.6

    fig, ax = plt.subplots(figsize=(12, 6))
    ax.bar(x, tp_counts, width, label="TP (correct)", color="forestgreen", alpha=0.8)
    ax.bar(x, fp_counts, width, bottom=tp_counts, label="FP (false positive)", color="tomato", alpha=0.8)
    ax.bar(x, fn_counts, width, bottom=[t + f for t, f in zip(tp_counts, fp_counts)],
           label="FN (missed)", color="gold", alpha=0.8)

    ax.set_xticks(x)
    ax.set_xticklabels(short, rotation=45, ha="right")
    ax.set_ylabel("Количество сущностей")
    ax.set_title("TP / FP / FN по моделям (все категории)")
    ax.legend()
    plt.tight_layout()
    plt.savefig(output, dpi=150)
    plt.close()
    print(f"  Сохранён: {output}")


def plot_error_taxonomy(errors_df: pd.DataFrame, output: str = "charts/error_taxonomy.png"):
    """Распределение типов ошибок."""
    fp_errors = errors_df[errors_df["error_kind"] == "FP"]
    fn_errors = errors_df[errors_df["error_kind"] == "FN"]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

    # FP taxonomy
    fp_counts = fp_errors["error_type"].value_counts()
    colors_fp = {"regex_artifact": "salmon", "over_extraction": "orange",
                 "granularity_mismatch": "skyblue", "category_confusion": "plum",
                 "hallucination": "tomato"}
    fp_colors = [colors_fp.get(t, "gray") for t in fp_counts.index]
    ax1.barh(fp_counts.index, fp_counts.values, color=fp_colors, edgecolor="black")
    ax1.set_xlabel("Количество")
    ax1.set_title("False Positives: типы ошибок")
    for i, v in enumerate(fp_counts.values):
        ax1.text(v + 0.5, i, str(v), va="center", fontsize=10)

    # FN taxonomy
    fn_counts = fn_errors["error_type"].value_counts()
    colors_fn = {"missed_by_llm": "gold", "not_in_text": "lightgreen",
                 "near_miss": "skyblue", "missed_by_regex": "salmon"}
    fn_colors = [colors_fn.get(t, "gray") for t in fn_counts.index]
    ax2.barh(fn_counts.index, fn_counts.values, color=fn_colors, edgecolor="black")
    ax2.set_xlabel("Количество")
    ax2.set_title("False Negatives: причины пропуска")
    for i, v in enumerate(fn_counts.values):
        ax2.text(v + 0.5, i, str(v), va="center", fontsize=10)

    plt.tight_layout()
    plt.savefig(output, dpi=150)
    plt.close()
    print(f"  Сохранён: {output}")


def plot_radar(errors_df: pd.DataFrame, models: list,
               output: str = "charts/model_radar.png"):
    """Radar chart: F1 по 5 категориям для каждой модели."""
    categories = ["actors", "malware", "tools", "ioc"]
    n_cats = len(categories)
    angles = np.linspace(0, 2 * np.pi, n_cats, endpoint=False).tolist()
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))

    colors = plt.cm.Set2(np.linspace(0, 1, len(models)))
    for model, color in zip(models, colors):
        values = []
        for cat in categories:
            cat_data = errors_df[(errors_df["model"] == model) & (errors_df["category"] == cat)]
            tp = len(cat_data[cat_data["error_kind"] == "TP"])
            fp = len(cat_data[cat_data["error_kind"] == "FP"])
            fn = len(cat_data[cat_data["error_kind"] == "FN"])
            p = tp / (tp + fp) if (tp + fp) > 0 else 0
            r = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0
            values.append(f1)
        values += values[:1]

        short = model.split("/")[-1][:12]
        ax.plot(angles, values, "o-", label=short, color=color, linewidth=1.5)
        ax.fill(angles, values, alpha=0.05, color=color)

    ax.set_thetagrids(np.degrees(angles[:-1]), categories)
    ax.set_ylim(0, 1)
    ax.set_title("F1 по категориям (radar)", fontsize=14, pad=20)
    ax.legend(loc="upper right", bbox_to_anchor=(1.3, 1.1), fontsize=8)
    plt.tight_layout()
    plt.savefig(output, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Сохранён: {output}")


def plot_jaccard_heatmap(jac_matrix: pd.DataFrame, output: str = "charts/jaccard_heatmap.png"):
    """Heatmap Jaccard similarity между моделями."""
    short_names = [n.split("/")[-1][:12] for n in jac_matrix.index]

    fig, ax = plt.subplots(figsize=(9, 7))
    im = ax.imshow(jac_matrix.values, cmap="YlOrRd", vmin=0, vmax=1, aspect="auto")

    ax.set_xticks(range(len(short_names)))
    ax.set_xticklabels(short_names, rotation=45, ha="right", fontsize=9)
    ax.set_yticks(range(len(short_names)))
    ax.set_yticklabels(short_names, fontsize=9)

    for i in range(len(short_names)):
        for j in range(len(short_names)):
            ax.text(j, i, f"{jac_matrix.values[i, j]:.2f}",
                    ha="center", va="center", fontsize=8,
                    color="white" if jac_matrix.values[i, j] > 0.5 else "black")

    ax.set_title("Jaccard Similarity (FP sets)\nВысокие значения = модели делают одинаковые ошибки", fontsize=12)
    plt.colorbar(im, ax=ax, label="Jaccard", shrink=0.8)
    plt.tight_layout()
    plt.savefig(output, dpi=150)
    plt.close()
    print(f"  Сохранён: {output}")


# ─────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Deep Error Analysis")
    parser.add_argument("--input", default="benchmark_full_9models_detailed.json")
    args = parser.parse_args()

    if not Path(args.input).exists():
        print(f"Файл {args.input} не найден!")
        return

    with open(args.input, "r", encoding="utf-8") as f:
        detailed = json.load(f)

    # Загружаем тексты отчётов
    report_texts = {}
    for entry in detailed:
        ds = entry["dataset"]
        txt_path = Path(f"data/{ds}.txt")
        if txt_path.exists() and ds not in report_texts:
            report_texts[ds] = txt_path.read_text(encoding="utf-8")

    print("=" * 70)
    print("ГЛУБОКИЙ АНАЛИЗ ОШИБОК (Error Taxonomy)")
    print(f"Записей: {len(detailed)}, Датасетов: {len(report_texts)}")
    print("=" * 70)

    # 1. Анализ ошибок
    print("\n1. Классификация ошибок...")
    all_errors = analyze_errors(detailed, report_texts)
    errors_df = pd.DataFrame(all_errors)

    models = sorted(errors_df["model"].unique())
    print(f"   Всего записей: {len(errors_df)}")
    print(f"   TP: {len(errors_df[errors_df['error_kind'] == 'TP'])}")
    print(f"   FP: {len(errors_df[errors_df['error_kind'] == 'FP'])}")
    print(f"   FN: {len(errors_df[errors_df['error_kind'] == 'FN'])}")

    # Таблица типов ошибок
    print("\n   Типы FP (false positives):")
    fp_summary = errors_df[errors_df["error_kind"] == "FP"]["error_type"].value_counts()
    for etype, count in fp_summary.items():
        print(f"     {etype:25s} {count:4d}")

    print("\n   Типы FN (пропуски):")
    fn_summary = errors_df[errors_df["error_kind"] == "FN"]["error_type"].value_counts()
    for etype, count in fn_summary.items():
        print(f"     {etype:25s} {count:4d}")

    # 2. Jaccard similarity
    print("\n2. Jaccard similarity между FP-множествами моделей...")
    jac_matrix = jaccard_similarity(errors_df, models)
    avg_jac = jac_matrix.values[np.triu_indices_from(jac_matrix.values, k=1)].mean()
    print(f"   Средний Jaccard (off-diagonal): {avg_jac:.3f}")
    if avg_jac > 0.5:
        print("   → Модели делают ПОХОЖИЕ ошибки (ensemble не поможет)")
    else:
        print("   → Модели делают РАЗНЫЕ ошибки (ensemble может помочь)")

    # 3. Визуализации
    print("\n3. Генерация графиков...")
    plot_stacked_bar(errors_df, models)
    plot_error_taxonomy(errors_df)
    plot_radar(errors_df, models)
    plot_jaccard_heatmap(jac_matrix)

    # 4. Сохраняем данные
    errors_df.to_csv("charts/error_analysis_detailed.csv", index=False)
    print(f"\n  Детальный CSV: charts/error_analysis_detailed.csv")

    # Топ-10 FP сущностей (по частоте)
    top_fp = errors_df[errors_df["error_kind"] == "FP"]["entity"].value_counts().head(15)
    print("\n  Топ-15 FP сущностей:")
    for entity, count in top_fp.items():
        print(f"    {entity[:40]:40s} × {count}")

    # Топ-10 FN
    top_fn = errors_df[errors_df["error_kind"] == "FN"]["entity"].value_counts().head(15)
    print("\n  Топ-15 FN (самые частые пропуски):")
    for entity, count in top_fn.items():
        print(f"    {entity[:40]:40s} × {count}")


if __name__ == "__main__":
    main()
