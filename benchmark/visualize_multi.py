"""
Визуализация результатов Multi-Model Benchmark.

Генерирует графики для диплома:
  1. F1 по моделям (bar chart)
  2. F1 по категориям (grouped bar chart)
  3. Precision vs Recall (scatter plot)
  4. Время обработки (bar chart)
  5. Radar chart по категориям
  6. Heatmap: модели × датасеты

Использование:
    python3 visualize_multi.py                              # default file
    python3 visualize_multi.py --input benchmark_results.csv
"""

import argparse
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # Для серверов без GUI
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

# Стиль для диплома
plt.rcParams.update({
    "figure.dpi": 150,
    "font.size": 11,
    "axes.titlesize": 13,
    "axes.labelsize": 11,
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,
    "legend.fontsize": 9,
    "figure.figsize": (10, 6),
})

OUTPUT_DIR = Path("charts")

# Сокращения для длинных имён моделей (для графиков)
SHORT_NAMES = {
    "alientelligence/cybersecuritythreatanalysisv2": "alien-cyber-v2",
    "qingmian/qwen2.5-14b-cybersecurity": "qwen2.5-14b-cyber",
}


def shorten_name(name: str) -> str:
    """Сокращает длинные имена моделей для графиков."""
    if name in SHORT_NAMES:
        return SHORT_NAMES[name]
    # Обработка формата "Hybrid+model_name" — убираем префикс перед поиском
    if "+" in name:
        prefix, model = name.split("+", 1)
        if model in SHORT_NAMES:
            return f"{prefix}+{SHORT_NAMES[model]}"
    return name


def load_data(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    # Сокращаем длинные имена
    df["Method"] = df["Method"].apply(shorten_name)
    print(f"Загружено {len(df)} записей из {csv_path}")
    return df


def plot_f1_overall(df: pd.DataFrame):
    """График 1: Средний F1 по моделям."""
    summary = df.groupby("Method")["F1_overall"].mean().sort_values(ascending=True)

    fig, ax = plt.subplots(figsize=(10, max(5, len(summary) * 0.6)))

    colors = []
    for method in summary.index:
        if "Hybrid" in method or "qwen" in method.lower():
            colors.append("#2196F3")
        elif method in ("SecureBERT", "GLiNER"):
            colors.append("#9E9E9E")
        else:
            colors.append("#4CAF50")

    bars = ax.barh(summary.index, summary.values, color=colors, edgecolor="white", height=0.6)

    for bar, val in zip(bars, summary.values):
        ax.text(val + 0.01, bar.get_y() + bar.get_height() / 2,
                f"{val:.3f}", va="center", fontsize=10, fontweight="bold")

    ax.set_xlabel("F1 Score (average across datasets)")
    ax.set_title("Overall F1 Score by Model")
    ax.set_xlim(0, min(1.0, summary.max() + 0.1))
    ax.axvline(x=summary.max(), color="red", linestyle="--", alpha=0.3, label="Best")

    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "01_f1_overall.png", bbox_inches="tight")
    plt.close()
    print("  [OK] 01_f1_overall.png")


def plot_f1_by_category(df: pd.DataFrame):
    """График 2: F1 по категориям (grouped bar chart)."""
    categories = ["F1_actors", "F1_malware", "F1_tools", "F1_ioc", "F1_attack_patterns"]
    cat_labels = ["Actors", "Malware", "Tools", "IoC", "ATT&CK"]

    # Фильтруем категории со всеми нулями
    summary = df.groupby("Method")[categories].mean()
    nonzero_cats = [(c, l) for c, l in zip(categories, cat_labels) if summary[c].sum() > 0]
    if not nonzero_cats:
        print("  [SKIP] 02_f1_by_category.png — все категории пустые")
        return

    categories, cat_labels = zip(*nonzero_cats)
    summary = summary[list(categories)]
    summary = summary.sort_values(categories[0], ascending=False)

    fig, ax = plt.subplots(figsize=(12, 6))

    x = np.arange(len(summary))
    n_cats = len(categories)
    width = 0.8 / n_cats
    multiplier = 0

    colors = ["#2196F3", "#4CAF50", "#FF9800", "#9C27B0", "#F44336"][:n_cats]

    for i, (cat, label) in enumerate(zip(categories, cat_labels)):
        offset = width * multiplier
        bars = ax.bar(x + offset, summary[cat], width, label=label, color=colors[i], alpha=0.85)
        multiplier += 1

    ax.set_xlabel("Model")
    ax.set_ylabel("F1 Score")
    ax.set_title("F1 Score by Entity Category")
    ax.set_xticks(x + width * (n_cats - 1) / 2)
    ax.set_xticklabels(summary.index, rotation=45, ha="right")
    ax.legend(loc="upper right")
    ax.set_ylim(0, 1.0)
    ax.grid(axis="y", alpha=0.3)

    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "02_f1_by_category.png", bbox_inches="tight")
    plt.close()
    print("  [OK] 02_f1_by_category.png")


def plot_precision_recall(df: pd.DataFrame):
    """График 3: Precision vs Recall scatter."""
    summary = df.groupby("Method")[["P_overall", "R_overall", "F1_overall"]].mean()

    fig, ax = plt.subplots(figsize=(8, 8))

    for method, row in summary.iterrows():
        color = "#2196F3" if "Hybrid" in method else "#9E9E9E"
        size = row["F1_overall"] * 300 + 50

        ax.scatter(row["R_overall"], row["P_overall"], s=size, c=color,
                   alpha=0.7, edgecolors="black", linewidth=0.5)
        ax.annotate(method, (row["R_overall"], row["P_overall"]),
                    textcoords="offset points", xytext=(8, 8), fontsize=8)

    # F1 изолинии
    for f1_val in [0.2, 0.4, 0.6, 0.8]:
        r_vals = np.linspace(0.01, 1, 100)
        p_vals = (f1_val * r_vals) / (2 * r_vals - f1_val)
        mask = (p_vals > 0) & (p_vals <= 1)
        ax.plot(r_vals[mask], p_vals[mask], "--", color="gray", alpha=0.3, linewidth=0.8)
        # Label
        idx = np.argmin(np.abs(p_vals - 0.95))
        if mask[idx]:
            ax.text(r_vals[idx], p_vals[idx], f"F1={f1_val}", fontsize=7, color="gray")

    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("Precision vs Recall")
    ax.set_xlim(0, 1.05)
    ax.set_ylim(0, 1.05)
    ax.set_aspect("equal")
    ax.grid(alpha=0.2)

    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "03_precision_recall.png", bbox_inches="tight")
    plt.close()
    print("  [OK] 03_precision_recall.png")


def plot_time_comparison(df: pd.DataFrame):
    """График 4: Время обработки по моделям."""
    summary = df.groupby("Method")["Time_sec"].mean().sort_values(ascending=True)

    fig, ax = plt.subplots(figsize=(10, max(5, len(summary) * 0.6)))

    colors = ["#FF9800" if t > 60 else "#4CAF50" for t in summary.values]

    bars = ax.barh(summary.index, summary.values, color=colors, edgecolor="white", height=0.6)

    for bar, val in zip(bars, summary.values):
        ax.text(val + 1, bar.get_y() + bar.get_height() / 2,
                f"{val:.1f}s", va="center", fontsize=10)

    ax.set_xlabel("Average Processing Time (seconds)")
    ax.set_title("Processing Time by Model")

    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "04_time_comparison.png", bbox_inches="tight")
    plt.close()
    print("  [OK] 04_time_comparison.png")


def plot_heatmap(df: pd.DataFrame):
    """График 5: Heatmap модели × датасеты."""
    pivot = df.pivot_table(
        values="F1_overall",
        index="Method",
        columns="Dataset",
        aggfunc="mean",
    )

    # Сортируем по среднему F1
    pivot["mean"] = pivot.mean(axis=1)
    pivot = pivot.sort_values("mean", ascending=False)
    pivot = pivot.drop("mean", axis=1)

    fig, ax = plt.subplots(figsize=(max(8, len(pivot.columns) * 2.5), max(5, len(pivot) * 0.7)))

    im = ax.imshow(pivot.values, cmap="YlOrRd", aspect="auto", vmin=0, vmax=1)

    ax.set_xticks(range(len(pivot.columns)))
    ax.set_xticklabels(pivot.columns, rotation=45, ha="right")
    ax.set_yticks(range(len(pivot.index)))
    ax.set_yticklabels(pivot.index)

    # Числа в ячейках
    for i in range(len(pivot.index)):
        for j in range(len(pivot.columns)):
            val = pivot.values[i, j]
            color = "white" if val > 0.5 else "black"
            ax.text(j, i, f"{val:.3f}", ha="center", va="center",
                    fontsize=10, color=color, fontweight="bold")

    ax.set_title("F1 Score: Model × Dataset")
    fig.colorbar(im, ax=ax, label="F1 Score", shrink=0.8)

    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "05_heatmap.png", bbox_inches="tight")
    plt.close()
    print("  [OK] 05_heatmap.png")


def plot_radar(df: pd.DataFrame):
    """График 6: Radar chart для топ-3 моделей."""
    all_categories = ["F1_actors", "F1_malware", "F1_tools", "F1_ioc", "F1_attack_patterns"]
    all_labels = ["Actors", "Malware", "Tools", "IoC", "ATT&CK\nPatterns"]

    summary_full = df.groupby("Method")[all_categories].mean()

    # Фильтруем категории со всеми нулями (не информативны для radar)
    nonzero = [(c, l) for c, l in zip(all_categories, all_labels) if summary_full[c].sum() > 0]
    if len(nonzero) < 3:
        print("  [SKIP] 06_radar_top3.png — недостаточно категорий")
        return
    categories, cat_labels = zip(*nonzero)
    categories = list(categories)
    cat_labels = list(cat_labels)

    summary = summary_full[categories]
    summary["avg"] = summary.mean(axis=1)
    top3 = summary.nlargest(3, "avg").drop("avg", axis=1)

    angles = np.linspace(0, 2 * np.pi, len(categories), endpoint=False).tolist()
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))

    colors = ["#2196F3", "#4CAF50", "#FF9800"]

    for i, (method, row) in enumerate(top3.iterrows()):
        values = row.values.tolist()
        values += values[:1]
        ax.plot(angles, values, "o-", linewidth=2, color=colors[i], label=method, markersize=6)
        ax.fill(angles, values, color=colors[i], alpha=0.1)

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(cat_labels)
    ax.set_ylim(0, 1)
    ax.set_title("Top 3 Models: Category Comparison", pad=20)
    ax.legend(loc="upper right", bbox_to_anchor=(1.3, 1.0))
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "06_radar_top3.png", bbox_inches="tight")
    plt.close()
    print("  [OK] 06_radar_top3.png")


def main():
    parser = argparse.ArgumentParser(description="Visualize benchmark results")
    parser.add_argument(
        "--input",
        type=str,
        default="benchmark_results.csv",
        help="Input CSV file from benchmark_multi_model.py",
    )
    args = parser.parse_args()

    if not Path(args.input).exists():
        print(f"Файл {args.input} не найден!")
        print("Сначала запусти: python3 benchmark_multi_model.py")
        return

    OUTPUT_DIR.mkdir(exist_ok=True)

    df = load_data(args.input)

    print("\nГенерация графиков...")

    plot_f1_overall(df)
    plot_f1_by_category(df)
    plot_precision_recall(df)
    plot_time_comparison(df)
    plot_heatmap(df)

    # Radar только если >= 3 модели
    if df["Method"].nunique() >= 3:
        plot_radar(df)

    print(f"\nВсе графики сохранены в {OUTPUT_DIR}/")
    print("Графики готовы для вставки в диплом!")


if __name__ == "__main__":
    main()
