"""
Статистический анализ результатов бенчмарка CTI-пайплайна.

Методы:
  1. Bootstrap 95% доверительные интервалы (BCa) для F1 каждой модели
  2. Wilcoxon signed-rank test между парами моделей + коррекция Бонферрони
  3. Friedman χ² тест + post-hoc Nemenyi (Critical Difference diagram)
  4. Cohen's d (эффект размера) для каждой пары моделей

Использование:
    cd benchmark
    python3 statistical_analysis.py
    python3 statistical_analysis.py --input benchmark_full_9models.csv
"""

import json
import argparse
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from scipy import stats

warnings.filterwarnings("ignore", category=RuntimeWarning)

CHARTS_DIR = Path("charts")
CHARTS_DIR.mkdir(exist_ok=True)


# ─────────────────────────────────────────────
#  1. Bootstrap Confidence Intervals (BCa)
# ─────────────────────────────────────────────

def bootstrap_ci(data: np.ndarray, n_boot: int = 10000, alpha: float = 0.05) -> dict:
    """BCa bootstrap 95% CI для среднего."""
    n = len(data)
    if n < 3:
        return {"mean": float(np.mean(data)), "std": float(np.std(data)),
                "ci_lower": float(np.min(data)), "ci_upper": float(np.max(data)),
                "n": n, "method": "minmax (n<3)"}

    observed = np.mean(data)

    # Bootstrap выборки
    rng = np.random.default_rng(42)
    boot_means = np.array([
        np.mean(rng.choice(data, size=n, replace=True))
        for _ in range(n_boot)
    ])

    # BCa: bias-correction
    z0 = stats.norm.ppf(np.mean(boot_means < observed))

    # BCa: acceleration (jackknife)
    jackknife = np.array([np.mean(np.delete(data, i)) for i in range(n)])
    jack_mean = np.mean(jackknife)
    num = np.sum((jack_mean - jackknife) ** 3)
    den = 6.0 * (np.sum((jack_mean - jackknife) ** 2) ** 1.5)
    a = num / den if den != 0 else 0.0

    # Adjusted percentiles
    z_alpha = stats.norm.ppf(alpha / 2)
    z_1alpha = stats.norm.ppf(1 - alpha / 2)

    p_lower = stats.norm.cdf(z0 + (z0 + z_alpha) / (1 - a * (z0 + z_alpha)))
    p_upper = stats.norm.cdf(z0 + (z0 + z_1alpha) / (1 - a * (z0 + z_1alpha)))

    # Clamp to valid range
    p_lower = np.clip(p_lower, 0.001, 0.999)
    p_upper = np.clip(p_upper, 0.001, 0.999)

    ci_lower = float(np.percentile(boot_means, p_lower * 100))
    ci_upper = float(np.percentile(boot_means, p_upper * 100))

    return {
        "mean": float(observed),
        "std": float(np.std(data)),
        "ci_lower": ci_lower,
        "ci_upper": ci_upper,
        "n": n,
        "method": "BCa bootstrap",
    }


# ─────────────────────────────────────────────
#  2. Pairwise Wilcoxon signed-rank tests
# ─────────────────────────────────────────────

def pairwise_wilcoxon(df: pd.DataFrame, models: list, metric: str = "F1_overall") -> pd.DataFrame:
    """Матрица p-values (Wilcoxon signed-rank) с коррекцией Бонферрони."""
    n_models = len(models)
    n_comparisons = n_models * (n_models - 1) // 2
    alpha_adj = 0.05 / n_comparisons if n_comparisons > 0 else 0.05

    p_matrix = pd.DataFrame(np.ones((n_models, n_models)), index=models, columns=models)

    for i in range(n_models):
        for j in range(i + 1, n_models):
            m1 = df[df["Model"] == models[i]]
            m2 = df[df["Model"] == models[j]]

            # Align on same datasets
            common = set(m1["Dataset"]) & set(m2["Dataset"])
            if len(common) < 3:
                continue

            v1 = m1[m1["Dataset"].isin(common)].sort_values("Dataset")[metric].values
            v2 = m2[m2["Dataset"].isin(common)].sort_values("Dataset")[metric].values

            if np.all(v1 == v2):
                p = 1.0
            else:
                try:
                    _, p = stats.wilcoxon(v1, v2, alternative="two-sided")
                except ValueError:
                    p = 1.0

            p_matrix.iloc[i, j] = p
            p_matrix.iloc[j, i] = p

    return p_matrix, alpha_adj


# ─────────────────────────────────────────────
#  3. Friedman test + Nemenyi post-hoc
# ─────────────────────────────────────────────

def friedman_test(df: pd.DataFrame, models: list, metric: str = "F1_overall"):
    """Friedman χ² тест + средние ранги."""
    datasets = sorted(df["Dataset"].unique())
    rank_matrix = []

    for ds in datasets:
        scores = []
        for m in models:
            row = df[(df["Model"] == m) & (df["Dataset"] == ds)]
            scores.append(row[metric].values[0] if len(row) > 0 else 0.0)
        # Ранг (1 = лучший)
        ranks = stats.rankdata([-s for s in scores])
        rank_matrix.append(ranks)

    rank_matrix = np.array(rank_matrix)
    avg_ranks = np.mean(rank_matrix, axis=0)

    # Friedman test
    try:
        chi2, p = stats.friedmanchisquare(*[rank_matrix[:, i] for i in range(len(models))])
    except ValueError:
        chi2, p = 0.0, 1.0

    # Critical Difference (Nemenyi)
    k = len(models)
    N = len(datasets)
    # q_alpha для Nemenyi (approx for k=9, alpha=0.05)
    q_alpha_table = {2: 1.960, 3: 2.344, 4: 2.569, 5: 2.728,
                     6: 2.850, 7: 2.949, 8: 3.031, 9: 3.102, 10: 3.164}
    q_alpha = q_alpha_table.get(k, 2.576)
    cd = q_alpha * np.sqrt(k * (k + 1) / (6 * N))

    return {
        "chi2": float(chi2),
        "p_value": float(p),
        "avg_ranks": dict(zip(models, avg_ranks.tolist())),
        "critical_difference": float(cd),
        "k": k,
        "N": N,
    }


# ─────────────────────────────────────────────
#  4. Cohen's d (effect size)
# ─────────────────────────────────────────────

def cohens_d(x: np.ndarray, y: np.ndarray) -> float:
    """Cohen's d для двух выборок."""
    nx, ny = len(x), len(y)
    pooled_std = np.sqrt(((nx - 1) * np.var(x, ddof=1) + (ny - 1) * np.var(y, ddof=1)) / (nx + ny - 2))
    return float((np.mean(x) - np.mean(y)) / pooled_std) if pooled_std > 0 else 0.0


# ─────────────────────────────────────────────
#  Визуализации
# ─────────────────────────────────────────────

def plot_ci_chart(ci_data: dict, output: str = "charts/bootstrap_ci.png"):
    """Bar chart с error bars (CI)."""
    models = list(ci_data.keys())
    means = [ci_data[m]["mean"] for m in models]
    ci_low = [ci_data[m]["mean"] - ci_data[m]["ci_lower"] for m in models]
    ci_high = [ci_data[m]["ci_upper"] - ci_data[m]["mean"] for m in models]

    # Короткие имена
    short = [m.split("/")[-1].split("+")[-1][:15] for m in models]

    fig, ax = plt.subplots(figsize=(12, 6))
    bars = ax.barh(range(len(models)), means, xerr=[ci_low, ci_high],
                   capsize=5, color="steelblue", alpha=0.8, edgecolor="black")
    ax.set_yticks(range(len(models)))
    ax.set_yticklabels(short, fontsize=10)
    ax.set_xlabel("F1 Overall (mean ± 95% CI)", fontsize=12)
    ax.set_title("Bootstrap 95% CI для F1 по моделям", fontsize=14)
    ax.axvline(x=0, color="gray", linestyle="--", alpha=0.3)

    # Аннотации
    for i, (m, cl, cu) in enumerate(zip(means, ci_low, ci_high)):
        ax.annotate(f"{m:.3f}", (m + cu + 0.005, i), va="center", fontsize=9)

    plt.tight_layout()
    plt.savefig(output, dpi=150)
    plt.close()
    print(f"  Сохранён: {output}")


def plot_pvalue_heatmap(p_matrix: pd.DataFrame, alpha_adj: float,
                        output: str = "charts/pvalue_heatmap.png"):
    """Heatmap матрицы p-values."""
    short_names = [n.split("/")[-1][:12] for n in p_matrix.index]

    fig, ax = plt.subplots(figsize=(10, 8))
    data = p_matrix.values.copy()
    np.fill_diagonal(data, np.nan)

    cmap = plt.cm.RdYlGn_r
    im = ax.imshow(data, cmap=cmap, vmin=0, vmax=0.1, aspect="auto")

    ax.set_xticks(range(len(short_names)))
    ax.set_xticklabels(short_names, rotation=45, ha="right", fontsize=9)
    ax.set_yticks(range(len(short_names)))
    ax.set_yticklabels(short_names, fontsize=9)

    # Аннотации
    for i in range(len(short_names)):
        for j in range(len(short_names)):
            if i != j:
                p = data[i, j]
                color = "white" if p < 0.05 else "black"
                marker = "**" if p < alpha_adj else ("*" if p < 0.05 else "")
                ax.text(j, i, f"{p:.3f}{marker}", ha="center", va="center",
                        fontsize=8, color=color)

    ax.set_title(f"Wilcoxon p-values (Bonferroni α={alpha_adj:.4f})\n** = значимо после коррекции", fontsize=12)
    plt.colorbar(im, ax=ax, label="p-value", shrink=0.8)
    plt.tight_layout()
    plt.savefig(output, dpi=150)
    plt.close()
    print(f"  Сохранён: {output}")


def plot_critical_difference(friedman_result: dict, output: str = "charts/critical_difference.png"):
    """Critical Difference diagram (Demšar 2006)."""
    avg_ranks = friedman_result["avg_ranks"]
    cd = friedman_result["critical_difference"]

    # Sort by rank
    sorted_models = sorted(avg_ranks.items(), key=lambda x: x[1])
    models = [m for m, _ in sorted_models]
    ranks = [r for _, r in sorted_models]
    short = [m.split("/")[-1][:15] for m in models]
    k = len(models)

    fig, ax = plt.subplots(figsize=(12, max(4, k * 0.6)))

    # Горизонтальная ось — ранги
    ax.set_xlim(0.5, k + 0.5)
    ax.set_ylim(-0.5, k + 1)
    ax.invert_xaxis()

    # Рисуем CD bar
    cd_y = k + 0.3
    ax.plot([1, 1 + cd], [cd_y, cd_y], "k-", linewidth=2)
    ax.plot([1, 1], [cd_y - 0.1, cd_y + 0.1], "k-", linewidth=2)
    ax.plot([1 + cd, 1 + cd], [cd_y - 0.1, cd_y + 0.1], "k-", linewidth=2)
    ax.text(1 + cd / 2, cd_y + 0.15, f"CD={cd:.2f}", ha="center", fontsize=10)

    # Рисуем модели
    for i, (name, rank) in enumerate(zip(short, ranks)):
        y = k - i - 0.5
        ax.plot(rank, y, "ko", markersize=8)
        ax.annotate(f"{name} ({rank:.2f})", (rank, y),
                    xytext=(10 if rank < (k + 1) / 2 else -10, 0),
                    textcoords="offset points",
                    ha="left" if rank < (k + 1) / 2 else "right",
                    va="center", fontsize=10)

    # Связи (модели с разницей < CD)
    for i in range(len(ranks)):
        for j in range(i + 1, len(ranks)):
            if abs(ranks[i] - ranks[j]) < cd:
                y_i = k - i - 0.5
                y_j = k - j - 0.5
                ax.plot([ranks[i], ranks[j]], [y_i, y_j], "b-", alpha=0.3, linewidth=2)

    ax.set_xlabel("Средний ранг (меньше = лучше)", fontsize=12)
    ax.set_title(f"Critical Difference Diagram (Friedman χ²={friedman_result['chi2']:.2f}, "
                 f"p={friedman_result['p_value']:.4f})", fontsize=13)
    ax.set_yticks([])
    ax.grid(axis="x", alpha=0.3)
    plt.tight_layout()
    plt.savefig(output, dpi=150)
    plt.close()
    print(f"  Сохранён: {output}")


# ─────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Statistical Analysis of CTI Benchmark")
    parser.add_argument("--input", default="benchmark_full_9models.csv",
                        help="Input CSV with benchmark results")
    parser.add_argument("--metric", default="F1_overall",
                        help="Metric column to analyze")
    args = parser.parse_args()

    if not Path(args.input).exists():
        print(f"Файл {args.input} не найден!")
        return

    df = pd.read_csv(args.input)
    models = sorted(df["Model"].unique())

    print("=" * 70)
    print("СТАТИСТИЧЕСКИЙ АНАЛИЗ БЕНЧМАРКА")
    print(f"Метрика: {args.metric}")
    print(f"Моделей: {len(models)}, Датасетов: {df['Dataset'].nunique()}")
    print("=" * 70)

    # 1. Bootstrap CI
    print("\n1. Bootstrap 95% CI (BCa, B=10000)")
    print("-" * 50)
    ci_results = {}
    for model in models:
        scores = df[df["Model"] == model][args.metric].values
        ci = bootstrap_ci(scores)
        ci_results[model] = ci
        short = model.split("/")[-1][:20]
        print(f"  {short:20s}  F1={ci['mean']:.3f} ± {ci['std']:.3f}  "
              f"CI=[{ci['ci_lower']:.3f}, {ci['ci_upper']:.3f}]  (n={ci['n']})")

    plot_ci_chart(ci_results)

    # 2. Wilcoxon pairwise
    print(f"\n2. Wilcoxon signed-rank (pairwise)")
    print("-" * 50)
    p_matrix, alpha_adj = pairwise_wilcoxon(df, models, args.metric)
    significant = (p_matrix < alpha_adj).sum().sum() // 2  # Each pair counted twice
    print(f"  Bonferroni α_adj = {alpha_adj:.5f}")
    print(f"  Значимых пар (после коррекции): {significant}/{len(models) * (len(models)-1) // 2}")

    plot_pvalue_heatmap(p_matrix, alpha_adj)

    # 3. Friedman test
    print(f"\n3. Friedman χ² + Nemenyi")
    print("-" * 50)
    friedman = friedman_test(df, models, args.metric)
    print(f"  Friedman χ² = {friedman['chi2']:.3f}, p = {friedman['p_value']:.5f}")
    print(f"  Critical Difference (CD) = {friedman['critical_difference']:.3f}")
    print(f"  k={friedman['k']} моделей, N={friedman['N']} датасетов")
    print("\n  Средние ранги:")
    for m, r in sorted(friedman["avg_ranks"].items(), key=lambda x: x[1]):
        short = m.split("/")[-1][:20]
        print(f"    {short:20s}  rank={r:.2f}")

    plot_critical_difference(friedman)

    # 4. Cohen's d
    print(f"\n4. Cohen's d (эффект размера) — лучшая модель vs остальные")
    print("-" * 50)
    best_model = min(friedman["avg_ranks"], key=friedman["avg_ranks"].get)
    best_scores = df[df["Model"] == best_model][args.metric].values
    short_best = best_model.split("/")[-1][:20]
    for model in models:
        if model == best_model:
            continue
        other_scores = df[df["Model"] == model][args.metric].values
        d = cohens_d(best_scores, other_scores)
        interp = "большой" if abs(d) > 0.8 else "средний" if abs(d) > 0.5 else "малый"
        short = model.split("/")[-1][:20]
        print(f"  {short_best} vs {short:20s}  d={d:+.3f} ({interp})")

    # Сохраняем результаты
    output = {
        "bootstrap_ci": ci_results,
        "friedman": friedman,
        "bonferroni_alpha": alpha_adj,
        "metric": args.metric,
    }
    out_file = "charts/statistical_analysis.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\nРезультаты сохранены в {out_file}")

    # LaTeX-таблица
    print("\n\nLaTeX-таблица для ВКР:")
    print("-" * 50)
    print("\\begin{tabular}{lcccc}")
    print("\\hline")
    print("Model & F1 & CI lower & CI upper & Rank \\\\")
    print("\\hline")
    for m, r in sorted(friedman["avg_ranks"].items(), key=lambda x: x[1]):
        ci = ci_results[m]
        short = m.split("/")[-1].replace("_", "\\_")[:20]
        print(f"{short} & {ci['mean']:.3f} & {ci['ci_lower']:.3f} & {ci['ci_upper']:.3f} & {r:.1f} \\\\")
    print("\\hline")
    print("\\end{tabular}")


if __name__ == "__main__":
    main()
