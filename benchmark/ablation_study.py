"""
Ablation Study — вклад каждого компонента CTI-пайплайна.

Тестирует 5 конфигураций на одной модели:
  1. FULL — полный пайплайн
  2. -NORM — без EntityNormalizer
  3. -KC — без AttackMapper (Kill Chain)
  4. -CONF — без Confidence Scoring
  5. -CHUNK — без chunking (весь текст одним куском)

Использование:
    cd benchmark
    python3 ablation_study.py --model gemma2:9b
"""

import json
import time
import argparse
from pathlib import Path
from datetime import datetime

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from scipy import stats

from benchmark_multi_model import calculate_metrics_detailed, TASKS

CHARTS_DIR = Path("charts")
CHARTS_DIR.mkdir(exist_ok=True)


#  Конфигурации ablation

ABLATION_CONFIGS = {
    "FULL": {"skip_normalize": False, "skip_kill_chain": False,
             "skip_confidence": False, "no_chunk": False},
    "-NORM": {"skip_normalize": True, "skip_kill_chain": False,
              "skip_confidence": False, "no_chunk": False},
    "-KC": {"skip_normalize": False, "skip_kill_chain": True,
            "skip_confidence": False, "no_chunk": False},
    "-CONF": {"skip_normalize": False, "skip_kill_chain": False,
              "skip_confidence": True, "no_chunk": False},
    "-CHUNK": {"skip_normalize": False, "skip_kill_chain": False,
               "skip_confidence": False, "no_chunk": True},
}


def run_ablation(model_name: str) -> pd.DataFrame:
    """Прогоняет все конфигурации ablation."""
    from models.run_full_pipeline import extract_full_pipeline

    results = []

    for config_name, config in ABLATION_CONFIGS.items():
        print(f"\n{'─' * 50}")
        print(f"CONFIG: {config_name}")
        print(f"  skip_normalize={config['skip_normalize']}, "
              f"skip_kill_chain={config['skip_kill_chain']}, "
              f"skip_confidence={config['skip_confidence']}, "
              f"no_chunk={config['no_chunk']}")
        print(f"{'─' * 50}")

        for task in TASKS:
            dataset_name = Path(task["text"]).stem
            if not Path(task["text"]).exists():
                print(f"  {dataset_name}: SKIP")
                continue

            print(f"  {dataset_name}...", end=" ", flush=True)

            with open(task["text"], "r", encoding="utf-8") as f:
                text = f.read()
            with open(task["truth"], "r", encoding="utf-8") as f:
                truth = json.load(f)

            try:
                start = time.time()
                result = extract_full_pipeline(
                    text, model_name=model_name,
                    skip_normalize=config["skip_normalize"],
                    skip_kill_chain=config["skip_kill_chain"],
                    skip_confidence=config["skip_confidence"],
                    no_chunk=config["no_chunk"],
                )
                duration = time.time() - start

                metrics = calculate_metrics_detailed(result, truth)
                strict = metrics["strict"]

                row = {
                    "Config": config_name,
                    "Dataset": dataset_name,
                    "Time_sec": round(duration, 1),
                    "F1_overall": strict["overall"]["f1"],
                    "F1_actors": strict["actors"]["f1"],
                    "F1_malware": strict["malware"]["f1"],
                    "F1_tools": strict["tools"]["f1"],
                    "F1_ioc": strict["ioc"]["f1"],
                    "F1_attack_patterns": strict["attack_patterns"]["f1"],
                }
                results.append(row)
                print(f"F1={strict['overall']['f1']:.3f} ({duration:.0f}s)")

            except Exception as e:
                print(f"ERROR: {e}")
                results.append({
                    "Config": config_name, "Dataset": dataset_name,
                    "Time_sec": 0,
                    "F1_overall": 0, "F1_actors": 0, "F1_malware": 0,
                    "F1_tools": 0, "F1_ioc": 0, "F1_attack_patterns": 0,
                })

    return pd.DataFrame(results)


def analyze_ablation(df: pd.DataFrame) -> dict:
    """Анализ результатов ablation: marginal contribution + значимость."""
    configs = list(ABLATION_CONFIGS.keys())
    full_scores = df[df["Config"] == "FULL"]["F1_overall"].values

    analysis = {}
    for config in configs:
        if config == "FULL":
            continue
        ablated_scores = df[df["Config"] == config]["F1_overall"].values

        if len(full_scores) != len(ablated_scores) or len(full_scores) < 3:
            continue

        delta_f1 = full_scores.mean() - ablated_scores.mean()

        # Wilcoxon test
        try:
            _, p = stats.wilcoxon(full_scores, ablated_scores)
        except ValueError:
            p = 1.0

        component = config.replace("-", "")
        analysis[component] = {
            "delta_f1": float(delta_f1),
            "full_mean": float(full_scores.mean()),
            "ablated_mean": float(ablated_scores.mean()),
            "p_value": float(p),
            "significant": p < 0.05,
        }

    return analysis


#  Визуализации

def plot_ablation_bar(analysis: dict, output: str = "charts/ablation_bar.png"):
    """Bar chart: marginal contribution каждого компонента."""
    components = list(analysis.keys())
    deltas = [analysis[c]["delta_f1"] for c in components]
    significant = [analysis[c]["significant"] for c in components]

    colors = ["forestgreen" if s else "lightgray" for s in significant]
    labels = {
        "NORM": "Normalizer\n(3-level)",
        "KC": "Kill Chain\n(2-stage)",
        "CONF": "Confidence\nScoring",
        "CHUNK": "Text\nChunking",
    }

    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(range(len(components)), deltas, color=colors, edgecolor="black", alpha=0.8)

    ax.set_xticks(range(len(components)))
    ax.set_xticklabels([labels.get(c, c) for c in components], fontsize=11)
    ax.set_ylabel("ΔF1 (FULL − ablated)", fontsize=12)
    ax.set_title("Ablation Study: Marginal Contribution of Pipeline Components\n"
                 "Green = statistically significant (p < 0.05)", fontsize=13)
    ax.axhline(0, color="black", linewidth=0.5)
    ax.grid(axis="y", alpha=0.3)

    # Аннотации
    for bar, delta, comp in zip(bars, deltas, components):
        p = analysis[comp]["p_value"]
        marker = "***" if p < 0.001 else "**" if p < 0.01 else "*" if p < 0.05 else "ns"
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.003,
                f"{delta:+.3f}\n({marker})",
                ha="center", va="bottom", fontsize=10)

    plt.tight_layout()
    plt.savefig(output, dpi=150)
    plt.close()
    print(f"  Сохранён: {output}")


def plot_ablation_table(df: pd.DataFrame, output: str = "charts/ablation_table.png"):
    """Таблица: Config × Category F1."""
    summary = df.groupby("Config").agg({
        "F1_overall": "mean", "F1_actors": "mean", "F1_malware": "mean",
        "F1_tools": "mean", "F1_ioc": "mean", "F1_attack_patterns": "mean",
        "Time_sec": "mean",
    }).round(3)

    # Reorder to have FULL first
    configs_order = ["FULL", "-NORM", "-KC", "-CONF", "-CHUNK"]
    summary = summary.reindex([c for c in configs_order if c in summary.index])

    fig, ax = plt.subplots(figsize=(12, 4))
    ax.axis("off")

    table = ax.table(
        cellText=summary.values,
        colLabels=["F1 Overall", "F1 Actors", "F1 Malware", "F1 Tools",
                    "F1 IoC", "F1 Attack", "Time (s)"],
        rowLabels=summary.index,
        cellLoc="center",
        loc="center",
    )
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1, 1.5)

    # Color the FULL row
    for j in range(len(summary.columns)):
        table[1, j].set_facecolor("#e6f3e6")

    ax.set_title("Ablation Study Results", fontsize=14, pad=20)
    plt.tight_layout()
    plt.savefig(output, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Сохранён: {output}")



def main():
    parser = argparse.ArgumentParser(description="Ablation Study")
    parser.add_argument("--model", default="gemma2:9b", help="Model to use")
    parser.add_argument("--input", default=None,
                        help="Load existing results instead of running")
    parser.add_argument("--output", default="ablation_results.csv")
    args = parser.parse_args()

    print("=" * 70)
    print("ABLATION STUDY")
    print(f"Дата: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"Модель: {args.model}")
    print(f"Конфигураций: {len(ABLATION_CONFIGS)}")
    print(f"Датасетов: {len(TASKS)}")
    print("=" * 70)

    if args.input and Path(args.input).exists():
        print(f"\nЗагрузка из {args.input}...")
        df = pd.read_csv(args.input)
    else:
        df = run_ablation(args.model)
        df.to_csv(args.output, index=False)
        print(f"\nРезультаты сохранены в {args.output}")

    # Сводка
    print("\n\n" + "=" * 70)
    print("РЕЗУЛЬТАТЫ")
    print("=" * 70)

    summary = df.groupby("Config").agg({
        "F1_overall": ["mean", "std"],
        "Time_sec": "mean",
    }).round(3)
    print(summary.to_string())

    # Анализ
    print("\n\nANALYSIS: Marginal Contribution")
    print("-" * 50)
    analysis = analyze_ablation(df)
    for comp, a in analysis.items():
        sig = "***" if a["p_value"] < 0.001 else "**" if a["p_value"] < 0.01 else "*" if a["p_value"] < 0.05 else "ns"
        print(f"  {comp:6s}  ΔF1={a['delta_f1']:+.4f}  "
              f"(FULL={a['full_mean']:.3f} → {a['ablated_mean']:.3f})  "
              f"p={a['p_value']:.4f} {sig}")

    # Графики
    print("\nГенерация графиков...")
    plot_ablation_bar(analysis)
    plot_ablation_table(df)

    # Сохраняем анализ
    out_file = "charts/ablation_analysis.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(analysis, f, indent=2, ensure_ascii=False, default=str)
    print(f"Анализ сохранён в {out_file}")

    # LaTeX
    print("\n\nLaTeX-таблица:")
    print("\\begin{tabular}{lccccc}")
    print("\\hline")
    print("Config & F1 Overall & ΔF1 & p-value & Significant \\\\")
    print("\\hline")
    full_f1 = df[df["Config"] == "FULL"]["F1_overall"].mean()
    print(f"FULL & {full_f1:.3f} & --- & --- & --- \\\\")
    for comp, a in sorted(analysis.items(), key=lambda x: -abs(x[1]["delta_f1"])):
        sig = "Yes" if a["significant"] else "No"
        print(f"$-${comp} & {a['ablated_mean']:.3f} & {a['delta_f1']:+.3f} & {a['p_value']:.4f} & {sig} \\\\")
    print("\\hline")
    print("\\end{tabular}")


if __name__ == "__main__":
    main()
