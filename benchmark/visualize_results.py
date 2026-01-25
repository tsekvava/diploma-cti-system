import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

def main():
    if not os.path.exists("final_benchmark.csv"):
        print("Сначала запусти benchmark_judge.py!")
        return

    df = pd.read_csv("final_benchmark.csv")

    sns.set_theme(style="whitegrid")
    
    fig, axes = plt.subplots(1, 2, figsize=(15, 6))

    sns.barplot(data=df, x="File", y="F1", hue="Method", ax=axes[0], palette="viridis")
    axes[0].set_title("Сравнение Точности (F1-Score)", fontsize=14, fontweight='bold')
    axes[0].set_ylabel("F1 Score (чем выше, тем лучше)")
    axes[0].set_xlabel("Статья")
    axes[0].legend(title="Метод")

    sns.barplot(data=df, x="File", y="Time", hue="Method", ax=axes[1], palette="magma")
    axes[1].set_title("Сравнение Скорости (сек)", fontsize=14, fontweight='bold')
    axes[1].set_ylabel("Время (сек) - логарифмическая шкала")
    axes[1].set_yscale("log")
    axes[1].set_xlabel("Статья")
    axes[1].legend(title="Метод")

    plt.tight_layout()
    plt.savefig("benchmark_chart.png", dpi=300)
    print("График сохранен как benchmark_chart.png 🖼️")
    plt.show()

if __name__ == "__main__":
    main()