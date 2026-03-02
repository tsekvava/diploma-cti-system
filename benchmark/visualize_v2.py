import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

def add_labels(ax):
    """Подписывает значения над столбцами."""
    for p in ax.patches:
        if p.get_height() > 0:
            ax.annotate(f'{p.get_height():.2f}', 
                        (p.get_x() + p.get_width() / 2., p.get_height()), 
                        ha='center', va='center', xytext=(0, 9), 
                        textcoords='offset points', fontsize=10, fontweight='bold')

def main():
    if not os.path.exists("final_benchmark.csv"):
        print("Сначала запусти benchmark_judge.py!")
        return

    df = pd.read_csv("final_benchmark_v2.csv")
    
    sns.set_theme(style="whitegrid")
    plt.rcParams.update({'figure.max_open_warning': 0})

    fig, axes = plt.subplots(2, 2, figsize=(18, 12))
    plt.subplots_adjust(hspace=0.4, wspace=0.3)

    df_melted = df.melt(id_vars=["Method", "File"], value_vars=["Precision", "Recall", "F1"], 
                        var_name="Metric", value_name="Score")
    
    sns.barplot(data=df_melted, x="Method", y="Score", hue="Metric", ax=axes[0, 0], palette="viridis")
    axes[0, 0].set_title("Детальный разбор: Точность vs Полнота", fontsize=14, fontweight='bold')
    axes[0, 0].set_ylim(0, 1.1)
    
    avg_time = df.groupby("Method")["Time"].mean().reset_index()
    sns.barplot(data=avg_time, x="Method", y="Time", ax=axes[0, 1], palette="magma")
    add_labels(axes[0, 1])
    axes[0, 1].set_title("Среднее время обработки (секунды)", fontsize=14, fontweight='bold')
    axes[0, 1].set_ylabel("Секунды (меньше = лучше)")

    avg_f1 = df.groupby("Method")["F1"].mean().reset_index()
    sns.barplot(data=avg_f1, x="Method", y="F1", ax=axes[1, 0], palette="rocket")
    add_labels(axes[1, 0])
    axes[1, 0].set_title("Среднее качество (F1 Score)", fontsize=14, fontweight='bold')
    axes[1, 0].set_ylabel("F1 Score (выше = лучше)")
    axes[1, 0].set_ylim(0, 1.0)

    avg_recall = df.groupby("Method")["Recall"].mean().reset_index()
    sns.barplot(data=avg_recall, x="Method", y="Recall", ax=axes[1, 1], palette="mako")
    add_labels(axes[1, 1])
    axes[1, 1].set_title("Средняя Полнота (Recall) - % найденных данных", fontsize=14, fontweight='bold')
    axes[1, 1].set_ylabel("Recall")

    output_file = "benchmark_chart_v2.png"
    plt.savefig(output_file, dpi=300)
    print(f"Графики сохранены в {output_file} 🖼️")
    plt.show()

if __name__ == "__main__":
    main()
