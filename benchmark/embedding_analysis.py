"""
Анализ embedding-пространства CTI-отчётов.

Методы:
  1. Cosine similarity matrix между отчётами (9×9)
  2. PCA → 2D проекция с explained variance
  3. t-SNE → 2D проекция
  4. K-means кластеризация + silhouette score
  5. Корреляция similarity ↔ F1 performance

Использование:
    cd benchmark
    python3 embedding_analysis.py
    python3 embedding_analysis.py --benchmark benchmark_full_9models.csv
"""

import json
import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

CHARTS_DIR = Path("charts")
CHARTS_DIR.mkdir(exist_ok=True)

DATA_DIR = Path("data")


#  1. Кодирование отчётов

def encode_reports(report_paths: list) -> tuple:
    """Кодирует CTI-отчёты через sentence-transformers."""
    from sentence_transformers import SentenceTransformer

    print("  Загрузка модели all-MiniLM-L6-v2...")
    model = SentenceTransformer("all-MiniLM-L6-v2")

    texts = []
    names = []
    for path in report_paths:
        text = path.read_text(encoding="utf-8")
        # Ограничиваем длину для эмбеддинга (первые 5000 символов)
        texts.append(text[:5000])
        names.append(path.stem)

    print(f"  Кодирование {len(texts)} отчётов...")
    embeddings = model.encode(texts, show_progress_bar=False)

    return np.array(embeddings), names, [len(t) for t in texts]


#  2. Cosine similarity

def cosine_similarity_matrix(embeddings: np.ndarray) -> np.ndarray:
    """Матрица cosine similarity."""
    norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
    normalized = embeddings / norms
    return normalized @ normalized.T


#  3. PCA

def pca_analysis(embeddings: np.ndarray, names: list) -> dict:
    """PCA анализ с explained variance."""
    from sklearn.decomposition import PCA

    pca = PCA(n_components=min(len(embeddings), embeddings.shape[1]))
    transformed = pca.fit_transform(embeddings)

    return {
        "coords_2d": transformed[:, :2],
        "explained_variance": pca.explained_variance_ratio_.tolist(),
        "cumulative_variance": np.cumsum(pca.explained_variance_ratio_).tolist(),
        "n_components_95": int(np.argmax(np.cumsum(pca.explained_variance_ratio_) >= 0.95)) + 1,
    }


#  4. t-SNE

def tsne_analysis(embeddings: np.ndarray, perplexity: float = 5.0) -> np.ndarray:
    """t-SNE 2D проекция."""
    from sklearn.manifold import TSNE

    # Perplexity must be < n_samples
    perp = min(perplexity, len(embeddings) - 1)
    tsne = TSNE(n_components=2, perplexity=perp, random_state=42, max_iter=1000)
    return tsne.fit_transform(embeddings)


#  5. Кластерный анализ

def cluster_analysis(embeddings: np.ndarray) -> dict:
    """K-means + silhouette score для k=2,3,4."""
    from sklearn.cluster import KMeans
    from sklearn.metrics import silhouette_score, davies_bouldin_score

    results = {}
    n_samples = len(embeddings)

    for k in range(2, min(5, n_samples)):
        kmeans = KMeans(n_clusters=k, random_state=42, n_init=10)
        labels = kmeans.fit_predict(embeddings)
        sil = silhouette_score(embeddings, labels)
        db = davies_bouldin_score(embeddings, labels)
        results[k] = {"silhouette": float(sil), "davies_bouldin": float(db),
                       "labels": labels.tolist()}

    best_k = max(results, key=lambda k: results[k]["silhouette"])
    return results, best_k


#  6. Корреляция similarity ↔ performance

def similarity_performance_correlation(sim_matrix: np.ndarray, names: list,
                                        benchmark_df: pd.DataFrame) -> dict:
    """Корреляция между средним cosine similarity и F1."""
    from scipy.stats import pearsonr, spearmanr

    n = len(names)
    avg_sim = []
    avg_f1 = []

    for i, name in enumerate(names):
        # Средняя similarity к остальным отчётам
        sims = [sim_matrix[i, j] for j in range(n) if j != i]
        avg_sim.append(np.mean(sims))

        # Средний F1 по всем моделям на этом датасете
        ds_data = benchmark_df[benchmark_df["Dataset"] == name]
        if len(ds_data) > 0:
            avg_f1.append(ds_data["F1_overall"].mean())
        else:
            avg_f1.append(0.0)

    avg_sim = np.array(avg_sim)
    avg_f1 = np.array(avg_f1)

    # Фильтруем датасеты без бенчмарк-данных
    mask = avg_f1 > 0
    if mask.sum() < 3:
        return {"pearson_r": 0, "pearson_p": 1, "spearman_r": 0, "spearman_p": 1,
                "avg_sim": avg_sim.tolist(), "avg_f1": avg_f1.tolist(), "names": names}

    r_pearson, p_pearson = pearsonr(avg_sim[mask], avg_f1[mask])
    r_spearman, p_spearman = spearmanr(avg_sim[mask], avg_f1[mask])

    return {
        "pearson_r": float(r_pearson), "pearson_p": float(p_pearson),
        "spearman_r": float(r_spearman), "spearman_p": float(p_spearman),
        "avg_sim": avg_sim.tolist(), "avg_f1": avg_f1.tolist(), "names": names,
    }


#  Визуализации

def plot_similarity_heatmap(sim_matrix: np.ndarray, names: list,
                             output: str = "charts/cosine_similarity.png"):
    """Heatmap cosine similarity."""
    fig, ax = plt.subplots(figsize=(8, 7))
    im = ax.imshow(sim_matrix, cmap="RdYlBu_r", vmin=0, vmax=1, aspect="auto")

    ax.set_xticks(range(len(names)))
    ax.set_xticklabels(names, rotation=45, ha="right", fontsize=9)
    ax.set_yticks(range(len(names)))
    ax.set_yticklabels(names, fontsize=9)

    for i in range(len(names)):
        for j in range(len(names)):
            ax.text(j, i, f"{sim_matrix[i, j]:.2f}",
                    ha="center", va="center", fontsize=8,
                    color="white" if sim_matrix[i, j] > 0.7 else "black")

    ax.set_title("Cosine Similarity между CTI-отчётами\n(all-MiniLM-L6-v2, 384-dim)", fontsize=12)
    plt.colorbar(im, ax=ax, label="Cosine Similarity", shrink=0.8)
    plt.tight_layout()
    plt.savefig(output, dpi=150)
    plt.close()
    print(f"  Сохранён: {output}")


def plot_pca_biplot(pca_result: dict, names: list, f1_scores: list = None,
                     output: str = "charts/pca_biplot.png"):
    """PCA 2D biplot с explained variance."""
    coords = pca_result["coords_2d"]
    ev = pca_result["explained_variance"]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

    # Biplot
    if f1_scores:
        colors = plt.cm.RdYlGn(np.array(f1_scores) / max(f1_scores) if max(f1_scores) > 0 else [0.5] * len(f1_scores))
    else:
        colors = ["steelblue"] * len(names)

    for i, (x, y) in enumerate(coords):
        ax1.scatter(x, y, c=[colors[i]], s=100, edgecolors="black", zorder=5)
        ax1.annotate(names[i], (x, y), xytext=(5, 5), textcoords="offset points", fontsize=9)

    ax1.set_xlabel(f"PC1 ({ev[0]*100:.1f}% variance)", fontsize=11)
    ax1.set_ylabel(f"PC2 ({ev[1]*100:.1f}% variance)", fontsize=11)
    ax1.set_title("PCA 2D проекция CTI-отчётов", fontsize=13)
    ax1.grid(alpha=0.3)
    ax1.axhline(0, color="gray", linestyle="--", alpha=0.3)
    ax1.axvline(0, color="gray", linestyle="--", alpha=0.3)

    # Scree plot
    n_show = min(len(ev), 10)
    cum = pca_result["cumulative_variance"][:n_show]
    ax2.bar(range(1, n_show + 1), ev[:n_show], color="steelblue", alpha=0.7, label="Individual")
    ax2.plot(range(1, n_show + 1), cum, "ro-", label="Cumulative")
    ax2.axhline(0.95, color="red", linestyle="--", alpha=0.5, label="95% threshold")
    ax2.set_xlabel("Principal Component", fontsize=11)
    ax2.set_ylabel("Explained Variance Ratio", fontsize=11)
    ax2.set_title("Scree Plot (PCA)", fontsize=13)
    ax2.legend(fontsize=9)
    ax2.set_xticks(range(1, n_show + 1))

    plt.tight_layout()
    plt.savefig(output, dpi=150)
    plt.close()
    print(f"  Сохранён: {output}")


def plot_tsne(tsne_coords: np.ndarray, names: list, cluster_labels: list = None,
              output: str = "charts/tsne_clusters.png"):
    """t-SNE visualization with cluster coloring."""
    fig, ax = plt.subplots(figsize=(8, 6))

    if cluster_labels:
        colors = plt.cm.Set2(np.array(cluster_labels) / max(cluster_labels) if max(cluster_labels) > 0 else [0] * len(cluster_labels))
    else:
        colors = ["steelblue"] * len(names)

    for i, (x, y) in enumerate(tsne_coords):
        ax.scatter(x, y, c=[colors[i]], s=120, edgecolors="black", zorder=5)
        ax.annotate(names[i], (x, y), xytext=(5, 5), textcoords="offset points", fontsize=9)

    ax.set_title("t-SNE проекция CTI-отчётов", fontsize=13)
    ax.set_xlabel("t-SNE dim 1", fontsize=11)
    ax.set_ylabel("t-SNE dim 2", fontsize=11)
    ax.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(output, dpi=150)
    plt.close()
    print(f"  Сохранён: {output}")


def plot_sim_vs_f1(corr_result: dict, output: str = "charts/similarity_vs_f1.png"):
    """Scatter: average similarity vs F1."""
    names = corr_result["names"]
    avg_sim = np.array(corr_result["avg_sim"])
    avg_f1 = np.array(corr_result["avg_f1"])

    mask = avg_f1 > 0

    fig, ax = plt.subplots(figsize=(8, 6))
    ax.scatter(avg_sim[mask], avg_f1[mask], s=100, c="steelblue", edgecolors="black", zorder=5)

    for i in range(len(names)):
        if mask[i]:
            ax.annotate(names[i], (avg_sim[i], avg_f1[i]),
                        xytext=(5, 5), textcoords="offset points", fontsize=9)

    # Regression line
    if mask.sum() >= 3:
        z = np.polyfit(avg_sim[mask], avg_f1[mask], 1)
        p = np.poly1d(z)
        x_line = np.linspace(avg_sim[mask].min(), avg_sim[mask].max(), 50)
        ax.plot(x_line, p(x_line), "r--", alpha=0.7,
                label=f"R²={corr_result['pearson_r']**2:.3f}")

    ax.set_xlabel("Средняя cosine similarity к другим отчётам", fontsize=11)
    ax.set_ylabel("Средний F1 по всем моделям", fontsize=11)
    ax.set_title(f"Similarity vs Performance\n"
                 f"Pearson r={corr_result['pearson_r']:.3f} (p={corr_result['pearson_p']:.3f}), "
                 f"Spearman ρ={corr_result['spearman_r']:.3f}", fontsize=12)
    ax.legend()
    ax.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(output, dpi=150)
    plt.close()
    print(f"  Сохранён: {output}")



def main():
    parser = argparse.ArgumentParser(description="Embedding Space Analysis")
    parser.add_argument("--benchmark", default="benchmark_full_9models.csv",
                        help="Benchmark CSV for F1 correlation")
    args = parser.parse_args()

    # Находим все текстовые отчёты
    report_paths = sorted(DATA_DIR.glob("*.txt"))
    if not report_paths:
        print("Нет текстовых отчётов в data/!")
        return

    print("=" * 70)
    print("АНАЛИЗ EMBEDDING-ПРОСТРАНСТВА CTI-ОТЧЁТОВ")
    print(f"Отчётов: {len(report_paths)}")
    print("=" * 70)

    # 1. Кодирование
    print("\n1. Кодирование отчётов...")
    embeddings, names, lengths = encode_reports(report_paths)
    print(f"   Размерность: {embeddings.shape}")
    for n, l in zip(names, lengths):
        print(f"     {n:25s}  {l:6d} символов")

    # 2. Cosine similarity
    print("\n2. Cosine similarity matrix...")
    sim_matrix = cosine_similarity_matrix(embeddings)
    avg_sim = sim_matrix[np.triu_indices_from(sim_matrix, k=1)].mean()
    print(f"   Средняя попарная similarity: {avg_sim:.3f}")
    plot_similarity_heatmap(sim_matrix, names)

    # 3. PCA
    print("\n3. PCA анализ...")
    pca_result = pca_analysis(embeddings, names)
    print(f"   Explained variance (PC1): {pca_result['explained_variance'][0]*100:.1f}%")
    print(f"   Explained variance (PC2): {pca_result['explained_variance'][1]*100:.1f}%")
    print(f"   Компонент для 95% variance: {pca_result['n_components_95']}")

    # Получаем F1 для раскраски
    f1_scores = [0.0] * len(names)
    if Path(args.benchmark).exists():
        bench_df = pd.read_csv(args.benchmark)
        for i, name in enumerate(names):
            ds_data = bench_df[bench_df["Dataset"] == name]
            if len(ds_data) > 0:
                f1_scores[i] = ds_data["F1_overall"].mean()

    plot_pca_biplot(pca_result, names, f1_scores)

    # 4. t-SNE
    print("\n4. t-SNE проекция...")
    tsne_coords = tsne_analysis(embeddings)

    # 5. Кластерный анализ
    print("\n5. Кластерный анализ...")
    cluster_results, best_k = cluster_analysis(embeddings)
    for k, res in cluster_results.items():
        marker = " ← best" if k == best_k else ""
        print(f"   k={k}: silhouette={res['silhouette']:.3f}, "
              f"davies_bouldin={res['davies_bouldin']:.3f}{marker}")

    best_labels = cluster_results[best_k]["labels"]
    plot_tsne(tsne_coords, names, best_labels)

    # 6. Корреляция similarity ↔ F1
    print("\n6. Корреляция similarity ↔ F1...")
    if Path(args.benchmark).exists():
        bench_df = pd.read_csv(args.benchmark)
        corr = similarity_performance_correlation(sim_matrix, names, bench_df)
        print(f"   Pearson r={corr['pearson_r']:.3f}, p={corr['pearson_p']:.3f}")
        print(f"   Spearman ρ={corr['spearman_r']:.3f}, p={corr['spearman_p']:.3f}")
        if abs(corr["pearson_r"]) > 0.5:
            print("   → Значимая корреляция: похожие отчёты → предсказуемая F1")
        else:
            print("   → Слабая корреляция: similarity не предсказывает качество")
        plot_sim_vs_f1(corr)
    else:
        print(f"   Пропуск: файл {args.benchmark} не найден")

    # Сохраняем результаты
    output = {
        "n_reports": len(names),
        "report_names": names,
        "embedding_dim": int(embeddings.shape[1]),
        "avg_pairwise_similarity": float(avg_sim),
        "pca_explained_variance": pca_result["explained_variance"][:5],
        "pca_n_components_95": pca_result["n_components_95"],
        "cluster_analysis": {str(k): {"silhouette": v["silhouette"], "davies_bouldin": v["davies_bouldin"]}
                             for k, v in cluster_results.items()},
        "best_k": best_k,
    }
    out_file = "charts/embedding_analysis.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\nРезультаты сохранены в {out_file}")


if __name__ == "__main__":
    main()
