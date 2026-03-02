"""
Multi-Model Benchmark — бенчмарк 5-10 LLM-моделей для CTI-экстракции.

Сравнивает модели по:
  - F1 (общий и по категориям: actors, malware, tools, IoC)
  - Precision, Recall
  - Время обработки
  - Количество галлюцинаций (несуществующие MITRE ID)

Тестирует:
  1. LLM-модели через Ollama (гибридный подход: regex + LLM)
  2. Базовые модели для сравнения: SecureBERT, GLiNER

Использование:
    cd benchmark
    python3 benchmark_multi_model.py
    python3 benchmark_multi_model.py --models qwen2.5:14b,llama3.1:8b
    python3 benchmark_multi_model.py --skip-baselines
"""

import json
import time
import re
import sys
import os
import argparse
from datetime import datetime
from pathlib import Path

# Добавляем корень проекта в PATH для импорта knowledge_base
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd

# --- Конфигурация ---

# Модели для тестирования через Ollama
# Коллеги тестировали: glm4, Qwen2.5-14B-CyberSecurity, ALIENTELLIGENCE
# Мы добавляем: qwen2.5:14b, qwen2.5:7b, llama3.1:8b, mistral:7b, gemma2:9b, phi3:14b
DEFAULT_LLM_MODELS = [
    "qwen2.5:14b",
    "qwen2.5:7b",
    "llama3.1:8b",
    "mistral:7b",
    "gemma2:9b",
    "glm4:9b",
    "deepseek-v2:16b",
    "alientelligence/cybersecuritythreatanalysisv2",
    "qingmian/qwen2.5-14b-cybersecurity",
]

TASKS = [
    {"text": "data/gold_salem.txt", "truth": "data/ground_truth_gold_salem.json"},
    {"text": "data/frost_beacon.txt", "truth": "data/ground_truth_frost_beacon.json"},
    {"text": "data/cve.txt", "truth": "data/ground_truth_cve.json"},
]


# --- Метрики ---

def normalize_entity(text: str) -> str:
    """Нормализация для сравнения: lower, убираем MITRE ID и спецсимволы."""
    text = str(text).lower().strip()
    text = re.sub(r"[\(\[]?t\d{4}(\.\d{3})?[\)\]]?", "", text)
    text = re.sub(r"[\(\[]?cve-\d{4}-\d+[\)\]]?", "", text)
    text = text.strip().strip(".,-:()")
    text = re.sub(r"\s+", " ", text).strip()
    return text


def calculate_f1_set(pred_set: set, truth_set: set) -> tuple:
    """Считает P/R/F1 для двух множеств."""
    if not truth_set:
        return (0.0, 0.0, 0.0)

    tp = len(pred_set & truth_set)
    fp = len(pred_set - truth_set)
    fn = len(truth_set - pred_set)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    return (round(precision, 4), round(recall, 4), round(f1, 4))


def get_entity_set(data: dict, keys: list) -> set:
    """Извлекает нормализованное множество сущностей из указанных ключей."""
    s = set()
    for key in keys:
        for item in data.get(key, []):
            norm = normalize_entity(item)
            if len(norm) > 2:
                s.add(norm)
    return s


def get_ioc_set(data: dict) -> set:
    """Извлекает множество IoC (IP, домены, хеши)."""
    s = set()
    indicators = data.get("indicators", {})
    for k, v in indicators.items():
        for item in v:
            s.add(str(item).lower().strip())
    return s


def _extract_mitre_ids(items: list) -> set:
    """Извлекает MITRE ATT&CK ID из списка attack_patterns.

    Обрабатывает:
      - "T1566.001"  (чистый ID из regex)
      - "Spearphishing Attachment (T1566.001)"  (ID в скобках)
      - "Command & Scripting Interpreter: PowerShell (T1059.003)"
    """
    ids = set()
    for item in items:
        found = re.findall(r"T\d{4}(?:\.\d{3})?", str(item))
        ids.update(f.lower() for f in found)
    return ids


def get_attack_pattern_set(data: dict) -> set:
    """Извлекает множество attack_patterns двумя способами:
    1. MITRE ID (T1566.001 → t1566.001) — для regex-extracted и ground truth
    2. Нормализованные имена (для текстовых описаний без ID)
    """
    items = data.get("attack_patterns", [])
    s = set()

    # Способ 1: извлекаем MITRE ID
    s.update(_extract_mitre_ids(items))

    # Способ 2: нормализованные текстовые имена (для записей без MITRE ID)
    for item in items:
        # Если у элемента есть MITRE ID — он уже обработан выше
        if re.search(r"T\d{4}", str(item)):
            continue
        # Иначе — нормализуем как текст
        norm = normalize_entity(item)
        if len(norm) > 2:
            s.add(norm)

    return s


def calculate_metrics_detailed(pred: dict, truth: dict) -> dict:
    """
    Считает метрики по категориям:
      - actors: threat_actor
      - malware: malware
      - tools: tools
      - attack_patterns: MITRE ID + текстовые названия
      - ioc: indicators (IP, domain, hash)
      - overall: все вместе
    """
    categories = {
        "actors": (["threat_actor"], ["threat_actor"]),
        "malware": (["malware"], ["malware"]),
        "tools": (["tools"], ["tools"]),
    }

    results = {}

    # По категориям (actors, malware, tools)
    for cat_name, (pred_keys, truth_keys) in categories.items():
        pred_set = get_entity_set(pred, pred_keys)
        truth_set = get_entity_set(truth, truth_keys)
        p, r, f1 = calculate_f1_set(pred_set, truth_set)
        results[cat_name] = {"precision": p, "recall": r, "f1": f1}

    # Attack patterns — специальная обработка через MITRE ID
    pred_ap = get_attack_pattern_set(pred)
    truth_ap = get_attack_pattern_set(truth)
    p, r, f1 = calculate_f1_set(pred_ap, truth_ap)
    results["attack_patterns"] = {"precision": p, "recall": r, "f1": f1}

    # IoC
    pred_ioc = get_ioc_set(pred)
    truth_ioc = get_ioc_set(truth)
    p, r, f1 = calculate_f1_set(pred_ioc, truth_ioc)
    results["ioc"] = {"precision": p, "recall": r, "f1": f1}

    # Overall (всё вместе)
    all_pred = (
        get_entity_set(pred, ["threat_actor", "malware", "tools"])
        | get_attack_pattern_set(pred)
        | get_ioc_set(pred)
    )
    all_truth = (
        get_entity_set(truth, ["threat_actor", "malware", "tools"])
        | get_attack_pattern_set(truth)
        | get_ioc_set(truth)
    )
    p, r, f1 = calculate_f1_set(all_pred, all_truth)
    results["overall"] = {"precision": p, "recall": r, "f1": f1}

    return results


# --- Запуск моделей ---

def run_llm_model(text: str, model_name: str) -> tuple:
    """Запускает LLM-модель и возвращает (результат, время)."""
    from models.run_llm_generic import extract_with_model

    start = time.time()
    result = extract_with_model(text, model_name=model_name)
    duration = time.time() - start
    return result, duration


def run_baseline_securebert(text: str) -> tuple:
    """SecureBERT baseline."""
    from models.run_securebert import extract_securebert

    start = time.time()
    result = extract_securebert(text)
    duration = time.time() - start
    return result, duration


def run_baseline_gliner(text: str) -> tuple:
    """GLiNER baseline."""
    from models.run_gliner import extract_gliner

    start = time.time()
    result = extract_gliner(text)
    duration = time.time() - start
    return result, duration


def check_model_available(model_name: str) -> bool:
    """Проверяет, доступна ли модель в Ollama."""
    try:
        import ollama
        models = ollama.list()
        available = [m.model for m in models.models]
        # Проверяем точное совпадение или с :latest
        for avail in available:
            if avail == model_name or avail == f"{model_name}:latest":
                return True
            # Убираем :latest для сравнения
            if avail.replace(":latest", "") == model_name.replace(":latest", ""):
                return True
        return False
    except Exception:
        return False


# --- Основной бенчмарк ---

def main():
    parser = argparse.ArgumentParser(description="Multi-Model CTI Benchmark")
    parser.add_argument(
        "--models",
        type=str,
        default=None,
        help="Comma-separated list of Ollama model names (default: all configured models)",
    )
    parser.add_argument(
        "--skip-baselines",
        action="store_true",
        help="Skip SecureBERT and GLiNER baselines",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="benchmark_results.csv",
        help="Output CSV file name",
    )
    args = parser.parse_args()

    # Определяем модели
    if args.models:
        llm_models = [m.strip() for m in args.models.split(",")]
    else:
        llm_models = DEFAULT_LLM_MODELS

    print("=" * 70)
    print("MULTI-MODEL CTI BENCHMARK")
    print(f"Дата: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"Датасеты: {len(TASKS)}")
    print(f"LLM модели: {len(llm_models)}")
    print("=" * 70)

    # Проверяем доступность моделей
    available_models = []
    for model in llm_models:
        if check_model_available(model):
            available_models.append(model)
            print(f"  [OK] {model}")
        else:
            print(f"  [SKIP] {model} — не найдена в Ollama (ollama pull {model})")

    if not available_models and not args.skip_baselines:
        print("\nНет доступных LLM-моделей, но запущу baselines...")
    elif not available_models:
        print("\nНет доступных моделей для тестирования!")
        return

    all_results = []
    detailed_results = []

    # --- LLM модели ---
    for model_name in available_models:
        print(f"\n{'─' * 50}")
        print(f"МОДЕЛЬ: {model_name}")
        print(f"{'─' * 50}")

        for task in TASKS:
            dataset_name = Path(task["text"]).stem
            print(f"\n  Dataset: {dataset_name}")

            with open(task["text"], "r", encoding="utf-8") as f:
                text = f.read()
            with open(task["truth"], "r", encoding="utf-8") as f:
                truth = json.load(f)

            try:
                result, duration = run_llm_model(text, model_name)
                metrics = calculate_metrics_detailed(result, truth)

                row = {
                    "Method": f"Hybrid+{model_name}",
                    "Model": model_name,
                    "Type": "LLM",
                    "Dataset": dataset_name,
                    "Time_sec": round(duration, 1),
                    "F1_overall": metrics["overall"]["f1"],
                    "P_overall": metrics["overall"]["precision"],
                    "R_overall": metrics["overall"]["recall"],
                    "F1_actors": metrics["actors"]["f1"],
                    "F1_malware": metrics["malware"]["f1"],
                    "F1_tools": metrics["tools"]["f1"],
                    "F1_ioc": metrics["ioc"]["f1"],
                    "F1_attack_patterns": metrics["attack_patterns"]["f1"],
                }
                all_results.append(row)

                print(f"    F1={metrics['overall']['f1']:.3f} "
                      f"(P={metrics['overall']['precision']:.3f}, R={metrics['overall']['recall']:.3f}) "
                      f"Time={duration:.1f}s")
                print(f"    actors={metrics['actors']['f1']:.3f} "
                      f"malware={metrics['malware']['f1']:.3f} "
                      f"tools={metrics['tools']['f1']:.3f} "
                      f"ioc={metrics['ioc']['f1']:.3f}")

                # Сохраняем детальные результаты (для отладки)
                detailed_results.append({
                    "model": model_name,
                    "dataset": dataset_name,
                    "extracted": result,
                    "metrics": metrics,
                    "time": duration,
                })

            except Exception as e:
                print(f"    [ERROR] {e}")
                all_results.append({
                    "Method": f"Hybrid+{model_name}",
                    "Model": model_name,
                    "Type": "LLM",
                    "Dataset": dataset_name,
                    "Time_sec": 0,
                    "F1_overall": 0,
                    "P_overall": 0,
                    "R_overall": 0,
                    "F1_actors": 0,
                    "F1_malware": 0,
                    "F1_tools": 0,
                    "F1_ioc": 0,
                    "F1_attack_patterns": 0,
                })

    # --- Baselines ---
    if not args.skip_baselines:
        baselines = [
            ("SecureBERT", run_baseline_securebert),
            ("GLiNER", run_baseline_gliner),
        ]

        for baseline_name, baseline_fn in baselines:
            print(f"\n{'─' * 50}")
            print(f"BASELINE: {baseline_name}")
            print(f"{'─' * 50}")

            for task in TASKS:
                dataset_name = Path(task["text"]).stem
                print(f"\n  Dataset: {dataset_name}")

                with open(task["text"], "r", encoding="utf-8") as f:
                    text = f.read()
                with open(task["truth"], "r", encoding="utf-8") as f:
                    truth = json.load(f)

                try:
                    result, duration = baseline_fn(text)
                    metrics = calculate_metrics_detailed(result, truth)

                    row = {
                        "Method": baseline_name,
                        "Model": baseline_name,
                        "Type": "Baseline",
                        "Dataset": dataset_name,
                        "Time_sec": round(duration, 1),
                        "F1_overall": metrics["overall"]["f1"],
                        "P_overall": metrics["overall"]["precision"],
                        "R_overall": metrics["overall"]["recall"],
                        "F1_actors": metrics["actors"]["f1"],
                        "F1_malware": metrics["malware"]["f1"],
                        "F1_tools": metrics["tools"]["f1"],
                        "F1_ioc": metrics["ioc"]["f1"],
                        "F1_attack_patterns": metrics["attack_patterns"]["f1"],
                    }
                    all_results.append(row)

                    print(f"    F1={metrics['overall']['f1']:.3f} "
                          f"(P={metrics['overall']['precision']:.3f}, R={metrics['overall']['recall']:.3f}) "
                          f"Time={duration:.1f}s")

                except Exception as e:
                    print(f"    [ERROR] {baseline_name}: {e}")
                    all_results.append({
                        "Method": baseline_name,
                        "Model": baseline_name,
                        "Type": "Baseline",
                        "Dataset": dataset_name,
                        "Time_sec": 0,
                        "F1_overall": 0,
                        "P_overall": 0,
                        "R_overall": 0,
                        "F1_actors": 0,
                        "F1_malware": 0,
                        "F1_tools": 0,
                        "F1_ioc": 0,
                        "F1_attack_patterns": 0,
                    })

    # --- Сводка ---
    if not all_results:
        print("\nНет результатов для отображения!")
        return

    df = pd.DataFrame(all_results)

    print("\n\n" + "=" * 70)
    print("ИТОГОВАЯ ТАБЛИЦА (средние по всем датасетам)")
    print("=" * 70)

    summary = df.groupby("Method").agg({
        "Time_sec": "mean",
        "F1_overall": "mean",
        "P_overall": "mean",
        "R_overall": "mean",
        "F1_actors": "mean",
        "F1_malware": "mean",
        "F1_tools": "mean",
        "F1_ioc": "mean",
    }).round(3).sort_values("F1_overall", ascending=False)

    print(summary.to_string())

    # Сохраняем
    df.to_csv(args.output, index=False)
    print(f"\nДетальные результаты сохранены в {args.output}")

    # Сохраняем сводку
    summary_file = args.output.replace(".csv", "_summary.csv")
    summary.to_csv(summary_file)
    print(f"Сводная таблица сохранена в {summary_file}")

    # Сохраняем детальный JSON
    if detailed_results:
        detail_file = args.output.replace(".csv", "_detailed.json")
        with open(detail_file, "w", encoding="utf-8") as f:
            json.dump(detailed_results, f, indent=2, ensure_ascii=False, default=str)
        print(f"Детальный JSON сохранён в {detail_file}")

    # Лучшая модель
    if not summary.empty:
        best = summary.index[0]
        best_f1 = summary.loc[best, "F1_overall"]
        print(f"\nЛучшая модель: {best} (F1={best_f1:.3f})")


if __name__ == "__main__":
    main()
