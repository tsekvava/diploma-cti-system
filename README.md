# CTI Pipeline — Локальная LLM-агентная система анализа киберугроз

Дипломный проект (НИУ ВШЭ, ФКН, ПМИ): локальная многокомпонентная система для SOC-аналитиков. Принимает неструктурированный отчёт о кибератаке и выдаёт:

- Структурированный JSON со всеми сущностями (APT-группы, вредоносное ПО, инструменты, IoC)
- Маппинг на MITRE ATT&CK Kill Chain с валидацией
- Аналитическую записку на русском языке
- STIX 2.1 Bundle для импорта в OpenCTI / TIP-платформы

Система работает полностью локально (air-gapped), без выхода в интернет.

---

## Архитектура

7-этапный гибридный пайплайн в классе `ReportSummarizer`:

```
Входной отчёт (txt / pdf / docx / html / image)
    │
    ▼
[1] Regex-экстракция IoC ─────────── IPv4, домены, MD5/SHA1/SHA256, CVE, email
    │
    ▼
[2] LLM-экстракция сущностей ─────── threat actors, malware, tools (через Ollama)
    │
    ▼
[3] 3-уровневая нормализация ──────── exact → alias → fuzzy (RapidFuzz ≥ 85)
    │
    ▼
[4] Двухэтапный Kill Chain mapper ─── 14 тактик → техники → валидация по SQLite
    │
    ▼
[5] Confidence Scoring ─────────────── базовая оценка LLM + бонусы нормализации/валидации
    │
    ▼
[6] LLM-суммаризация на EN
    │
    ▼
[7] Перевод EN → RU + аналитическая записка
    │
    ▼
JSON (OpenCTI) + Markdown-записка + STIX 2.1 Bundle
```

---

## Структура проекта

```
project/
├── cli.py                      # Единый CLI (8 команд)
├── mcp_server.py               # MCP-сервер (7 инструментов)
├── opencti_exporter.py         # Экспорт в OpenCTI / STIX 2.1
├── web_ui.py                   # Streamlit Web UI (4 страницы)
├── rag_engine.py               # RAG на ChromaDB + sentence-transformers
├── requirements.txt            # Python-зависимости
├── Dockerfile, docker-compose.yml
│
├── summarizer/                 # CTI-пайплайн
│   ├── report_summarizer.py    # 7-этапный оркестратор
│   ├── input_loader.py         # Multi-format loader (txt/pdf/docx/html/image + OCR)
│   ├── translator.py           # Перевод EN → RU
│   └── profiler.py             # Профилирование APT и ВПО
│
├── knowledge_base/             # База знаний MITRE ATT&CK + NVD
│   ├── mitre_catalog.py        # Сборка SQLite из XLSX + STIX JSON
│   ├── mitre.db                # SQLite (634 техники, 172 группы, 784 ПО)
│   ├── nvd_db.py               # Локальный кэш NVD 2.0 (CVE + CVSS + CWE)
│   ├── normalizer.py           # 3-уровневая нормализация
│   ├── attack_mapper.py        # Двухэтапный Kill Chain mapper
│   ├── query_enricher.py       # Контекст MITRE для LLM
│   └── intel_sync.py           # Синхронизация с OpenCTI
│
├── prompts/                    # 9 LLM-промптов в отдельных файлах
│
├── benchmark/                  # Сравнительный бенчмарк + аналитика
│   ├── benchmark_multi_model.py    # Главный скрипт (Hybrid + Full Pipeline, 3 протокола)
│   ├── statistical_analysis.py     # Bootstrap BCa, Wilcoxon, Friedman, Nemenyi
│   ├── error_analysis_deep.py      # Таксономия ошибок, Jaccard
│   ├── embedding_analysis.py       # PCA, t-SNE, silhouette
│   ├── calibration.py              # ECE / MCE / Brier + рекалибровка
│   ├── ablation_study.py           # Вклад компонентов пайплайна
│   ├── visualize_multi.py          # Базовые графики
│   ├── benchmark_9x9_hybrid.csv    # 81 прогон (9 моделей × 9 датасетов)
│   ├── charts/                     # 30+ PNG-графиков для ВКР
│   ├── data/                       # 9 размеченных CTI-отчётов + ground truth
│   └── models/                     # Обёртки для Hybrid и Full Pipeline режимов
│
├── data/
│   └── mitre/                  # MITRE ATT&CK source data
│       ├── enterprise-attack.json     # STIX JSON
│       └── mitre_v18_translation.xlsm # Перевод v18 на русский
│
├── tests/                      # pytest-инфраструктура (6 модулей)
├── finetuning/                 # LoRA-адаптер для Qwen2.5-3B (фильтр Threat/Spam)
└── opencti/
    └── docker-compose.yml      # Инфраструктура OpenCTI
```

---

## Установка и запуск

### Требования
- Python 3.10+
- [Ollama](https://ollama.com/) — локальный LLM-инференс
- Tesseract OCR — для PDF-сканов и встроенных изображений

### Установка
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
ollama pull gemma2:9b
```

При удалённом Ollama:
```bash
export CTI_OLLAMA_HOST=10.10.10.50
export CTI_OLLAMA_PORT=11434
```

### CLI

```bash
# Анализ одного отчёта
python3 cli.py analyze -f report.pdf
python3 cli.py analyze -f report.txt --model qwen2.5:14b --rag --stix output.json

# Пакетная обработка
python3 cli.py analyze-batch -d ./reports/ -o ./results/

# Обогащение MITRE-запроса
python3 cli.py enrich "Lazarus Group" --json
python3 cli.py enrich T1059

# Профилирование APT / ПО
python3 cli.py profile "APT28"
python3 cli.py profile "Cobalt Strike" --type software --lang ru

# Бенчмарк (Hybrid)
python3 cli.py benchmark --models "gemma2:9b,qwen2.5:14b"

# Бенчмарк (Full Pipeline — с EntityNormalizer + AttackMapper)
python3 benchmark/benchmark_multi_model.py --full-pipeline --models gemma2:9b

# Управление базой MITRE
python3 cli.py mitre-db --rebuild

# Синхронизация с OpenCTI
python3 cli.py intel-sync --url https://opencti.local --token $TOKEN

# NVD-кэш (CVE + CVSS)
python3 cli.py nvd --update --days 30
```

### Web UI (Streamlit)

```bash
streamlit run web_ui.py
# открыть http://localhost:8501
```

Четыре страницы: «Анализ отчёта», «MITRE Enrichment», «Профиль APT/Software», «Бенчмарк».

### MCP-сервер

```bash
python3 mcp_server.py                                       # stdio (Claude Desktop)
python3 mcp_server.py --transport sse --port 8000           # SSE для веб-клиентов
```

Конфиг для Claude Desktop — `mcp_config_example.json`.

### Docker

```bash
docker-compose up -d
# Streamlit: http://localhost:8501
# Ollama:    http://localhost:11434
```

---

## Аналитические модули

В `benchmark/` реализованы шесть модулей для глубокого анализа:

| Модуль | Что делает |
|--------|-----------|
| `statistical_analysis.py` | Bootstrap BCa 95% CI, Wilcoxon с поправкой Бонферрони, Friedman χ², post-hoc Nemenyi (Critical Difference) |
| `error_analysis_deep.py` | Автоматическая классификация FP (5 типов: over-extraction, granularity_mismatch, regex_artifact, hallucination) и FN (4 типа); Jaccard-сходство ошибок между моделями |
| `embedding_analysis.py` | Cosine similarity, PCA, t-SNE, K-means + silhouette; корреляция семантической похожести и качества |
| `calibration.py` | Reliability diagrams, ECE, MCE, Brier score; рекалибровка изотонической регрессией и Platt scaling |
| `ablation_study.py` | Вклад компонентов пайплайна (NORM / Kill Chain / Confidence / Chunk) |
| `visualize_multi.py` | Базовые графики бенчмарка (F1, P/R, радар, теплокарты, время) |

---

## Результаты бенчмарка

Сравнили **9 локальных LLM** на **9 размеченных CTI-датасетах** = **81 прогон**.

### Топ-модели (Hybrid режим)

| Модель | Macro F1 | Fuzzy F1 | Time (с) | Сильная категория |
|--------|---------:|---------:|---------:|------------------|
| **gemma2:9b** | **0.486** | **0.505** | 366 | Malware (0.656) |
| qwen2.5:14b | 0.458 | 0.503 | 346 | Malware (0.571) |
| alientelligence/cybersecuritythreatanalysisv2 | 0.440 | 0.495 | 169 | Malware (0.563) |
| llama3.1:8b | 0.416 | 0.486 | 236 | Malware (0.488) |
| deepseek-v2:16b | 0.348 | 0.487 | **90** | IoC (0.400) |
| mistral:7b | 0.394 | 0.477 | 113 | Malware (0.504) |

### Ключевые цифры

- **Friedman χ² = 28.16, p = 0.00045** — различия между моделями статистически значимы
- **ECE 0.261 → 0.082** (−69%) после изотонической регрессии
- **Kill Chain mapper** — самый важный компонент: ΔF1 = +0.031; F1 attack patterns без него падает с 0.207 до 0.000
- **Jaccard FP = 0.574** — модели делают похожие ошибки (простой ensemble малополезен)

Полные результаты: `benchmark/benchmark_9x9_hybrid.csv`. Графики: `benchmark/charts/` (30+ PNG).

---

## MITRE ATT&CK SQLite

Локальная база `knowledge_base/mitre.db`:
- 14 тактик (Kill Chain Enterprise)
- 634 техники и подтехники (v18 с переводом на русский)
- 172 APT-группы с алиасами
- 784 единицы ВПО и инструментов
- 4 276 связей группа → техника
- 10 434 связей ПО → техника
- Отдельный intel-слой (`intel_*`) для синхронизации с OpenCTI

Собирается из двух источников:
1. XLSX с переводом MITRE ATT&CK v18 на русский
2. STIX JSON `enterprise-attack.json` от MITRE

Перестроить базу: `python3 cli.py mitre-db --rebuild`.

---

## Стек технологий

| Компонент | Технология |
|-----------|------------|
| LLM-инференс | Ollama (9 локальных моделей) |
| Нормализация | RapidFuzz (Levenshtein, C++) |
| База знаний | SQLite (один файл, ~3 МБ) |
| Векторное хранилище | ChromaDB + sentence-transformers (all-MiniLM-L6-v2, 384-dim) |
| Статистика | scipy, scikit-learn |
| Визуализация | matplotlib, seaborn |
| Web UI | Streamlit |
| Экспорт CTI | pycti + stix2 (STIX 2.1 Bundle) |
| MCP | FastMCP (Python SDK) |
| Fine-tuning | PEFT/LoRA + Hugging Face Transformers |
| OCR | Tesseract (rus + eng) |
| Контейнеризация | Docker, Docker Compose |
| Тесты | pytest |

---

## Тестирование

```bash
pytest tests/ -v
```

Покрытие: трёхуровневая нормализация, regex IoC, метрики бенчмарка, multi-format input loader, STIX 2.1 экспорт, query enricher.

---

## Лицензия и обратная связь

Проект разработан в рамках выпускной квалификационной работы на образовательной программе «Программная инженерия» НИУ ВШЭ. Использование, замечания и pull-request'ы приветствуются.
