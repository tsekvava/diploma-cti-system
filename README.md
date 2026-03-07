# CTI Pipeline — Автоматизированная система анализа киберугроз

Дипломный проект: система для SOC-аналитиков, которая принимает неструктурированные отчёты об угрозах и выдаёт:
- Структурированный JSON со всеми сущностями (APT-группы, вредоносное ПО, инструменты, IoC)
- Маппинг на MITRE ATT&CK Kill Chain с валидацией
- Аналитическую записку на русском языке
- Экспорт в OpenCTI через STIX 2.1 Bundle (для закрытого контура)

Система работает полностью локально (air-gapped), без выхода в интернет.

---

## Архитектура

```
Входной отчёт (текст/HTML)
    |
    v
[1] Regex-экстракция IoC (IP, домены, хеши, CVE)
    |
    v
[2] LLM-экстракция сущностей (threat actors, malware, tools)
    |
    v
[3] Нормализация по MITRE ATT&CK (exact → alias → fuzzy match)
    |
    v
[4] Kill Chain маппинг (2-этапный: тактика → техники + валидация в SQLite)
    |
    v
[5] Расчёт Confidence Score (корректировка по результатам нормализации)
    |
    v
[6] LLM-суммаризация (аналитическая записка на EN)
    |
    v
[7] Перевод EN → RU (с сохранением технических терминов)
    |
    v
Результат: JSON (для OpenCTI) + Записка (для аналитика) + STIX Bundle
```

---

## Структура проекта

```
project/
├── cli.py                      # Единый CLI (7 команд)
├── mcp_server.py               # MCP-сервер (7 инструментов, для LLM-клиентов)
├── opencti_exporter.py         # Экспорт в OpenCTI / STIX 2.1 Bundle
├── requirements.txt            # Зависимости Python
│
├── summarizer/                 # Модуль суммаризации
│   ├── report_summarizer.py    # 7-этапный пайплайн анализа отчёта
│   ├── translator.py           # Перевод EN → RU
│   └── profiler.py             # Профилирование APT-групп и ВПО
│
├── knowledge_base/             # База знаний MITRE ATT&CK
│   ├── mitre_catalog.py        # Сборка SQLite из XLSX + STIX JSON
│   ├── mitre.db                # SQLite база (634 техники, 172 группы, 784 ПО)
│   ├── normalizer.py           # Нормализация сущностей (3 уровня)
│   ├── attack_mapper.py        # Kill Chain маппинг (2-этапный LLM + валидация)
│   └── query_enricher.py       # Обогащение коротких запросов (T1059, G0032, CVE...)
│
├── prompts/                    # Все промпты в отдельных файлах (9 шт.)
│   ├── extract_entities.txt    # Экстракция сущностей
│   ├── map_killchain_tactics.txt   # Определение тактик
│   ├── map_killchain_techniques.txt # Выбор техник
│   ├── summarize.txt           # Суммаризация
│   ├── translate.txt           # Перевод
│   ├── classify.txt            # Классификация THREAT/SPAM
│   ├── enrich.txt              # Обогащение запроса
│   ├── profile_group.txt       # Профиль APT-группы
│   └── profile_software.txt    # Профиль ПО
│
├── benchmark/                  # Бенчмарк 9 моделей
│   ├── benchmark_multi_model.py    # Основной скрипт бенчмарка
│   ├── visualize_multi.py          # Генерация графиков для диплома
│   ├── benchmark_full_9models.csv  # Результаты (27 записей: 9 моделей × 3 датасета)
│   ├── charts/                     # 6 графиков (PNG) для вставки в ВКР
│   ├── data/                       # 3 тестовых отчёта + ground truth
│   └── models/                     # Обёртки для запуска моделей
│
├── data/
│   └── mitre/                  # MITRE ATT&CK данные
│       ├── enterprise-attack.json  # STIX JSON (APT-группы, ПО, связи)
│       └── mitre_v18_translation.xlsm  # Перевод v18 на русский
│
├── tests/                      # Тестовые JSON-файлы
├── finetuning/                 # Fine-tuning спам-фильтра (Qwen 2.5-3B + LoRA)
└── opencti/
    └── docker-compose.yml      # Инфраструктура OpenCTI
```

---

## Установка и запуск

### Требования
- Python 3.10+
- [Ollama](https://ollama.com/) (локальный LLM inference)

### Установка
```bash
# Зависимости Python
pip install -r requirements.txt

# Скачать хотя бы одну модель для Ollama
ollama pull gemma2:9b
```

Если Ollama запущен на удалённом хосте, можно задать endpoint через переменные:
```bash
export CTI_OLLAMA_HOST=10.10.10.50
export CTI_OLLAMA_PORT=11434
```

### Команды CLI

```bash
# Полный анализ отчёта
python3 cli.py analyze -f report.txt
python3 cli.py analyze -f report.txt --model qwen2.5:14b --export stix_bundle.json
python3 cli.py analyze -f report.txt --ollama-host 10.10.10.50 --ollama-port 11434

# Обогащение запроса из MITRE ATT&CK
python3 cli.py enrich T1059
python3 cli.py enrich "Lazarus Group" --json
python3 cli.py enrich G0032

# Профилирование APT-группы или ПО
python3 cli.py profile "APT28"
python3 cli.py profile "Cobalt Strike" --type software
python3 cli.py profile "APT28" --ollama-host 10.10.10.50 --ollama-port 11434

# Экспорт в STIX Bundle (для air-gapped OpenCTI)
python3 cli.py export -i result.json --stix-bundle output.json

# Экспорт напрямую в OpenCTI API
python3 cli.py export -i result.json --url http://opencti:8080 --token API_TOKEN

# Запуск бенчмарка
python3 cli.py benchmark --models "gemma2:9b,qwen2.5:14b"
python3 cli.py benchmark --models "gemma2:9b,qwen2.5:14b" --ollama-host 10.10.10.50

# Пересоздание базы MITRE ATT&CK
python3 cli.py mitre-db

```

### MCP-сервер (для Claude Desktop и других LLM-клиентов)

```bash
# Запуск через stdio (Claude Desktop)
python3 mcp_server.py

# Запуск через SSE (веб-клиенты)
python3 mcp_server.py --transport sse --port 8000
python3 mcp_server.py --transport sse --port 8000 --ollama-host 10.10.10.50 --ollama-port 11434
```

Конфигурация для Claude Desktop — см. `mcp_config_example.json`.

---

## Результаты бенчмарка (9 моделей)

| Модель | F1 (общий) | Время (сек) | Лучшая категория |
|--------|-----------|------------|------------------|
| alientelligence/cybersecuritythreatanalysisv2 | **0.400** | 165 | Malware (0.717) |
| gemma2:9b | 0.397 | 364 | Malware (0.713) |
| qwen2.5:14b | 0.396 | 351 | Malware (0.589) |
| glm4:9b | 0.378 | 234 | Tools (0.428) |
| qwen2.5:7b | 0.376 | 262 | Malware (0.426) |
| llama3.1:8b | 0.375 | 227 | Malware (0.548) |
| deepseek-v2:16b | 0.371 | **87** | Tools (0.399) |
| mistral:7b | 0.369 | 119 | Malware (0.376) |
| qwen2.5-14b-cybersecurity | 0.336 | 438 | IoC (0.391) |

Тестирование на 3 датасетах: Gold Salem, Frost Beacon, CVE.
Графики в `benchmark/charts/`.

---

## MITRE ATT&CK SQLite

Локальная база `knowledge_base/mitre.db` содержит:
- 14 тактик (Kill Chain)
- 634 техники и подтехники (v18, с переводом на русский)
- 172 APT-группы с алиасами
- 784 записи вредоносного ПО и инструментов
- 4 276 связей группа→техника
- 10 434 связей ПО→техника
- 37 источников данных, 44 меры предотвращения

Собирается из двух источников:
1. XLSX-файл с переводом MITRE ATT&CK v18 на русский (от научрука)
2. STIX JSON `enterprise-attack.json` (APT-группы, ПО, связи)

---

## Стек технологий

| Компонент | Технология |
|-----------|------------|
| LLM inference | Ollama (локальный, 9 моделей) |
| Нормализация | rapidfuzz (fuzzy match, C++ backend) |
| Справочник MITRE | SQLite (встраиваемая, один файл) |
| Экспорт | pycti + stix2 (STIX 2.1 Bundle) |
| MCP | FastMCP (Python MCP SDK) |
| Графики | matplotlib + seaborn |
| Fine-tuning | PEFT/LoRA + HuggingFace Transformers |
| Эмбеддинги | all-MiniLM-L6-v2 (sentence-transformers) |
| Векторная БД | ChromaDB (прототип) → Qdrant (продакшн) |
