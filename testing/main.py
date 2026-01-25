import ollama
import json
import os
import glob
from datetime import datetime

MODEL_NAME = "qwen2.5"
INPUT_FOLDER = "data"
OUTPUT_FOLDER = "reports"

SYSTEM_PROMPT = """
Ты — старший аналитик Threat Intelligence. Твоя задача — извлечь ключевые данные из отчета о киберугрозе.
Проанализируй предоставленный текст и сформируй JSON-отчет.

Структура JSON должна быть такой:
{
    "actor_name": "Имя группировки (строка)",
    "aliases": ["Список", "других", "имен"],
    "target_sector": ["Список", "атакуемых", "отраслей"],
    "malware_tools": ["Список", "ПО", "и", "инструментов"],
    "iocs": {
        "ips": ["Список IP"],
        "domains": ["Список доменов"],
        "hashes": ["Список хешей"]
    },
    "threat_level": "Low/Medium/High/Critical (оцени сам)",
    "summary": "Краткое резюме на русском языке (1 предложение)"
}
Отвечай ТОЛЬКО валидным JSON. Не добавляй markdown разметку.
"""


def ensure_directories():
    """Создает папку для отчетов, если её нет"""
    if not os.path.exists(OUTPUT_FOLDER):
        os.makedirs(OUTPUT_FOLDER)


def analyze_file(filepath):
    """Читает файл и отправляет его в LLM"""
    print(f"[*] Анализирую файл: {filepath}...")

    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    try:
        response = ollama.chat(model=MODEL_NAME, messages=[
            {'role': 'system', 'content': SYSTEM_PROMPT},
            {'role': 'user', 'content': content},
        ])

        raw_answer = response['message']['content']

        clean_answer = raw_answer.replace("```json", "").replace("```", "").strip()

        parsed_json = json.loads(clean_answer)

        parsed_json['analysis_timestamp'] = datetime.now().isoformat()
        parsed_json['source_file'] = os.path.basename(filepath)

        return parsed_json

    except Exception as e:
        print(f"[!] Ошибка при анализе {filepath}: {e}")
        return None


def save_report(data):
    """Сохраняет результат в JSON файл"""
    if not data:
        return

    filename = f"report_{data.get('actor_name', 'unknown')}_{int(datetime.now().timestamp())}.json"
    filepath = os.path.join(OUTPUT_FOLDER, filename)

    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

    print(f"[+] Отчет сохранен: {filepath}")


def main():
    print(f"--- ЗАПУСК TI PIPELINE (Model: {MODEL_NAME}) ---")
    ensure_directories()

    files = glob.glob(os.path.join(INPUT_FOLDER, "*.txt"))

    if not files:
        print(f"[!] Нет файлов для анализа в папке {INPUT_FOLDER}")
        return

    for file in files:
        result = analyze_file(file)
        save_report(result)

    print("--- РАБОТА ЗАВЕРШЕНА ---")


if __name__ == "__main__":
    main()