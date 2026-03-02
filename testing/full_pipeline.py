import requests
from bs4 import BeautifulSoup
import ollama
import json
import os
from datetime import datetime

MODEL_NAME = "qwen2.5"
OUTPUT_FOLDER = "final_reports"


def fetch_article_content(url):
    """Скачивает статью как браузер и вытаскивает текст."""
    print(f"\n[*] Агент-Сборщик: Иду по ссылке {url}...")

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')

        for script in soup(["script", "style", "nav", "footer", "header", "aside"]):
            script.extract()

        text_content = ' '.join([p.get_text() for p in soup.find_all('p')])

        if len(text_content) < 500:
            print("[!] Внимание: Текста слишком мало. Возможно, защита сайта или некорректная ссылка.")
            return None

        print(f"[+] Успешно скачано {len(text_content)} символов.")
        return text_content

    except Exception as e:
        print(f"[!] Ошибка сбора данных: {e}")
        return None


def analyze_threat_data(text_content):
    """Отправляет текст в LLM и получает структуру по угрозам."""
    print("[*] Агент-Аналитик: Читаю текст и извлекаю сущности (это может занять 10-30 сек)...")

    system_prompt = """
    Ты — эксперт Threat Intelligence. Твоя цель — извлечь факты из статьи о кибербезопасности.

    Сформируй JSON со следующими полями:
    - summary: (краткая суть инцидента на русском, 1-2 предложения)
    - threat_actor: (название группировки, если есть, иначе "Unknown")
    - targeted_countries: (список стран)
    - malware_family: (названия вирусов, троянов)
    - iocs: { "ips": [], "domains": [], "hashes": [] } (индикаторы компрометации)
    - tactics: (использованные методы, например: Phishing, DDoS, Zero-day)
    - threat_level: "Low", "Medium", "High" или "Critical" (оцени сам)

    Верни ТОЛЬКО валидный JSON. Без markdown разметки.
    """

    try:
        response = ollama.chat(model=MODEL_NAME, messages=[
            {'role': 'system', 'content': system_prompt},
            {'role': 'user', 'content': text_content},
        ])

        raw_json = response['message']['content']
        clean_json = raw_json.replace("```json", "").replace("```", "").strip()
        return json.loads(clean_json)

    except Exception as e:
        print(f"[!] Ошибка анализа LLM: {e}")
        return None


def save_result(data, source_url):
    if not os.path.exists(OUTPUT_FOLDER):
        os.makedirs(OUTPUT_FOLDER)

    timestamp = int(datetime.now().timestamp())
    actor = data.get('threat_actor', 'unknown').replace(" ", "_")
    filename = f"{OUTPUT_FOLDER}/report_{actor}_{timestamp}.json"

    final_report = {
        "meta": {
            "source_url": source_url,
            "scan_date": datetime.now().isoformat(),
            "model_used": MODEL_NAME
        },
        "intelligence": data
    }

    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(final_report, f, indent=4, ensure_ascii=False)

    return filename


def print_summary(data, filename):
    """Печатает короткое резюме в консоль."""
    print("\n" + "=" * 60)
    print(f"ОТЧЕТ СФОРМИРОВАН: {datetime.now().strftime('%H:%M:%S')}")
    print("=" * 60)
    print(f"📂 Файл:       {filename}")
    print(f"💀 Группировка: {data.get('threat_actor', 'N/A')}")
    print(f"🌍 Цели:        {', '.join(data.get('targeted_countries', []))}")
    print(f"🦠 Малварь:     {', '.join(data.get('malware_family', []))}")
    print(f"🔥 Уровень:     {data.get('threat_level', 'N/A')}")
    print("-" * 60)
    print(f"📝 Суть: {data.get('summary', 'Нет описания')}")

    iocs = data.get('iocs', {})
    ioc_count = len(iocs.get('ips', [])) + len(iocs.get('domains', [])) + len(iocs.get('hashes', []))
    print(f"🔍 Найдено IoC: {ioc_count} шт.")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    print(f"=== AGENTIC TI SYSTEM v0.3 (Loop Mode) ===")
    print(f"Модель: {MODEL_NAME}")
    print("Вставляйте ссылки по одной. Для выхода нажмите Enter или введите '-'.")

    while True:
        target_url = input("\n>>> Введите URL статьи: ").strip()

        if not target_url or target_url == "-":
            print("\n[EXIT] Работа завершена. Удачи с дипломом!")
            break

        content = fetch_article_content(target_url)

        if content:
            analysis = analyze_threat_data(content)

            if analysis:
                saved_file = save_result(analysis, target_url)
                print_summary(analysis, saved_file)
            else:
                print("[!] Не удалось извлечь данные из этой статьи.")
        else:
            print("[!] Не удалось скачать контент.")
