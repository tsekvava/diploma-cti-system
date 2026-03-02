import time
import json
import os
from datetime import datetime
import ollama

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup

MODEL_NAME = "qwen2.5"
OUTPUT_FOLDER = "final_reports"
CHUNK_SIZE = 12000


def fetch_content_selenium(url):
    """Тянет страницу через headless Chrome, когда обычный requests не проходит."""
    print(f"\n[*] Агент-Сборщик (Selenium): Запускаю браузер для {url}...")

    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument(
        "user-agent=Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

    driver = None
    try:
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)

        driver.get(url)
        time.sleep(5)

        page_source = driver.page_source

        soup = BeautifulSoup(page_source, 'html.parser')

        for script in soup(["script", "style", "nav", "footer", "header", "aside", "iframe"]):
            script.extract()

        text_content = ' '.join([p.get_text() for p in soup.find_all(['p', 'article', 'div'])])

        text_content = ' '.join(text_content.split())

        print(f"[+] Успешно скачано {len(text_content)} символов.")
        return text_content

    except Exception as e:
        print(f"[!] Ошибка Selenium: {e}")
        return None
    finally:
        if driver:
            driver.quit()


def split_text(text, chunk_size):
    """Режет длинный текст на чанки."""
    return [text[i:i + chunk_size] for i in range(0, len(text), chunk_size)]


def merge_reports(reports):
    """Склеивает частичные JSON-отчеты в один итоговый."""
    final_data = {
        "threat_actor": "Unknown",
        "targeted_countries": [],
        "malware_family": [],
        "iocs": {"ips": [], "domains": [], "hashes": []},
        "tactics": [],
        "threat_level": "Unknown",
        "summary": ""
    }

    summaries = []

    for r in reports:
        if not r: continue

        if r.get("threat_actor") not in ["Unknown", "N/A", None]:
            final_data["threat_actor"] = r.get("threat_actor")

        final_data["targeted_countries"] = list(set(final_data["targeted_countries"] + r.get("targeted_countries", [])))
        final_data["malware_family"] = list(set(final_data["malware_family"] + r.get("malware_family", [])))
        final_data["tactics"] = list(set(final_data["tactics"] + r.get("tactics", [])))

        iocs = r.get("iocs", {})
        final_data["iocs"]["ips"] = list(set(final_data["iocs"]["ips"] + iocs.get("ips", [])))
        final_data["iocs"]["domains"] = list(set(final_data["iocs"]["domains"] + iocs.get("domains", [])))
        final_data["iocs"]["hashes"] = list(set(final_data["iocs"]["hashes"] + iocs.get("hashes", [])))

        if r.get("summary"):
            summaries.append(r.get("summary"))

        levels = ["Low", "Medium", "High", "Critical"]
        current_lvl = final_data["threat_level"]
        new_lvl = r.get("threat_level", "Low")
        if new_lvl in levels and (current_lvl not in levels or levels.index(new_lvl) > levels.index(current_lvl)):
            final_data["threat_level"] = new_lvl

    final_data["summary"] = " ".join(summaries[:2])

    return final_data


def analyze_with_llm(text_chunk, chunk_index, total_chunks):
    print(f"[*] Агент-Аналитик: Обрабатываю часть {chunk_index}/{total_chunks}...")

    system_prompt = """
    Ты — эксперт Threat Intelligence. Извлеки сущности из текста.
    Верни СТРОГО JSON со следующими полями:
    - summary: (краткая суть этого фрагмента)
    - threat_actor: (название группировки или "Unknown")
    - targeted_countries: (список стран)
    - malware_family: (названия вирусов)
    - iocs: { "ips": [], "domains": [], "hashes": [] }
    - tactics: (использованные методы)
    - threat_level: "Low", "Medium", "High", "Critical"

    Если информации в этом куске нет, верни пустые списки. НЕ ПИШИ MARKDOWN.
    """

    try:
        response = ollama.chat(model=MODEL_NAME, messages=[
            {'role': 'system', 'content': system_prompt},
            {'role': 'user', 'content': text_chunk},
        ])
        clean_json = response['message']['content'].replace("```json", "").replace("```", "").strip()
        return json.loads(clean_json)
    except Exception as e:
        print(f"[!] Ошибка в куске {chunk_index}: {e}")
        return None


def full_analysis_pipeline(text):
    chunks = split_text(text, CHUNK_SIZE)
    total = len(chunks)
    print(f"[*] Текст разбит на {total} частей (Chunking). Начинаю анализ...")

    partial_reports = []
    for i, chunk in enumerate(chunks, 1):
        report = analyze_with_llm(chunk, i, total)
        if report:
            partial_reports.append(report)

    print("[*] Объединяю результаты (Merging)...")
    return merge_reports(partial_reports)


def save_result(data, source_url):
    if not os.path.exists(OUTPUT_FOLDER):
        os.makedirs(OUTPUT_FOLDER)

    timestamp = int(datetime.now().timestamp())
    actor = data.get('threat_actor', 'unknown').replace(" ", "_")[:20]
    filename = f"{OUTPUT_FOLDER}/report_{actor}_{timestamp}.json"

    final_report = {
        "meta": {
            "source_url": source_url,
            "scan_date": datetime.now().isoformat(),
            "model_used": MODEL_NAME,
            "engine": "Selenium + Chunking"
        },
        "intelligence": data
    }

    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(final_report, f, indent=4, ensure_ascii=False)

    return filename


def print_summary(data, filename):
    print("\n" + "=" * 60)
    print(f"ОТЧЕТ ГОТОВ (v0.4 Advanced): {datetime.now().strftime('%H:%M:%S')}")
    print("=" * 60)
    print(f"📂 Файл:       {filename}")
    print(f"💀 Группировка: {data.get('threat_actor', 'N/A')}")
    print(f"🦠 Малварь:     {', '.join(data.get('malware_family', [])[:5])}")
    print(f"🔥 Уровень:     {data.get('threat_level', 'N/A')}")

    iocs = data.get('iocs', {})
    ioc_count = len(iocs.get('ips', [])) + len(iocs.get('domains', [])) + len(iocs.get('hashes', []))
    print(f"🔍 Найдено IoC: {ioc_count} шт.")
    print("-" * 60)
    if iocs.get('ips'):
        print(f"Примеры IP: {', '.join(iocs.get('ips')[:3])}...")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    print(f"=== AGENTIC TI SYSTEM v0.4 (Selenium + Chunking) ===")
    print("Система готова обходить защиты и читать лонгриды.")
    print("Для выхода введите '-'.")

    while True:
        target_url = input("\n>>> Введите URL статьи: ").strip()

        if not target_url or target_url == "-":
            print("\n[EXIT] Работа завершена.")
            break

        content = fetch_content_selenium(target_url)

        if content:
            analysis = full_analysis_pipeline(content)

            if analysis:
                saved_file = save_result(analysis, target_url)
                print_summary(analysis, saved_file)
            else:
                print("[!] Не удалось сформировать отчет.")
        else:
            print("[!] Не удалось скачать контент.")
