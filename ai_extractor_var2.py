import os
import json
import ollama
from bs4 import BeautifulSoup

INPUT_FILE = "GOLD SALEM html.html"
OUTPUT_FILE = "ai_extraction_result_var2.json"
MODEL_NAME = "qwen2.5:14b"

CHUNK_SIZE = 6000
OVERLAP = 500

def read_and_clean_html(file_path):
    if not os.path.exists(file_path):
        print(f"[ERROR] Файл не найден: {file_path}")
        return None
    
    print(f"[1/5] Читаю файл: {file_path}...")
    with open(file_path, 'r', encoding='utf-8') as f:
        html_content = f.read()

    soup = BeautifulSoup(html_content, 'html.parser')
    for script in soup(["script", "style", "nav", "footer", "header", "meta", "noscript", "svg"]):
        script.extract()

    text = soup.get_text(separator=' ')
    clean_text = ' '.join(text.split())
    print(f"      -> Общая длина текста: {len(clean_text)} символов.")
    return clean_text

def chunk_text(text, size, overlap):
    """Генератор, который выдает текст кусками с перекрытием"""
    start = 0
    while start < len(text):
        end = start + size
        yield text[start:end]
        start += size - overlap 

def extract_from_chunk(chunk_text, chunk_id, total_chunks):
    """Обрабатывает один кусочек текста"""
    print(f"      Processing chunk {chunk_id}/{total_chunks}...")

    schema_structure = {
      "threat_actor": ["Name"],
      "malware": ["Name"],
      "tools": ["Name"],
      "indicators": {
        "ipv4": ["1.1.1.1"],
        "domain": ["example.com"],
        "hash": ["md5_or_sha256"]
      },
      "targeted_countries": ["Country"]
    }

    system_prompt = f"""
    You are a strict extraction engine. Analyze the text chunk and extract IoCs and Entities.
    RULES:
    1. Output valid JSON only. Schema: {json.dumps(schema_structure)}
    2. Extract ALL IPv4 addresses, domains, and file hashes you see.
    3. If a list is empty, return [].
    """

    try:
        response = ollama.chat(
            model=MODEL_NAME,
            messages=[
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': chunk_text},
            ],
            format='json',
            options={'temperature': 0.0}
        )
        return json.loads(response['message']['content'])
    except Exception as e:
        print(f"      [WARN] Ошибка в чанке {chunk_id}: {e}")
        return None

def merge_results(results_list):
    """Склеивает список JSON-ов в один, удаляя дубликаты"""
    print(f"[4/5] Агрегация результатов из {len(results_list)} чанков...")
    
    final_data = {
        "threat_actor": set(),
        "malware": set(),
        "tools": set(),
        "indicators": {
            "ipv4": set(),
            "domain": set(),
            "hash": set()
        },
        "targeted_countries": set()
    }

    for res in results_list:
        if not res: continue
        
        for key in ["threat_actor", "malware", "tools", "targeted_countries"]:
            if key in res and isinstance(res[key], list):
                for item in res[key]:
                    final_data[key].add(item)
        
        if "indicators" in res:
            for i_key in ["ipv4", "domain", "hash"]:
                if i_key in res["indicators"] and isinstance(res["indicators"][i_key], list):
                    for item in res["indicators"][i_key]:
                        final_data["indicators"][i_key].add(item)

    output = {
        "threat_actor": list(final_data["threat_actor"]),
        "malware": list(final_data["malware"]),
        "tools": list(final_data["tools"]),
        "indicators": {
            "ipv4": list(final_data["indicators"]["ipv4"]),
            "domain": list(final_data["indicators"]["domain"]),
            "hash": list(final_data["indicators"]["hash"])
        },
        "targeted_countries": list(final_data["targeted_countries"])
    }
    return output

def main():
    full_text = read_and_clean_html(INPUT_FILE)
    if not full_text: return

    chunks = list(chunk_text(full_text, CHUNK_SIZE, OVERLAP))
    print(f"[2/5] Текст разбит на {len(chunks)} чанков (по {CHUNK_SIZE} симв).")

    print(f"[3/5] Начинаю обработку чанков моделью {MODEL_NAME}...")
    results = []
    for i, chunk in enumerate(chunks):
        res = extract_from_chunk(chunk, i+1, len(chunks))
        if res:
            results.append(res)

    final_json = merge_results(results)

    print(f"[5/5] Сохраняю в {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(final_json, f, ensure_ascii=False, indent=4)
    
    print("\n[SUCCESS] Готово! Проверь файл.")
    print(f"Найдено IP: {len(final_json['indicators']['ipv4'])}")
    print(f"Найдено Доменов: {len(final_json['indicators']['domain'])}")
    print(f"Найдено Хешей: {len(final_json['indicators']['hash'])}")

if __name__ == "__main__":
    main()