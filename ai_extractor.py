import os
import json
import ollama
from bs4 import BeautifulSoup

INPUT_FILE = "GOLD SALEM html.html"
MODEL_NAME = "qwen2.5:14b"
OUTPUT_FILE = "ai_extraction_result.json"

def read_and_clean_html(file_path):
    if not os.path.exists(file_path):
        print(f"[ERROR] Файл не найден: {file_path}")
        return None

    print(f"[1/4] Читаю файл: {file_path}...")
    with open(file_path, 'r', encoding='utf-8') as f:
        html_content = f.read()

    soup = BeautifulSoup(html_content, 'html.parser')

    for script in soup(["script", "style", "nav", "footer", "header", "meta", "noscript", "svg"]):
        script.extract()

    text = soup.get_text(separator=' ')
    
    clean_text = ' '.join(text.split())
    
    print(f"      -> Длина текста: {len(clean_text)} символов.")
    return clean_text

def extract_ti_data(text):
    print(f"[2/4] Отправляю запрос в модель {MODEL_NAME} (режим JSON)...")
    
    schema_structure = {
      "threat_actor": ["Name"],
      "malware": ["Name"],
      "tools": ["Name"],
      "indicators": {
        "ipv4": ["1.1.1.1"],
        "domain": ["example.com"],
        "hash": ["md5_or_sha256"]
      },
      "vulnerabilities": ["CVE-XXXX-XXXX"],
      "targeted_countries": ["Country"]
    }

    system_prompt = f"""
    You are a strict data extraction engine. 
    Analyze the user's text and extract Cyber Threat Intelligence entities.
    
    RULES:
    1. Output MUST be a valid JSON object.
    2. Use this exact schema: {json.dumps(schema_structure)}
    3. If you find no data for a field, use an empty list [].
    4. Do not include markdown formatting like ```json.
    """

    truncated_text = text[:30000] 

    try:
        response = ollama.chat(
            model=MODEL_NAME,
            messages=[
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': truncated_text},
            ],
            format='json',
            options={
                'temperature': 0.0,
                'num_ctx': 8192
            }
        )
        
        raw_content = response['message']['content']
        print("[3/4] Ответ получен.")
        return raw_content

    except Exception as e:
        print(f"[ERROR] Ошибка Ollama: {e}")
        return None

def main():
    clean_text = read_and_clean_html(INPUT_FILE)
    if not clean_text: return

    json_response_str = extract_ti_data(clean_text)
    if not json_response_str: return

    try:
        data = json.loads(json_response_str)
        
        print(f"[4/4] Сохраняю результат в {OUTPUT_FILE}...")
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
            
        print("\n[SUCCESS] Успех! Файл создан.")
        print("-" * 30)
        print(json.dumps(data, indent=2, ensure_ascii=False)[:500] + "\n...")
        
    except json.JSONDecodeError:
        print("\n[FAIL] Даже в JSON-режиме что-то пошло не так. Ответ:")
        print(json_response_str)

if __name__ == "__main__":
    main()