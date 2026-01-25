import os
import json
from pycti import OpenCTIApiClient 

# --- КОНФИГУРАЦИЯ ---
# Используем внешний порт (51380), так как скрипт запускаем с хоста (твоего ноутбука)
api_url = "http://localhost:51380" 
api_token = "E27FA78B-8C86-4509-853C-60B18887AFBD"

files_to_import = [
    # "data/frost_beacon.json",
    # "data/gold_salem.json",
    # "data/cve_report.json",
    "data/objects.json"
]

def main():
    print(f"Подключение к OpenCTI: {api_url}")
    client = OpenCTIApiClient(api_url, api_token)

    for file_name in files_to_import:
        file_path = os.path.join(os.getcwd(), file_name)
        
        if not os.path.exists(file_path):
            print(f"[!] Файл не найден: {file_name}")
            continue

        print(f"\n[+] Начало импорта: {file_name}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                bundle_content = f.read()
            
            client.stix2.import_bundle_from_json(bundle_content, update=True)
            
            print(f"[V] Успешно импортирован: {file_name}")
            
        except Exception as e:
            print(f"[X] Ошибка при импорте {file_name}:")
            print(e)

if __name__ == "__main__":
    main()