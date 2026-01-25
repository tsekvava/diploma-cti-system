import json
import os
from pycti import OpenCTIApiClient
from dotenv import load_dotenv

API_URL = os.getenv("OPENCTI_URL", "http://localhost:8080") 
API_TOKEN = os.getenv("OPENCTI_TOKEN")

INPUT_JSON = "ai_extraction_result_var2.json"

def main():
    print(f"Подключение к OpenCTI: {API_URL}")
    client = OpenCTIApiClient(API_URL, API_TOKEN)

    if not os.path.exists(INPUT_JSON):
        print("Файл с данными не найден! Сначала запусти ai_extractor_var2.py")
        return

    with open(INPUT_JSON, 'r', encoding='utf-8') as f:
        data = json.load(f)

    print("Данные загружены. Начинаю импорт в OpenCTI...")

    actor_objects = []
    for actor_name in data.get("threat_actor", []):
        print(f"[+] Создаю группировку: {actor_name}")
        actor = client.intrusion_set.create(
            name=actor_name,
            description="Imported from AI Analysis",
            update=True
        )
        actor_objects.append(actor)

    malware_objects = []
    for malware_name in data.get("malware", []):
        print(f"[+] Создаю малварь: {malware_name}")
        malware = client.malware.create(
            name=malware_name,
            is_family=True,
            description="Imported from AI Analysis",
            update=True
        )
        malware_objects.append(malware)

    tool_objects = []
    for tool_name in data.get("tools", []):
        print(f"[+] Создаю инструмент: {tool_name}")
        tool = client.tool.create(
            name=tool_name,
            description="Tool detected by AI",
            update=True
        )
        tool_objects.append(tool)

    
    def link_indicator_to_malware(indicator_id):
        if malware_objects:
            main_malware = malware_objects[0]
            client.stix_core_relationship.create(
                fromId=indicator_id,
                toId=main_malware["id"],
                relationship_type="indicates",
                description="AI inferred this indicator is related to this malware"
            )

    for domain in data["indicators"].get("domain", []):
        print(f"[.] Домен: {domain}")
        indicator = client.indicator.create(
            name=domain,
            pattern=f"[domain-name:value = '{domain}']",
            pattern_type="stix",
            x_opencti_main_observable_type="Domain-Name",
            update=True
        )
        link_indicator_to_malware(indicator["id"])

    for file_hash in data["indicators"].get("hash", []):
        length = len(file_hash)
        
        if length == 64:
            hash_type = "SHA-256"
        elif length == 40:
            hash_type = "SHA-1"
        elif length == 32:
            hash_type = "MD5"
        else:
            print(f"[!] Пропускаю странный хеш (неизвестная длина {length}): {file_hash}")
            continue

        pattern_value = f"[file:hashes.'{hash_type}' = '{file_hash}']"
        
        print(f"[.] Хеш ({hash_type}): {file_hash}")
        try:
            indicator = client.indicator.create(
                name=file_hash,
                pattern=pattern_value,
                pattern_type="stix",
                x_opencti_main_observable_type="StixFile",
                update=True
            )
            link_indicator_to_malware(indicator["id"])
        except Exception as e:
            print(f"[ERROR] Не удалось создать индикатор {file_hash}: {e}")

    print("\n[∞] Создаю связи (Knowledge Graph)...")

    for actor in actor_objects:
        if not actor or "id" not in actor: continue
        
        actor_name = actor.get("name", "Unknown Actor")

        for malware in malware_objects:
            if not malware or "id" not in malware: continue
            
            malware_name = malware.get("name", "Unknown Malware")
            
            print(f"   Link: {actor_name} uses {malware_name}")
            try:
                client.stix_core_relationship.create(
                    fromId=actor["id"],
                    toId=malware["id"],
                    relationship_type="uses",
                    description="AI extraction detected both in same report"
                )
            except Exception as e:
                print(f"   [!] Ошибка связи: {e}")

    for actor in actor_objects:
        if not actor or "id" not in actor: continue
        actor_name = actor.get("name", "Unknown Actor")

        for tool in tool_objects:
            if not tool or "id" not in tool: continue
            tool_name = tool.get("name", "Unknown Tool")

            print(f"   Link: {actor_name} uses tool {tool_name}")
            try:
                client.stix_core_relationship.create(
                    fromId=actor["id"],
                    toId=tool["id"],
                    relationship_type="uses"
                )
            except Exception as e:
                print(f"   [!] Ошибка связи: {e}")

    print("\n[SUCCESS] Импорт завершен! Иди в OpenCTI и смотри Граф.")

if __name__ == "__main__":
    main()