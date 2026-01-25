import json
import os
from pycti import OpenCTIApiClient
from dotenv import load_dotenv

API_URL = os.getenv("OPENCTI_URL", "http://localhost:8080") 
API_TOKEN = os.getenv("OPENCTI_TOKEN")
INPUT_JSON = "final_extraction_result.json"

def main():
    print(f"Подключение к OpenCTI: {API_URL}")
    try:
        client = OpenCTIApiClient(API_URL, API_TOKEN)
    except ValueError:
        print("[!] Ошибка: Не могу подключиться. Проверь, запущен ли Docker и правильный ли порт.")
        return

    if not os.path.exists(INPUT_JSON):
        print(f"[!] Файл {INPUT_JSON} не найден. Сначала запусти hybrid_extractor_gold.py")
        return

    with open(INPUT_JSON, 'r', encoding='utf-8') as f:
        data = json.load(f)

    print("\n[1/6] Загрузка Группировок (Threat Actors)...")
    actor_objects = []
    for name in data.get("threat_actor", []):
        try:
            actor = client.intrusion_set.create(
                name=name,
                description=f"Imported from report: {data['metadata'].get('source_url', 'Unknown')}",
                update=True
            )
            actor_objects.append(actor)
            print(f"   [+] {name}")
        except Exception as e: print(f"   [!] Error {name}: {e}")

    print("\n[2/6] Загрузка Малвари (Malware)...")
    malware_objects = []
    for name in data.get("malware", []):
        try:
            malware = client.malware.create(
                name=name,
                is_family=True,
                description="Detected by AI Analysis",
                update=True
            )
            malware_objects.append(malware)
            print(f"   [+] {name}")
        except: pass

    print("\n[3/6] Загрузка Инструментов (Tools)...")
    tool_objects = []
    for name in data.get("tools", []):
        try:
            tool = client.tool.create(
                name=name,
                description="Detected by AI Analysis",
                update=True
            )
            tool_objects.append(tool)
        except: pass

    print("\n[4/6] Загрузка MITRE ATT&CK (Techniques)...")
    mitre_objects = []
    for pattern in data.get("attack_patterns", []):
        try:
            mitre_id = pattern.split(" ")[0] if "T" in pattern else pattern
            attack = client.attack_pattern.create(
                name=pattern,
                x_mitre_id=mitre_id,
                description="Extracted Technique",
                update=True
            )
            mitre_objects.append(attack)
            print(f"   [+] MITRE: {pattern}")
        except Exception as e: 
            pass

    print("\n[5/6] Загрузка Индикаторов (IoC)...")
    def create_link(source_id, target_objs, rel_type="uses"):
        for target in target_objs:
            if not target or "id" not in target: continue
            try:
                client.stix_core_relationship.create(
                    fromId=source_id,
                    toId=target["id"],
                    relationship_type=rel_type,
                    update=True
                )
            except: pass

    for i_type, i_list in data["indicators"].items():
        for value in i_list:
            pattern = ""
            main_type = ""
            if i_type == "ipv4":
                pattern = f"[ipv4-addr:value = '{value}']"
                main_type = "IPv4-Addr"
            elif i_type == "domain":
                pattern = f"[domain-name:value = '{value}']"
                main_type = "Domain-Name"
            elif i_type == "hash":
                algo = "SHA-256" if len(value) == 64 else ("SHA-1" if len(value) == 40 else "MD5")
                pattern = f"[file:hashes.'{algo}' = '{value}']"
                main_type = "StixFile"

            try:
                indicator = client.indicator.create(
                    name=value,
                    pattern=pattern,
                    pattern_type="stix",
                    x_opencti_main_observable_type=main_type,
                    update=True
                )
                if malware_objects:
                    create_link(indicator["id"], [malware_objects[0]], "indicates")
            except Exception as e:
                pass

    print("\n[6/6] Построение Графа (Связи)...")
    
    for actor in actor_objects:
        create_link(actor["id"], malware_objects, "uses")
        create_link(actor["id"], tool_objects, "uses")
        create_link(actor["id"], mitre_objects, "uses")

    for actor in actor_objects:
        for country in data.get("targeted_countries", []):
            try:
                loc = client.location.create(
                    name=country,
                    type="Country",
                    update=True
                )
                client.stix_core_relationship.create(
                    fromId=actor["id"],
                    toId=loc["id"],
                    relationship_type="targets",
                    update=True
                )
                print(f"   [+] Target: {country}")
            except: pass

    print("\n[SUCCESS] Импорт завершен! Дубликаты предотвращены.")
    if data.get("summary"):
        print("\n--- AI SUMMARY ---")
        print(data["summary"])
        print("------------------")

if __name__ == "__main__":
    main()