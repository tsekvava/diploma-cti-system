import os
import json
import re
import ollama
from bs4 import BeautifulSoup
from datetime import datetime

INPUT_FILE = "GOLD SALEM html.html"
OUTPUT_FILE = "hybrid_extraction_result_final.json"
MODEL_NAME = "qwen2.5:14b"
CHUNK_SIZE = 5000
OVERLAP = 500

REGEX_PATTERNS = {
    "ipv4": r"\b(?!127\.|10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.)(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    "domain": r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b",
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "sha1": r"\b[a-fA-F0-9]{40}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "cve": r"CVE-\d{4}-\d{4,7}",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "mitre_id": r"\bT\d{4}(?:\.\d{3})?\b" 
}

IGNORE_EXTENSIONS = {'.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.ttf', '.html', '.php', '.json', '.xml'}
IGNORE_DOMAINS = {'sophos.com', 'google.com', 'microsoft.com', 'schema.org', 'w3.org', 'twitter.com', 'linkedin.com', 'facebook.com'}

class HybridExtractor:
    def __init__(self, input_file, output_file, model_name):
        self.input_file = input_file
        self.output_file = output_file
        self.model_name = model_name
        self.full_text = ""
        self.results = {
            "metadata": {"source": input_file, "date": str(datetime.now())},
            "threat_actor": set(),
            "malware": set(),
            "tools": set(),
            "attack_patterns": set(),
            "indicators": {
                "ipv4": set(),
                "domain": set(),
                "hash": set(),
                "email": set()
            },
            "vulnerabilities": set(),
            "targeted_countries": set()
        }

    def clean_html(self):
        if not os.path.exists(self.input_file):
            print(f"[ERROR] Файл {self.input_file} не найден.")
            return False
        print(f"[1/5] Читаю и чищу HTML: {self.input_file}...")
        with open(self.input_file, 'r', encoding='utf-8') as f:
            soup = BeautifulSoup(f.read(), 'html.parser')
        for tag in soup(["script", "style", "nav", "footer", "header", "meta", "noscript", "svg", "button", "input"]):
            tag.extract()
        text = soup.get_text(separator=' ')
        self.full_text = ' '.join(text.split())
        print(f"      -> Длина текста: {len(self.full_text)} символов.")
        return True

    def extract_with_regex(self):
        print("[2/5] Запуск Regex-движка (IoC + MITRE IDs)...")
        self.results["indicators"]["ipv4"].update(re.findall(REGEX_PATTERNS["ipv4"], self.full_text))
        
        all_hashes = set(re.findall(REGEX_PATTERNS["md5"], self.full_text) + 
                         re.findall(REGEX_PATTERNS["sha1"], self.full_text) + 
                         re.findall(REGEX_PATTERNS["sha256"], self.full_text))
        self.results["indicators"]["hash"].update(all_hashes)
        
        self.results["vulnerabilities"].update(re.findall(REGEX_PATTERNS["cve"], self.full_text))

        mitre_ids = re.findall(REGEX_PATTERNS["mitre_id"], self.full_text)
        self.results["attack_patterns"].update(mitre_ids)

        raw_domains = re.finditer(REGEX_PATTERNS["domain"], self.full_text)
        for match in raw_domains:
            domain = match.group(0).lower()
            if any(domain.endswith(ext) for ext in IGNORE_EXTENSIONS): continue
            if domain in IGNORE_DOMAINS: continue
            self.results["indicators"]["domain"].add(domain)

        print(f"      -> Regex нашел: {len(mitre_ids)} MITRE IDs, {len(all_hashes)} Хешей.")

    def _chunk_text(self):
        start = 0
        while start < len(self.full_text):
            end = start + CHUNK_SIZE
            yield self.full_text[start:end]
            start += CHUNK_SIZE - OVERLAP

    def extract_with_llm(self):
        chunks = list(self._chunk_text())
        print(f"[3/5] Запуск LLM ({self.model_name}) для {len(chunks)} чанков...")

        schema = {
            "threat_actor": ["Name"],
            "malware": ["Name"],
            "tools": ["Name"],
            "attack_patterns": ["TXXXX - Technique Name"],
            "targeted_countries": ["Name"]
        }

        system_prompt = f"""
        You are a Cyber Threat Intelligence Expert. Extract semantic entities.
        
        FOCUS ON:
        1. Threat Actors (Groups)
        2. Malware Families
        3. Tools (Software used for attack)
        4. MITRE ATT&CK Techniques (Look for descriptions of behaviors like 'Lateral Movement via SMB', 'Phishing', 'DLL Sideloading'). 
           Try to output them as "TXXXX - Name" if possible, or just the Technique Name.
        5. Targeted Countries
        
        IGNORE IPs, Hashes, Domains (already extracted).
        
        Response format: JSON matching this schema: {json.dumps(schema)}
        """

        for i, chunk in enumerate(chunks):
            print(f"      -> Обработка чанка {i+1}/{len(chunks)}...")
            try:
                response = ollama.chat(
                    model=self.model_name,
                    messages=[
                        {'role': 'system', 'content': system_prompt},
                        {'role': 'user', 'content': chunk},
                    ],
                    format='json',
                    options={'temperature': 0.1, 'num_ctx': 4096}
                )
                data = json.loads(response['message']['content'])
                
                if "threat_actor" in data: self.results["threat_actor"].update(data["threat_actor"])
                if "malware" in data: self.results["malware"].update(data["malware"])
                if "tools" in data: self.results["tools"].update(data["tools"])
                if "attack_patterns" in data: self.results["attack_patterns"].update(data["attack_patterns"])
                if "targeted_countries" in data: self.results["targeted_countries"].update(data["targeted_countries"])

            except Exception as e:
                print(f"      [!] Ошибка в чанке {i+1}: {e}")

    def save_results(self):
        print(f"[4/5] Подготовка итогового JSON...")
        
        final_json = {
            "threat_actor": sorted(list(self.results["threat_actor"])),
            "malware": sorted(list(self.results["malware"])),
            "tools": sorted(list(self.results["tools"])),
            "attack_patterns": sorted(list(self.results["attack_patterns"])),
            "vulnerabilities": sorted(list(self.results["vulnerabilities"])),
            "indicators": {
                "ipv4": sorted(list(self.results["indicators"]["ipv4"])),
                "domain": sorted(list(self.results["indicators"]["domain"])),
                "hash": sorted(list(self.results["indicators"]["hash"])),
            },
            "targeted_countries": sorted(list(self.results["targeted_countries"]))
        }

        with open(self.output_file, 'w', encoding='utf-8') as f:
            json.dump(final_json, f, ensure_ascii=False, indent=4)
        
        print(f"[5/5] УСПЕХ! Результат: {self.output_file}")
        print("-" * 40)
        print(f"Actors:  {len(final_json['threat_actor'])}")
        print(f"Malware: {len(final_json['malware'])}")
        print(f"MITRE:   {len(final_json['attack_patterns'])}")
        print(f"IoCs:    {len(final_json['indicators']['hash']) + len(final_json['indicators']['domain'])}")

if __name__ == "__main__":
    extractor = HybridExtractor(INPUT_FILE, OUTPUT_FILE, MODEL_NAME)
    if extractor.clean_html():
        extractor.extract_with_regex()
        extractor.extract_with_llm()
        extractor.save_results()