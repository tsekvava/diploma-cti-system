import os
import json
import re
import ollama
from bs4 import BeautifulSoup
from datetime import datetime

INPUT_FILE = "GOLD SALEM html.html"
OUTPUT_FILE = "final_extraction_result.json"
MODEL_NAME = "qwen2.5:14b"
SOURCE_URL = "https://www.sophos.com/en-us/blog/gold-salem-tradecraft-for-deploying-warlock-ransomware" 

CHUNK_SIZE = 6000
OVERLAP = 500

REGEX_PATTERNS = {
    "ipv4": r"\b(?!127\.|10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.)(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    "domain": r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b",
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "sha1": r"\b[a-fA-F0-9]{40}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "cve": r"CVE-\d{4}-\d{4,7}",
    "mitre_id": r"\bT\d{4}(?:\.\d{3})?\b" 
}

IGNORE_EXTENSIONS = {'.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.ttf', '.html', '.php', '.json', '.xml', '.txt'}
IGNORE_DOMAINS = {'sophos.com', 'google.com', 'microsoft.com', 'schema.org', 'w3.org', 'twitter.com', 'linkedin.com', 'facebook.com', 'cloudflare.com'}

class HybridExtractor:
    def __init__(self, input_file, output_file, model_name):
        self.input_file = input_file
        self.output_file = output_file
        self.model_name = model_name
        self.full_text = ""
        self.results = {
            "metadata": {
                "source_file": input_file, 
                "source_url": SOURCE_URL,
                "extraction_date": str(datetime.now())
            },
            "summary": "", 
            "threat_actor": set(),
            "malware": set(),
            "tools": set(),
            "attack_patterns": set(),
            "indicators": {
                "ipv4": set(),
                "domain": set(),
                "hash": set(),
            },
            "vulnerabilities": set(),
            "targeted_countries": set()
        }

    def clean_html(self):
        if not os.path.exists(self.input_file):
            print(f"[ERROR] Файл {self.input_file} не найден.")
            return False
        print(f"[1/6] Читаю и чищу HTML...")
        with open(self.input_file, 'r', encoding='utf-8') as f:
            soup = BeautifulSoup(f.read(), 'html.parser')
        
        for tag in soup(["script", "style", "nav", "footer", "header", "meta", "noscript", "svg", "button", "input", "aside"]):
            tag.extract()
            
        text = soup.get_text(separator=' ')
        self.full_text = ' '.join(text.split())
        print(f"      -> Длина чистого текста: {len(self.full_text)} символов.")
        return True

    def generate_summary(self):
        """НОВЫЙ ЭТАП: Генерируем краткое описание инцидента"""
        print(f"[2/6] Генерирую Summary отчета с помощью LLM...")
        
        intro_text = self.full_text[:6000]
        
        prompt = """
        You are a Senior Threat Intelligence Analyst.
        Read the beginning of this threat report and write a concise SUMMARY (3-4 sentences).
        Include: Who is the attacker? What did they do? Who did they target?
        Do not use markdown. Just plain text.
        """
        
        try:
            response = ollama.chat(
                model=self.model_name,
                messages=[
                    {'role': 'system', 'content': prompt},
                    {'role': 'user', 'content': intro_text},
                ],
                options={'temperature': 0.3}
            )
            summary = response['message']['content'].strip()
            self.results["summary"] = summary
            print(f"      -> Summary готово ({len(summary)} символов).")
        except Exception as e:
            print(f"      [!] Не удалось создать Summary: {e}")

    def extract_with_regex(self):
        print("[3/6] Запуск Regex-движка (IoC + MITRE)...")
        
        self.results["indicators"]["ipv4"].update(re.findall(REGEX_PATTERNS["ipv4"], self.full_text))
        
        hashes = (re.findall(REGEX_PATTERNS["md5"], self.full_text) + 
                  re.findall(REGEX_PATTERNS["sha1"], self.full_text) + 
                  re.findall(REGEX_PATTERNS["sha256"], self.full_text))
        self.results["indicators"]["hash"].update(hashes)
        
        self.results["vulnerabilities"].update(re.findall(REGEX_PATTERNS["cve"], self.full_text))

        mitre_ids = re.findall(REGEX_PATTERNS["mitre_id"], self.full_text)
        self.results["attack_patterns"].update(mitre_ids)

        raw_domains = re.finditer(REGEX_PATTERNS["domain"], self.full_text)
        for match in raw_domains:
            domain = match.group(0).lower()
            if any(domain.endswith(ext) for ext in IGNORE_EXTENSIONS): continue
            if domain in IGNORE_DOMAINS: continue
            if len(domain) < 4: continue
            self.results["indicators"]["domain"].add(domain)

        print(f"      -> Найдено: {len(mitre_ids)} MITRE, {len(hashes)} Хешей, {len(self.results['indicators']['domain'])} Доменов.")

    def _chunk_text(self):
        start = 0
        while start < len(self.full_text):
            end = start + CHUNK_SIZE
            yield self.full_text[start:end]
            start += CHUNK_SIZE - OVERLAP

    def extract_with_llm(self):
        chunks = list(self._chunk_text())
        print(f"[4/6] Запуск LLM для глубокого анализа ({len(chunks)} чанков)...")

        schema = {
            "threat_actor": ["Name"],
            "malware": ["Name"],
            "tools": ["Name"],
            "attack_patterns": ["Technique Name (e.g. Phishing)"],
            "targeted_countries": ["Name"]
        }

        system_prompt = f"""
        You are a Cyber Threat Intelligence Expert. Extract semantic entities.
        Rules:
        1. Extract Threat Actors, Malware, Tools, and Targeted Countries.
        2. Look for MITRE ATT&CK techniques descriptions (e.g., "LSASS dumping", "Lateral Movement").
        3. IGNORE IPs, Hashes, Domains.
        4. Return JSON matching: {json.dumps(schema)}
        """

        for i, chunk in enumerate(chunks):
            print(f"      -> Чанк {i+1}/{len(chunks)}...")
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
                
                for key in ["threat_actor", "malware", "tools", "attack_patterns", "targeted_countries"]:
                    if key in data and isinstance(data[key], list):
                        self.results[key].update(data[key])

            except Exception as e:
                print(f"      [!] Ошибка в чанке {i+1}: {e}")

    def save_results(self):
        print(f"[5/6] Подготовка JSON...")
        
        final_json = {
            "metadata": self.results["metadata"],
            "summary": self.results["summary"],
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
        
        print(f"[6/6] ГОТОВО! Файл: {self.output_file}")
        print("="*50)
        print(f"SUMMARY: {final_json['summary'][:100]}...")
        print(f"MITRE IDs: {len(final_json['attack_patterns'])}")

if __name__ == "__main__":
    extractor = HybridExtractor(INPUT_FILE, OUTPUT_FILE, MODEL_NAME)
    if extractor.clean_html():
        extractor.generate_summary()
        extractor.extract_with_regex()
        extractor.extract_with_llm()
        extractor.save_results()