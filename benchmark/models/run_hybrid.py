import re
import ollama
import json
import sys

MODEL_NAME = "qwen2.5:14b"
CHUNK_SIZE = 4000
OVERLAP = 500

REGEX_PATTERNS = {
    "ipv4": r"\b(?!127\.|10\.|192\.168\.)(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    "domain": r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b",
    "hash": r"\b[a-fA-F0-9]{32,64}\b",
    "mitre": r"\bT\d{4}(?:\.\d{3})?\b"
}

def extract_hybrid(text):
    print(f"   [Hybrid] Запуск Regex...", file=sys.stderr)
    results = {
        "threat_actor": set(), "malware": set(), "tools": set(), "attack_patterns": set(),
        "indicators": {"ipv4": set(), "domain": set(), "hash": set()}
    }

    results["indicators"]["ipv4"].update(re.findall(REGEX_PATTERNS["ipv4"], text))
    results["indicators"]["hash"].update(re.findall(REGEX_PATTERNS["hash"], text))
    results["attack_patterns"].update(re.findall(REGEX_PATTERNS["mitre"], text))
    
    raw_domains = re.finditer(REGEX_PATTERNS["domain"], text)
    ignore = {'.exe', '.dll', '.sys', '.png', '.jpg', '.js', '.html', '.json'}
    for m in raw_domains:
        d = m.group(0).lower()
        if not any(d.endswith(x) for x in ignore):
            results["indicators"]["domain"].add(d)

    print(f"   [Hybrid] Запуск LLM ({MODEL_NAME})...", file=sys.stderr)
    
    chunks = []
    start = 0
    while start < len(text):
        chunks.append(text[start : start + CHUNK_SIZE])
        start += CHUNK_SIZE - OVERLAP
    
    schema = {
        "threat_actor": ["Name"],
        "malware": ["Name"],
        "tools": ["Name"]
    }
    
    for chunk in chunks:
        try:
            resp = ollama.chat(
                model=MODEL_NAME,
                messages=[{
                    'role': 'system', 
                    'content': f"Extract CTI entities JSON: {json.dumps(schema)}. Ignore IPs/Hashes."
                }, {'role': 'user', 'content': chunk}],
                format='json',
                options={'temperature': 0.0}
            )
            
            if 'message' in resp:
                data = json.loads(resp['message']['content'])
                if "threat_actor" in data: results["threat_actor"].update(data["threat_actor"])
                if "malware" in data: results["malware"].update(data["malware"])
                if "tools" in data: results["tools"].update(data["tools"])
        except Exception as e:
            print(f"   [Hybrid Warning] Ошибка чанка: {e}", file=sys.stderr)

    final_data = {}
    for key, value in results.items():
        if isinstance(value, set):
            final_data[key] = list(value)
        elif isinstance(value, dict):
            final_data[key] = {k: list(v) if isinstance(v, set) else v for k, v in value.items()}
        else:
            final_data[key] = value
            
    return final_data