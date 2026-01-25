from gliner import GLiNER
import sys
import torch

MODEL_NAME = "urchade/gliner_medium-v2.1"

def extract_gliner(text):
    print("   [GLiNER] Загрузка модели...", file=sys.stderr)
    # Если есть GPU, используем, иначе CPU
    device = "cuda" if torch.cuda.is_available() else "cpu"
    if device == "cpu" and torch.backends.mps.is_available(): device = "mps"
    
    try:
        model = GLiNER.from_pretrained(MODEL_NAME).to(device)
    except:
        model = GLiNER.from_pretrained(MODEL_NAME)

    labels = ["threat actor", "malware", "hacking tool", "ip address", "domain", "file hash"]
    
    results = {
        "threat_actor": set(),
        "malware": set(),
        "tools": set(),
        "indicators": {"ipv4": set(), "hash": set(), "domain": set()}
    }

    chunk = text[:5000] 
    
    print("   [GLiNER] Инференс...", file=sys.stderr)
    entities = model.predict_entities(chunk, labels)
    
    for e in entities:
        txt = e["text"]
        lbl = e["label"]
        
        if lbl == "threat actor": results["threat_actor"].add(txt)
        elif lbl == "malware": results["malware"].add(txt)
        elif lbl == "hacking tool": results["tools"].add(txt)
        elif lbl == "ip address": results["indicators"]["ipv4"].add(txt)
        elif lbl == "domain": results["indicators"]["domain"].add(txt)
        elif lbl == "file hash": results["indicators"]["hash"].add(txt)

    return {k: list(v) if isinstance(v, set) else v for k, v in results.items()}