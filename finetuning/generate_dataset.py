import ollama
import json
import random
import pandas as pd
from tqdm import tqdm

TEACHER_MODEL = "qwen2.5:14b"
OUTPUT_FILE = "telegram_dataset.jsonl"
SAMPLES_PER_CLASS = 50

PROMPTS = {
    "threat": """
    You are a cybersecurity expert. Generate 5 examples of Telegram posts from hacker channels (like LockBit, Lapsus$, breaches).
    The posts should contain: leaked databases, ransomware announcements, or DDoS claims.
    Format: JSON list of strings. Do not add numbering.
    Example: ["We hacked NASA. 50GB data for sale.", "DDoS attack on Google started."]
    """,
    
    "spam": """
    You are a spam generator. Generate 5 examples of garbage Telegram posts often found in cyber channels.
    Topics: crypto scams, "carding" courses, selling credit cards, drugs, or off-topic ads.
    Format: JSON list of strings.
    Example: ["Buy Bitcoin cheap!", "Best carding course 2025, DM me.", "Join our pump and dump channel."]
    """
}

def generate_data():
    dataset = []
    
    print(f"🚀 Генерация датасета с помощью {TEACHER_MODEL}...")
    
    for _ in tqdm(range(SAMPLES_PER_CLASS // 5), desc="Generating Threats"):
        try:
            resp = ollama.chat(model=TEACHER_MODEL, messages=[{'role': 'user', 'content': PROMPTS["threat"]}])
            text = resp['message']['content']
            start = text.find('[')
            end = text.rfind(']') + 1
            examples = json.loads(text[start:end])
            
            for ex in examples:
                dataset.append({"text": ex, "label": 1})
        except: pass

    for _ in tqdm(range(SAMPLES_PER_CLASS // 5), desc="Generating Spam"):
        try:
            resp = ollama.chat(model=TEACHER_MODEL, messages=[{'role': 'user', 'content': PROMPTS["spam"]}])
            text = resp['message']['content']
            start = text.find('[')
            end = text.rfind(']') + 1
            examples = json.loads(text[start:end])
            
            for ex in examples:
                dataset.append({"text": ex, "label": 0})
        except: pass

    random.shuffle(dataset)
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for entry in dataset:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            
    print(f"✅ Готово! Сохранено {len(dataset)} примеров в {OUTPUT_FILE}")
    
    df = pd.DataFrame(dataset)
    print("\nПримеры данных:")
    print(df.head())

if __name__ == "__main__":
    generate_data()