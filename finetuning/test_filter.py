import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer
import sys

BASE_MODEL = "Qwen/Qwen2.5-3B-Instruct"
ADAPTER_DIR = "diploma_filter_adapter"

def classify_text(model, tokenizer, text):
    messages = [
        {"role": "system", "content": "You are a cybersecurity analyst. Classify the text as 'THREAT' or 'SPAM'."},
        {"role": "user", "content": text}
    ]
    
    text_prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = tokenizer([text_prompt], return_tensors="pt")

    with torch.no_grad():
        generated_ids = model.generate(
            **inputs,
            max_new_tokens=10, 
            pad_token_id=tokenizer.eos_token_id,
            do_sample=False,
            temperature=None,
            top_p=None
        )
    
    response = tokenizer.batch_decode(generated_ids[:, inputs.input_ids.shape[1]:], skip_special_tokens=True)[0]
    return response.strip()

def main():
    print(f"🚀 Загрузка базовой модели {BASE_MODEL} на CPU (для стабильности)...")
    try:
        base_model = AutoModelForCausalLM.from_pretrained(
            BASE_MODEL,
            torch_dtype=torch.float32, 
            device_map="cpu" 
        )
        tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
        
        print(f"🧠 Подключение адаптера {ADAPTER_DIR}...")
        model = PeftModel.from_pretrained(base_model, ADAPTER_DIR)
        model.eval() 
        
    except Exception as e:
        print(f"Ошибка загрузки: {e}")
        return

    test_cases = [
        "DDoS attack targeting Ministry of Finance starts at 14:00 UTC.",
        "Buy premium Viagra and Cialis, cheap delivery!",
        "We have successfully encrypted the servers of a large logistics company. Contact for ransom.",
        "Join my crypto pump group, 1000% profit guaranteed!",
        "Leaked SQL database of US voters available for sale.",
        "Looking for a job? Earn $500/day working from home.",
        "Exploit for CVE-2025-1234 published on GitHub.",
        "Best carding tutorial 2026, dm me telegram @scammer"
    ]

    print("\n=== РЕЗУЛЬТАТЫ ТЕСТИРОВАНИЯ (FILTER v1.0) ===")
    print(f"{'TEXT (First 50 chars)':<60} | {'PREDICTION':<10}")
    print("-" * 75)

    for text in test_cases:
        prediction = classify_text(model, tokenizer, text)
        
        if "SPAM" in prediction.upper():
            color = "\033[91m"
        elif "THREAT" in prediction.upper():
            color = "\033[92m"
        else:
            color = "\033[93m"
            
        reset = "\033[0m"
        
        short_text = (text[:57] + '...') if len(text) > 57 else text
        print(f"{short_text:<60} | {color}{prediction}{reset}")

if __name__ == "__main__":
    main()