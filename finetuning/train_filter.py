import json
import torch
from datasets import Dataset
from transformers import AutoTokenizer, AutoModelForCausalLM, TrainingArguments
from trl import SFTTrainer, SFTConfig
from peft import LoraConfig, get_peft_model, TaskType
import sys
import os

MODEL_NAME = "Qwen/Qwen2.5-3B-Instruct" 
DATA_FILE = "telegram_dataset.jsonl"
OUTPUT_DIR = "diploma_filter_adapter"

def main():
    print(f"🚀 Загрузка модели {MODEL_NAME} на MPS (Mac GPU)...")
    
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    tokenizer.pad_token = tokenizer.eos_token 

    model = AutoModelForCausalLM.from_pretrained(
        MODEL_NAME,
        torch_dtype=torch.float16,
        device_map="auto"
    )

    peft_config = LoraConfig(
        r=16,
        lora_alpha=32,
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]
    )

    print("📦 Подготовка датасета...")
    data = []
    if not os.path.exists(DATA_FILE):
        print(f"Ошибка: Файл {DATA_FILE} не найден! Сначала запусти generate_dataset.py")
        return

    with open(DATA_FILE, "r", encoding="utf-8") as f:
        for line in f:
            item = json.loads(line)
            label_text = "THREAT" if item["label"] == 1 else "SPAM"
            
            messages = [
                {"role": "system", "content": "You are a cybersecurity analyst. Classify the text as 'THREAT' or 'SPAM'."},
                {"role": "user", "content": item["text"]},
                {"role": "assistant", "content": label_text}
            ]
            text_prompt = tokenizer.apply_chat_template(messages, tokenize=False)
            data.append({"text": text_prompt})

    dataset = Dataset.from_list(data)

    training_args = TrainingArguments(
        output_dir=OUTPUT_DIR,
        num_train_epochs=3,
        per_device_train_batch_size=2,
        gradient_accumulation_steps=4,
        learning_rate=2e-4,
        logging_steps=5,
        save_strategy="no",
        report_to="none",
    )

    print("🔥 Начинаем обучение (это займет 5-10 минут)...")
    
    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=dataset,
        peft_config=peft_config,
    )

    trainer.train()

    print(f"💾 Сохраняем адаптер в {OUTPUT_DIR}...")
    trainer.save_model(OUTPUT_DIR)
    print("✅ ГОТОВО! Модель обучена.")

if __name__ == "__main__":
    main()