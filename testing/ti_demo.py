import ollama
import json

raw_report_text = """
Группировка TWELVE — одна из самых активных атакующих Россию хактивистских группировок.
Используемое ПО: ADRecon, Advanced IP Scanner, AnyDesk, Babuk, Cobalt Strike, LockBit 3.0, Mimikatz, ngrok.
Вредоносные действия атакующие производили с подконтрольного им IP-адреса 103.14.26.208.
Обычно злоумышленники получали первоначальный доступ используя RDP.
"""

system_prompt = """
Ты — эксперт по Threat Intelligence (TI). Твоя задача — извлечь сущности из текста.
Верни ответ СТРОГО в формате JSON. Не пиши ничего лишнего, только JSON.
Поля:
- Actor (кто атакует)
- Target_Country (кого атакуют)
- Tools (список инструментов)
- IoCs (IP-адреса, домены, хеши)
- TTPs (методы атаки)
"""

print("--- ЗАПУСК ЛОКАЛЬНОГО АГЕНТА (Qwen 2.5) ---")

try:
    response = ollama.chat(model='qwen2.5', messages=[
        {'role': 'system', 'content': system_prompt},
        {'role': 'user', 'content': raw_report_text},
    ])

    content = response['message']['content']

    if "```json" in content:
        content = content.replace("```json", "").replace("```", "")

    data = json.loads(content)

    print("\n--- УСПЕХ! ПОЛУЧЕННЫЙ JSON: ---")
    print(json.dumps(data, indent=4, ensure_ascii=False))

except Exception as e:
    print(f"Произошла ошибка: {e}")
    print("Сырой ответ модели:", response['message']['content'])