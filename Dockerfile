FROM python:3.11-slim

# Системные зависимости для OCR и pdf
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-rus \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Зависимости (сначала requirements для кеширования слоя)
COPY requirements-docker.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Код проекта
COPY . .

# Streamlit порт
EXPOSE 8501

# По умолчанию — Streamlit UI
CMD ["streamlit", "run", "web_ui.py", \
     "--server.headless", "true", \
     "--server.port", "8501", \
     "--server.address", "0.0.0.0"]
