FROM python:3.11-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      tesseract-ocr \
      libtesseract-dev \
      libleptonica-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN pip install --no-cache-dir -r requirements.txt

CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:10000"]
