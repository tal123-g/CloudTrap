FROM python:3.11-slim

RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

RUN mkdir -p /app/logs

ENV LOG_FILE=/app/logs/logs.jsonl
ENV CLOUD_PROVIDER=aws

EXPOSE 5001

CMD ["python", "app.py"]