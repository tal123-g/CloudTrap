FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY analyzer.py .

RUN mkdir -p /app/logs/api-service \
             /app/logs/s3-service \
             /app/logs/login-portal \
             /app/reports

ENV API_LOG_FILE=/app/logs/api-service/logs.jsonl
ENV S3_LOG_FILE=/app/logs/s3-service/logs.jsonl
ENV LOGIN_LOG_FILE=/app/logs/login-portal/logs.jsonl
ENV OUTPUT_REPORT=/app/reports/analysis_report.json

CMD ["sh", "-c", "while true; do python analyzer.py; sleep 60; done"]