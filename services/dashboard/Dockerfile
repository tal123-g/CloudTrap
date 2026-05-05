FROM python:3.11-slim

RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY static/ static/

RUN mkdir -p /app/reports

ENV OUTPUT_REPORT=/app/reports/analysis_report.json

EXPOSE 5003

CMD ["python", "app.py"]