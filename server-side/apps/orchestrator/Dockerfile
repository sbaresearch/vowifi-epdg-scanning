# Base: the scanner image (scanner package, psycopg, pg_dump); compose builds it first.
FROM epdg-scanner

WORKDIR /app

COPY requirements.txt /app/orchestrator-requirements.txt
RUN pip install --no-cache-dir -r /app/orchestrator-requirements.txt

COPY vantage /app/vantage

CMD ["python3", "-u", "-m", "vantage.main"]
