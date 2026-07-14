FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY zulip/ ./zulip/

CMD ["python", "zulip/key_collision_bot.py"]
