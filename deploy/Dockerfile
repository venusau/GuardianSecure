# Single image for all GuardianSecure services (gateway, scan-worker, notifier).
# The process started is chosen per-service via `command:` in docker-compose.yml,
# so we build one image and run it three ways.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# System deps for psycopg2 / building wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

# Default command (overridden per service in compose)
CMD ["python", "app.py"]
