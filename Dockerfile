# Bastion exporter image.
# Serves /metrics, the detection-ingest webhook, /healthz and /status.
FROM python:3.11-slim

# Don't write .pyc, flush stdout/stderr immediately (clean container logs).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install deps first for layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the package + sample assets + example configs.
COPY bastion ./bastion
COPY sample ./sample
COPY config.example.yaml slos.example.yaml runbooks.example.yaml ./

EXPOSE 9300

# Default config can be overridden with BASTION_CONFIG or --config.
ENV BASTION_CONFIG=config.example.yaml

# Lightweight liveness probe against the always-200 health endpoint.
HEALTHCHECK --interval=15s --timeout=3s --retries=5 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:9300/healthz', timeout=2).status==200 else 1)"

CMD ["python", "-m", "bastion.exporter"]
