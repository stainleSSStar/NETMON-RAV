FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    NETMON_DATA_DIR=/data \
    NETMON_FRONTEND_DIR=/app/frontend \
    NETMON_POLL_INTERVAL=60 \
    NETMON_RETENTION_DAYS=30

# iputils-ping gives us the ICMP reachability check; the container is started
# with cap_add NET_RAW so the unprivileged app user can still ping.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

COPY backend/ /app/backend/
COPY frontend/ /app/frontend/

RUN useradd --system --uid 10001 --home /app appuser \
    && mkdir -p /data \
    && chown -R appuser:appuser /data /app

USER appuser
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=4).status==200 else 1)"

CMD ["uvicorn", "backend.app:app", "--host", "0.0.0.0", "--port", "8080"]
