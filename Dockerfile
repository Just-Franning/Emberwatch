FROM python:3.15-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DATA_DIR=/data \
    STATIC_DIR=/app/frontend \
    PING_BIN=/usr/local/bin/ping \
    TRACEROUTE_BIN=/usr/bin/traceroute \
    FORWARDED_ALLOW_IPS=*

# ping/traceroute for the network tools.
# ping is copied without file capabilities: with no-new-privileges and cap_drop ALL the original
# (cap_net_raw=ep) could not start. The copy uses ICMP datagram sockets, which are allowed via
# net.ipv4.ping_group_range (see compose.yml). traceroute uses UDP and needs no root.
RUN apt-get update \
 && apt-get install -y --no-install-recommends iputils-ping traceroute \
 && cp /usr/bin/ping /usr/local/bin/ping \
 && test -x /usr/local/bin/ping && test -x /usr/bin/traceroute \
 && rm -rf /var/lib/apt/lists/*

RUN useradd --system --uid 10001 --create-home emberwatch \
 && mkdir -p /data && chown emberwatch /data

WORKDIR /app
COPY backend/requirements.txt backend/requirements.txt
RUN pip install -r backend/requirements.txt

COPY backend/app backend/app
COPY frontend frontend

USER emberwatch
EXPOSE 8000
VOLUME ["/data"]

HEALTHCHECK --interval=60s --timeout=5s --start-period=30s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4)"

# Exactly one worker: the collectors run in-process and SQLite has a single writer.
# --proxy-headers trusts X-Forwarded-* only from FORWARDED_ALLOW_IPS (set it to your proxy's address if the
# container port is reachable by anything other than the reverse proxy).
CMD ["uvicorn", "app.main:app", "--app-dir", "backend", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--proxy-headers"]
