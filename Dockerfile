# Python 3.12 to match the deployed host interpreter — the dashboard code uses
# 3.12-only f-string syntax (backslashes inside f-string expressions), so it
# will NOT parse on 3.10/3.11. The app is pure-stdlib, so there are no runtime
# pip dependencies to install.
FROM python:3.12-slim

# tzdata: the dashboard renders timestamps in America/New_York via zoneinfo,
# which needs the system tz database (not present in -slim images).
RUN apt-get update \
    && apt-get install -y --no-install-recommends tzdata \
    && rm -rf /var/lib/apt/lists/*

# Run as a non-root user. It only needs to read the (world-readable) Cowrie logs
# and write the /data volume, and it binds 9999 (a non-privileged port). The
# compose file adds the host's cowrie group (gid 988) as a supplementary group
# so log reads keep working even if those files stop being world-readable.
RUN groupadd -g 10001 app && useradd -u 10001 -g 10001 -M -s /usr/sbin/nologin app

# Defaults target a generic bridge-network run (docker run -p ...). The compose
# file overrides SERVE_HOST / OLLAMA_URL for the host-network deployment.
ENV PYTHONUNBUFFERED=1 \
    TZ=America/New_York \
    HONEYPOT_DATA_DIR=/data \
    COWRIE_LOG_PATH=/cowrie-logs/cowrie.json \
    OLLAMA_URL=http://host.docker.internal:11434 \
    SERVE_HOST=0.0.0.0 \
    SERVE_PORT=9999 \
    REGEN_INTERVAL=300

WORKDIR /app
COPY app/ /app/

RUN mkdir -p /data && chown 10001:10001 /data
VOLUME ["/data"]
USER 10001:10001
EXPOSE 9999

# scheduler.py supervises serve.py + periodic generate/analytics.
CMD ["python3", "scheduler.py"]
