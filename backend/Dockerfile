FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# Docker CLI only (no daemon). It talks to the restricted socket proxy, never to the raw host socket.
COPY --from=docker:27-cli /usr/local/bin/docker /usr/local/bin/docker
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --create-home --uid 10002 appuser \
    && mkdir -p /data /workspaces && chown -R appuser /data /workspaces /app
USER appuser
EXPOSE 8000
ENTRYPOINT ["./entrypoint.sh"]
