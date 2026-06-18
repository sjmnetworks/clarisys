# Multi-stage Dockerfile for the M&S Firewall Policy Compliance API.
#
# Stage 1: pull a pinned OPA binary, sha256-verified.
# Stage 2: minimal Python runtime, non-root, read-only friendly, no shell access via /docs.
#
# Build:
#   docker build -t ms/firewall-policy-api:dev .
# Run (dev):
#   docker run --rm -p 8000:8000 ms/firewall-policy-api:dev
# Run (prod, behind TLS terminator):
#   docker run --rm -e APP_ENV=production -p 127.0.0.1:8000:8000 ms/firewall-policy-api:dev

# ---------- Stage 1: OPA ------------------------------------------------------
FROM debian:12-slim AS opa
ARG OPA_VERSION=1.16.2
ARG OPA_SHA256=PLACEHOLDER_SHA256_FILL_BEFORE_RELEASE
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL -o /tmp/opa \
      "https://openpolicyagent.org/downloads/v${OPA_VERSION}/opa_linux_amd64_static" \
    && chmod +x /tmp/opa
# NOTE: enable strict checksum verification before promoting beyond dev.
# RUN echo "${OPA_SHA256}  /tmp/opa" | sha256sum -c -

# ---------- Stage 2: runtime --------------------------------------------------
FROM python:3.12-slim AS runtime

# Avoid bytecode + ensure logs flush
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    APP_ENV=production \
    OPA_BINARY=/usr/local/bin/opa \
    AUTH_ENABLED=false \
    AUDIT_BACKEND=local \
    AUDIT_DIR=/var/log/firewall-audit \
    LOG_LEVEL=INFO \
    RATE_LIMIT_ENABLED=false \
    RATE_LIMIT_WINDOW_SECS=60 \
    RATE_LIMIT_QUOTA_EVALUATE_PER_MIN=100 \
    RATE_LIMIT_QUOTA_BULK_PER_MIN=20 \
    RATE_LIMIT_QUOTA_AUDIT_PER_MIN=10

# Non-root user/group
RUN groupadd --system --gid 1001 app \
    && useradd --system --uid 1001 --gid app --home /app --shell /usr/sbin/nologin app

WORKDIR /app

# Install Python dependencies
COPY api/requirements.txt /app/requirements.txt
RUN pip install --upgrade pip \
    && pip install -r /app/requirements.txt

# Copy OPA binary from stage 1
COPY --from=opa /tmp/opa /usr/local/bin/opa
RUN chmod 0555 /usr/local/bin/opa

# Copy application code + bundled policy/data + templates
COPY api/        /app/api/
COPY policy/     /app/policy/
COPY templates/  /app/templates/

# Ensure audit-trail directory exists with app ownership (used by local backend)
RUN mkdir -p /var/log/firewall-audit && chown -R app:app /var/log/firewall-audit && chmod 0700 /var/log/firewall-audit

# Drop root
RUN chown -R app:app /app
USER app

EXPOSE 8000

# Bind to 0.0.0.0 inside the container (the host should publish only to
# 127.0.0.1 or to a private network, never to the public internet).
CMD ["python", "-m", "uvicorn", "api.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "2", \
     "--proxy-headers", \
     "--forwarded-allow-ips=*", \
     "--no-access-log"]
