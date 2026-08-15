# syntax=docker/dockerfile:1.7

# Prefix for the base images. CI sets this to GitLab's dependency proxy so
# node/python are pulled through the cache rather than Docker Hub, which
# both speeds up builds and avoids anonymous pull limits. Empty locally.
ARG BASE_REGISTRY=

# ---------------------------------------------------------------------------
# Stage 1: build the Vue admin UI.
#
# The output is copied into the Python image and served by FastAPI itself, so
# the whole stack is one container with no separate web server to configure.
# outDir is overridden here because the checked-in vite config writes straight
# into the backend tree, which does not exist in this stage.
# ---------------------------------------------------------------------------
FROM ${BASE_REGISTRY}node:22-alpine AS frontend

WORKDIR /build

# Manifests first: the dependency layer then caches across source edits.
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install --no-audit --no-fund

COPY frontend/ ./
RUN npx vite build --outDir /build/dist --emptyOutDir


# ---------------------------------------------------------------------------
# Stage 2: Python dependencies into a venv, isolated from the app source so
# editing code does not reinstall the dependency tree.
# ---------------------------------------------------------------------------
FROM ${BASE_REGISTRY}python:3.12-slim AS deps

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt /tmp/requirements.txt
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip setuptools wheel \
    && /opt/venv/bin/pip install -r /tmp/requirements.txt


# ---------------------------------------------------------------------------
# Stage 3: runtime.
# ---------------------------------------------------------------------------
FROM ${BASE_REGISTRY}python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    STORAGE_PATH=/data/packages

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin minireg

COPY --from=deps /opt/venv /opt/venv

WORKDIR /app
COPY --chown=minireg:minireg backend/app /app/app
COPY --chown=minireg:minireg backend/pyproject.toml /app/
# The CLI is served to users from /api/cli/download, so it ships in the image.
COPY --chown=minireg:minireg cli /app/cli
COPY --from=frontend --chown=minireg:minireg /build/dist /app/app/static

RUN mkdir -p /data/packages && chown -R minireg:minireg /data

USER minireg
EXPOSE 8000
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8000/health || exit 1

# One worker per container. The download-log batcher and the housekeeping loop
# are per-process, so scale out with replicas rather than --workers.
CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--proxy-headers", \
     "--forwarded-allow-ips", "*", \
     "--no-access-log"]
