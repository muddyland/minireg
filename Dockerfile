# syntax=docker/dockerfile:1.7

# Optional prefix for the base images, e.g. a mirror ("<host>/<path>/",
# trailing slash included). Empty means Docker Hub.
ARG BASE_REGISTRY=

# The Python images for the dependency stage and the runtime stage. Both
# default to python:3.14-slim. To build on a hardened, shell-less runtime
# instead, set them to a matching Docker Hardened Images pair: the "-dev"
# variant with a shell and pip to install into, and its runtime sibling to
# ship. Both must use the same libc; slim and DHI's debian13 variant are glibc.
#
#   --build-arg PYTHON_BUILDER_IMAGE=dhi.io/python:3.14-debian13-dev
#   --build-arg PYTHON_RUNTIME_IMAGE=dhi.io/python:3.14-debian13
#
# CI does this when USE_DHI=true; see docs/installation.md#hardened-base-image.
ARG PYTHON_BUILDER_IMAGE=${BASE_REGISTRY}python:3.14-slim
ARG PYTHON_RUNTIME_IMAGE=${BASE_REGISTRY}python:3.14-slim

# ---------------------------------------------------------------------------
# Stage 1: build the Vue admin UI.
#
# The output is copied into the Python image and served by FastAPI itself, so
# the whole stack is one container with no separate web server to configure.
# outDir is overridden here because the checked-in vite config writes straight
# into the backend tree, which does not exist in this stage.
# ---------------------------------------------------------------------------
FROM ${BASE_REGISTRY}node:22-alpine AS frontend
# Unset unless passed; npm then uses its default registry.
ARG NPM_CONFIG_REGISTRY

WORKDIR /build

# Manifests first: the dependency layer then caches across source edits.
COPY frontend/package.json frontend/package-lock.json ./
# `ci` not `install`: it installs exactly what the lockfile pins and fails if
# the two have drifted, so an image build cannot quietly resolve different
# dependencies than CI tested.
RUN npm ci --no-audit --no-fund

COPY frontend/ ./
RUN npx vite build --outDir /build/dist --emptyOutDir


# ---------------------------------------------------------------------------
# Stage 2: Python dependencies, isolated from the app source so editing code
# does not reinstall the dependency tree.
#
# --target into a plain directory rather than a venv: a venv records the
# builder's interpreter path, and slim keeps it in /usr/local while DHI keeps
# it in /usr. A directory on PYTHONPATH works on either.
# ---------------------------------------------------------------------------
FROM ${PYTHON_BUILDER_IMAGE} AS deps
# Unset unless passed; pip then uses PyPI.
ARG PIP_INDEX_URL

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

# The lock, not the range file. requirements.txt carries floors and caps, so
# two builds of the same commit could resolve different dependency trees --
# which is not a property a registry that exists to secure other people's
# dependencies should have. --require-hashes makes every artifact verified.
# --only-binary: every locked package ships a wheel for this interpreter, so
# no compiler is needed and none is installed.
COPY backend/requirements.lock /tmp/requirements.lock
RUN pip install --only-binary=:all: --require-hashes --target /opt/pydeps -r /tmp/requirements.lock \
    && mkdir -p /skel/data/packages


# ---------------------------------------------------------------------------
# Stage 3: runtime.
#
# No RUN steps: the hardened runtime has no shell, so everything here is a
# COPY or metadata and the stage builds the same way on either base.
# ---------------------------------------------------------------------------
FROM ${PYTHON_RUNTIME_IMAGE} AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/opt/pydeps \
    STORAGE_PATH=/data/packages \
    UVICORN_FORWARDED_ALLOW_IPS=127.0.0.1

# Dependencies and code stay root-owned, so the process can read them but not
# change them. (They used to be chowned to the app user, which let a
# compromised process rewrite its own code.)
COPY --from=deps /opt/pydeps /opt/pydeps

WORKDIR /app
COPY backend/app /app/app
COPY backend/pyproject.toml /app/
# The CLI is served to users from /api/cli/download, so it ships in the image.
COPY cli /app/cli
# The documentation is served from /api/help and rendered in the UI. This
# registry is often deployed with no route to the internet and no access to
# the repository it was built from, so the docs travel with it.
COPY docs /app/app/docs
COPY --from=frontend /build/dist /app/app/static

# /data is the only writable path. It ships owned by the app user, so a fresh
# named volume inherits that on first mount. Numeric ids: neither base needs
# a passwd entry for them.
COPY --from=deps --chown=10001:10001 /skel/data /data

USER 10001:10001
EXPOSE 8000
VOLUME ["/data"]

# Exec form, no curl: there is no shell or curl in the hardened image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4)"]

# One worker per container. The download-log batcher and the housekeeping loop
# are per-process, so scale out with replicas rather than --workers.
# uvicorn's --forwarded-allow-ips only governs `request.client`; it does not
# understand CIDRs and it is not what the application reads. The address used
# for rate limits and audit records is resolved in core.deps.client_ip, which
# checks the peer against TRUSTED_PROXY_IPS before believing any forwarding
# header. Keep both narrow.
#
# No shell to expand ${UVICORN_FORWARDED_ALLOW_IPS} any more: uvicorn reads
# UVICORN_<OPTION> from the environment itself (click auto_envvar_prefix), so
# the variable still works, with the default set in ENV above.
#
# --timeout-graceful-shutdown lets in-flight artifact streams finish; the
# compose stop_grace_period is set slightly higher so the runtime does not
# SIGKILL through it.
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--timeout-graceful-shutdown", "50", "--no-access-log"]
