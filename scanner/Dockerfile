# syntax=docker/dockerfile:1.7
#
# minireg scanner worker: Trivy plus a small job loop.
#
# Deliberately separate from the registry image. This container unpacks
# untrusted image layers for a living, so it holds nothing worth stealing: a
# scan-only token, no database credentials, no upstream credentials. Run it
# read-only, non-root, with no new privileges and hard memory/pid limits (the
# shipped compose file does).

ARG BASE_REGISTRY=
ARG TRIVY_VERSION=0.74.0

FROM ${BASE_REGISTRY}python:3.12-slim AS trivy
ARG TRIVY_VERSION
# Official release tarball, verified against the release's checksum file.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && cd /tmp \
    && base="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}" \
    && curl -fsSLO "${base}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    && curl -fsSLO "${base}/trivy_${TRIVY_VERSION}_checksums.txt" \
    && grep " trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz\$" "trivy_${TRIVY_VERSION}_checksums.txt" | sha256sum -c - \
    && tar -xzf "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" trivy \
    && install -m 0755 trivy /usr/local/bin/trivy

FROM ${BASE_REGISTRY}python:3.12-slim
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY scanner/worker.py /app/worker.py
RUN useradd --create-home --uid 10002 --shell /usr/sbin/nologin scanner \
    && mkdir -p /cache \
    && chown scanner:scanner /cache
USER scanner
ENV TRIVY_CACHE_DIR=/cache \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
VOLUME ["/cache"]
ENTRYPOINT ["python", "/app/worker.py"]
