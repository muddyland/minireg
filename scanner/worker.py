#!/usr/bin/env python3
"""minireg scanner worker.

Runs next to minireg with Trivy and nothing else:

* no database access -- it talks to minireg over HTTP with a token that
  holds only the ``scanner`` scope;
* no upstream credentials -- it pulls images from minireg's own /v2, by
  digest, so every byte it scans has already been digest-verified;
* no shared filesystem -- results go back as an upload.

Loop: claim a job, run Trivy (a full image scan that also emits a CycloneDX
SBOM, or a rescan of the stored SBOM against today's vulnerability
database), post the JSON report back, repeat. A heartbeat keeps the job's
lease alive while Trivy runs; if the worker dies the lease lapses and
minireg hands the job to someone else.

Standard library only, so the image is Trivy plus a Python runtime.

Environment:
  MINIREG_URL            http://minireg:8000
  MINIREG_SCANNER_TOKEN  mrg_... (scope: scanner)
  SCANNER_NAME           defaults to the hostname
  SCANNER_POLL_SECONDS   idle poll interval, default 5
  TRIVY_BIN              default "trivy"
  TRIVY_CACHE_DIR        vulnerability DB + layer cache, default /cache
  TRIVY_DB_REPOSITORY    override the DB source minireg suggests
  SCANNER_DB_REFRESH_HOURS  how often to refresh the DB, default 12
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from urllib.parse import quote, urlsplit

log = logging.getLogger("scanner")

URL = os.environ.get("MINIREG_URL", "http://minireg:8000").rstrip("/")
TOKEN = os.environ.get("MINIREG_SCANNER_TOKEN", "")
NAME = os.environ.get("SCANNER_NAME") or socket.gethostname()
POLL = float(os.environ.get("SCANNER_POLL_SECONDS", "5"))
TRIVY = os.environ.get("TRIVY_BIN", "trivy")
CACHE = os.environ.get("TRIVY_CACHE_DIR", "/cache")
DB_REFRESH = float(os.environ.get("SCANNER_DB_REFRESH_HOURS", "12")) * 3600

_stop = threading.Event()


class ApiError(Exception):
    def __init__(self, status: int, body: str):
        super().__init__(f"HTTP {status}: {body[:300]}")
        self.status = status


def api(method: str, path: str, *, body: bytes | None = None, ctype: str | None = None, timeout=60):
    req = urllib.request.Request(URL + path, data=body, method=method)
    req.add_header("Authorization", f"Bearer {TOKEN}")
    req.add_header("User-Agent", f"minireg-scanner/1 ({NAME})")
    if ctype:
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
            return resp.status, data
    except urllib.error.HTTPError as exc:
        raise ApiError(exc.code, exc.read().decode("utf-8", "replace")) from exc


def api_json(method: str, path: str, payload: dict | None = None):
    body = json.dumps(payload).encode() if payload is not None else None
    status, data = api(method, path, body=body, ctype="application/json" if body else None)
    if status == 204 or not data:
        return None
    return json.loads(data)


def multipart(fields: dict[str, str], files: dict[str, tuple[str, bytes]]) -> tuple[bytes, str]:
    boundary = uuid.uuid4().hex
    parts: list[bytes] = []
    for name, value in fields.items():
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode()
        )
    for name, (filename, data) in files.items():
        parts.append(
            (
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; "
                f'filename="{filename}"\r\nContent-Type: application/json\r\n\r\n'
            ).encode()
            + data
            + b"\r\n"
        )
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


# --------------------------------------------------------------------------- #
# Trivy
# --------------------------------------------------------------------------- #
def trivy_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("MINIREG_")}
    env["TRIVY_CACHE_DIR"] = CACHE
    env["TRIVY_NO_PROGRESS"] = "true"
    # Registry credentials for pulling from minireg: Trivy reads these for
    # any registry. The token is scan-only.
    env["TRIVY_USERNAME"] = "scanner"
    env["TRIVY_PASSWORD"] = TOKEN
    if URL.startswith("http://"):
        env["TRIVY_INSECURE"] = "true"
        env["TRIVY_NON_SSL"] = "true"
    return env


def run(cmd: list[str], timeout: float) -> subprocess.CompletedProcess:
    log.debug("run: %s", " ".join(cmd))
    return subprocess.run(cmd, env=trivy_env(), capture_output=True, timeout=timeout, check=False)


_db_checked = 0.0
_db_repo: str | None = None
_java_db_repo: str | None = None


def ensure_db() -> None:
    """Download or refresh the vulnerability DB, through minireg when it
    has a ghcr upstream (ghcr.io rate-limits this 100+ MB artifact hard)."""
    global _db_checked, _db_repo, _java_db_repo
    if time.monotonic() - _db_checked < DB_REFRESH and _db_checked:
        return
    if _db_repo is None:
        # Asking minireg first matters: without its answer Trivy goes
        # straight to ghcr.io, the rate limit this cache exists to avoid. A
        # minireg that is still starting is retried by the caller rather than
        # settled for the default source until the process restarts.
        try:
            cfg = api_json("GET", "/api/docker/scanner/config") or {}
        except OSError as exc:
            raise RuntimeError(f"minireg not reachable yet: {exc}") from exc
        except ApiError as exc:
            if exc.status in (401, 403):
                raise
            log.warning("could not read scanner config: %s", exc)
            cfg = {}
        _db_repo = os.environ.get("TRIVY_DB_REPOSITORY") or cfg.get("db_repository") or ""
        _java_db_repo = os.environ.get("TRIVY_JAVA_DB_REPOSITORY") or cfg.get("java_db_repository") or ""
    cmd = [TRIVY, "image", "--download-db-only", "--quiet"]
    if _db_repo:
        cmd += ["--db-repository", _db_repo]
    proc = run(cmd, timeout=1800)
    if proc.returncode != 0:
        # An old DB is still a DB; carry on with it if one exists.
        log.error("vulnerability DB update failed: %s", proc.stderr.decode(errors="replace")[-600:])
        if not os.path.exists(os.path.join(CACHE, "db", "trivy.db")):
            raise RuntimeError("no vulnerability database available")
    else:
        log.info("vulnerability DB ready (source: %s)", _db_repo or "trivy default")
    _db_checked = time.monotonic()


def registry_ref(image: str) -> str:
    host = urlsplit(URL).netloc
    return f"{host}/{image}"


def common_flags(job: dict) -> list[str]:
    flags = ["--quiet", "--skip-db-update", "--scanners", "vuln", "--timeout", f"{job['timeout_seconds']}s"]
    if _java_db_repo:
        flags += ["--java-db-repository", _java_db_repo]
    else:
        flags += ["--skip-java-db-update"]
    severities = job.get("severities") or []
    if severities:
        flags += ["--severity", ",".join(severities)]
    if job.get("ignore_unfixed"):
        flags += ["--ignore-unfixed"]
    return flags


def scan_image(job: dict, workdir: str) -> tuple[bytes, bytes]:
    ref = registry_ref(job["image"])
    sbom_path = os.path.join(workdir, "sbom.cdx.json")
    report_path = os.path.join(workdir, "report.json")
    timeout = job["timeout_seconds"] + 60
    # One image pull: the SBOM run fetches and analyses the layers into the
    # cache; the vulnerability run is then a cache hit.
    base = ["--image-src", "remote"]
    if job.get("platform"):
        base += ["--platform", job["platform"]]
    proc = run([TRIVY, "image", *base, "--quiet", "--skip-db-update", "--format", "cyclonedx", "-o", sbom_path, ref], timeout)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode(errors="replace")[-1500:])
    proc = run([TRIVY, "sbom", *common_flags(job), "--format", "json", "-o", report_path, sbom_path], timeout)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode(errors="replace")[-1500:])
    with open(report_path, "rb") as fh:
        report = fh.read()
    with open(sbom_path, "rb") as fh:
        sbom = fh.read()
    return report, sbom


def scan_sbom(job: dict, workdir: str) -> bytes:
    _, data = api("GET", f"/api/docker/scanner/jobs/{job['job_id']}/sbom", timeout=120)
    sbom_path = os.path.join(workdir, "sbom.cdx.json")
    report_path = os.path.join(workdir, "report.json")
    with open(sbom_path, "wb") as fh:
        fh.write(data)
    proc = run([TRIVY, "sbom", *common_flags(job), "--format", "json", "-o", report_path, sbom_path], job["timeout_seconds"] + 60)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode(errors="replace")[-1500:])
    with open(report_path, "rb") as fh:
        return fh.read()


# --------------------------------------------------------------------------- #
# Loop
# --------------------------------------------------------------------------- #
def heartbeat(job_id: int, every: float, done: threading.Event) -> None:
    while not done.wait(every):
        try:
            api("POST", f"/api/docker/scanner/jobs/{job_id}/heartbeat?worker={quote(NAME)}", timeout=20)
        except (ApiError, OSError) as exc:
            log.warning("heartbeat for job %s failed: %s", job_id, exc)


def work_one() -> bool:
    ensure_db()
    job = api_json("POST", "/api/docker/scanner/claim", {"worker": NAME})
    if not job:
        return False
    log.info("job %s: %s scan of %s", job["job_id"], job["mode"], job["image"])
    done = threading.Event()
    beat = threading.Thread(
        target=heartbeat, args=(job["job_id"], max(10, job.get("lease_seconds", 120) / 3), done), daemon=True
    )
    beat.start()
    workdir = tempfile.mkdtemp(prefix="scan-")
    started = time.monotonic()
    try:
        if job["mode"] == "sbom":
            report, sbom = scan_sbom(job, workdir), None
        else:
            report, sbom = scan_image(job, workdir)
        files = {"report": ("report.json", report)}
        if sbom is not None:
            files["sbom"] = ("sbom.cdx.json", sbom)
        duration = int((time.monotonic() - started) * 1000)
        body, ctype = multipart({"worker": NAME, "duration_ms": str(duration)}, files)
        api("POST", f"/api/docker/scanner/jobs/{job['job_id']}/result", body=body, ctype=ctype, timeout=300)
        log.info("job %s: done in %.1fs", job["job_id"], duration / 1000)
    except Exception as exc:
        message = str(exc) or type(exc).__name__
        permanent = "unsupported" in message.lower() and "os" in message.lower()
        log.warning("job %s failed: %s", job["job_id"], message[-400:])
        try:
            api_json(
                "POST",
                f"/api/docker/scanner/jobs/{job['job_id']}/fail",
                {"worker": NAME, "error": message[-3900:], "permanent": permanent},
            )
        except (ApiError, OSError) as report_exc:
            log.error("could not report failure for job %s: %s", job["job_id"], report_exc)
    finally:
        done.set()
        shutil.rmtree(workdir, ignore_errors=True)
    return True


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    if not TOKEN:
        log.error("MINIREG_SCANNER_TOKEN is not set")
        return 2
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: _stop.set())
    log.info("scanner %s polling %s", NAME, URL)
    backoff = POLL
    while not _stop.is_set():
        try:
            busy = work_one()
            backoff = POLL
            if busy:
                continue
        except ApiError as exc:
            if exc.status in (401, 403):
                log.error("minireg refused the scanner token (%s); check its scope", exc.status)
            else:
                log.warning("minireg API error: %s", exc)
            backoff = min(backoff * 2, 300)
        except (OSError, RuntimeError) as exc:
            log.warning("scanner loop error: %s", exc)
            backoff = min(backoff * 2, 300)
        _stop.wait(backoff)
    log.info("scanner stopping")
    return 0


if __name__ == "__main__":
    sys.exit(main())
