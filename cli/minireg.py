#!/usr/bin/env python3
"""minireg -- command line client for a minireg package registry.

Deliberately a single file with no third-party imports: it is fetched straight
from the registry it talks to, and asking someone to set up a virtualenv before
they can point npm at their own mirror would defeat the purpose.

    minireg login                 authenticate via the browser
    minireg configure             point npm / pip at the registry
    minireg audit                 check this project's dependencies for CVEs
    minireg search <query>        search the registry
    minireg info <package>        show a package, its versions and CVEs
    minireg whoami                show the current identity
    minireg logout                forget the stored token
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import platform
import re
import socket
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path

__version__ = "1.2.0"

DEFAULT_TIMEOUT = 30
USER_AGENT = f"minireg-cli/{__version__}"

#: The registry stamps every API response with the CLI version it ships. We
#: record it as a side effect of ordinary traffic, so noticing that we are out
#: of date costs nothing extra.
CLI_VERSION_HEADER = "x-minireg-cli-version"
_server_cli_version: str | None = None


# --------------------------------------------------------------------------- #
# Terminal helpers
# --------------------------------------------------------------------------- #
def _supports_colour() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("MINIREG_FORCE_COLOR"):
        return True
    return sys.stdout.isatty()


COLOUR = _supports_colour()


def paint(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if COLOUR else text


def bold(t):     return paint(t, "1")
def dim(t):      return paint(t, "2")
def red(t):      return paint(t, "31")
def green(t):    return paint(t, "32")
def yellow(t):   return paint(t, "33")
def blue(t):     return paint(t, "34")
def magenta(t):  return paint(t, "35")


def severity_colour(score):
    if score is None:
        return dim
    if score >= 9.0:
        return magenta
    if score >= 7.0:
        return red
    if score >= 4.0:
        return yellow
    return dim


def die(message: str, code: int = 1):
    print(f"{red('error')}: {message}", file=sys.stderr)
    raise SystemExit(code)


def info(message: str):
    # Flush stdout first: it is block-buffered when redirected, so an
    # unbuffered stderr note would otherwise appear before the output it
    # describes.
    sys.stdout.flush()
    print(message, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(Path.home(), ".config")
    return Path(base) / "minireg"


def config_path() -> Path:
    return config_dir() / "config.json"


def load_config() -> dict:
    path = config_path()
    data = {}
    if path.is_file():
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            data = {}
    # Environment always wins, so CI can inject credentials without a file.
    if os.environ.get("MINIREG_URL"):
        data["registry"] = os.environ["MINIREG_URL"]
    if os.environ.get("MINIREG_TOKEN"):
        data["token"] = os.environ["MINIREG_TOKEN"]
    return data


def save_config(data: dict):
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    # Written 0600 before any secret goes in, not after.
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")
    os.chmod(path, 0o600)


def require_registry(args) -> str:
    url = getattr(args, "url", None) or load_config().get("registry")
    if not url:
        die("no registry configured. Run: minireg login --url https://registry.example.com")
    return url.rstrip("/")


def require_token() -> str:
    token = load_config().get("token")
    if not token:
        die("not logged in. Run: minireg login")
    return token


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
class ApiError(Exception):
    def __init__(self, status, detail):
        super().__init__(detail)
        self.status = status
        self.detail = detail


def api(
    registry: str,
    path: str,
    method: str = "GET",
    body=None,
    token: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    insecure: bool = False,
):
    url = f"{registry.rstrip('/')}{path}"
    data = None
    headers = {"accept": "application/json", "user-agent": USER_AGENT}
    if body is not None:
        data = json.dumps(body).encode()
        headers["content-type"] = "application/json"
    if token:
        headers["authorization"] = f"Bearer {token}"

    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    context = None
    if insecure:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    global _server_cli_version
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            _server_cli_version = (
                response.headers.get(CLI_VERSION_HEADER) or _server_cli_version
            )
            payload = response.read()
            return json.loads(payload) if payload else None
    except urllib.error.HTTPError as exc:
        _server_cli_version = exc.headers.get(CLI_VERSION_HEADER) or _server_cli_version
        raw = exc.read()
        detail = None
        try:
            parsed = json.loads(raw)
            detail = parsed.get("detail") or parsed.get("error") or parsed.get("message")
        except Exception:
            detail = raw.decode("utf-8", "replace")[:300] or exc.reason
        raise ApiError(exc.code, detail) from exc
    except urllib.error.URLError as exc:
        raise ApiError(0, f"could not reach {registry}: {exc.reason}") from exc


# --------------------------------------------------------------------------- #
# login / logout / whoami
# --------------------------------------------------------------------------- #
def cmd_login(args):
    registry = (args.url or load_config().get("registry") or "").rstrip("/")
    if not registry:
        die("specify the registry: minireg login --url https://registry.example.com")

    scopes = [s.strip() for s in (args.scopes or "read").split(",") if s.strip()]

    try:
        start = api(
            registry,
            "/api/cli/auth/start",
            "POST",
            {
                "hostname": socket.gethostname(),
                "platform": platform.platform(),
                "scopes": scopes,
            },
            insecure=args.insecure,
        )
    except ApiError as exc:
        die(f"could not start login: {exc.detail}")

    user_code = start["user_code"]
    verify_url = start.get("verification_url_complete") or start["verification_url"]

    # Explicitly flushed: stdout is block-buffered when it is not a TTY, so a
    # piped or wrapped `minireg login` would otherwise show nothing at all
    # while it waits for a code the user cannot see.
    print()
    print(f"  Open {bold(blue(verify_url))}")
    print(f"  and confirm this code:  {bold(green(user_code))}")
    print(flush=True)
    info(dim("  Waiting for approval… (Ctrl-C to cancel)"))

    if len(scopes) > 1 or scopes != ["read"]:
        info(dim(f"  Requesting: {', '.join(scopes)}"))

    if not args.no_browser:
        with contextlib.suppress(Exception):
            webbrowser.open(verify_url)

    interval = max(1, int(start.get("interval", 3)))
    deadline = time.time() + int(start.get("expires_in", 600))

    while time.time() < deadline:
        time.sleep(interval)
        try:
            result = api(
                registry,
                "/api/cli/auth/poll",
                "POST",
                {"device_code": start["device_code"]},
                insecure=args.insecure,
            )
        except ApiError as exc:
            if exc.status == 429:
                interval = min(interval * 2, 15)
                continue
            if exc.detail == "access_denied":
                die("the request was denied in the browser")
            if exc.detail == "expired_token":
                die("the login request expired; run 'minireg login' again")
            die(f"login failed: {exc.detail}")

        if result.get("status") == "complete":
            config = load_config()
            config.update(
                {
                    # The URL the user typed, not one the response nominated.
                    # Adopting a server-supplied registry means a compromised
                    # or merely misconfigured deployment could redirect every
                    # later command -- and this token -- to a host of its
                    # choosing.
                    "registry": registry,
                    "token": result["token"],
                    "username": result.get("username"),
                }
            )
            save_config(config)
            print()
            print(f"  {green('✓')} Signed in as {bold(result.get('username') or 'unknown')}")
            print(f"  {dim('Token stored in ' + str(config_path()) + ' (mode 600)')}")
            print()
            print(f"  Next:  {bold('minireg configure')}", flush=True)
            return 0

    die("timed out waiting for approval")


def cmd_logout(args):
    config = load_config()
    if not config.get("token"):
        info("Not logged in.")
        return 0
    config.pop("token", None)
    config.pop("username", None)
    save_config(config)
    info(f"{green('✓')} Signed out. The token remains valid until revoked in the web UI.")
    return 0


def cmd_whoami(args):
    registry = require_registry(args)
    token = require_token()
    try:
        me = api(registry, "/api/auth/me", token=token, insecure=args.insecure)
    except ApiError as exc:
        if exc.status == 401:
            die("stored token is not valid. Run: minireg login")
        die(exc.detail)

    user = me["user"]
    print(f"  {bold(user['username'])}  {dim(registry)}")
    print(f"  role    : {'administrator' if user['is_admin'] else 'user'}")
    print(f"  publish : {'yes' if user['can_publish'] else 'no'}")
    print(f"  scopes  : {', '.join(me.get('scopes') or [])}")
    return 0


# --------------------------------------------------------------------------- #
# configure
# --------------------------------------------------------------------------- #
def _npmrc_path() -> Path:
    return Path.home() / ".npmrc"


def _upsert_lines(path: Path, lines: list[str], marker: str) -> None:
    """Replace our managed block, leaving anything else in the file alone."""
    begin = f"# >>> {marker} >>>"
    end = f"# <<< {marker} <<<"
    block = "\n".join([begin, *lines, end])

    existing = path.read_text() if path.is_file() else ""
    if begin in existing and end in existing:
        pattern = re.compile(
            re.escape(begin) + r".*?" + re.escape(end), re.DOTALL
        )
        updated = pattern.sub(block, existing)
    else:
        separator = "" if not existing or existing.endswith("\n") else "\n"
        updated = f"{existing}{separator}{block}\n"

    path.parent.mkdir(parents=True, exist_ok=True)
    # Create with 0600 from the start. Writing then chmod'ing leaves the file
    # world-readable for the moment in between, and these files hold an API
    # token. Written to a temp file and renamed so a crash cannot truncate an
    # existing config.
    tmp = path.with_name(path.name + ".minireg-tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(updated)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    os.chmod(path, 0o600)


def cmd_configure(args):
    registry = require_registry(args)
    config = load_config()
    token = config.get("token")

    try:
        client = api(registry, "/api/client-config", token=token, insecure=args.insecure)
    except ApiError as exc:
        if exc.status == 401:
            die("not logged in. Run: minireg login")
        die(exc.detail)

    targets = args.target
    if targets == "all":
        targets = "npm,pip,cargo"
    wanted = {t.strip() for t in targets.split(",") if t.strip()}

    host = registry.split("://", 1)[-1]
    changed = []

    if "npm" in wanted:
        lines = [f"registry={client['npm']['registry']}"]
        if token:
            lines.append(f"//{host}/npm/:_authToken={token}")
        else:
            info(dim("  no token stored; writing npm registry without credentials"))
        if args.dry_run:
            print(f"\n{bold(str(_npmrc_path()))}\n" + "\n".join(lines))
        else:
            _upsert_lines(_npmrc_path(), lines, "minireg")
            changed.append(str(_npmrc_path()))

    if "pip" in wanted:
        pip_conf = Path(
            os.environ.get("XDG_CONFIG_HOME") or os.path.join(Path.home(), ".config")
        ) / "pip" / "pip.conf"
        index_url = client["pip"]["index_url"]
        if token:
            # pip has no auth-token header; credentials go in the URL.
            scheme, _, rest = index_url.partition("://")
            index_url = f"{scheme}://__token__:{urllib.parse.quote(token, safe='')}@{rest}"
        # A second `[global]` section makes configparser raise
        # DuplicateSectionError, which breaks pip completely -- so only emit
        # the header when the file does not already have one outside our block.
        existing_conf = pip_conf.read_text() if pip_conf.is_file() else ""
        outside = re.sub(
            r"# >>> minireg >>>.*?# <<< minireg <<<", "", existing_conf, flags=re.DOTALL
        )
        lines = []
        if not re.search(r"^\s*\[global\]", outside, re.M):
            lines.append("[global]")
        lines.append(f"index-url = {index_url}")
        if registry.startswith("http://"):
            lines.append(f"trusted-host = {host.split(':')[0]}")
        if args.dry_run:
            print(f"\n{bold(str(pip_conf))}\n" + "\n".join(lines))
        else:
            _upsert_lines(pip_conf, lines, "minireg")
            changed.append(str(pip_conf))

    if "cargo" in wanted:
        cargo_conf = Path(os.environ.get("CARGO_HOME") or (Path.home() / ".cargo")) / "config.toml"
        cargo = client.get("cargo")
        if not cargo:
            info(dim("  registry does not serve a cargo index; skipping"))
        else:
            # Source replacement, not a `[registries]` entry: it redirects every
            # crates.io dependency without editing a single Cargo.toml. No token
            # is written -- cargo only sends credentials to an index that
            # declares `auth-required`, and a read-only mirror does not.
            lines = [
                "[source.crates-io]",
                'replace-with = "minireg"',
                "",
                "[source.minireg]",
                f'registry = "{cargo["registry"]}"',
            ]
            if args.dry_run:
                print(f"\n{bold(str(cargo_conf))}\n" + "\n".join(lines))
            else:
                # The managed block goes at the end of the file on first write.
                # That matters for TOML in a way it does not for npmrc: these
                # are table headers, so anything following them would be read as
                # part of `[source.minireg]`.
                _upsert_lines(cargo_conf, lines, "minireg")
                changed.append(str(cargo_conf))

    if args.dry_run:
        info(dim("\n(dry run — nothing written)"))
        return 0

    for path in changed:
        print(f"  {green('✓')} wrote {path}")
    if not token:
        info(dim("\n  Tip: run 'minireg login' first to include credentials."))
    return 0


# --------------------------------------------------------------------------- #
# audit
# --------------------------------------------------------------------------- #
def parse_package_lock(path: Path) -> list[dict]:
    """npm lockfile v1, v2 and v3."""
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return []

    found = {}

    # v2/v3: a flat "packages" map keyed by install path.
    for location, entry in (data.get("packages") or {}).items():
        if not location or not isinstance(entry, dict):
            continue  # "" is the project itself
        if entry.get("link"):
            continue
        name = entry.get("name") or location.split("node_modules/")[-1]
        version = entry.get("version")
        if name and version:
            found[(name, version)] = True

    # v1: a nested "dependencies" tree.
    def walk(node):
        for name, entry in (node or {}).items():
            if not isinstance(entry, dict):
                continue
            version = entry.get("version")
            if version:
                found[(name, version)] = True
            walk(entry.get("dependencies"))

    if not found:
        walk(data.get("dependencies"))

    return [{"name": n, "version": v} for n, v in found]


#: Requirement lines that named a package but no exact version. Reported rather
#: than dropped -- a requirements.txt full of ranges used to audit as "1 package
#: found", which reads exactly like the file was ignored.
UNPINNED: dict[Path, list[str]] = {}

# `==` and `===` (arbitrary equality). The `(?!=)` stops `===1.0` being read as
# `==` followed by a version of "=1.0".
_PIN_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*===?(?!=)\s*(?P<version>[^\s;#]+)"
)
_NAMED_RE = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(?P<rest>.*)$")


def parse_requirements(path: Path) -> list[dict]:
    """requirements.txt.

    Only exactly-pinned entries can be audited: a range like ``>=2.0`` has no
    single version to look up. Anything named but unpinned is recorded in
    UNPINNED so the caller can say so out loud.
    """
    out = []
    unpinned = []
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return out

    for raw in lines:
        line = raw.split("#", 1)[0].strip().rstrip("\\").strip()
        # Options (-r, -e, --hash continuation lines) and URL requirements are
        # not version pins.
        if not line or line.startswith("-") or "://" in line:
            continue

        pin = _PIN_RE.match(line)
        if pin:
            out.append({"name": pin.group("name"), "version": pin.group("version")})
            continue

        named = _NAMED_RE.match(line)
        if named and named.group("rest").lstrip()[:1] in ("", "<", ">", "~", "!", "="):
            unpinned.append(line)

    UNPINNED[path] = unpinned
    return out


def parse_poetry_lock(path: Path) -> list[dict]:
    """Minimal TOML scan; poetry.lock is regular enough not to need a parser."""
    out = []
    try:
        text = path.read_text()
    except OSError:
        return out
    for block in text.split("[[package]]")[1:]:
        name = re.search(r'^\s*name\s*=\s*"([^"]+)"', block, re.MULTILINE)
        version = re.search(r'^\s*version\s*=\s*"([^"]+)"', block, re.MULTILINE)
        if name and version:
            out.append({"name": name.group(1), "version": version.group(1)})
    return out


def parse_uv_lock(path: Path) -> list[dict]:
    return parse_poetry_lock(path)  # same [[package]] name/version shape


def parse_cargo_lock(path: Path) -> list[dict]:
    """Cargo.lock.

    Same ``[[package]]`` shape as poetry.lock, with one difference that matters:
    the file also lists the workspace's own crates and any git or path
    dependencies. Those carry no ``source`` key (or a ``git+`` one) and are not
    on crates.io, so sending them to the registry would ask about packages that
    cannot exist there -- every local crate would come back unknown and read as
    a gap in coverage rather than as "this is your own code".
    """
    out = []
    try:
        text = path.read_text()
    except OSError:
        return out
    for block in text.split("[[package]]")[1:]:
        name = re.search(r'^\s*name\s*=\s*"([^"]+)"', block, re.MULTILINE)
        version = re.search(r'^\s*version\s*=\s*"([^"]+)"', block, re.MULTILINE)
        source = re.search(r'^\s*source\s*=\s*"([^"]+)"', block, re.MULTILINE)
        if not (name and version):
            continue
        if source is None or not source.group(1).startswith("registry+"):
            continue
        out.append({"name": name.group(1), "version": version.group(1)})
    return out


def parse_pipfile_lock(path: Path) -> list[dict]:
    out = []
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return out
    for section in ("default", "develop"):
        for name, entry in (data.get(section) or {}).items():
            version = (entry or {}).get("version") or ""
            if version.startswith("=="):
                out.append({"name": name, "version": version[2:]})
    return out


LOCKFILES = [
    ("package-lock.json", "npm", parse_package_lock),
    ("npm-shrinkwrap.json", "npm", parse_package_lock),
    ("poetry.lock", "pypi", parse_poetry_lock),
    ("uv.lock", "pypi", parse_uv_lock),
    ("Pipfile.lock", "pypi", parse_pipfile_lock),
    ("Cargo.lock", "cargo", parse_cargo_lock),
    ("requirements.txt", "pypi", parse_requirements),
]

SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def discover(root: Path) -> list[tuple[Path, str, list[dict]]]:
    """Every dependency file we recognise, including ones that yielded nothing.

    A file that parsed to zero packages is still reported: dropping it silently
    is indistinguishable from not supporting the format, and the caller needs to
    explain *why* it found nothing.
    """
    found = []
    for filename, ecosystem, parser in LOCKFILES:
        path = root / filename
        if path.is_file():
            found.append((path, ecosystem, parser(path)))
    return found


def cmd_audit(args):
    registry = require_registry(args)
    token = require_token()
    root = Path(args.path).resolve()

    if root.is_file():
        matched = next((e for name, e, p in LOCKFILES if root.name == name), None)
        parser = next((p for name, _e, p in LOCKFILES if root.name == name), None)
        if parser is None:
            die(f"don't know how to read {root.name}")
        sources = [(root, matched, parser(root))]
    else:
        sources = discover(root)

    if not sources:
        die(
            f"no dependency file found in {root}\n"
            f"  looked for: {', '.join(name for name, _, _ in LOCKFILES)}"
        )

    total_findings = []
    total_unscanned = 0
    worst = 0.0
    exit_blocked = False
    per_source: list[tuple[Path, str, list[dict]]] = []

    for path, ecosystem, packages in sources:
        rel = path.name
        unpinned = UNPINNED.get(path, [])

        if not packages:
            # Recognised the file, got nothing auditable out of it. Say so --
            # staying quiet here reads as "the file was ignored".
            info(f"{dim('skipping')} {bold(rel)} {dim('— no exactly-pinned versions')}")
            if unpinned:
                info(
                    dim(
                        f"  {len(unpinned)} requirement(s) specify a range, which has no "
                        "single version to audit."
                    )
                )
                for entry in unpinned[:5]:
                    info(dim(f"    {entry}"))
                if len(unpinned) > 5:
                    info(dim(f"    … and {len(unpinned) - 5} more"))
                info(
                    dim(
                        "  Generate a lockfile (pip-compile, poetry, uv) or pin with '==' "
                        "to audit these."
                    )
                )
            continue

        suffix = f", {len(unpinned)} unpinned" if unpinned else ""
        info(
            f"{dim('scanning')} {bold(rel)} "
            f"{dim(f'({len(packages)} packages, {ecosystem}{suffix})')}"
        )

        try:
            result = api(
                registry,
                "/api/cli/audit",
                "POST",
                {"ecosystem": ecosystem, "packages": packages, "scan_unknown": not args.offline},
                token=token,
                timeout=180,
                insecure=args.insecure,
            )
        except ApiError as exc:
            if exc.status == 401:
                die("not logged in. Run: minireg login")
            die(f"audit failed: {exc.detail}")

        findings = result.get("findings") or []
        total_findings.extend(findings)
        per_source.append((path, ecosystem, findings))

        if args.json:
            continue

        print()
        if not findings:
            print(f"  {green('✓')} no known CVEs in {len(packages)} packages")
        else:
            for finding in findings:
                score = finding.get("max_cvss")
                paint_fn = severity_colour(score)
                worst = max(worst, score or 0)
                head = f"  {bold(finding['name'])}@{finding['version']}"
                if score is not None:
                    head += f"  {paint_fn(f'CVSS {score:.1f}')}"
                if finding.get("blocked"):
                    exit_blocked = True
                    head += f"  {red('[BLOCKED BY REGISTRY]')}"
                print(head)
                if finding.get("block_reason"):
                    print(f"      {red('policy')}: {finding['block_reason']}")
                for cve in finding.get("cves") or []:
                    score_text = (
                        f"{cve['cvss_score']:.1f}" if cve.get("cvss_score") is not None else " -- "
                    )
                    fix = (
                        f"  fixed in {green(cve['fixed_version'])}"
                        if cve.get("fixed_version")
                        else "  " + dim("no fix available")
                    )
                    print(
                        f"      {severity_colour(cve.get('cvss_score'))(score_text)}"
                        f"  {cve['cve_id']}{fix}"
                    )
                    if cve.get("summary"):
                        print(f"           {dim(cve['summary'][:88])}")
                print()

        unscanned = result.get("unscanned_total") or 0
        total_unscanned += unscanned
        if unscanned:
            info(
                dim(
                    f"  {unscanned} package(s) could not be scanned"
                    + (" (offline mode)" if args.offline else "")
                )
            )
        if unpinned:
            info(
                dim(
                    f"  {len(unpinned)} unpinned requirement(s) in {rel} were not audited"
                )
            )

    if args.json:
        print(
            json.dumps(
                {
                    "findings": total_findings,
                    "unscanned_total": total_unscanned,
                    "blocked": bool(exit_blocked),
                },
                indent=2,
            )
        )
        # Falls through to the exit-code logic below rather than returning
        # here. `--json --fail-on critical` used to always exit 0, so a CI job
        # that asked for machine-readable output silently stopped gating.
    elif args.fix:
        apply_fixes(args, registry, token, root, per_source)

    if not args.json:
        blocked = [f for f in total_findings if f.get("blocked")]
        parts = [f"{len(total_findings)} package(s) with findings"]
        if blocked:
            # A blocked package is not advisory: the registry will refuse to
            # serve it, so the install fails outright.
            parts.append(red(f"{len(blocked)} blocked — these will not install"))
        if total_unscanned:
            parts.append(f"{total_unscanned} unscanned")
        print(f"  {bold('Summary')}: " + ", ".join(parts))

    return audit_exit_code(args, total_findings, exit_blocked, total_unscanned)


def audit_exit_code(args, findings, exit_blocked, unscanned) -> int:
    """Translate an audit into a process exit code.

    "We could not check" is not "we checked and it is fine". An unreachable
    OSV, `--offline`, a package the registry has never seen, or a batch past
    the server's scan cap all produce zero findings -- and exiting 0 on those
    turns a CI gate into decoration. `--fail-on-unscanned` (on by default
    whenever `--fail-on` is given) is what closes that.
    """
    threshold = (args.fail_on or "").lower()
    if not threshold or threshold == "never":
        return 0

    limit = SEVERITY_ORDER.get(threshold)
    if limit is None:
        die(f"unknown --fail-on value: {threshold}")

    for finding in findings:
        for cve in finding.get("cves") or []:
            if SEVERITY_ORDER.get((cve.get("severity") or "none"), 0) >= limit:
                return 2
    if exit_blocked:
        return 2

    fail_unscanned = args.fail_on_unscanned
    if fail_unscanned is None:
        fail_unscanned = True
    if unscanned and fail_unscanned:
        info(
            red(
                f"  {unscanned} package(s) could not be checked. Failing because "
                "an unchecked dependency is not a clean one "
                "(pass --no-fail-on-unscanned to allow it)."
            )
        )
        return 3
    return 0



# --------------------------------------------------------------------------- #
# --fix: rewrite dependency declarations to versions that clear the CVEs
# --------------------------------------------------------------------------- #
# Which file to edit for each ecosystem. For npm we audit the lockfile but edit
# package.json: raising the declared floor is what stops `npm install`
# regenerating a vulnerable lock, and the lockfile itself is generated output.
FIX_TARGETS = {"npm": "package.json", "pypi": None, "cargo": None}

_REQ_PIN_RE = re.compile(
    r"^(?P<lead>\s*)(?P<name>[A-Za-z0-9._-]+)(?P<extras>\s*\[[^\]]*\])?"
    r"(?P<space>\s*)(?P<op>===?)(?P<gap>\s*)(?P<version>[^\s;#]+)(?P<rest>.*)$"
)
# Keep the operator the declaration already used, so a project's convention
# survives the edit.
_NPM_RANGE_RE = re.compile(r"^(?P<op>[\^~]|>=|>)?(?P<version>\d.*)$")


def _print_cargo_fix_advice(path: Path, findings: list[dict]) -> int:
    """Hand back the `cargo update` lines that would clear what we found.

    Returns how many were printed, so the caller can tell "we told you what to
    run" apart from "there is nothing to do".
    """
    fixes = sorted({(f["name"], f["fix_version"]) for f in findings if f.get("fix_version")})
    if not fixes:
        if findings:
            print(f"    {dim(path.name)}: nothing with a published fix")
        return 0
    print(f"    {dim(path.name)}: run these — cargo owns the lockfile")
    for name, version in fixes:
        print(f"      cargo update -p {name} --precise {version}")
    return len(fixes)


def normalize_key(ecosystem: str, name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if ecosystem == "pypi" else name.lower()


def plan_requirements_fix(path: Path, fixes: dict) -> tuple[str, list[str]]:
    """Return the rewritten requirements.txt and a description of each change."""
    original = path.read_text()
    changes = []
    out = []

    for line in original.splitlines(keepends=True):
        stripped = line.split("#", 1)[0].strip()
        match = _REQ_PIN_RE.match(stripped) if stripped else None
        if match is None:
            out.append(line)
            continue

        target = fixes.get(normalize_key("pypi", match.group("name")))
        if not target or target == match.group("version"):
            out.append(line)
            continue

        old_pin = f"{match.group('op')}{match.group('gap')}{match.group('version')}"
        new_pin = f"{match.group('op')}{match.group('gap')}{target}"
        # Replace only the version token, so comments, markers and spacing
        # survive untouched.
        out.append(line.replace(old_pin, new_pin, 1))
        changes.append(f"{match.group('name')}  {match.group('version')} -> {target}")

    return "".join(out), changes


def plan_package_json_fix(path: Path, fixes: dict) -> tuple[str, list[str], list[str]]:
    """Rewrite package.json dependency ranges. Returns (text, changes, skipped)."""
    original = path.read_text()
    try:
        data = json.loads(original)
    except json.JSONDecodeError:
        return original, [], ["package.json is not valid JSON"]

    changes, skipped = [], []
    text = original

    for section in (
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ):
        for name, spec in (data.get(section) or {}).items():
            target = fixes.get(normalize_key("npm", name))
            if not target or not isinstance(spec, str):
                continue

            match = _NPM_RANGE_RE.match(spec.strip())
            if match is None:
                # A tag, git URL or file: path -- not something we can safely
                # bump by rewriting a version number.
                skipped.append(f"{name} ({spec})")
                continue
            if match.group("version") == target:
                continue

            new_spec = f"{match.group('op') or ''}{target}"
            # Edit the raw text rather than re-serialising, so key order,
            # indentation and any trailing newline are preserved exactly.
            needle = f'"{name}": "{spec}"'
            if needle not in text:
                skipped.append(f"{name} (could not locate its declaration)")
                continue
            text = text.replace(needle, f'"{name}": "{new_spec}"', 1)
            changes.append(f"{name}  {spec} -> {new_spec}")

    return text, changes, skipped


def render_diff(path: Path, before: str, after: str) -> str:
    import difflib

    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=str(path),
            tofile=f"{path} (proposed)",
            n=1,
        )
    )

def apply_fixes(args, registry, token, root: Path, per_source) -> None:
    """Propose (and optionally write) dependency bumps that clear the CVEs."""
    print()
    print(f"  {bold('Remediation')}")

    planned = []
    # Sources we cannot rewrite but did give the user something actionable, so
    # the "nothing to change" line below does not contradict advice we just
    # printed.
    advised = 0
    for path, ecosystem, findings in per_source:
        if ecosystem == "cargo":
            # Cargo.lock is generated output, and Cargo.toml declares ranges
            # against a workspace and feature graph we would have to resolve to
            # edit safely -- a floor raised in the wrong member is a build
            # break, not a bump. cargo already owns this operation, so print the
            # exact invocations instead of guessing at the file.
            advised += _print_cargo_fix_advice(path, findings)
            continue

        fixable = {
            normalize_key(ecosystem, f["name"]): f["fix_version"]
            for f in findings
            if f.get("fix_version")
        }
        unfixable = [f for f in findings if f.get("cves") and not f.get("fix_version")]

        target_name = FIX_TARGETS.get(ecosystem)
        target = (path.parent / target_name) if target_name else path

        if not fixable:
            if findings:
                print(f"    {dim(path.name)}: nothing with a published fix")
            continue
        if not target.is_file():
            info(f"    {yellow('skip')} {path.name}: {target.name} not found next to it")
            continue

        before = target.read_text()
        if target.name == "package.json":
            after, changes, skipped = plan_package_json_fix(target, fixable)
        else:
            if "--hash=" in before:
                # Editing a version invalidates every recorded hash, and we
                # cannot recompute them without downloading the artifacts.
                info(
                    f"    {yellow('skip')} {target.name}: it pins hashes; "
                    "regenerate it with pip-compile instead"
                )
                continue
            after, changes = plan_requirements_fix(target, fixable)
            skipped = []

        for entry in skipped:
            info(dim(f"    could not rewrite {entry}"))
        if not changes:
            print(f"    {dim(target.name)}: already at or above the fixed versions")
            continue

        planned.append((target, before, after, changes, ecosystem, fixable))
        for entry in unfixable:
            print(f"    {red('no fix')} {entry['name']}@{entry['version']}")

    if not planned:
        if not advised:
            print(f"    {dim('nothing to change')}")
        return

    for target, _before, _after, changes, _eco, _fixes in planned:
        print(f"\n    {bold(str(target))}")
        for entry in changes:
            print(f"      {green(entry)}")

    # Say whether the proposed versions are actually clean. A CVE's "fixed in"
    # only speaks for that CVE; the target release can carry others.
    residual = verify_fixes(registry, token, planned, args)
    if residual:
        print()
        print(f"    {yellow('after upgrading, these would still have findings:')}")
        for name, version, score in residual:
            marker = f" CVSS {score:.1f}" if score else ""
            print(f"      {name}@{version}{marker}")

    if args.dry_run:
        info(dim("\n  (dry run — nothing written)"))
        return

    if not args.yes:
        print()
        try:
            answer = input("  Write these changes? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer not in ("y", "yes"):
            info(dim("  Not written."))
            return

    for target, _before, after, changes, _eco, _fixes in planned:
        target.write_text(after)
        print(f"  {green('✓')} wrote {target} ({len(changes)} change(s))")

    info(
        dim(
            "\n  Regenerate your lockfile so the change takes effect: "
            "`npm install` or `pip install -r requirements.txt`."
        )
    )


def verify_fixes(registry, token, planned, args):
    """Re-audit the proposed versions and report anything still affected."""
    residual = []
    for _target, _before, _after, _changes, ecosystem, fixes in planned:
        packages = [{"name": name, "version": version} for name, version in fixes.items()]
        if not packages:
            continue
        try:
            result = api(
                registry,
                "/api/cli/audit",
                "POST",
                {"ecosystem": ecosystem, "packages": packages, "scan_unknown": True},
                token=token,
                timeout=180,
                insecure=args.insecure,
            )
        except ApiError as exc:
            # Not "clean". Returning an empty list here meant a failed
            # re-check printed the same reassuring output as a passed one, so
            # `--fix` could hand over versions it had never managed to verify.
            info(
                yellow(
                    "  could not re-check the proposed versions "
                    f"({exc.detail}); they are unverified"
                )
            )
            return None
        for finding in result.get("findings") or []:
            residual.append((finding["name"], finding["version"], finding.get("max_cvss")))
    return residual


# --------------------------------------------------------------------------- #
# search / info
# --------------------------------------------------------------------------- #
def cmd_search(args):
    registry = require_registry(args)
    token = require_token()
    params = {"q": args.query, "limit": args.limit}
    if args.ecosystem:
        params["ecosystem"] = args.ecosystem
    query = urllib.parse.urlencode(params)

    try:
        result = api(registry, f"/api/search?{query}", token=token, insecure=args.insecure)
    except ApiError as exc:
        if exc.status == 401:
            die("not logged in. Run: minireg login")
        die(exc.detail)

    results = result.get("results") or []
    if not results:
        info("No packages matched.")
        return 0

    for item in results:
        tag = {"npm": blue("npm"), "pypi": yellow("pypi")}.get(
            item["ecosystem"], red("cargo")
        )
        line = f"  {tag}  {bold(item['name'])}"
        if item.get("latest_version"):
            line += f"  {dim(item['latest_version'])}"
        if item.get("blocked"):
            line += f"  {red('[blocked]')}"
        print(line)
        if item.get("description"):
            print(f"        {dim(item['description'][:96])}")
    print()
    print(dim(f"  {len(results)} of {result.get('total', len(results))} results"))
    return 0


def cmd_info(args):
    registry = require_registry(args)
    token = require_token()
    ecosystem = args.ecosystem or ("npm" if not args.package.startswith("py:") else "pypi")
    name = args.package

    try:
        pkg = api(
            registry,
            f"/api/packages/{ecosystem}/{urllib.parse.quote(name, safe='@/')}",
            token=token,
            insecure=args.insecure,
        )
    except ApiError as exc:
        if exc.status == 404:
            die(f"{name} not found in {ecosystem}")
        if exc.status == 401:
            die("not logged in. Run: minireg login")
        die(exc.detail)

    print(f"\n  {bold(pkg['name'])}  {dim(pkg['ecosystem'])}")
    if pkg.get("description"):
        print(f"  {pkg['description']}")
    print()
    if pkg.get("blocked"):
        print(f"  {red('BLOCKED')}: {pkg.get('block_reason')}")
        print()

    print(f"  latest    : {pkg.get('latest_version') or '--'}")
    print(f"  versions  : {len(pkg.get('versions') or [])}")
    print(f"  downloads : {pkg.get('download_count', 0)}")
    if pkg.get("license"):
        print(f"  license   : {pkg['license']}")

    sources = pkg.get("upstreams") or []
    if sources:
        print(f"\n  {bold('Available from')}")
        for source in sources:
            location = source.get("web_url") or source.get("index_url") or ""
            label = source["name"]
            if source.get("tier") is not None and source.get("kind") != "local":
                label += f" (tier {source['tier']})"
            print(f"    {label}  {dim(location)}")

    vulnerable = [v for v in (pkg.get("versions") or []) if v.get("cves")]
    if vulnerable:
        print(f"\n  {bold('Versions with known CVEs')}")
        for version in vulnerable[: args.limit]:
            ids = ", ".join(c["cve_id"] for c in version["cves"][:4])
            score = version.get("max_cvss")
            print(
                f"    {version['version']:<14} "
                f"{severity_colour(score)(f'{score:.1f}' if score else '  --')}  {dim(ids)}"
            )
    print()
    return 0


# --------------------------------------------------------------------------- #
# update
# --------------------------------------------------------------------------- #
def fetch_text(registry: str, path: str, insecure: bool = False, timeout: int = 60) -> str:
    """Fetch a non-JSON body. Used for the CLI source itself."""
    request = urllib.request.Request(
        f"{registry.rstrip('/')}{path}",
        headers={"user-agent": USER_AGENT, "accept": "*/*"},
    )
    context = None
    if insecure:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            return response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        raise ApiError(exc.code, f"HTTP {exc.code} fetching {path}") from exc
    except urllib.error.URLError as exc:
        raise ApiError(0, f"could not reach {registry}: {exc.reason}") from exc


def install_path() -> Path:
    """Where this script lives, following symlinks."""
    return Path(__file__).resolve()


def cmd_update(args):
    registry = require_registry(args)

    # Overwriting this file with whatever the network returns is remote code
    # execution, and TLS is the only thing standing between the two. With
    # --insecure the certificate is not checked at all, so anyone on the path
    # can serve the replacement.
    if args.insecure:
        die(
            "refusing to self-update with --insecure: the downloaded script "
            "replaces this program, and an unverified connection means anyone "
            "on the network path chooses what it contains"
        )
    if not registry.lower().startswith("https://"):
        die(
            "refusing to self-update over plaintext HTTP: the downloaded "
            "script replaces this program"
        )

    try:
        remote = api(registry, "/api/cli/version", insecure=args.insecure)
    except ApiError as exc:
        die(f"could not check for updates: {exc.detail}")

    latest = remote.get("version")
    if not latest:
        die("the registry did not report a CLI version")

    print(f"  installed : {__version__}")
    print(f"  registry  : {latest}")

    if latest == __version__ and not args.force:
        print(f"  {green('✓')} already up to date")
        return 0
    if args.check:
        print(f"  {yellow('an update is available')} — run: minireg update")
        return 1

    source = fetch_text(registry, "/api/cli/download", insecure=args.insecure)

    # Three checks before anything is overwritten. A truncated or mangled
    # download that replaced this file would leave no working CLI to recover
    # with, and the whole point is that it is the only tool installed.
    expected = remote.get("sha256")
    actual = hashlib.sha256(source.encode()).hexdigest()
    if not expected:
        die(
            "the registry did not publish a checksum for the CLI; refusing to "
            "overwrite this program with an unverified download"
        )
    if expected != actual:
        die(f"checksum mismatch: expected {expected[:16]}…, got {actual[:16]}…")
    try:
        compile(source, "<downloaded minireg>", "exec")
    except SyntaxError as exc:
        die(f"the downloaded CLI is not valid Python ({exc}); refusing to install it")
    if "def main(" not in source or "__version__" not in source:
        die("the downloaded file does not look like the minireg CLI; refusing to install it")

    target = install_path()
    try:
        # Stage beside the target so the rename is atomic and cannot leave a
        # half-written script behind.
        fd, tmp_name = tempfile.mkstemp(dir=str(target.parent), prefix=".minireg-")
        with os.fdopen(fd, "w") as handle:
            handle.write(source)
        os.chmod(tmp_name, target.stat().st_mode & 0o777 or 0o755)
        os.replace(tmp_name, target)
    except PermissionError:
        die(
            f"no permission to write {target}\n"
            f"  try:  sudo minireg update\n"
            f"  or reinstall: curl -fsSL {registry}/api/cli/install.sh | sh"
        )
    except OSError as exc:
        die(f"could not replace {target}: {exc}")

    print(f"  {green('✓')} updated to {latest}")
    return 0


def warn_if_outdated():
    """One line, after the command has done its work.

    Uses the version learned from responses already made, so it never adds a
    request of its own and never fires for a command that did not talk to the
    registry.
    """
    if not _server_cli_version or _server_cli_version == __version__:
        return
    info(
        dim(
            f"  note: this registry ships CLI {_server_cli_version}, you have "
            f"{__version__} — run 'minireg update'"
        )
    )


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="minireg",
        description="Command line client for a minireg package registry.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  minireg login --url https://registry.example.com\n"
            "  minireg configure\n"
            "  minireg audit --fail-on high\n"
            "  minireg search express\n"
            "  minireg info lodash\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"minireg {__version__}")
    parser.add_argument("--url", help="registry URL (defaults to the stored one)")
    parser.add_argument(
        "--insecure", action="store_true", help="skip TLS verification (development only)"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    login = sub.add_parser("login", help="authenticate via the browser")
    login.add_argument("--no-browser", action="store_true", help="do not open a browser")
    login.add_argument(
        "--scopes", default="read", help="comma-separated: read,publish,admin (default: read)"
    )
    login.set_defaults(func=cmd_login)

    sub.add_parser("logout", help="forget the stored token").set_defaults(func=cmd_logout)

    update = sub.add_parser("update", help="update this CLI from the registry")
    update.add_argument(
        "--check", action="store_true", help="report whether an update exists, exit 1 if so"
    )
    update.add_argument("--force", action="store_true", help="reinstall even if versions match")
    update.set_defaults(func=cmd_update)
    sub.add_parser("whoami", help="show the current identity").set_defaults(func=cmd_whoami)

    configure = sub.add_parser(
        "configure", help="point npm / pip / cargo at the registry"
    )
    configure.add_argument(
        "target", nargs="?", default="all", help="npm, pip, cargo, or all (default: all)"
    )
    configure.add_argument("--dry-run", action="store_true", help="print instead of writing")
    configure.set_defaults(func=cmd_configure)

    audit_cmd = sub.add_parser("audit", help="check this project's dependencies for CVEs")
    audit_cmd.add_argument("path", nargs="?", default=".", help="project directory or lockfile")
    audit_cmd.add_argument(
        "--fail-on",
        default="never",
        help="exit 2 if a CVE at this severity or above is found: low, medium, high, critical",
    )
    audit_cmd.add_argument("--json", action="store_true", help="machine-readable output")
    audit_cmd.add_argument(
        "--fail-on-unscanned",
        dest="fail_on_unscanned",
        action="store_true",
        default=None,
        help=(
            "exit 3 when a dependency could not be checked (the default "
            "whenever --fail-on is given)"
        ),
    )
    audit_cmd.add_argument(
        "--no-fail-on-unscanned",
        dest="fail_on_unscanned",
        action="store_false",
        help="treat dependencies that could not be checked as acceptable",
    )
    audit_cmd.add_argument(
        "--offline", action="store_true", help="do not scan packages the registry has not seen"
    )
    audit_cmd.add_argument(
        "--fix",
        action="store_true",
        help="rewrite requirements.txt / package.json to versions that clear the CVEs",
    )
    audit_cmd.add_argument(
        "--yes", action="store_true", help="apply --fix without confirming"
    )
    audit_cmd.add_argument(
        "--dry-run", action="store_true", help="with --fix, show the changes without writing"
    )
    audit_cmd.set_defaults(func=cmd_audit)

    search = sub.add_parser("search", help="search the registry")
    search.add_argument("query")
    search.add_argument("--ecosystem", choices=["npm", "pypi", "cargo"])
    search.add_argument("--limit", type=int, default=25)
    search.set_defaults(func=cmd_search)

    info_cmd = sub.add_parser("info", help="show a package")
    info_cmd.add_argument("package")
    info_cmd.add_argument("--ecosystem", choices=["npm", "pypi", "cargo"], default="npm")
    info_cmd.add_argument("--limit", type=int, default=20)
    info_cmd.set_defaults(func=cmd_info)

    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        code = args.func(args) or 0
    except KeyboardInterrupt:
        info("\nCancelled.")
        return 130
    except ApiError as exc:
        die(exc.detail or f"HTTP {exc.status}")
        return 1
    if args.command != "update":
        warn_if_outdated()
    return code


if __name__ == "__main__":
    sys.exit(main())
