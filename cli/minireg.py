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
import json
import os
import platform
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path

__version__ = "1.0.0"

DEFAULT_TIMEOUT = 30
USER_AGENT = f"minireg-cli/{__version__}"


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

    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            payload = response.read()
            return json.loads(payload) if payload else None
    except urllib.error.HTTPError as exc:
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
                    "registry": result.get("registry") or registry,
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
    path.write_text(updated)


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
        targets = "npm,pip"
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
            os.chmod(_npmrc_path(), 0o600)
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
        lines = ["[global]", f"index-url = {index_url}"]
        if registry.startswith("http://"):
            lines.append(f"trusted-host = {host.split(':')[0]}")
        if args.dry_run:
            print(f"\n{bold(str(pip_conf))}\n" + "\n".join(lines))
        else:
            _upsert_lines(pip_conf, lines, "minireg")
            os.chmod(pip_conf, 0o600)
            changed.append(str(pip_conf))

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


def parse_requirements(path: Path) -> list[dict]:
    """requirements.txt, pinned entries only -- a range has no single version
    to audit."""
    out = []
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return out
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        match = re.match(r"^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*==\s*([^\s;]+)", line)
        if match:
            out.append({"name": match.group(1), "version": match.group(2)})
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
    ("requirements.txt", "pypi", parse_requirements),
]

SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def discover(root: Path) -> list[tuple[Path, str, list[dict]]]:
    found = []
    for filename, ecosystem, parser in LOCKFILES:
        path = root / filename
        if path.is_file():
            packages = parser(path)
            if packages:
                found.append((path, ecosystem, packages))
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
            f"no lockfile found in {root}\n"
            f"  looked for: {', '.join(name for name, _, _ in LOCKFILES)}"
        )

    total_findings = []
    worst = 0.0
    exit_blocked = False

    for path, ecosystem, packages in sources:
        rel = path.name
        info(f"{dim('scanning')} {bold(rel)} {dim(f'({len(packages)} packages, {ecosystem})')}")

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
        if unscanned:
            info(
                dim(
                    f"  {unscanned} package(s) could not be scanned"
                    + (" (offline mode)" if args.offline else "")
                )
            )

    if args.json:
        print(json.dumps({"findings": total_findings}, indent=2))
        return 0

    blocked = [f for f in total_findings if f.get("blocked")]
    parts = [f"{len(total_findings)} package(s) with findings"]
    if blocked:
        # A blocked package is not advisory: the registry will refuse to serve
        # it, so the install fails outright.
        parts.append(red(f"{len(blocked)} blocked — these will not install"))
    print(f"  {bold('Summary')}: " + ", ".join(parts))

    threshold = (args.fail_on or "").lower()
    if threshold and threshold != "never":
        limit = SEVERITY_ORDER.get(threshold)
        if limit is None:
            die(f"unknown --fail-on value: {threshold}")
        for finding in total_findings:
            for cve in finding.get("cves") or []:
                if SEVERITY_ORDER.get((cve.get("severity") or "none"), 0) >= limit:
                    return 2
        if exit_blocked:
            return 2
    return 0


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
        tag = blue("npm") if item["ecosystem"] == "npm" else yellow("pypi")
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
    sub.add_parser("whoami", help="show the current identity").set_defaults(func=cmd_whoami)

    configure = sub.add_parser("configure", help="point npm / pip at the registry")
    configure.add_argument(
        "target", nargs="?", default="all", help="npm, pip, or all (default: all)"
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
        "--offline", action="store_true", help="do not scan packages the registry has not seen"
    )
    audit_cmd.set_defaults(func=cmd_audit)

    search = sub.add_parser("search", help="search the registry")
    search.add_argument("query")
    search.add_argument("--ecosystem", choices=["npm", "pypi"])
    search.add_argument("--limit", type=int, default=25)
    search.set_defaults(func=cmd_search)

    info_cmd = sub.add_parser("info", help="show a package")
    info_cmd.add_argument("package")
    info_cmd.add_argument("--ecosystem", choices=["npm", "pypi"], default="npm")
    info_cmd.add_argument("--limit", type=int, default=20)
    info_cmd.set_defaults(func=cmd_info)

    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args) or 0
    except KeyboardInterrupt:
        info("\nCancelled.")
        return 130
    except ApiError as exc:
        die(exc.detail or f"HTTP {exc.status}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
