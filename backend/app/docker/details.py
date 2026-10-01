"""What is inside an image: config, build history, layers, SBOM packages.

Pure functions over bytes the registry already holds (the image config blob
and the CycloneDX SBOM the scanner uploaded), so the image page can show
them without anyone pulling the image. Everything here reads untrusted
input: sizes are capped, strings clipped, and anything malformed yields
"not available" rather than an error.
"""

from __future__ import annotations

import json
from collections import OrderedDict
from typing import Any

#: Image configs are a few KB; a big one is a sign of abuse, not of a big image.
MAX_CONFIG_BYTES = 4 * 1024 * 1024
#: SBOMs of large images (a CUDA base, a fat JVM app) run to tens of MB.
MAX_SBOM_BYTES = 64 * 1024 * 1024
#: Components returned to the page. The count is always reported in full.
MAX_COMPONENTS = 5000

_PROP = "aquasecurity:trivy:"


def _s(value: Any, limit: int = 512) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    return value[:limit]


def _str_list(value: Any, limit: int = 100, each: int = 1024) -> list[str]:
    if isinstance(value, str):
        return [value[:each]]
    if not isinstance(value, list):
        return []
    return [str(v)[:each] for v in value[:limit] if v is not None]


# --------------------------------------------------------------------------- #
# Image config
# --------------------------------------------------------------------------- #
def parse_config(raw: bytes | None) -> dict[str, Any] | None:
    """The parts of an OCI/Docker image config a person wants to read."""
    if not raw:
        return None
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(doc, dict):
        return None
    cfg = doc.get("config") if isinstance(doc.get("config"), dict) else {}
    labels = cfg.get("Labels") if isinstance(cfg.get("Labels"), dict) else {}
    ports = cfg.get("ExposedPorts") if isinstance(cfg.get("ExposedPorts"), dict) else {}
    volumes = cfg.get("Volumes") if isinstance(cfg.get("Volumes"), dict) else {}
    health = cfg.get("Healthcheck") if isinstance(cfg.get("Healthcheck"), dict) else {}
    history = []
    for entry in (doc.get("history") if isinstance(doc.get("history"), list) else [])[:500]:
        if not isinstance(entry, dict):
            continue
        history.append(
            {
                "created": _s(entry.get("created"), 64),
                "created_by": _s(entry.get("created_by"), 4096),
                "comment": _s(entry.get("comment"), 512),
                "author": _s(entry.get("author"), 256),
                "empty_layer": bool(entry.get("empty_layer")),
            }
        )
    rootfs = doc.get("rootfs") if isinstance(doc.get("rootfs"), dict) else {}
    return {
        "os": _s(doc.get("os"), 64),
        "architecture": _s(doc.get("architecture"), 64),
        "variant": _s(doc.get("variant"), 64),
        "created": _s(doc.get("created"), 64),
        "author": _s(doc.get("author"), 256),
        "user": _s(cfg.get("User"), 256),
        "working_dir": _s(cfg.get("WorkingDir"), 1024),
        "entrypoint": _str_list(cfg.get("Entrypoint")),
        "cmd": _str_list(cfg.get("Cmd")),
        "env": _str_list(cfg.get("Env"), limit=500, each=4096),
        "labels": {str(k)[:256]: _s(v, 2048) for k, v in list(labels.items())[:200]},
        "exposed_ports": sorted(str(p)[:32] for p in list(ports)[:100]),
        "volumes": sorted(str(v)[:1024] for v in list(volumes)[:100]),
        "stop_signal": _s(cfg.get("StopSignal"), 32),
        "healthcheck": _str_list(health.get("Test")),
        "history": history,
        "diff_ids": _str_list(rootfs.get("diff_ids"), limit=1000, each=80),
    }


def layer_history(layer_count: int, history: list[dict]) -> list[dict | None]:
    """The build step that produced each layer, in layer order.

    Every history entry without ``empty_layer`` made exactly one layer, in
    order. When the counts disagree (a hand-built image, a squashed one) the
    pairing would be guesswork, so nothing is paired.
    """
    producing = [h for h in history if not h.get("empty_layer")]
    if len(producing) != layer_count:
        return [None] * layer_count
    return producing


# --------------------------------------------------------------------------- #
# SBOM
# --------------------------------------------------------------------------- #
def _licenses(entry: dict) -> list[str]:
    out = []
    for item in entry.get("licenses") or []:
        if not isinstance(item, dict):
            continue
        if item.get("expression"):
            out.append(str(item["expression"])[:128])
            continue
        lic = item.get("license") if isinstance(item.get("license"), dict) else {}
        name = lic.get("id") or lic.get("name")
        if name:
            out.append(str(name)[:128])
    return out[:10]


def _props(entry: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    for prop in entry.get("properties") or []:
        if isinstance(prop, dict) and isinstance(prop.get("name"), str) and prop["name"].startswith(_PROP):
            # First value wins: Trivy repeats some keys (DiffID) on the target.
            out.setdefault(prop["name"][len(_PROP) :], str(prop.get("value"))[:1024])
    return out


def _walk(components: Any, depth: int = 0):
    if not isinstance(components, list) or depth > 8:
        return
    for c in components:
        if isinstance(c, dict):
            yield c
            yield from _walk(c.get("components"), depth + 1)


def summarize_sbom(raw: bytes | None) -> dict[str, Any] | None:
    """A CycloneDX SBOM as a package list the page can filter and sort."""
    if not raw:
        return None
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return {"format": "unreadable", "components": [], "total": 0, "truncated": False}
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
        return {"format": "unsupported", "components": [], "total": 0, "truncated": False}
    meta = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
    tools = meta.get("tools")
    tool = None
    if isinstance(tools, dict) and isinstance(tools.get("components"), list) and tools["components"]:
        t = tools["components"][0]
        if isinstance(t, dict):
            tool = " ".join(x for x in (_s(t.get("name"), 64), _s(t.get("version"), 32)) if x)
    elif isinstance(tools, list) and tools and isinstance(tools[0], dict):
        tool = " ".join(x for x in (_s(tools[0].get("name"), 64), _s(tools[0].get("version"), 32)) if x)

    os_info = None
    components = []
    total = 0
    by_type: dict[str, int] = {}
    for c in _walk(doc.get("components")):
        ctype = _s(c.get("type"), 32) or "library"
        if ctype == "operating-system":
            os_info = " ".join(x for x in (_s(c.get("name"), 64), _s(c.get("version"), 64)) if x)
            continue
        props = _props(c)
        pkg_type = props.get("PkgType") or ctype
        total += 1
        by_type[pkg_type] = by_type.get(pkg_type, 0) + 1
        if len(components) < MAX_COMPONENTS:
            components.append(
                {
                    "name": _s(c.get("name"), 256) or "?",
                    "version": _s(c.get("version"), 128),
                    "type": pkg_type,
                    "purl": _s(c.get("purl"), 1024),
                    "licenses": _licenses(c),
                    "layer_digest": props.get("LayerDigest"),
                    "path": props.get("FilePath"),
                }
            )
    return {
        "format": f"CycloneDX {_s(doc.get('specVersion'), 8) or ''}".strip(),
        "generated_at": _s(meta.get("timestamp"), 64),
        "tool": tool,
        "os": os_info,
        "total": total,
        "by_type": dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
        "truncated": total > len(components),
        "components": components,
    }


class _Cache:
    """Parsed SBOMs by digest. Content-addressed, so never stale."""

    def __init__(self, size: int = 16) -> None:
        self.size = size
        self.items: OrderedDict[str, dict] = OrderedDict()

    def get(self, key: str) -> dict | None:
        value = self.items.get(key)
        if value is not None:
            self.items.move_to_end(key)
        return value

    def put(self, key: str, value: dict) -> None:
        self.items[key] = value
        self.items.move_to_end(key)
        while len(self.items) > self.size:
            self.items.popitem(last=False)


SBOM_CACHE = _Cache()
