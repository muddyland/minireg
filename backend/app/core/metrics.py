"""Process-wide counters and gauges, with a Prometheus text rendering.

Counters were a plain dict in ``app.main``. They moved here so the registry
and scanner code can count things without importing the application module
(which is what ``services.osv`` had to do, lazily, to avoid a cycle).

Deliberately small: counters are ``name{label="v"}`` strings with integer
values, gauges are set by whoever owns the figure. No client library, no
histogram buckets -- the point is to make silent failure modes and the
upstream quota visible, not to reimplement Prometheus.
"""

from __future__ import annotations

import re
from collections import defaultdict

COUNTERS: dict[str, int] = defaultdict(int)
GAUGES: dict[str, float] = {}

_LABEL_RE = re.compile(r"[^a-zA-Z0-9_]")


def _key(name: str, labels: dict[str, str] | None) -> str:
    if not labels:
        return name
    inner = ",".join(f'{k}="{_escape(str(v))}"' for k, v in sorted(labels.items()))
    return f"{name}{{{inner}}}"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")[:200]


def bump(name: str, amount: int = 1, **labels: str) -> None:
    COUNTERS[_key(name, labels)] += amount


def gauge(name: str, value: float, **labels: str) -> None:
    GAUGES[_key(name, labels)] = value


def snapshot() -> dict[str, dict]:
    return {"counters": dict(sorted(COUNTERS.items())), "gauges": dict(sorted(GAUGES.items()))}


def _metric_name(key: str) -> str:
    base = key.split("{", 1)[0]
    return "minireg_" + _LABEL_RE.sub("_", base)


def prometheus_text() -> str:
    """Render in the Prometheus text exposition format."""
    lines: list[str] = []
    seen: set[str] = set()
    for store, kind in ((COUNTERS, "counter"), (GAUGES, "gauge")):
        for key, value in sorted(store.items()):
            metric = _metric_name(key)
            labels = key[len(key.split("{", 1)[0]) :]
            if metric not in seen:
                lines.append(f"# TYPE {metric} {kind}")
                seen.add(metric)
            lines.append(f"{metric}{labels} {value}")
    return "\n".join(lines) + "\n"
