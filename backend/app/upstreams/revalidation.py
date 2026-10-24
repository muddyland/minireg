"""Conditional revalidation of cached upstream metadata.

A metadata refresh used to be a full GET every ``META_CACHE_TTL`` seconds:
the whole packument downloaded, parsed and rewritten even when nothing had
changed upstream -- 37 MB for vite, every minute, for every popular package.
Registries answer ``If-None-Match`` / ``If-Modified-Since`` with an empty 304,
which costs one round trip and no parsing at all.

Validators are only meaningful to the server that issued them, so they are
stored bound to the upstream that served the document and only ever sent back
to that same upstream. A document merged from several upstreams (PyPI's
multi-index merge) has no single validator and is never revalidated.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

#: The column the encoded validators live in (``packages.cached_etag``) is
#: VARCHAR(255). Anything longer is dropped rather than truncated: a truncated
#: ETag would never match and would only cost a wasted conditional request.
_MAX_ENCODED = 255
_SEP = "|"


class UpstreamNotModified(Exception):
    """The upstream answered 304: the copy we hold is still current."""


@dataclass(frozen=True, slots=True)
class Validators:
    upstream_id: int
    etag: str | None = None
    last_modified: str | None = None

    @property
    def usable(self) -> bool:
        return bool(self.etag or self.last_modified)

    def headers(self) -> dict[str, str]:
        out: dict[str, str] = {}
        if self.etag:
            out["if-none-match"] = self.etag
        if self.last_modified:
            out["if-modified-since"] = self.last_modified
        return out

    @classmethod
    def from_response(cls, upstream_id: int, resp: httpx.Response) -> Validators | None:
        etag = (resp.headers.get("etag") or "").strip() or None
        last_modified = (resp.headers.get("last-modified") or "").strip() or None
        found = cls(upstream_id=upstream_id, etag=etag, last_modified=last_modified)
        return found if found.usable else None

    # -- storage ------------------------------------------------------------ #
    def encode(self) -> str | None:
        """``"<upstream id>|<last-modified>|<etag>"``, or None if it cannot fit.

        The ETag goes last because it is the one field that may itself
        contain the separator. An HTTP date never does; one that somehow
        does is dropped.
        """
        last_modified = self.last_modified or ""
        if _SEP in last_modified:
            last_modified = ""
        for etag, lm in ((self.etag or "", last_modified), ("", last_modified), (self.etag or "", "")):
            if not (etag or lm):
                continue
            encoded = f"{self.upstream_id}{_SEP}{lm}{_SEP}{etag}"
            if len(encoded) <= _MAX_ENCODED:
                return encoded
        return None

    @classmethod
    def decode(cls, stored: str | None) -> Validators | None:
        """Inverse of :meth:`encode`. Anything else -- including a bare ETag
        written before validators were bound to an upstream -- is None, since
        there is no way to know which server it belongs to."""
        if not stored:
            return None
        parts = stored.split(_SEP, 2)
        if len(parts) != 3 or not parts[0].isdigit():
            return None
        found = cls(upstream_id=int(parts[0]), etag=parts[2] or None, last_modified=parts[1] or None)
        return found if found.usable else None


def bound_prefix(upstream_id: int) -> str:
    """LIKE prefix matching every stored validator issued by one upstream."""
    return f"{upstream_id}{_SEP}"


def check_not_modified(resp: httpx.Response, validators: Validators | None) -> None:
    """Raise :class:`UpstreamNotModified` for a 304 we actually asked for.

    A 304 to an unconditional request is a broken upstream, not a
    confirmation of anything we hold; let it fall through to the caller's
    ordinary status handling, which treats it as an error.
    """
    if resp.status_code == 304 and validators is not None and validators.usable:
        raise UpstreamNotModified()
