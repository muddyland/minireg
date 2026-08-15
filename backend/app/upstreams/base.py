"""Upstream provider interface and the shared HTTP client.

A provider translates one remote registry's dialect into the neutral
``RemotePackage`` shape below. Everything above this layer (routing, caching,
policy, rendering) is ecosystem-aware but provider-agnostic.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import httpx

from ..config import settings
from ..core.security import decrypt_credential
from ..models import Upstream

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Neutral wire types
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class RemoteFile:
    filename: str
    url: str
    hashes: dict[str, str] = field(default_factory=dict)
    size: int | None = None
    requires_python: str | None = None
    yanked: bool | str = False
    core_metadata: bool | dict | None = None
    upload_time: datetime | None = None
    packagetype: str | None = None
    python_version: str | None = None
    content_type: str = "application/octet-stream"
    # Which upstream this file came from, so the artifact fetch can reuse the
    # right credentials. Set by the resolver.
    upstream_id: int | None = None


@dataclass(slots=True)
class RemoteVersion:
    version: str
    metadata: dict[str, Any] = field(default_factory=dict)
    files: list[RemoteFile] = field(default_factory=list)
    deprecated: str | None = None
    yanked: bool | str = False
    requires_python: str | None = None
    published_at: datetime | None = None


@dataclass(slots=True)
class RemotePackage:
    name: str
    versions: list[RemoteVersion] = field(default_factory=list)
    dist_tags: dict[str, str] = field(default_factory=dict)
    description: str | None = None
    author: str | None = None
    homepage: str | None = None
    license: str | None = None
    keywords: list[str] = field(default_factory=list)
    readme: str | None = None
    time: dict[str, str] = field(default_factory=dict)
    # Verbatim upstream document, preserved so we can re-serve fields we do not
    # model. For npm this is the packument, which matters for 1:1 fidelity.
    raw: dict[str, Any] = field(default_factory=dict)
    etag: str | None = None
    upstream_id: int | None = None
    upstream_name: str | None = None


@dataclass(slots=True)
class SearchHit:
    name: str
    version: str | None = None
    description: str | None = None
    keywords: list[str] = field(default_factory=list)
    author: str | None = None
    date: datetime | None = None
    links: dict[str, str] = field(default_factory=dict)
    score: float = 0.0


class UpstreamError(Exception):
    """Recoverable upstream failure; the router moves to the next candidate."""


class UpstreamNotFound(UpstreamError):
    """Upstream answered authoritatively that the package does not exist."""


# --------------------------------------------------------------------------- #
# Shared client
# --------------------------------------------------------------------------- #
_client: httpx.AsyncClient | None = None


def get_http_client() -> httpx.AsyncClient:
    """One pooled client process-wide.

    Connection reuse is the single biggest win when a CI fleet asks for a few
    hundred packages at once, so this is deliberately a shared pool rather than
    a client per request.
    """
    global _client
    if _client is None:
        _client = httpx.AsyncClient(
            timeout=httpx.Timeout(
                settings.upstream_timeout_seconds,
                connect=settings.upstream_connect_timeout_seconds,
            ),
            limits=httpx.Limits(
                max_connections=settings.upstream_max_connections,
                max_keepalive_connections=settings.upstream_max_keepalive,
            ),
            follow_redirects=True,
            http2=True,
            headers={"user-agent": f"{settings.app_name}/1.0 (+{settings.public_url})"},
        )
    return _client


async def close_http_client() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
    _client = None


# --------------------------------------------------------------------------- #
# Provider base
# --------------------------------------------------------------------------- #
class UpstreamProvider:
    """Base class. Subclasses implement the ecosystem-specific methods."""

    #: Whether this provider can enumerate its full package list for indexing.
    supports_indexing: bool = False
    #: Whether this provider can be a publish target.
    supports_publish: bool = False
    #: Whether this provider has a native search endpoint.
    supports_search: bool = False

    def __init__(self, upstream: Upstream) -> None:
        self.upstream = upstream
        self.id = upstream.id
        self.name = upstream.name
        self.base_url = upstream.url.rstrip("/")

    # -- auth --------------------------------------------------------------- #
    def auth_headers(self) -> dict[str, str]:
        secret = decrypt_credential(self.upstream.credential_enc)
        if not secret:
            return {}
        auth_type = (self.upstream.auth_type or "none").lower()
        if auth_type == "bearer":
            return {"authorization": f"Bearer {secret}"}
        if auth_type == "basic":
            import base64

            # Credential is stored as "user:password".
            token = base64.b64encode(secret.encode()).decode()
            return {"authorization": f"Basic {token}"}
        if auth_type == "token_header":
            header = self.upstream.auth_header_name or "PRIVATE-TOKEN"
            return {header: secret}
        return {}

    # -- request helper ----------------------------------------------------- #
    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        retries: int | None = None,
        **kwargs,
    ) -> httpx.Response:
        client = get_http_client()
        merged = {**self.auth_headers(), **(headers or {})}
        attempts = (retries if retries is not None else settings.upstream_retries) + 1
        timeout = httpx.Timeout(
            self.upstream.timeout_seconds or settings.upstream_timeout_seconds,
            connect=settings.upstream_connect_timeout_seconds,
        )
        last: Exception | None = None
        for attempt in range(attempts):
            try:
                resp = await client.request(
                    method, url, headers=merged, timeout=timeout, **kwargs
                )
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last = exc
                if attempt + 1 < attempts:
                    # Exponential backoff; a struggling upstream should not be
                    # hammered while it recovers.
                    await asyncio.sleep(0.2 * (2**attempt))
                    continue
                raise UpstreamError(f"{self.name}: {exc}") from exc
            # 5xx and 429 are retryable; 4xx is authoritative.
            if resp.status_code >= 500 or resp.status_code == 429:
                last = UpstreamError(f"{self.name}: HTTP {resp.status_code}")
                if attempt + 1 < attempts:
                    await asyncio.sleep(0.2 * (2**attempt))
                    continue
            return resp
        raise UpstreamError(str(last) if last else f"{self.name}: exhausted retries")

    async def stream(
        self, url: str, *, headers: dict[str, str] | None = None
    ) -> tuple[httpx.Response, AsyncIterator[bytes]]:
        """Open a streaming GET. Caller must close the response."""
        client = get_http_client()
        merged = {**self.auth_headers(), **(headers or {})}
        req = client.build_request("GET", url, headers=merged)
        resp = await client.send(req, stream=True)
        return resp, resp.aiter_bytes(settings.stream_chunk_size)

    # -- interface ---------------------------------------------------------- #
    async def fetch_package(self, name: str) -> RemotePackage:
        raise NotImplementedError

    async def health_check(self) -> tuple[bool, str | None]:
        raise NotImplementedError

    async def list_packages(self) -> list[str]:
        raise NotImplementedError

    async def search(self, query: str, size: int = 20, offset: int = 0) -> list[SearchHit]:
        raise NotImplementedError

    async def publish(self, payload: dict, ecosystem: str) -> tuple[bool, str]:
        raise NotImplementedError

    def artifact_url(self, remote_url: str) -> str:
        """Hook for providers that must rewrite artifact URLs."""
        return remote_url

    # -- provenance links --------------------------------------------------- #
    def package_index_url(self, name: str) -> str:
        """The address this provider actually fetches the package from.

        Always available, always correct -- it is the URL we really use.
        """
        raise NotImplementedError

    def default_web_url(self, name: str) -> str | None:
        """Human-facing page for well-known public hosts. None otherwise."""
        return None

    def package_web_url(self, name: str) -> str | None:
        """Where a person should click to read about this package upstream.

        Prefers the admin-configured template, so a private or self-hosted
        registry can point at its own UI; falls back to a derived default for
        hosts we recognise.
        """
        template = self.upstream.web_url_template
        if template:
            from ..core.naming import normalize_name_for

            try:
                return template.format(
                    name=name,
                    normalized_name=normalize_name_for(self.upstream.ecosystem.value, name),
                )
            except (KeyError, IndexError):
                # A malformed template must not break the page it appears on.
                log.warning("upstream %s has an invalid web_url_template", self.name)
                return None
        return self.default_web_url(name)
