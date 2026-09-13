"""Upstream provider interface and the shared HTTP client.

A provider translates one remote registry's dialect into the neutral
``RemotePackage`` shape below. Everything above this layer (routing, caching,
policy, rendering) is ecosystem-aware but provider-agnostic.
"""

from __future__ import annotations

import asyncio
import logging
import random
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any

import httpx

from ..config import settings
from ..core.security import decrypt_credential
from ..models import Upstream
from .netguard import check_fetchable, same_origin

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
_insecure_client: httpx.AsyncClient | None = None
#: Redirect hops allowed on an artifact fetch, each re-checked before it is taken.
_MAX_REDIRECTS = 5
#: Longest Retry-After we will sit out inline rather than failing the request.
_MAX_RETRY_AFTER_WAIT = 5.0


def _backoff(attempt: int) -> float:
    """Exponential backoff with jitter.

    Jitter matters here: without it a fleet of workers that all failed against
    the same upstream retries in lockstep, which is the shape of a
    self-inflicted thundering herd.
    """
    base = 0.2 * (2**attempt)
    return base + random.uniform(0, base)


def _retry_after_seconds(value: str | None) -> float | None:
    """Parse Retry-After, which is either delta-seconds or an HTTP date."""
    if not value:
        return None
    value = value.strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    parsed = parsedate_to_datetime(value)
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return max(0.0, (parsed - datetime.now(UTC)).total_seconds())


def _build_client(verify: bool) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        verify=verify,
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


def get_insecure_http_client() -> httpx.AsyncClient:
    """Pool for upstreams with TLS verification switched off.

    A separate client because `verify` is fixed at construction. The admin UI
    has always offered this toggle; until now nothing read it, so an operator
    who ticked it got verification anyway. Silently ignoring a security
    control is worse than either honouring it or removing it, so it is
    honoured -- and the upstream list shows which upstreams have it set.
    """
    global _insecure_client
    if _insecure_client is None:
        _insecure_client = _build_client(verify=False)
    return _insecure_client


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
    global _client, _insecure_client
    if _client is not None:
        await _client.aclose()
    _client = None
    if _insecure_client is not None:
        await _insecure_client.aclose()
    _insecure_client = None


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
    @property
    def client(self) -> httpx.AsyncClient:
        """The pooled client this upstream's TLS setting calls for."""
        if getattr(self.upstream, "verify_ssl", True):
            return get_http_client()
        return get_insecure_http_client()

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
    def check_body_size(self, resp: httpx.Response) -> httpx.Response:
        """Reject an oversized metadata document.

        Packuments are read whole and then written to `packages.cached_document`
        on every refresh -- the biggest public ones are already tens of
        megabytes, and there was no ceiling at all, so a hostile upstream
        could hand over as much as it liked and the row would follow it into
        the database.
        """
        limit = settings.max_metadata_bytes
        if not limit:
            return resp
        declared = resp.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > limit:
            raise UpstreamError(
                f"{self.name}: metadata document is {declared} bytes, over the "
                f"{limit} byte limit"
            )
        if len(resp.content) > limit:
            raise UpstreamError(
                f"{self.name}: metadata document exceeds the {limit} byte limit"
            )
        return resp

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        retries: int | None = None,
        **kwargs,
    ) -> httpx.Response:
        client = self.client
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
                    await asyncio.sleep(_backoff(attempt))
                    continue
                raise UpstreamError(f"{self.name}: {exc}") from exc

            if resp.status_code == 429:
                # "Too many requests" is the one status where retrying makes
                # things worse. Honour Retry-After if it is short enough to be
                # worth waiting for, and only ever try once more -- three
                # attempts 200ms apart, multiplied across a raced tier, is how
                # a rate-limited upstream gets pushed further under.
                last = UpstreamError(f"{self.name}: HTTP 429")
                delay = _retry_after_seconds(resp.headers.get("retry-after"))
                if attempt == 0 and delay is not None and delay <= _MAX_RETRY_AFTER_WAIT:
                    await resp.aclose()
                    await asyncio.sleep(delay)
                    continue
                return resp

            if resp.status_code >= 500:
                last = UpstreamError(f"{self.name}: HTTP {resp.status_code}")
                if attempt + 1 < attempts:
                    await resp.aclose()
                    await asyncio.sleep(_backoff(attempt))
                    continue
            return resp
        raise UpstreamError(str(last) if last else f"{self.name}: exhausted retries")

    async def stream(
        self, url: str, *, headers: dict[str, str] | None = None
    ) -> tuple[httpx.Response, AsyncIterator[bytes]]:
        """Open a streaming GET. Caller must close the response.

        Credentials go only to the upstream's own origin. The URL here comes
        from upstream metadata, and httpx strips `Authorization` across a
        cross-origin redirect but not a custom header -- so a GitLab
        `PRIVATE-TOKEN` followed a 302 to object storage, or to wherever a
        hostile packument pointed. Redirects are followed manually for the
        same reason: each hop has to be re-checked before it is taken.
        """
        client = self.client
        merged = dict(headers or {})
        if same_origin(url, self.upstream.url):
            merged.update(self.auth_headers())

        current = url
        for _ in range(_MAX_REDIRECTS):
            req = client.build_request("GET", current, headers=merged)
            resp = await client.send(req, stream=True, follow_redirects=False)
            if resp.status_code not in (301, 302, 303, 307, 308):
                return resp, resp.aiter_bytes(settings.stream_chunk_size)

            location = resp.headers.get("location")
            await resp.aclose()
            if not location:
                raise UpstreamError(f"{self.name}: redirect with no Location header")
            current = str(httpx.URL(current).join(location))
            check_fetchable(current, upstream_url=self.upstream.url)
            if not same_origin(current, self.upstream.url):
                # Left our origin: drop the credential rather than replay it.
                merged = dict(headers or {})
        raise UpstreamError(f"{self.name}: too many redirects fetching an artifact")

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
