"""Application settings, loaded from environment / .env."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_PLACEHOLDER_SECRETS = {
    "change-me-in-production-please-32b+",
    "change-me-generate-a-long-random-value",
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore", case_sensitive=False
    )

    # --- Identity -----------------------------------------------------------
    app_name: str = "minireg"
    # Public base URL clients use. Tarball/file URLs are rendered against this,
    # so it MUST match what npm/pip actually connect to.
    public_url: str = "http://localhost:8000"
    environment: Literal["dev", "prod"] = "prod"
    log_level: str = "INFO"

    # --- Secrets ------------------------------------------------------------
    secret_key: str = Field(default="change-me-in-production-please-32b+")
    # Separate key for encrypting upstream credentials at rest.
    credential_key: str | None = None

    # --- Database -----------------------------------------------------------
    database_url: str = "postgresql+asyncpg://minireg:minireg@postgres:5432/minireg"
    db_pool_size: int = 20
    db_max_overflow: int = 20
    db_echo: bool = False
    # Seconds a request will wait for a pooled connection before failing.
    db_pool_timeout_seconds: float = 10.0
    # Server-side caps, applied per connection (Postgres only).
    db_statement_timeout_seconds: float = 30.0
    db_idle_transaction_timeout_seconds: float = 60.0

    # --- Redis --------------------------------------------------------------
    redis_url: str = "redis://redis:6379/0"
    # Metadata cache TTLs (seconds). Short TTL keeps upstream freshness sane
    # while absorbing the thundering herd of a CI fleet.
    meta_cache_ttl: int = 60
    meta_negative_cache_ttl: int = 30
    search_cache_ttl: int = 120

    # --- Storage ------------------------------------------------------------
    storage_path: str = "/data/packages"
    # Refuse to cache new upstream artifacts once the blob store exceeds this.
    # Publishes are still accepted -- locally published packages exist nowhere
    # else, so dropping them to save space would lose data, while a cached
    # artifact can always be re-fetched. 0 disables the cap.
    storage_quota_bytes: int = 0
    # Immutable artifacts: once fetched, never re-fetched unless evicted.
    cache_artifacts: bool = True
    # Stream threshold: files larger than this are streamed rather than buffered.
    stream_chunk_size: int = 256 * 1024

    # --- Request / response limits ------------------------------------------
    # Largest publish body accepted, checked against Content-Length before the
    # body is read. npm sends the tarball base64-encoded inside a JSON
    # document, so the wire size is ~1.4x the tarball and the peak resident
    # cost is several times that again.
    max_publish_bytes: int = 256 * 1024 * 1024
    # Largest upstream metadata document (packument, simple page, index file)
    # we will buffer. Public packuments top out around 40 MB today.
    max_metadata_bytes: int = 96 * 1024 * 1024
    # Largest artifact we will stream from an upstream into the blob store.
    # 0 disables the cap.
    max_artifact_bytes: int = 2 * 1024 * 1024 * 1024
    # Total wall-clock budget for one artifact download, independent of the
    # per-chunk read timeout -- a trickling upstream otherwise holds the
    # herd-guard lock indefinitely.
    artifact_download_timeout_seconds: float = 900.0

    # --- Auth ---------------------------------------------------------------
    session_cookie: str = "minireg_session"
    session_ttl_seconds: int = 60 * 60 * 12
    token_prefix: str = "mrg"
    # Allow anonymous reads of the registry endpoints (typical for a mirror).
    allow_anonymous_read: bool = True
    # Bootstrap admin, created on first start if no users exist.
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str | None = None
    bootstrap_admin_email: str = "admin@localhost"

    # --- OIDC (Authentik) ---------------------------------------------------
    oidc_enabled: bool = False
    oidc_issuer: str | None = None  # e.g. https://authentik.example.com/application/o/minireg/
    oidc_client_id: str | None = None
    oidc_client_secret: str | None = None
    oidc_scopes: str = "openid profile email"
    # Authentik ships groups in the `groups` claim when the scope is mapped.
    oidc_groups_claim: str = "groups"
    oidc_admin_group: str = "minireg-admins"
    oidc_user_group: str | None = None  # if set, membership is required to log in
    oidc_auto_create_users: bool = True
    oidc_username_claim: str = "preferred_username"

    # --- Upstream fetching --------------------------------------------------
    # Artifact URLs come out of upstream metadata, so they are attacker-chosen
    # whenever an upstream is hostile or spoofed. Fetches are restricted to the
    # upstream's own host plus these, and never to a private or link-local
    # address unless explicitly allowed.
    upstream_artifact_hosts: str = (
        "registry.npmjs.org,files.pythonhosted.org,pypi.org,"
        "static.crates.io,crates.io,index.crates.io"
    )
    upstream_allow_private_addresses: bool = False
    upstream_allow_plaintext_http: bool = False
    upstream_timeout_seconds: float = 20.0
    upstream_connect_timeout_seconds: float = 5.0
    upstream_max_connections: int = 100
    upstream_max_keepalive: int = 40
    upstream_retries: int = 2
    # A tier is exhausted before the next one is tried.
    upstream_tier_parallel: bool = True

    # --- OSV / CVE ----------------------------------------------------------
    osv_enabled: bool = True
    osv_api_url: str = "https://api.osv.dev"
    osv_batch_size: int = 200
    osv_timeout_seconds: float = 30.0
    # Inline scan on first sight of a package version.
    osv_inline_scan: bool = True
    # Inline scan budget; on timeout we fail-open (or closed, see below) and
    # queue a background scan.
    osv_inline_timeout_seconds: float = 4.0
    osv_refresh_interval_seconds: int = 6 * 3600
    # Ignore OSV records that carry no CVE alias. Malicious-package (MAL-*)
    # advisories are always kept regardless of this flag: npm and PyPI malware
    # is rarely assigned a CVE, so honouring it there would filter out exactly
    # the records this registry exists to act on.
    osv_cve_only: bool = False
    # Concurrent /v1/vulns fetches while hydrating one batch.
    osv_hydrate_concurrency: int = 8
    # Wall-clock budget for the CVE refresh pass in one housekeeping cycle.
    # The pass keeps taking batches until the backlog is drained or the budget
    # is spent, so a large backlog clears in days rather than weeks.
    osv_housekeeping_budget_seconds: float = 600.0

    # --- Rate limiting ------------------------------------------------------
    rate_limit_enabled: bool = True
    rate_limit_anonymous_per_minute: int = 600
    rate_limit_authenticated_per_minute: int = 3000
    rate_limit_publish_per_minute: int = 60
    rate_limit_login_per_minute: int = 10
    # Number of reverse proxies in front of the app. The client address is
    # taken this many hops from the right of X-Forwarded-For; everything to the
    # left of that was written by something we do not control.
    trusted_proxy_hops: int = 1

    # --- Housekeeping -------------------------------------------------------
    download_log_retention_days: int = 365
    audit_log_retention_days: int = 730

    @field_validator("public_url")
    @classmethod
    def _strip_trailing_slash(cls, v: str) -> str:
        return v.rstrip("/")

    @model_validator(mode="after")
    def _reject_placeholder_secrets(self) -> Settings:
        """Refuse to run in production with a guessable signing key.

        The key signs session cookies and, unless CREDENTIAL_KEY is set
        separately, derives the key that encrypts every stored upstream
        credential. Anyone who knows it can mint an admin session. The shipped
        placeholders pass a "is it set?" check in compose, so the check has to
        look at the value.
        """
        if self.environment != "prod":
            return self
        placeholder = (
            not self.secret_key
            or len(self.secret_key) < 32
            or self.secret_key in _PLACEHOLDER_SECRETS
            or self.secret_key.lower().startswith("change-me")
        )
        if placeholder:
            raise ValueError(
                "SECRET_KEY is unset, too short, or still the shipped placeholder. "
                "Generate one with: python -c 'import secrets; print(secrets.token_urlsafe(48))'"
            )
        return self

    @property
    def artifact_host_allowlist(self) -> frozenset[str]:
        return frozenset(
            h.strip().lower() for h in self.upstream_artifact_hosts.split(",") if h.strip()
        )

    @property
    def npm_base(self) -> str:
        return f"{self.public_url}/npm"

    @property
    def pypi_base(self) -> str:
        return f"{self.public_url}/pypi"

    @property
    def cargo_base(self) -> str:
        return f"{self.public_url}/cargo"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
