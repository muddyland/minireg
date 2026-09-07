"""Application settings, loaded from environment / .env."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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

    # --- Redis --------------------------------------------------------------
    redis_url: str = "redis://redis:6379/0"
    # Metadata cache TTLs (seconds). Short TTL keeps upstream freshness sane
    # while absorbing the thundering herd of a CI fleet.
    meta_cache_ttl: int = 60
    meta_negative_cache_ttl: int = 30
    search_cache_ttl: int = 120

    # --- Storage ------------------------------------------------------------
    storage_path: str = "/data/packages"
    # 0 disables the cap.
    storage_quota_bytes: int = 0
    # Immutable artifacts: once fetched, never re-fetched unless evicted.
    cache_artifacts: bool = True
    # Stream threshold: files larger than this are streamed rather than buffered.
    stream_chunk_size: int = 256 * 1024

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
    osv_fail_closed: bool = False
    osv_refresh_interval_seconds: int = 6 * 3600
    # CVE-only: ignore OSV records that carry no CVE alias.
    osv_cve_only: bool = True

    # --- Rate limiting ------------------------------------------------------
    rate_limit_enabled: bool = True
    rate_limit_anonymous_per_minute: int = 600
    rate_limit_authenticated_per_minute: int = 3000
    rate_limit_publish_per_minute: int = 60
    rate_limit_login_per_minute: int = 10

    # --- Housekeeping -------------------------------------------------------
    download_log_retention_days: int = 365
    audit_log_retention_days: int = 730

    @field_validator("public_url")
    @classmethod
    def _strip_trailing_slash(cls, v: str) -> str:
        return v.rstrip("/")

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
