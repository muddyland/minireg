"""SQLAlchemy models.

Design notes
------------
* PostgreSQL is the target. Every JSON column is JSONB there and plain JSON on
  SQLite so the unit-test suite can run without a server.
* Hot read paths (packument render, simple-index render) are served from a
  single row's JSONB blob plus a child-row scan, so they need one index hit.
* ``download_log`` is append-only and high volume: it carries no foreign keys
  that would force referential checks on insert, and it is BRIN-indexed on time.
"""

from __future__ import annotations

import enum
from datetime import UTC, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

JSONType = JSON().with_variant(JSONB(), "postgresql")

# SQLite only autoincrements a column declared exactly ``INTEGER PRIMARY KEY``,
# so a BIGINT surrogate key never gets a generated value there. Postgres keeps
# the 64-bit width it needs for the append-only log tables.
BigIntPK = BigInteger().with_variant(Integer(), "sqlite")


class Base(DeclarativeBase):
    pass


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _now_col(**kw) -> Mapped[datetime]:
    """A created-at style column.

    Carries both a Python-side and a server-side default. The Python default is
    what matters at runtime: without it the value is server-generated, so the
    ORM marks the attribute as unloaded after INSERT and emits a lazy SELECT the
    first time anything reads it -- which is illegal inside an async session and
    costs a round-trip even when it is legal. The server default remains so that
    rows inserted outside the ORM still get a timestamp.
    """
    return mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now(), **kw
    )


def _updated_col(**kw) -> Mapped[datetime]:
    """An updated-at column, refreshed on every flush."""
    return mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        onupdate=_utcnow,
        server_default=func.now(),
        **kw,
    )


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class Ecosystem(str, enum.Enum):
    npm = "npm"
    pypi = "pypi"


class UpstreamKind(str, enum.Enum):
    npm = "npm"
    pypi = "pypi"
    gitlab_npm = "gitlab_npm"
    gitlab_pypi = "gitlab_pypi"


class RuleAction(str, enum.Enum):
    block = "block"
    allow = "allow"


class AuthProvider(str, enum.Enum):
    local = "local"
    oidc = "oidc"


# --------------------------------------------------------------------------- #
# Identity
# --------------------------------------------------------------------------- #
class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(150), unique=True, index=True)
    email: Mapped[str | None] = mapped_column(String(320), index=True)
    full_name: Mapped[str | None] = mapped_column(String(255))
    password_hash: Mapped[str | None] = mapped_column(String(255))
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    can_publish: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    provider: Mapped[AuthProvider] = mapped_column(
        Enum(AuthProvider, native_enum=False, length=16), default=AuthProvider.local, nullable=False
    )
    oidc_subject: Mapped[str | None] = mapped_column(String(255), index=True)
    oidc_issuer: Mapped[str | None] = mapped_column(String(512))

    created_at: Mapped[datetime] = _now_col()
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    tokens: Mapped[list["ApiToken"]] = relationship(back_populates="user", cascade="all, delete-orphan")

    __table_args__ = (UniqueConstraint("oidc_issuer", "oidc_subject", name="uq_user_oidc"),)


class ApiToken(Base):
    """Bearer token used by npm/pip clients and the admin API.

    Only a SHA-256 of the secret is stored. ``prefix`` is the public,
    non-sensitive leading segment used to look the row up in O(1) so we never
    have to hash-compare against every token in the table.
    """

    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    prefix: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), index=True)
    # Subset of {"read", "publish", "admin"}
    scopes: Mapped[list] = mapped_column(JSONType, default=list)
    created_at: Mapped[datetime] = _now_col()
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    user: Mapped[User] = relationship(back_populates="tokens")


class DeviceAuthorization(Base):
    """A pending ``minireg login`` from the CLI.

    Implements the OAuth device-authorization shape (RFC 8628) so the CLI never
    handles a password: it shows a short user code, the person approves it in
    the browser under their existing session -- including OIDC -- and the CLI
    polls until a token appears.

    ``device_code`` is the CLI's bearer secret for polling and is stored hashed;
    ``user_code`` is short enough to type, which is safe only because it expires
    in minutes, is single-use, and the approve/poll endpoints are rate limited.
    """

    __tablename__ = "device_authorizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_code_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_code: Mapped[str] = mapped_column(String(16), unique=True, index=True)

    created_at: Mapped[datetime] = _now_col()
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # What the CLI told us about itself, shown on the approval screen so the
    # person can tell whether this is really their terminal.
    client_hostname: Mapped[str | None] = mapped_column(String(255))
    client_platform: Mapped[str | None] = mapped_column(String(255))
    client_ip: Mapped[str | None] = mapped_column(String(64))

    approved_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE")
    )
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    denied: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    token_id: Mapped[int | None] = mapped_column(ForeignKey("api_tokens.id", ondelete="SET NULL"))
    # The one-time plaintext token, held only until the CLI collects it.
    token_plaintext: Mapped[str | None] = mapped_column(String(255))
    collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (Index("ix_device_auth_expiry", "expires_at"),)


class AuditLog(Base):
    """Every login and every admin mutation lands here. Append-only."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True)
    ts: Mapped[datetime] = _now_col(index=True)
    actor_user_id: Mapped[int | None] = mapped_column(Integer, index=True)
    actor_username: Mapped[str | None] = mapped_column(String(150), index=True)
    actor_type: Mapped[str] = mapped_column(String(32), default="user")  # user|token|system|anonymous
    action: Mapped[str] = mapped_column(String(100), index=True)
    target_type: Mapped[str | None] = mapped_column(String(64))
    target_id: Mapped[str | None] = mapped_column(String(255), index=True)
    success: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    detail: Mapped[dict] = mapped_column(JSONType, default=dict)

    __table_args__ = (Index("ix_audit_ts_action", "ts", "action"),)


# --------------------------------------------------------------------------- #
# Upstreams
# --------------------------------------------------------------------------- #
class Upstream(Base):
    """A remote registry. Tiers are tried in ascending order; within a tier,
    upstreams are raced (or tried by priority when racing is disabled)."""

    __tablename__ = "upstreams"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    ecosystem: Mapped[Ecosystem] = mapped_column(
        Enum(Ecosystem, native_enum=False, length=8), index=True, nullable=False
    )
    kind: Mapped[UpstreamKind] = mapped_column(
        Enum(UpstreamKind, native_enum=False, length=16), nullable=False
    )
    url: Mapped[str] = mapped_column(String(1024))
    tier: Mapped[int] = mapped_column(Integer, default=1, nullable=False, index=True)
    priority: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    auth_type: Mapped[str] = mapped_column(String(32), default="none")  # none|bearer|basic|token_header
    # Encrypted at rest with CREDENTIAL_KEY.
    credential_enc: Mapped[str | None] = mapped_column(Text)
    auth_header_name: Mapped[str | None] = mapped_column(String(64))

    timeout_seconds: Mapped[float] = mapped_column(Float, default=20.0)
    verify_ssl: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    cache_artifacts: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Human-facing page for a package on this upstream, e.g.
    # "https://www.npmjs.com/package/{name}". Placeholders: {name},
    # {normalized_name}. Left NULL, a default is derived for the well-known
    # public hosts and the index URL is used for everything else.
    web_url_template: Mapped[str | None] = mapped_column(String(512))

    # GitLab specifics
    gitlab_project_id: Mapped[str | None] = mapped_column(String(64))
    gitlab_group_id: Mapped[str | None] = mapped_column(String(64))
    # When true this upstream is a publish target.
    allow_publish: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # When true, its package list is periodically indexed for search.
    index_packages: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_indexed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Health tracking, used to short-circuit dead upstreams.
    healthy: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_error: Mapped[str | None] = mapped_column(Text)
    last_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    extra: Mapped[dict] = mapped_column(JSONType, default=dict)
    created_at: Mapped[datetime] = _now_col()

    __table_args__ = (Index("ix_upstream_route", "ecosystem", "enabled", "tier", "priority"),)


# --------------------------------------------------------------------------- #
# Packages
# --------------------------------------------------------------------------- #
class Package(Base):
    __tablename__ = "packages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ecosystem: Mapped[Ecosystem] = mapped_column(
        Enum(Ecosystem, native_enum=False, length=8), nullable=False
    )
    # Display name as the ecosystem spells it (npm: as published; pypi: as uploaded).
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    # npm: lowercased name. pypi: PEP 503 normalized. This is the lookup key.
    normalized_name: Mapped[str] = mapped_column(String(512), nullable=False)

    description: Mapped[str | None] = mapped_column(Text)
    latest_version: Mapped[str | None] = mapped_column(String(128))
    keywords: Mapped[list] = mapped_column(JSONType, default=list)
    author: Mapped[str | None] = mapped_column(String(512))
    homepage: Mapped[str | None] = mapped_column(String(1024))
    license: Mapped[str | None] = mapped_column(String(255))

    # True when at least one version was published directly to this registry.
    is_local: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    origin_upstream_id: Mapped[int | None] = mapped_column(
        ForeignKey("upstreams.id", ondelete="SET NULL")
    )

    # Cached upstream document (npm packument / pypi file list) for fast rerender.
    cached_document: Mapped[dict | None] = mapped_column(JSONType)
    cached_etag: Mapped[str | None] = mapped_column(String(255))
    cached_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    download_count: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    first_seen_at: Mapped[datetime] = _now_col()
    updated_at: Mapped[datetime] = _updated_col()

    # Denormalized policy verdict, refreshed whenever rules or scans change.
    # NULL = not evaluated yet.
    blocked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    block_reason: Mapped[str | None] = mapped_column(Text)

    versions: Mapped[list["PackageVersion"]] = relationship(
        back_populates="package", cascade="all, delete-orphan"
    )
    dist_tags: Mapped[list["DistTag"]] = relationship(
        back_populates="package", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("ecosystem", "normalized_name", name="uq_package_eco_name"),
        Index("ix_package_lookup", "ecosystem", "normalized_name"),
        Index("ix_package_downloads", "ecosystem", "download_count"),
    )


class PackageVersion(Base):
    __tablename__ = "package_versions"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True)
    package_id: Mapped[int] = mapped_column(
        ForeignKey("packages.id", ondelete="CASCADE"), index=True, nullable=False
    )
    version: Mapped[str] = mapped_column(String(128), nullable=False)
    # PEP 440 normalized (pypi) / semver as-is (npm)
    normalized_version: Mapped[str] = mapped_column(String(128), nullable=False)

    # Full per-version metadata: package.json for npm, core metadata for pypi.
    metadata_json: Mapped[dict] = mapped_column(JSONType, default=dict)
    requires_python: Mapped[str | None] = mapped_column(String(255))

    yanked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    yanked_reason: Mapped[str | None] = mapped_column(Text)
    deprecated: Mapped[str | None] = mapped_column(Text)

    is_local: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    upstream_id: Mapped[int | None] = mapped_column(ForeignKey("upstreams.id", ondelete="SET NULL"))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    first_seen_at: Mapped[datetime] = _now_col()

    # CVE policy verdict for this exact version.
    blocked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    block_reason: Mapped[str | None] = mapped_column(Text)
    max_cvss: Mapped[float | None] = mapped_column(Float)
    scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    package: Mapped[Package] = relationship(back_populates="versions")
    files: Mapped[list["PackageFile"]] = relationship(
        back_populates="version", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("package_id", "normalized_version", name="uq_version_pkg_ver"),
        Index("ix_version_scan", "scanned_at"),
    )


class PackageFile(Base):
    """One distributable artifact: an npm .tgz or a PyPI wheel/sdist."""

    __tablename__ = "package_files"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True)
    version_id: Mapped[int] = mapped_column(
        ForeignKey("package_versions.id", ondelete="CASCADE"), index=True, nullable=False
    )
    filename: Mapped[str] = mapped_column(String(512), nullable=False)

    # Content-addressed pointer into the blob store. NULL until cached.
    blob_sha256: Mapped[str | None] = mapped_column(String(64), index=True)
    size: Mapped[int | None] = mapped_column(BigInteger)
    content_type: Mapped[str] = mapped_column(String(128), default="application/octet-stream")

    # Digests published to clients. npm needs sha1 (shasum) + optional SRI
    # integrity; PyPI needs sha256, and legacy uploads carry md5/blake2b.
    sha256: Mapped[str | None] = mapped_column(String(64))
    sha1: Mapped[str | None] = mapped_column(String(40))
    md5: Mapped[str | None] = mapped_column(String(32))
    blake2b_256: Mapped[str | None] = mapped_column(String(64))
    integrity: Mapped[str | None] = mapped_column(String(255))

    # PyPI classification
    packagetype: Mapped[str | None] = mapped_column(String(32))  # sdist|bdist_wheel
    python_version: Mapped[str | None] = mapped_column(String(32))
    requires_python: Mapped[str | None] = mapped_column(String(255))
    # PEP 658/714: metadata availability, either bool or {alg: digest}
    core_metadata: Mapped[dict | None] = mapped_column(JSONType)

    yanked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    yanked_reason: Mapped[str | None] = mapped_column(Text)

    # Where to fetch it from if it isn't cached yet.
    upstream_url: Mapped[str | None] = mapped_column(Text)
    upstream_id: Mapped[int | None] = mapped_column(ForeignKey("upstreams.id", ondelete="SET NULL"))

    upload_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cached_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    download_count: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)

    version: Mapped[PackageVersion] = relationship(back_populates="files")

    __table_args__ = (
        UniqueConstraint("version_id", "filename", name="uq_file_version_name"),
        Index("ix_file_cached", "blob_sha256", "cached_at"),
    )


class DistTag(Base):
    """npm dist-tags. `latest` is mandatory for a publishable package."""

    __tablename__ = "dist_tags"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    package_id: Mapped[int] = mapped_column(
        ForeignKey("packages.id", ondelete="CASCADE"), index=True, nullable=False
    )
    tag: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[str] = mapped_column(String(128), nullable=False)

    package: Mapped[Package] = relationship(back_populates="dist_tags")

    __table_args__ = (UniqueConstraint("package_id", "tag", name="uq_disttag_pkg_tag"),)


class Blob(Base):
    """Content-addressed artifact store entry. Deduplicated across ecosystems."""

    __tablename__ = "blobs"

    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    path: Mapped[str] = mapped_column(String(1024), nullable=False)
    refcount: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_at: Mapped[datetime] = _now_col()
    last_accessed_at: Mapped[datetime] = _now_col(index=True)
    access_count: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)


# --------------------------------------------------------------------------- #
# Policy
# --------------------------------------------------------------------------- #
class PackageRule(Base):
    """Allow/block rule. Patterns are fnmatch globs against the normalized name,
    optionally narrowed to a version specifier.

    Block always wins: the evaluator collects every matching rule and denies if
    any block matches, regardless of allow rules. Allow rules exist to carve
    exceptions out of *allowlist mode*, not to override a block.
    """

    __tablename__ = "package_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ecosystem: Mapped[Ecosystem | None] = mapped_column(Enum(Ecosystem, native_enum=False, length=8))
    pattern: Mapped[str] = mapped_column(String(512), nullable=False)
    action: Mapped[RuleAction] = mapped_column(
        Enum(RuleAction, native_enum=False, length=8), nullable=False
    )
    version_spec: Mapped[str | None] = mapped_column(String(255))
    reason: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by: Mapped[str | None] = mapped_column(String(150))
    created_at: Mapped[datetime] = _now_col()

    __table_args__ = (Index("ix_rule_lookup", "ecosystem", "enabled", "action"),)


class Vulnerability(Base):
    """An OSV record that carries a CVE alias. CVE-only by policy."""

    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # OSV id, e.g. GHSA-xxxx
    cve_id: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    ecosystem: Mapped[Ecosystem] = mapped_column(
        Enum(Ecosystem, native_enum=False, length=8), index=True, nullable=False
    )
    summary: Mapped[str | None] = mapped_column(Text)
    details: Mapped[str | None] = mapped_column(Text)
    severity_type: Mapped[str | None] = mapped_column(String(16))  # CVSS_V4|CVSS_V3|CVSS_V2
    cvss_vector: Mapped[str | None] = mapped_column(String(255))
    cvss_score: Mapped[float | None] = mapped_column(Float, index=True)
    severity_label: Mapped[str | None] = mapped_column(String(16))  # none|low|medium|high|critical
    aliases: Mapped[list] = mapped_column(JSONType, default=list)
    references: Mapped[list] = mapped_column(JSONType, default=list)
    published: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    modified: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    withdrawn: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    raw: Mapped[dict] = mapped_column(JSONType, default=dict)
    fetched_at: Mapped[datetime] = _now_col()


class PackageVulnerability(Base):
    """Join between an affected package version and a CVE."""

    __tablename__ = "package_vulnerabilities"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True)
    version_id: Mapped[int] = mapped_column(
        ForeignKey("package_versions.id", ondelete="CASCADE"), index=True, nullable=False
    )
    vulnerability_id: Mapped[str] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"), index=True, nullable=False
    )
    fixed_version: Mapped[str | None] = mapped_column(String(128))
    detected_at: Mapped[datetime] = _now_col()
    # Set when an admin accepts the risk for this specific pairing.
    suppressed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    suppressed_reason: Mapped[str | None] = mapped_column(Text)

    vulnerability: Mapped[Vulnerability] = relationship()

    __table_args__ = (
        UniqueConstraint("version_id", "vulnerability_id", name="uq_pkgvuln"),
    )


class Setting(Base):
    """Runtime-editable configuration (CVE thresholds, allowlist mode, ...)."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[dict] = mapped_column(JSONType, default=dict)
    updated_at: Mapped[datetime] = _updated_col()
    updated_by: Mapped[str | None] = mapped_column(String(150))


# --------------------------------------------------------------------------- #
# Telemetry
# --------------------------------------------------------------------------- #
class DownloadLog(Base):
    """Every metadata and artifact request. Append-only, no FKs on purpose."""

    __tablename__ = "download_log"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True)
    ts: Mapped[datetime] = _now_col(index=True)
    ecosystem: Mapped[str] = mapped_column(String(8), nullable=False)
    package_name: Mapped[str] = mapped_column(String(512), index=True, nullable=False)
    version: Mapped[str | None] = mapped_column(String(128))
    filename: Mapped[str | None] = mapped_column(String(512))
    kind: Mapped[str] = mapped_column(String(16), default="file")  # file|metadata
    user_id: Mapped[int | None] = mapped_column(Integer, index=True)
    username: Mapped[str | None] = mapped_column(String(150))
    token_id: Mapped[int | None] = mapped_column(Integer)
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    bytes_sent: Mapped[int] = mapped_column(BigInteger, default=0)
    cache_hit: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    upstream_id: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[int] = mapped_column(Integer, default=200)
    duration_ms: Mapped[int | None] = mapped_column(Integer)

    __table_args__ = (
        Index("ix_dl_pkg_ts", "ecosystem", "package_name", "ts"),
        Index("ix_dl_user_ts", "user_id", "ts"),
        CheckConstraint("kind in ('file','metadata')", name="ck_dl_kind"),
    )
