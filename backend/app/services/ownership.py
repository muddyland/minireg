"""Who may publish, retag, deprecate and unpublish a package name.

The registry proxies public ecosystems *and* accepts local publishes into the
same namespace, so "who owns this name" is the question that decides whether a
caching mirror can be turned into a malware delivery service. Three rules,
in the order they are checked:

1. **A name that resolves upstream is not yours.** Publishing `lodash` here
   would shadow the real one for every consumer, permanently -- a package with
   any local version is treated as authoritative and is never refreshed from
   upstream again. Refused unless an admin has explicitly carved the name out
   as a private namespace.
2. **A name someone else published is theirs.** First publisher owns it;
   admins can override with an admin-scoped credential.
3. **A version that was published and withdrawn cannot come back different.**

Rule 1 is what makes this different from a plain registry: on npm, publishing
`lodash` fails because the name is taken. Here the same publish used to
*succeed* and quietly win.
"""

from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.naming import normalize_name_for
from ..models import Ecosystem, Package, RetiredVersion, User
from .policy import PolicyEngine

log = logging.getLogger(__name__)

#: Setting key holding the private-namespace patterns.
KEY_PUBLISH_NAMESPACES = "publish_namespaces"


class PublishDenied(Exception):
    """Publishing is not permitted. ``reason`` is safe to show the client."""

    def __init__(self, reason: str, status_code: int = 403):
        super().__init__(reason)
        self.reason = reason
        self.status_code = status_code


@dataclass(slots=True)
class PublishGrant:
    """Outcome of an authorization check, carrying what the caller must apply."""

    package: Package | None
    #: Set on the package row when the publish goes through.
    owner_user_id: int | None
    #: True when this publish creates the name.
    is_new_name: bool


async def _namespace_patterns(session: AsyncSession, ecosystem: Ecosystem) -> list[str]:
    """Glob patterns an admin has reserved for local publishing.

    Stored as ``{"npm": ["@corp/*"], "pypi": ["corp-*"]}``. An empty list means
    nothing is reserved, which is the safe default: no name may shadow an
    upstream.
    """
    engine = PolicyEngine(session)
    value = await engine.get_setting(KEY_PUBLISH_NAMESPACES, {})
    if not isinstance(value, dict):
        return []
    patterns = value.get(ecosystem.value) or []
    return [p for p in patterns if isinstance(p, str) and p.strip()]


def _matches_namespace(name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, p.strip().lower()) for p in patterns)


async def _resolves_upstream(session: AsyncSession, ecosystem: Ecosystem, name: str) -> bool:
    """Whether any configured upstream serves this name today.

    Publishes are rare and rate limited, so one resolution is affordable and
    is the only way to catch the case that matters most: a brand-new local
    name that collides with a *public* package the registry has simply never
    been asked for yet.

    A resolution error is treated as "not found" deliberately. Failing the
    publish because an upstream is briefly down would be a worse trade than
    accepting a name that will, at worst, be caught by the cached-row check
    on the next attempt.
    """
    from .resolver import Resolver

    try:
        result = await Resolver(session).resolve(ecosystem, name)
    except Exception:
        log.warning("upstream shadow check failed for %s:%s", ecosystem.value, name)
        return False
    return result is not None


async def authorize_publish(
    session: AsyncSession,
    ecosystem: Ecosystem,
    display_name: str,
    *,
    user_id: int | None,
    is_admin: bool,
    check_upstream: bool = True,
) -> PublishGrant:
    """Decide whether ``user_id`` may publish to ``display_name``.

    Raises :class:`PublishDenied` with a client-safe reason, or returns the
    package row (if any) plus the owner to record.
    """
    from .packages import get_package_row

    normalized = normalize_name_for(ecosystem.value, display_name)
    package = await get_package_row(session, ecosystem, normalized)
    patterns = await _namespace_patterns(session, ecosystem)
    reserved = _matches_namespace(normalized, patterns)

    if package is not None and not package.is_local:
        # The name is already in the cache from an upstream. Publishing into
        # it is the shadowing attack, whichever version number is used.
        if not reserved:
            raise PublishDenied(
                f"'{display_name}' is served by an upstream registry and cannot be "
                "published here. Ask an administrator to reserve the name as a "
                "private namespace if it really is yours."
            )
        return PublishGrant(package=package, owner_user_id=user_id, is_new_name=False)

    if package is not None:
        owner = package.owner_user_id
        if owner is None:
            # Published before ownership existed. First mutation adopts it,
            # which is the least surprising migration for existing content.
            return PublishGrant(package=package, owner_user_id=user_id, is_new_name=False)
        if owner != user_id and not is_admin:
            raise PublishDenied(
                f"'{display_name}' is owned by another user. Ask them to publish, "
                "or ask an administrator."
            )
        return PublishGrant(package=package, owner_user_id=owner, is_new_name=False)

    # Brand new name here. Make sure it is not a public package we simply have
    # not been asked for yet.
    if not reserved and check_upstream and await _resolves_upstream(
        session, ecosystem, display_name
    ):
        raise PublishDenied(
            f"'{display_name}' already exists in an upstream registry. Publishing it "
            "here would shadow the upstream package for everyone using this mirror."
        )
    return PublishGrant(package=None, owner_user_id=user_id, is_new_name=True)


async def authorize_mutation(
    package: Package,
    *,
    user_id: int | None,
    is_admin: bool,
    action: str,
) -> None:
    """Guard retag / deprecate / unpublish on an existing package.

    These used to be reachable by any publish-scoped credential, so repointing
    `latest` for a cached public package at a known-vulnerable release was a
    single request.
    """
    if not package.is_local:
        if not is_admin:
            raise PublishDenied(
                f"'{package.name}' is mirrored from an upstream registry; "
                f"only an administrator can {action} it."
            )
        return
    owner = package.owner_user_id
    if owner is not None and owner != user_id and not is_admin:
        raise PublishDenied(f"'{package.name}' is owned by another user.")


async def assert_not_retired(
    session: AsyncSession,
    ecosystem: Ecosystem,
    normalized_name: str,
    normalized_version: str,
) -> None:
    row = (
        await session.execute(
            select(RetiredVersion).where(
                RetiredVersion.ecosystem == ecosystem,
                RetiredVersion.normalized_name == normalized_name,
                RetiredVersion.normalized_version == normalized_version,
            )
        )
    ).scalar_one_or_none()
    if row is not None:
        raise PublishDenied(
            f"version {row.version} was published here and withdrawn; that version "
            "number cannot be reused. Publish a new version instead.",
            status_code=409,
        )


async def retire_version(
    session: AsyncSession,
    ecosystem: Ecosystem,
    normalized_name: str,
    version: str,
    normalized_version: str,
    *,
    sha256: str | None,
    integrity: str | None,
    user: User | None,
    username: str | None,
) -> None:
    """Record a tombstone so the version number cannot be reused."""
    existing = (
        await session.execute(
            select(RetiredVersion).where(
                RetiredVersion.ecosystem == ecosystem,
                RetiredVersion.normalized_name == normalized_name,
                RetiredVersion.normalized_version == normalized_version,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return
    session.add(
        RetiredVersion(
            ecosystem=ecosystem,
            normalized_name=normalized_name,
            version=version,
            normalized_version=normalized_version,
            sha256=sha256,
            integrity=integrity,
            removed_by_user_id=user.id if user else None,
            removed_by_username=username,
        )
    )
