"""npm registry semantics the public registry has and a mirror must keep.

Each test drives the real routes the npm CLI talks to, with the request
shapes libnpmpublish and npm-registry-fetch actually send.

``TEST_DATABASE_URL`` runs the module against PostgreSQL (a fresh schema per
test), which is stricter than SQLite about OFFSET, types and constraints.
"""

from __future__ import annotations

import os

import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app import db as db_module
from app.services.policy import invalidate_policy_cache
from app.services.storage import BlobStore, set_store

from .test_publish_ownership import _make_user, as_user, publish_body


@pytest_asyncio.fixture
async def env(tmp_path):
    from app.main import app

    pg_url = os.environ.get("TEST_DATABASE_URL")
    if pg_url:
        db_module.init_engine(pg_url)
        from app.models import Base

        async with db_module.get_engine().begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
    else:
        db_module.init_engine(f"sqlite+aiosqlite:///{tmp_path / 'npm.db'}")
    await db_module.create_schema()
    store = BlobStore(str(tmp_path / "storage"))
    store.ensure_dirs()
    set_store(store)
    await invalidate_policy_cache()

    tokens = {
        "alice": await _make_user("alice"),
        "bob": await _make_user("bob"),
        "admin": await _make_user("root", is_admin=True, scopes=("read", "publish", "admin")),
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://registry.test"
    ) as client:
        yield client, tokens

    await db_module.dispose_engine()
    set_store(None)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Search paging
# --------------------------------------------------------------------------- #
async def test_search_tolerates_junk_and_negative_paging(env):
    """``from=abc`` was a 500 and ``from=-5`` a negative OFFSET, which
    PostgreSQL rejects. npmjs reads junk as the default and clamps."""
    client, tokens = env
    as_user(client, tokens["alice"])
    assert (await client.put("/npm/findme", json=publish_body("findme", "1.0.0"))).status_code == 201

    for query in ("from=abc", "from=-5", "from=", "size=abc", "size=-3", "size=100000",
                  "from=99999999999999999999999"):
        response = await client.get(f"/npm/-/v1/search?text=findme&{query}")
        assert response.status_code == 200, (query, response.text)

    first = (await client.get("/npm/-/v1/search?text=findme&from=-5")).json()
    assert [o["package"]["name"] for o in first["objects"]] == ["findme"]
    assert (await client.get("/npm/-/v1/search?text=findme&from=1")).json()["objects"] == []


# --------------------------------------------------------------------------- #
# dist-tag names
# --------------------------------------------------------------------------- #
BAD_TAGS = ("v1.0.0", "1", "1.x", "^2", "x", "%20", "a%20b", "a%2Bb", "caf%C3%A9")


async def test_dist_tag_names_npm_cannot_install_are_refused(env):
    """``v1.0.0`` was accepted (only strict semver was refused), as were
    ``' '`` and ``'a b'``; npm reads a range before a tag, so none of these
    could ever be installed by name, and the blank ones break the URL."""
    client, tokens = env
    as_user(client, tokens["alice"])
    assert (await client.put("/npm/tagpkg", json=publish_body("tagpkg", "1.0.0"))).status_code == 201

    for tag in BAD_TAGS:
        response = await client.put(f"/npm/-/package/tagpkg/dist-tags/{tag}", content='"1.0.0"')
        assert response.status_code == 400, (tag, response.text)
    good = await client.put("/npm/-/package/tagpkg/dist-tags/next-1_rc.2", content='"1.0.0"')
    assert good.status_code == 200, good.text

    tags = (await client.get("/npm/-/package/tagpkg/dist-tags")).json()
    assert tags == {"latest": "1.0.0", "next-1_rc.2": "1.0.0"}


async def test_publish_document_dist_tags_follow_the_same_rules(env):
    client, tokens = env
    as_user(client, tokens["alice"])
    for tag in ("v1.0.0", " ", "", "a b", "~1"):
        body = publish_body("doctags", "1.0.0")
        body["dist-tags"] = {tag: "1.0.0"}
        response = await client.put("/npm/doctags", json=body)
        assert response.status_code == 400, (tag, response.text)
    # Nothing was created by the refused publishes.
    assert (await client.get("/npm/doctags")).status_code == 404


# --------------------------------------------------------------------------- #
# GET /{pkg}/{tag} agrees with the packument
# --------------------------------------------------------------------------- #
async def _block(pattern: str, version_spec: str) -> None:
    from app.models import Ecosystem, PackageRule, RuleAction

    async with db_module.session_scope() as session:
        session.add(
            PackageRule(
                ecosystem=Ecosystem.npm,
                pattern=pattern,
                action=RuleAction.block,
                version_spec=version_spec,
                reason=f"blocked {pattern}@{version_spec}",
            )
        )
    await invalidate_policy_cache()


async def test_version_route_resolves_latest_like_the_packument(env):
    """With `latest` blocked, the packument and the dist-tags endpoint point
    it at the newest surviving release, but GET /pkg/latest answered 403."""
    client, tokens = env
    as_user(client, tokens["alice"])
    for version in ("1.0.0", "2.0.0"):
        assert (await client.put("/npm/vdoc", json=publish_body("vdoc", version))).status_code == 201
    body = publish_body("vdoc", "3.0.0-rc.1")
    body["dist-tags"] = {"next": "3.0.0-rc.1"}
    assert (await client.put("/npm/vdoc", json=body)).status_code == 201
    await _block("vdoc", "2.0.0 || 3.0.0-rc.1")

    packument = (await client.get("/npm/vdoc")).json()
    assert packument["dist-tags"] == {"latest": "1.0.0"}
    assert (await client.get("/npm/-/package/vdoc/dist-tags")).json() == {"latest": "1.0.0"}

    latest = await client.get("/npm/vdoc/latest")
    assert latest.status_code == 200, latest.text
    assert latest.json()["version"] == "1.0.0"

    # A blocked version asked for by number, or a tag that only names a
    # blocked version, is still refused with the policy's reason.
    assert (await client.get("/npm/vdoc/2.0.0")).status_code == 403
    nxt = await client.get("/npm/vdoc/next")
    assert nxt.status_code == 403
    assert "blocked" in nxt.json()["error"]
    assert (await client.get("/npm/vdoc/nonesuch")).status_code == 404


# --------------------------------------------------------------------------- #
# Build metadata
# --------------------------------------------------------------------------- #
async def test_build_metadata_cannot_reuse_a_withdrawn_or_taken_version(env):
    """``1.0.0+r`` is 1.0.0 to every range and installer, but was stored as
    its own string: it passed both the tombstone of an unpublished 1.0.0 and
    the duplicate check beside a live 1.1.0."""
    client, tokens = env
    as_user(client, tokens["alice"])
    for version in ("1.0.0", "1.1.0"):
        assert (await client.put("/npm/tomb", json=publish_body("tomb", version))).status_code == 201
    assert (await client.delete("/npm/tomb/-/tomb-1.0.0.tgz/-rev/1")).status_code == 200
    assert (await client.put("/npm/tomb", json=publish_body("tomb", "1.0.0", b"x"))).status_code == 409

    for sneaky in ("1.0.0+r", "1.1.0+dup", "2.0.0-rc.1+b5"):
        response = await client.put("/npm/tomb", json=publish_body("tomb", sneaky, b"bad"))
        assert response.status_code == 400, (sneaky, response.text)
        assert "build metadata" in response.json()["error"]

    assert sorted((await client.get("/npm/tomb")).json()["versions"]) == ["1.1.0"]


# --------------------------------------------------------------------------- #
# A publish with nothing in it claims nothing
# --------------------------------------------------------------------------- #
async def _package_row(name: str):
    from sqlalchemy import select

    from app.models import Ecosystem, Package

    async with db_module.session_scope() as session:
        return (
            await session.execute(
                select(Package).where(
                    Package.ecosystem == Ecosystem.npm, Package.normalized_name == name
                )
            )
        ).scalar_one_or_none()


async def _reserve(patterns: list[str]) -> None:
    from app.models import Setting

    async with db_module.session_scope() as session:
        session.add(Setting(key="publish_namespaces", value={"npm": patterns}))
    await invalidate_policy_cache()


async def _cache_upstream_row(name: str, versions=("1.0.0",)) -> None:
    """A package as the proxy path leaves it: not local, no owner."""
    from datetime import UTC, datetime

    from app.models import DistTag, Ecosystem, Package, PackageVersion

    async with db_module.session_scope() as session:
        package = Package(
            ecosystem=Ecosystem.npm,
            name=name,
            normalized_name=name,
            is_local=False,
            latest_version=versions[-1],
            cached_at=datetime.now(UTC),
        )
        session.add(package)
        await session.flush()
        for version in versions:
            session.add(
                PackageVersion(
                    package_id=package.id,
                    version=version,
                    normalized_version=version,
                    metadata_json={"name": name, "version": version},
                )
            )
        session.add(DistTag(package_id=package.id, tag="latest", version=versions[-1]))


async def test_publish_without_versions_does_not_create_or_claim_a_name(env):
    client, tokens = env
    as_user(client, tokens["alice"])
    for body in (
        {"name": "squatted-name"},
        {"name": "squatted-name", "versions": {}, "_attachments": {}},
        # Attachments but no version to attach them to.
        {
            "name": "squatted-name",
            "_attachments": publish_body("squatted-name", "1.0.0")["_attachments"],
        },
    ):
        response = await client.put("/npm/squatted-name", json=body)
        assert response.status_code == 400, response.text
    assert await _package_row("squatted-name") is None

    # The name is still free for whoever publishes a real version first.
    as_user(client, tokens["bob"])
    real = await client.put("/npm/squatted-name", json=publish_body("squatted-name", "1.0.0"))
    assert real.status_code == 201, real.text


async def test_empty_publish_does_not_freeze_a_cached_package_in_a_reserved_namespace(env):
    """In a reserved namespace the grant hands back the cached upstream row;
    an empty PUT flipped it to `is_local`, after which it was never
    refreshed from upstream again."""
    client, tokens = env
    await _reserve(["@corp/*"])
    await _cache_upstream_row("@corp/lib")

    as_user(client, tokens["alice"])
    response = await client.put("/npm/@corp%2flib", json={"name": "@corp/lib"})
    assert response.status_code == 400, response.text
    row = await _package_row("@corp/lib")
    assert row is not None and row.is_local is False and row.owner_user_id is None


# --------------------------------------------------------------------------- #
# Scoped publishes in libnpmpublish's exact shape
# --------------------------------------------------------------------------- #
def libnpmpublish_document(name: str, version: str, tarball: bytes, *, provenance=False):
    """What libnpmpublish's buildMetadata() PUTs, field for field.

    The attachment is keyed ``${manifest.name}-${version}.tgz`` -- scope
    included -- and ``dist.tarball`` is ``${registry}/${name}/-/${that}``.
    With ``--provenance`` a second attachment carries the sigstore bundle,
    its ``data`` the bundle's JSON serialisation rather than base64.
    """
    import base64
    import hashlib
    import json

    tarball_name = f"{name}-{version}.tgz"
    manifest = {
        "name": name,
        "version": version,
        "description": "x",
        "_id": f"{name}@{version}",
        "dist": {
            "integrity": "sha512-" + base64.b64encode(hashlib.sha512(tarball).digest()).decode(),
            "shasum": hashlib.sha1(tarball).hexdigest(),
            "tarball": f"http://registry.test/npm/{name}/-/{tarball_name}",
        },
    }
    doc = {
        "_id": name,
        "name": name,
        "description": "x",
        "dist-tags": {"latest": version},
        "versions": {version: manifest},
        "access": None,
        "_attachments": {
            tarball_name: {
                "content_type": "application/octet-stream",
                "data": base64.b64encode(tarball).decode(),
                "length": len(tarball),
            }
        },
    }
    if provenance:
        bundle = json.dumps(
            {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {"tlogEntries": [{"logIndex": "1"}]},
                "dsseEnvelope": {"payload": "e30=", "signatures": []},
            }
        )
        doc["_attachments"][f"{name}-{version}.sigstore"] = {
            "content_type": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "data": bundle,
            "length": len(bundle),
        }
    return doc


async def _install(client, name: str, version: str) -> bytes:
    """What `npm install` does: abbreviated packument, then dist.tarball."""
    packument = await client.get(
        f"/npm/{name.replace('/', '%2f')}",
        headers={"accept": "application/vnd.npm.install-v1+json"},
    )
    assert packument.status_code == 200, packument.text
    url = packument.json()["versions"][version]["dist"]["tarball"]
    fetched = await client.get(url)
    assert fetched.status_code == 200, (url, fetched.text)
    return fetched.content


async def test_scoped_publish_from_the_npm_cli_is_installable(env):
    """The attachment was stored under its key, `@acme/widget-1.0.0.tgz`, and
    the advertised `.../-/%40acme%2Fwidget-1.0.0.tgz` answered 404; with
    `--provenance` the bundle failed base64 decoding and the publish 400'd."""
    client, tokens = env
    await _reserve(["@acme/*"])
    as_user(client, tokens["alice"])

    plain = await client.put(
        "/npm/@acme%2fwidget", json=libnpmpublish_document("@acme/widget", "1.0.0", b"one")
    )
    assert plain.status_code == 201, plain.text
    signed = await client.put(
        "/npm/@acme%2fwidget",
        json=libnpmpublish_document("@acme/widget", "1.0.1", b"two", provenance=True),
    )
    assert signed.status_code == 201, signed.text

    assert await _install(client, "@acme/widget", "1.0.0") == b"one"
    assert await _install(client, "@acme/widget", "1.0.1") == b"two"
    full = (await client.get("/npm/@acme/widget")).json()
    assert full["versions"]["1.0.1"]["dist"]["tarball"].endswith("/widget/-/widget-1.0.1.tgz")

    # `npm unpublish @acme/widget@1.0.0` deletes the tarball by that URL.
    gone = await client.delete("/npm/@acme/widget/-/widget-1.0.0.tgz/-rev/1")
    assert gone.status_code == 200, gone.text


async def test_publish_with_only_a_provenance_bundle_is_refused(env):
    client, tokens = env
    await _reserve(["@acme/*"])
    as_user(client, tokens["alice"])
    doc = libnpmpublish_document("@acme/widget", "1.0.0", b"one", provenance=True)
    del doc["_attachments"]["@acme/widget-1.0.0.tgz"]
    response = await client.put("/npm/@acme%2fwidget", json=doc)
    assert response.status_code == 400
    assert "no tarball attachment" in response.json()["error"]
    assert await _package_row("@acme/widget") is None


async def test_startup_repairs_scoped_tarball_names_stored_by_older_releases(env):
    """Rows the old publish path wrote keep working once the repair runs."""
    from sqlalchemy import select, update

    from app.models import PackageFile

    client, tokens = env
    await _reserve(["@acme/*"])
    as_user(client, tokens["alice"])
    doc = libnpmpublish_document("@acme/old", "1.0.0", b"legacy")
    assert (await client.put("/npm/@acme%2fold", json=doc)).status_code == 201

    # What the old code stored: the attachment key, scope and all.
    async with db_module.session_scope() as session:
        await session.execute(update(PackageFile).values(filename="@acme/old-1.0.0.tgz"))
    from app.services.packages import invalidate_package_cache

    await invalidate_package_cache("npm", "@acme/old")
    packument = (await client.get("/npm/@acme%2fold")).json()
    broken = packument["versions"]["1.0.0"]["dist"]["tarball"]
    assert (await client.get(broken)).status_code == 404

    await db_module.create_schema()
    await db_module.create_schema()  # idempotent
    async with db_module.session_scope() as session:
        names = (await session.execute(select(PackageFile.filename))).scalars().all()
    assert names == ["old-1.0.0.tgz"]
    await invalidate_package_cache("npm", "@acme/old")
    assert await _install(client, "@acme/old", "1.0.0") == b"legacy"


# --------------------------------------------------------------------------- #
# `npm unpublish pkg@x` and policy-hidden versions
# --------------------------------------------------------------------------- #
async def npm_unpublish(client, name: str, version: str, *, write: bool = True) -> str:
    """libnpmpublish's unpublish(), step for step; returns the branch taken.

    GET the packument with ?write=true; with one version left (or none) it
    DELETEs the whole package, otherwise it drops the version and any tag
    naming it, re-points `latest`, PUTs the document to /-rev/{rev}, then
    DELETEs the tarball by its dist.tarball path.
    """
    from urllib.parse import urlsplit

    from app.core.semver import SemVer

    path = f"/npm/{name.replace('/', '%2f')}"
    pkg = (await client.get(path, params={"write": "true"} if write else None)).json()
    versions = pkg.get("versions") or {}
    if version not in versions:
        return "absent"
    if len(versions) == 1:
        response = await client.delete(f"{path}/-rev/{pkg['_rev']}")
        assert response.status_code == 200, response.text
        return "deleted-package"
    dist = versions.pop(version)["dist"]
    latest = pkg["dist-tags"].get("latest")
    pkg["dist-tags"] = {t: v for t, v in pkg["dist-tags"].items() if v != version}
    if latest == version:
        pkg["dist-tags"]["latest"] = sorted(versions, key=SemVer.parse)[-1]
    pkg.pop("_revisions", None)
    pkg.pop("_attachments", None)
    response = await client.put(f"{path}/-rev/{pkg['_rev']}", json=pkg)
    assert response.status_code == 200, response.text
    rev = (await client.get(path, params={"write": "true"})).json().get("_rev", "0")
    tarball = urlsplit(dist["tarball"]).path
    response = await client.delete(f"{tarball}/-rev/{rev}")
    assert response.status_code == 200, response.text
    return "edited"


async def _stored_and_retired(name: str):
    from sqlalchemy import select

    from app.models import Package, PackageVersion, RetiredVersion

    async with db_module.session_scope() as session:
        stored = (
            await session.execute(
                select(PackageVersion.version)
                .join(Package, Package.id == PackageVersion.package_id)
                .where(Package.normalized_name == name)
            )
        ).scalars().all()
        retired = (
            await session.execute(
                select(RetiredVersion.version).where(RetiredVersion.normalized_name == name)
            )
        ).scalars().all()
    return sorted(stored), sorted(retired)


async def test_npm_unpublish_leaves_policy_hidden_versions_alone(env):
    client, tokens = env
    as_user(client, tokens["alice"])
    for version in ("1.0.0", "1.1.0", "2.0.0"):
        assert (await client.put("/npm/victim", json=publish_body("victim", version))).status_code == 201
    await _block("victim", "1.1.0")

    # Installers still do not see the blocked version...
    assert sorted((await client.get("/npm/victim")).json()["versions"]) == ["1.0.0", "2.0.0"]
    # ...but its owner's editable view does, and is not cached for others.
    write = await client.get("/npm/victim", params={"write": "true"})
    assert sorted(write.json()["versions"]) == ["1.0.0", "1.1.0", "2.0.0"]
    assert "no-store" in write.headers["cache-control"]
    as_user(client, tokens["bob"])
    assert sorted((await client.get("/npm/victim", params={"write": "true"})).json()["versions"]) == [
        "1.0.0",
        "2.0.0",
    ]

    as_user(client, tokens["alice"])
    assert await npm_unpublish(client, "victim", "2.0.0") == "edited"
    stored, retired = await _stored_and_retired("victim")
    assert stored == ["1.0.0", "1.1.0"]
    assert retired == ["2.0.0"]
    assert (await client.get("/npm/-/package/victim/dist-tags")).json() == {"latest": "1.0.0"}


async def test_npm_unpublish_with_one_visible_version_does_not_delete_the_package(env):
    """Filtered down to one version, the CLI took its "only version" branch
    and DELETEd the whole package, hidden versions and all."""
    client, tokens = env
    as_user(client, tokens["alice"])
    for version in ("1.0.0", "2.0.0"):
        assert (await client.put("/npm/solo", json=publish_body("solo", version))).status_code == 201
    await _block("solo", "1.0.0")

    assert await npm_unpublish(client, "solo", "2.0.0") == "edited"
    stored, retired = await _stored_and_retired("solo")
    assert stored == ["1.0.0"]
    assert retired == ["2.0.0"]


async def test_packument_edit_from_the_filtered_view_spares_hidden_versions(env):
    """A client that edits the installer's (filtered) view, not the write
    view, must not take the versions it never saw with it."""
    client, tokens = env
    as_user(client, tokens["alice"])
    for version in ("1.0.0", "1.1.0", "2.0.0"):
        assert (await client.put("/npm/oldcli", json=publish_body("oldcli", version))).status_code == 201
    await _block("oldcli", "1.1.0")

    assert await npm_unpublish(client, "oldcli", "2.0.0", write=False) == "edited"
    stored, retired = await _stored_and_retired("oldcli")
    assert stored == ["1.0.0", "1.1.0"]
    assert retired == ["2.0.0"]
