# ruff: noqa: F811  -- fixtures imported from sibling modules are re-bound as parameters
"""The npm protocol surface: what the CLI sends and what it expects back.

Covers the audit endpoint's memory footprint and wire format, the rendered
packument cache, `npm unpublish pkg@version`, conditional requests, 404
bodies and the publish-time metadata and refusal paths.
"""

from __future__ import annotations

import base64
import hashlib
import io
import tarfile
from datetime import UTC, datetime

import pytest
import pytest_asyncio
import sqlalchemy

from app import db as db_module
from app.api import npm as npm_api
from app.core import cache
from app.models import (
    Ecosystem,
    Package,
    PackageVersion,
    PackageVulnerability,
    RetiredVersion,
    Vulnerability,
)
from app.services import npm_publish
from app.services.storage import get_store

from .test_integration import app_client, auth  # noqa: F401  (fixture import)
from .test_publish_ownership import as_user, env, publish_body  # noqa: F401
from .test_query_footprint import SqlRecorder

BIG_PACKUMENT = {"versions": {f"1.0.{i}": {"pad": "x" * 512} for i in range(200)}}
VERSION_COUNT = 60


class MemRedis:
    """Just enough of redis.asyncio for the cache helpers."""

    def __init__(self):
        self.d: dict[str, bytes] = {}

    async def get(self, key):
        return self.d.get(key)

    async def set(self, key, value, ex=None, nx=False):
        if nx and key in self.d:
            return None
        self.d[key] = value
        return True

    async def delete(self, *keys):
        for key in keys:
            self.d.pop(key, None)

    async def scan(self, cursor=0, match="*", count=500):
        prefix = match.rstrip("*")
        return 0, [k for k in self.d if k.startswith(prefix)]

    async def eval(self, *args):
        return 0


@pytest.fixture
def mem_redis(monkeypatch):
    fake = MemRedis()
    monkeypatch.setattr(cache, "_redis", fake)
    return fake


def blob_files() -> list:
    return [p for p in get_store().blobs_dir.rglob("*") if p.is_file()]


def make_tgz(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buf.getvalue()


# --------------------------------------------------------------------------- #
# Fixtures: a fat mirrored package with known vulnerabilities
# --------------------------------------------------------------------------- #
@pytest_asyncio.fixture
async def audited(app_client):
    async with db_module.session_scope() as session:
        package = Package(
            ecosystem=Ecosystem.npm,
            name="playwright",
            normalized_name="playwright",
            latest_version=f"1.0.{VERSION_COUNT - 1}",
            keywords=[],
            is_local=False,
            # Fresh, so no route has a reason to refresh from upstream.
            cached_at=datetime.now(UTC),
            cached_document=BIG_PACKUMENT,
        )
        session.add(package)
        await session.flush()
        rows = {}
        for i in range(VERSION_COUNT):
            row = PackageVersion(
                package_id=package.id,
                version=f"1.0.{i}",
                normalized_version=f"1.0.{i}",
                metadata_json={"name": "playwright", "pad": "y" * 512},
                scanned_at=datetime.now(UTC),
            )
            session.add(row)
            rows[i] = row
        await session.flush()

        vulns = [
            Vulnerability(id="GHSA-medium", cve_id="CVE-2026-0001", ecosystem=Ecosystem.npm,
                          summary="medium one", severity_label="medium", cvss_score=5.0),
            Vulnerability(id="GHSA-none", cve_id="CVE-2026-0002", ecosystem=Ecosystem.npm,
                          summary="rated none", severity_label="none", cvss_score=0.0),
            Vulnerability(id="GHSA-unrated", cve_id="CVE-2026-0003", ecosystem=Ecosystem.npm,
                          summary=None, severity_label=None, cvss_score=None),
            Vulnerability(id="GHSA-suppressed", cve_id="CVE-2026-0004", ecosystem=Ecosystem.npm,
                          summary="accepted", severity_label="critical", cvss_score=9.9),
        ]
        session.add_all(vulns)
        await session.flush()
        # GHSA-medium hits 1.0.1, 1.0.2 and 1.0.10; fixed in 1.0.11.
        for i in (1, 2, 10):
            session.add(PackageVulnerability(
                version_id=rows[i].id, vulnerability_id="GHSA-medium", fixed_version="1.0.11"))
        session.add(PackageVulnerability(version_id=rows[1].id, vulnerability_id="GHSA-none"))
        session.add(PackageVulnerability(version_id=rows[3].id, vulnerability_id="GHSA-unrated"))
        session.add(PackageVulnerability(
            version_id=rows[1].id, vulnerability_id="GHSA-suppressed", suppressed=True))

        # Plenty of other packages, so an N-queries implementation shows up.
        for n in range(40):
            session.add(Package(
                ecosystem=Ecosystem.npm, name=f"other-{n}", normalized_name=f"other-{n}",
                keywords=[], is_local=False, cached_at=datetime.now(UTC),
                cached_document=BIG_PACKUMENT,
            ))
    return app_client


class TestAuditBulkFootprint:
    async def test_bulk_audit_selects_no_packuments(self, audited):
        body = {"playwright": ["1.0.1"], **{f"other-{n}": ["1.0.0"] for n in range(40)}}
        with SqlRecorder() as sql:
            response = await audited.post(
                "/npm/-/npm/v1/security/advisories/bulk",
                json=body,
                headers=auth(audited, "reader"),
            )
        assert response.status_code == 200
        assert "playwright" in response.json()
        sql.assert_no_heavy_columns("npm bulk audit")

    async def test_bulk_audit_query_count_does_not_scale_with_names(self, audited):
        body = {"playwright": ["1.0.1"], **{f"other-{n}": ["1.0.0"] for n in range(40)}}
        with SqlRecorder() as sql:
            response = await audited.post(
                "/npm/-/npm/v1/security/advisories/bulk",
                json=body,
                headers=auth(audited, "reader"),
            )
        assert response.status_code == 200
        selects = [s for s in sql.statements if s.lstrip().upper().startswith("SELECT")]
        # Auth plus three audit queries; 41 names must not mean 41 lookups.
        assert len(selects) < 12, "\n".join(selects)

    async def test_lean_routes_never_select_the_packument(self, audited):
        client = audited
        with SqlRecorder() as sql:
            tags = await client.get(
                "/npm/-/package/playwright/dist-tags", headers=auth(client, "reader")
            )
            assert tags.status_code == 200
            assert tags.json()["latest"] == f"1.0.{VERSION_COUNT - 1}"
            put = await client.put(
                "/npm/-/package/playwright/dist-tags/beta",
                content='"1.0.3"',
                headers=auth(client, "admin"),
            )
            assert put.status_code == 200
            deleted = await client.delete(
                "/npm/-/package/playwright/dist-tags/beta", headers=auth(client, "admin")
            )
            assert deleted.status_code == 200
        sql.assert_no_heavy_columns("dist-tag routes")

    async def test_version_document_reads_one_version(self, audited):
        client = audited
        with SqlRecorder() as sql:
            response = await client.get("/npm/playwright/1.0.7", headers=auth(client, "reader"))
        assert response.status_code == 200
        assert response.json()["version"] == "1.0.7"
        assert not sql.selects_touching("cached_document")
        heavy = sql.selects_touching("metadata_json")
        assert heavy and all("package_versions.version =" in s for s in heavy), heavy


# --------------------------------------------------------------------------- #
# Audit wire format
# --------------------------------------------------------------------------- #
class TestAuditFormat:
    async def _audit(self, client, body):
        response = await client.post(
            "/npm/-/npm/v1/security/advisories/bulk", json=body, headers=auth(client, "reader")
        )
        assert response.status_code == 200
        return response.json()

    async def test_one_advisory_per_vulnerability_covering_every_known_version(self, audited):
        out = await self._audit(audited, {"playwright": ["1.0.1", "1.0.2", "1.0.10"]})
        medium = [a for a in out["playwright"] if a["id"] == "GHSA-medium"]
        # arborist memoises by id: three advisories with one exact version
        # each flagged only the first installed version.
        assert len(medium) == 1
        assert medium[0]["vulnerable_versions"] == "1.0.1 || 1.0.2 || 1.0.10"
        assert medium[0]["severity"] == "moderate"
        assert medium[0]["fixAvailable"] == {"version": "1.0.11"}

    async def test_range_is_the_vulnerabilitys_not_the_request(self, audited):
        out = await self._audit(audited, {"playwright": ["1.0.2"]})
        medium = next(a for a in out["playwright"] if a["id"] == "GHSA-medium")
        assert medium["vulnerable_versions"] == "1.0.1 || 1.0.2 || 1.0.10"
        # Same id whatever was asked: stable across requests.
        again = await self._audit(audited, {"playwright": ["1.0.10"]})
        assert [a["id"] for a in again["playwright"]] == ["GHSA-medium"]

    async def test_severities_are_npms_vocabulary(self, audited):
        out = await self._audit(audited, {"playwright": ["1.0.1", "1.0.3"]})
        by_id = {a["id"]: a for a in out["playwright"]}
        assert by_id["GHSA-medium"]["severity"] == "moderate"
        assert by_id["GHSA-none"]["severity"] == "info"
        assert by_id["GHSA-unrated"]["severity"] == "low"
        assert "GHSA-suppressed" not in by_id
        allowed = {"info", "low", "moderate", "high", "critical"}
        assert {a["severity"] for a in out["playwright"]} <= allowed

    async def test_unaffected_versions_and_unknown_names_report_nothing(self, audited):
        out = await self._audit(audited, {"playwright": ["1.0.5"], "nonexistent": ["1.0.0"]})
        assert out == {}

    def test_severity_mapping(self):
        assert npm_api.npm_severity("critical", 9.8) == "critical"
        assert npm_api.npm_severity("high", 7.5) == "high"
        assert npm_api.npm_severity("medium", 5.0) == "moderate"
        assert npm_api.npm_severity("low", 2.0) == "low"
        assert npm_api.npm_severity("none", 0.0) == "info"
        assert npm_api.npm_severity(None, 7.1) == "high"
        assert npm_api.npm_severity(None, None) == "low"
        assert npm_api.npm_severity("unknown", None) == "low"


# --------------------------------------------------------------------------- #
# Rendered packument cache
# --------------------------------------------------------------------------- #
class TestPackumentCache:
    async def test_cache_holds_the_served_bytes(self, env, mem_redis):
        client, tokens = env
        alice = as_user(client, tokens["alice"])
        assert (await alice.put("/npm/cached-lib", json=publish_body("cached-lib", "1.0.0"))).status_code == 201

        first = await client.get("/npm/cached-lib")
        assert first.status_code == 200
        key = next(k for k in mem_redis.d if k.endswith(":full"))
        assert isinstance(mem_redis.d[key], bytes)
        assert mem_redis.d[key] == first.content

    async def test_hit_is_served_verbatim(self, env, mem_redis):
        client, tokens = env
        alice = as_user(client, tokens["alice"])
        await alice.put("/npm/cached-lib", json=publish_body("cached-lib", "1.0.0"))
        await client.get("/npm/cached-lib")
        key = next(k for k in mem_redis.d if k.endswith(":full"))
        # Byte-for-byte, not parsed and re-encoded: key order and spacing kept.
        sentinel = b'{"name":"cached-lib",  "versions":{}}'
        mem_redis.d[key] = sentinel
        hit = await client.get("/npm/cached-lib")
        assert hit.content == sentinel
        assert hit.headers["etag"] == '"' + hashlib.sha256(sentinel).hexdigest() + '"'

    async def test_abbreviated_and_full_are_cached_separately(self, env, mem_redis):
        client, tokens = env
        await as_user(client, tokens["alice"]).put(
            "/npm/cached-lib", json=publish_body("cached-lib", "1.0.0")
        )
        full = await client.get("/npm/cached-lib")
        abbrev = await client.get(
            "/npm/cached-lib", headers={"accept": "application/vnd.npm.install-v1+json"}
        )
        assert abbrev.headers["content-type"].startswith("application/vnd.npm.install-v1+json")
        assert full.content != abbrev.content
        assert {k.rsplit(":", 1)[-1] for k in mem_redis.d if "cached-lib" in k} >= {"full", "abbrev"}

    async def test_large_documents_are_not_cached(self, env, mem_redis, monkeypatch):
        client, tokens = env
        await as_user(client, tokens["alice"]).put(
            "/npm/cached-lib", json=publish_body("cached-lib", "1.0.0")
        )
        monkeypatch.setattr(npm_api, "PACKUMENT_CACHE_MAX_BYTES", 64)
        response = await client.get("/npm/cached-lib")
        assert response.status_code == 200
        assert len(response.content) > 64
        assert not [k for k in mem_redis.d if k.endswith(":full")]


# --------------------------------------------------------------------------- #
# npm unpublish pkg@version
# --------------------------------------------------------------------------- #
async def libnpmpublish_unpublish(client, path_name: str, version: str):
    """What libnpmpublish's unpublish() sends for one version of many."""
    pkg = (await client.get(f"/npm/{path_name}", params={"write": "true"})).json()
    dist = pkg["versions"][version]["dist"]
    del pkg["versions"][version]
    latest = pkg["dist-tags"].get("latest")
    for tag, tagged in list(pkg["dist-tags"].items()):
        if tagged == version:
            del pkg["dist-tags"][tag]
    if latest == version:
        pkg["dist-tags"]["latest"] = sorted(pkg["versions"])[-1]
    pkg.pop("_revisions", None)
    pkg.pop("_attachments", None)
    put = await client.put(f"/npm/{path_name}/-rev/{pkg['_rev']}", json=pkg)
    if put.status_code != 200:
        return put, None
    rev = (await client.get(f"/npm/{path_name}", params={"write": "true"})).json()["_rev"]
    tarball_path = dist["tarball"].split("://", 1)[1].split("/", 1)[1]
    delete = await client.delete(f"/{tarball_path}/-rev/{rev}")
    return put, delete


class TestVersionUnpublishViaPut:
    async def test_unpublish_one_version(self, env):
        client, tokens = env
        alice = as_user(client, tokens["alice"])
        for version in ("1.0.0", "1.1.0"):
            body = publish_body("internal-lib", version, tarball=f"bytes-{version}".encode())
            assert (await alice.put("/npm/internal-lib", json=body)).status_code == 201
        assert len(blob_files()) == 2

        put, delete = await libnpmpublish_unpublish(alice, "internal-lib", "1.1.0")
        assert put.status_code == 200, put.text
        assert delete.status_code == 200, delete.text

        document = (await client.get("/npm/internal-lib")).json()
        assert list(document["versions"]) == ["1.0.0"]
        assert document["dist-tags"] == {"latest": "1.0.0"}
        assert len(blob_files()) == 1

        async with db_module.session_scope() as session:
            tombs = (await session.execute(sqlalchemy.select(RetiredVersion))).scalars().all()
            assert [t.version for t in tombs] == ["1.1.0"]

        # The tombstone holds: the number cannot come back with new bytes.
        again = await alice.put(
            "/npm/internal-lib",
            json=publish_body("internal-lib", "1.1.0", tarball=b"different"),
        )
        assert again.status_code == 409

    async def test_scoped_package(self, env):
        client, tokens = env
        alice = as_user(client, tokens["alice"])
        for version in ("1.0.0", "2.0.0"):
            body = publish_body("@acme/lib", version, tarball=f"scoped-{version}".encode())
            assert (await alice.put("/npm/@acme%2flib", json=body)).status_code == 201

        put, delete = await libnpmpublish_unpublish(alice, "@acme%2flib", "1.0.0")
        assert put.status_code == 200, put.text
        assert delete.status_code == 200, delete.text
        document = (await client.get("/npm/@acme%2flib")).json()
        assert list(document["versions"]) == ["2.0.0"]
        assert document["dist-tags"]["latest"] == "2.0.0"

    async def test_another_user_cannot(self, env):
        client, tokens = env
        alice = as_user(client, tokens["alice"])
        for version in ("1.0.0", "1.1.0"):
            await alice.put("/npm/internal-lib", json=publish_body("internal-lib", version))
        pkg = (await client.get("/npm/internal-lib")).json()
        del pkg["versions"]["1.1.0"]
        bob = as_user(client, tokens["bob"])
        response = await bob.put(f"/npm/internal-lib/-rev/{pkg['_rev']}", json=pkg)
        assert response.status_code == 403
        document = (await client.get("/npm/internal-lib")).json()
        assert set(document["versions"]) == {"1.0.0", "1.1.0"}

    async def test_removing_every_version_is_refused(self, env):
        client, tokens = env
        alice = as_user(client, tokens["alice"])
        await alice.put("/npm/internal-lib", json=publish_body("internal-lib", "1.0.0"))
        pkg = (await client.get("/npm/internal-lib")).json()
        pkg["versions"] = {}
        response = await alice.put(f"/npm/internal-lib/-rev/{pkg['_rev']}", json=pkg)
        assert response.status_code == 400
        missing = {k: v for k, v in pkg.items() if k != "versions"}
        response = await alice.put(f"/npm/internal-lib/-rev/{pkg['_rev']}", json=missing)
        assert response.status_code == 400
        assert "1.0.0" in (await client.get("/npm/internal-lib")).json()["versions"]

    async def test_deprecate_on_the_rev_route(self, env):
        client, tokens = env
        alice = as_user(client, tokens["alice"])
        for version in ("1.0.0", "1.1.0"):
            await alice.put("/npm/internal-lib", json=publish_body("internal-lib", version))
        pkg = (await client.get("/npm/internal-lib")).json()
        pkg["versions"]["1.0.0"]["deprecated"] = "use 1.1.0"
        response = await alice.put(f"/npm/internal-lib/-rev/{pkg['_rev']}", json=pkg)
        assert response.status_code == 200
        document = (await client.get("/npm/internal-lib")).json()
        assert document["versions"]["1.0.0"]["deprecated"] == "use 1.1.0"
        assert set(document["versions"]) == {"1.0.0", "1.1.0"}

    async def test_plain_put_still_publishes(self, env):
        """The new route must not shadow publish or the DELETE routes."""
        client, tokens = env
        alice = as_user(client, tokens["alice"])
        assert (await alice.put(
            "/npm/@acme%2fother", json=publish_body("@acme/other", "1.0.0")
        )).status_code == 201
        assert (await alice.put(
            "/npm/@acme%2fother", json=publish_body("@acme/other", "1.1.0")
        )).status_code == 201
        removed = await alice.delete("/npm/@acme/other/-/other-1.0.0.tgz/-rev/1")
        assert removed.status_code == 200
        gone = await alice.delete("/npm/@acme%2fother/-rev/1")
        assert gone.status_code == 200


# --------------------------------------------------------------------------- #
# ETag / 304
# --------------------------------------------------------------------------- #
class TestConditionalRequests:
    async def test_packument_etag_and_304(self, env):
        client, tokens = env
        await as_user(client, tokens["alice"]).put(
            "/npm/internal-lib", json=publish_body("internal-lib", "1.0.0")
        )
        first = await client.get("/npm/internal-lib")
        etag = first.headers["etag"]
        assert etag == '"' + hashlib.sha256(first.content).hexdigest() + '"'
        assert "accept" in first.headers.get("vary", "").lower()

        cached = await client.get("/npm/internal-lib", headers={"if-none-match": etag})
        assert cached.status_code == 304
        assert cached.content == b""
        assert cached.headers["etag"] == etag

        abbrev = await client.get(
            "/npm/internal-lib",
            headers={"accept": "application/vnd.npm.install-v1+json", "if-none-match": etag},
        )
        assert abbrev.status_code == 200
        assert abbrev.headers["etag"] != etag

        stale = await client.get("/npm/internal-lib", headers={"if-none-match": '"nope"'})
        assert stale.status_code == 200

    async def test_version_document_etag_and_304(self, env):
        client, tokens = env
        await as_user(client, tokens["alice"]).put(
            "/npm/internal-lib", json=publish_body("internal-lib", "1.0.0")
        )
        first = await client.get("/npm/internal-lib/1.0.0")
        etag = first.headers["etag"]
        assert etag == '"' + hashlib.sha256(first.content).hexdigest() + '"'
        second = await client.get(
            "/npm/internal-lib/1.0.0", headers={"if-none-match": f'W/{etag}, "other"'}
        )
        assert second.status_code == 304

    async def test_tarball_304(self, env):
        client, tokens = env
        tarball = b"tarball-bytes"
        await as_user(client, tokens["alice"]).put(
            "/npm/internal-lib", json=publish_body("internal-lib", "1.0.0", tarball=tarball)
        )
        first = await client.get("/npm/internal-lib/-/internal-lib-1.0.0.tgz")
        assert first.status_code == 200
        etag = first.headers["etag"]
        assert etag == '"' + hashlib.sha256(tarball).hexdigest() + '"'
        second = await client.get(
            "/npm/internal-lib/-/internal-lib-1.0.0.tgz", headers={"if-none-match": etag}
        )
        assert second.status_code == 304
        assert second.content == b""


# --------------------------------------------------------------------------- #
# 404 bodies
# --------------------------------------------------------------------------- #
class TestNotFoundBodies:
    async def test_every_npm_404_says_not_found(self, env):
        client, tokens = env
        alice = as_user(client, tokens["alice"])
        await alice.put("/npm/internal-lib", json=publish_body("internal-lib", "1.0.0"))
        responses = [
            await client.get("/npm/missing-pkg"),
            await client.get("/npm/missing-pkg/1.0.0"),
            await client.get("/npm/internal-lib/9.9.9"),
            await client.get("/npm/-/package/missing-pkg/dist-tags"),
            await client.get("/npm/missing-pkg/-/missing-pkg-1.0.0.tgz"),
            await client.get("/npm/internal-lib/-/internal-lib-9.9.9.tgz"),
            await alice.put("/npm/-/package/internal-lib/dist-tags/beta", content='"9.9.9"'),
            await alice.delete("/npm/-/package/internal-lib/dist-tags/beta"),
            await alice.delete("/npm/missing-pkg/-rev/1"),
            await alice.put("/npm/missing-pkg/-rev/1", json={"name": "missing-pkg", "versions": {}}),
        ]
        for response in responses:
            assert response.status_code == 404, (response.request.url, response.text)
            assert response.json()["error"] == "Not found", (response.request.url, response.text)


# --------------------------------------------------------------------------- #
# Publish metadata and refusals
# --------------------------------------------------------------------------- #
class TestPublishMetadata:
    async def _abbreviated_version(self, client, name, version):
        doc = (await client.get(
            f"/npm/{name}", headers={"accept": "application/vnd.npm.install-v1+json"}
        )).json()
        return doc["versions"][version]

    async def test_has_install_script_from_scripts(self, env):
        client, tokens = env
        body = publish_body("internal-lib", "1.0.0")
        body["versions"]["1.0.0"]["scripts"] = {"postinstall": "node setup.js", "test": "x"}
        assert (await as_user(client, tokens["alice"]).put("/npm/internal-lib", json=body)).status_code == 201
        meta = await self._abbreviated_version(client, "internal-lib", "1.0.0")
        assert meta["hasInstallScript"] is True

    async def test_has_install_script_from_binding_gyp(self, env):
        client, tokens = env
        tarball = make_tgz({
            "package/package.json": b'{"name":"native-lib","version":"1.0.0"}',
            "package/binding.gyp": b"{}",
        })
        body = publish_body("native-lib", "1.0.0", tarball=tarball)
        assert (await as_user(client, tokens["alice"]).put("/npm/native-lib", json=body)).status_code == 201
        meta = await self._abbreviated_version(client, "native-lib", "1.0.0")
        assert meta["hasInstallScript"] is True

    async def test_no_install_script_and_client_claim_ignored(self, env):
        client, tokens = env
        tarball = make_tgz({"package/package.json": b"{}", "package/lib/binding.gyp": b"{}"})
        body = publish_body("plain-lib", "1.0.0", tarball=tarball)
        body["versions"]["1.0.0"]["scripts"] = {"test": "x"}
        body["versions"]["1.0.0"]["hasInstallScript"] = True
        assert (await as_user(client, tokens["alice"]).put("/npm/plain-lib", json=body)).status_code == 201
        meta = await self._abbreviated_version(client, "plain-lib", "1.0.0")
        assert "hasInstallScript" not in meta

    def test_integrity_verification_unit(self):
        data = b"some tarball"
        digests = npm_publish.digest_tarball(data)
        good512 = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()
        good1 = "sha1-" + base64.b64encode(hashlib.sha1(data).digest()).decode()
        npm_publish.verify_declared_digests("1.0.0", {"dist": {"integrity": good512}}, digests)
        npm_publish.verify_declared_digests(
            "1.0.0", {"dist": {"integrity": f"{good512} {good1}"}}, digests
        )
        # Unknown algorithms prove nothing either way.
        npm_publish.verify_declared_digests("1.0.0", {"dist": {"integrity": "sha384-xyz"}}, digests)
        for bad in ("sha512-" + "A" * 86, "sha512-not base64!", f"{good512} sha1-AAAA"):
            with pytest.raises(npm_publish.PublishError):
                npm_publish.verify_declared_digests("1.0.0", {"dist": {"integrity": bad}}, digests)


class TestRefusedPublishLeavesNoBlob:
    async def test_shasum_mismatch(self, env):
        client, tokens = env
        body = publish_body("internal-lib", "1.0.0")
        body["versions"]["1.0.0"]["dist"] = {"shasum": "0" * 40}
        response = await as_user(client, tokens["alice"]).put("/npm/internal-lib", json=body)
        assert response.status_code == 400
        assert blob_files() == []

    async def test_integrity_mismatch(self, env):
        client, tokens = env
        body = publish_body("internal-lib", "1.0.0")
        body["versions"]["1.0.0"]["dist"] = {"integrity": "sha512-" + "A" * 86}
        response = await as_user(client, tokens["alice"]).put("/npm/internal-lib", json=body)
        assert response.status_code == 400
        assert blob_files() == []

    async def test_cve_policy_refusal(self, env, monkeypatch):
        from app.services.policy import PolicyEngine, Verdict

        original = PolicyEngine.evaluate

        async def evaluate(self, ecosystem, normalized_name, version=None, **kwargs):
            if version is not None:
                return Verdict(allowed=False, reason="blocked by CVE policy", source="cve")
            return await original(self, ecosystem, normalized_name, version, **kwargs)

        monkeypatch.setattr(PolicyEngine, "evaluate", evaluate)
        client, tokens = env
        response = await as_user(client, tokens["alice"]).put(
            "/npm/internal-lib", json=publish_body("internal-lib", "1.0.0")
        )
        assert response.status_code == 403
        assert blob_files() == []

    async def test_second_version_refused_stores_neither(self, env):
        client, tokens = env
        body = publish_body("internal-lib", "1.0.0", tarball=b"first")
        second = publish_body("internal-lib", "1.1.0", tarball=b"second")
        body["versions"].update(second["versions"])
        body["_attachments"].update(second["_attachments"])
        body["versions"]["1.1.0"]["dist"] = {"shasum": "0" * 40}
        response = await as_user(client, tokens["alice"]).put("/npm/internal-lib", json=body)
        assert response.status_code == 400
        assert blob_files() == []
