"""PyPI and cargo protocol-surface regressions, and CVE-refresh invalidation.

* PEP 691 negotiation: legacy ``text/html`` requests get ``text/html``.
* PEP 658/714: ``core-metadata`` carries only real digests, never the file.
* PEP 658: the ``.metadata`` sidecar is byte-exact, so its digest verifies.
* A refused upload leaves nothing in the blob store.
* ETag / 304 on the cargo index and the PyPI simple pages.
* The background CVE refresh invalidates the rendered documents it changed.
"""

from __future__ import annotations

import base64
import hashlib
import io
import zipfile
from datetime import UTC, datetime

import httpx
import pytest
import respx
from sqlalchemy import select, update

from app import db as db_module
from app.models import Ecosystem, Package, PackageFile, PackageVersion, Setting
from app.services import pypi_render
from app.services.policy import KEY_CVE_POLICY, invalidate_policy_cache
from app.services.pypi_publish import core_metadata_record
from app.services.pypi_render import (
    HTML_CONTENT_TYPE,
    JSON_CONTENT_TYPE,
    render_project_html,
    render_project_json,
    select_content_type,
)
from app.services.storage import get_store

from .conftest import add_file, make_package
from .test_cargo_spec import cargo_client, mock_cargo_upstream  # noqa: F401
from .test_integration import app_client, basic_auth  # noqa: F401

# Latin-1 in METADATA: not valid UTF-8, so decoding with errors="replace" and
# re-encoding changes the bytes -- and the digest.
RAW_METADATA = b"Metadata-Version: 2.1\nName: my-package\nVersion: 1.0.0\nAuthor: Jos\xe9\n"
RAW_SHA256 = hashlib.sha256(RAW_METADATA).hexdigest()
WHEEL_NAME = "my_package-1.0.0-py3-none-any.whl"


def build_wheel(metadata: bytes = RAW_METADATA) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("my_package-1.0.0.dist-info/METADATA", metadata)
        archive.writestr("my_package/__init__.py", "")
    return buffer.getvalue()


def upload_form(content: bytes, **fields):
    return (
        {
            ":action": "file_upload",
            "protocol_version": "1",
            "name": "my-package",
            "version": "1.0.0",
            "filetype": "bdist_wheel",
            "pyversion": "py3",
            "metadata_version": "2.1",
            **fields,
        },
        {"content": (WHEEL_NAME, content, "application/octet-stream")},
    )


async def upload(client, content: bytes | None = None, **fields):
    data, files = upload_form(content if content is not None else build_wheel(), **fields)
    return await client.post("/pypi/legacy/", data=data, files=files, headers=basic_auth(client))


def blob_files() -> list:
    """Everything in the blob store, temp files included."""
    return [p for p in get_store().root.rglob("*") if p.is_file()]


def pypi_package_with(core_metadata) -> Package:
    package = make_package(name="my-package", ecosystem=Ecosystem.pypi, versions=(("1.0.0", {}),))
    add_file(package.versions[0], WHEEL_NAME, sha256="a" * 64, size=1, core_metadata=core_metadata)
    return package


# --------------------------------------------------------------------------- #
# 1. Content negotiation
# --------------------------------------------------------------------------- #
class TestNegotiation:
    @pytest.mark.parametrize(
        "accept,expected",
        [
            # pip >= 22.2
            (
                "application/vnd.pypi.simple.v1+json, "
                "application/vnd.pypi.simple.v1+html; q=0.1, text/html; q=0.01",
                JSON_CONTENT_TYPE,
            ),
            ("text/html; q=0.5, application/vnd.pypi.simple.v1+html", HTML_CONTENT_TYPE),
            ("application/vnd.pypi.simple.v1+html; q=0.2, text/html", "text/html"),
            # q=0 is "not acceptable", never a candidate.
            ("application/vnd.pypi.simple.v1+json; q=0", "text/html"),
            ("text/*", "text/html"),
        ],
    )
    def test_q_values(self, accept, expected):
        assert select_content_type(accept) == expected

    @pytest.mark.parametrize(
        "accept,expected_prefix",
        [
            (None, "text/html"),
            ("text/html", "text/html"),
            ("*/*", "text/html"),
            ("application/vnd.pypi.simple.v1+html", HTML_CONTENT_TYPE),
            ("application/vnd.pypi.simple.v1+json", JSON_CONTENT_TYPE),
        ],
    )
    async def test_served_content_type(self, app_client, accept, expected_prefix):  # noqa: F811
        assert (await upload(app_client)).status_code == 200
        headers = {"accept": accept} if accept else {}
        for path in ("/pypi/simple/", "/pypi/simple/my-package/"):
            response = await app_client.get(path, headers=headers)
            assert response.status_code == 200
            # pip < 22.2's _ensure_html_header: startswith("text/html").
            assert response.headers["content-type"].startswith(expected_prefix)
            assert response.headers["vary"] == "Accept"


# --------------------------------------------------------------------------- #
# 2. core-metadata carries digests only
# --------------------------------------------------------------------------- #
class TestCoreMetadataAdvertisement:
    def test_stored_bytes_never_leak(self):
        package = pypi_package_with(core_metadata_record(RAW_METADATA))
        entry = render_project_json(package)["files"][0]
        assert entry["core-metadata"] == {"sha256": RAW_SHA256}
        assert entry["dist-info-metadata"] == {"sha256": RAW_SHA256}
        html = render_project_html(package)
        assert f'data-core-metadata="sha256={RAW_SHA256}"' in html
        assert f'data-dist-info-metadata="sha256={RAW_SHA256}"' in html
        assert "_raw" not in html and "Metadata-Version" not in html

    def test_legacy_raw_row_gets_a_computed_digest(self):
        text = "Metadata-Version: 2.1\nName: my-package\n"
        package = pypi_package_with({"_raw": text})
        entry = render_project_json(package)["files"][0]
        assert entry["core-metadata"] == {"sha256": hashlib.sha256(text.encode()).hexdigest()}
        assert "_raw" not in render_project_html(package)

    def test_upstream_digest_is_kept_and_sha256_first(self):
        package = pypi_package_with({"blake2b_256": "c" * 64, "sha256": "b" * 64, "_raw": "x"})
        entry = render_project_json(package)["files"][0]
        assert entry["core-metadata"] == {"sha256": "b" * 64, "blake2b_256": "c" * 64}
        assert f'data-core-metadata="sha256={"b" * 64}"' in render_project_html(package)

    def test_true_only_when_servable_without_a_digest(self):
        assert (
            render_project_json(pypi_package_with({"available": True}))["files"][0][
                "core-metadata"
            ]
            is True
        )
        # Junk keys, no digest, nothing stored: omitted rather than `true`.
        entry = render_project_json(pypi_package_with({"note": "zzz"}))["files"][0]
        assert "core-metadata" not in entry
        entry = render_project_json(pypi_package_with({"sha256": "not hex!"}))["files"][0]
        assert "core-metadata" not in entry


# --------------------------------------------------------------------------- #
# 3. The sidecar is byte-exact
# --------------------------------------------------------------------------- #
class TestByteExactSidecar:
    async def test_upload_advertises_and_serves_the_exact_bytes(self, app_client):  # noqa: F811
        assert (await upload(app_client)).status_code == 200
        page = await app_client.get(
            "/pypi/simple/my-package/", headers={"accept": JSON_CONTENT_TYPE}
        )
        advertised = page.json()["files"][0]["core-metadata"]
        assert advertised == {"sha256": RAW_SHA256}

        sidecar = await app_client.get(f"/pypi/files/my-package/{WHEEL_NAME}.metadata")
        assert sidecar.status_code == 200
        assert sidecar.content == RAW_METADATA
        assert hashlib.sha256(sidecar.content).hexdigest() == advertised["sha256"]
        # Not valid UTF-8, so it must not be labelled as such.
        assert "charset=utf-8" not in sidecar.headers["content-type"]

    async def test_utf8_metadata_is_labelled_text(self, app_client):  # noqa: F811
        raw = b"Metadata-Version: 2.1\nName: my-package\nVersion: 1.0.0\n"
        assert (await upload(app_client, build_wheel(raw))).status_code == 200
        sidecar = await app_client.get(f"/pypi/files/my-package/{WHEEL_NAME}.metadata")
        assert sidecar.content == raw
        assert sidecar.headers["content-type"].startswith("text/plain")

    async def _set_core_metadata(self, value):
        async with db_module.session_scope() as session:
            await session.execute(update(PackageFile).values(core_metadata=value))

    async def _stored_core_metadata(self):
        async with db_module.session_scope() as session:
            return (await session.execute(select(PackageFile.core_metadata))).scalar_one()

    async def test_legacy_row_without_digest_is_self_consistent(self, app_client):  # noqa: F811
        assert (await upload(app_client)).status_code == 200
        decoded = RAW_METADATA.decode("utf-8", "replace")
        await self._set_core_metadata({"_raw": decoded})

        page = await app_client.get(
            "/pypi/simple/my-package/", headers={"accept": JSON_CONTENT_TYPE}
        )
        advertised = page.json()["files"][0]["core-metadata"]["sha256"]
        sidecar = await app_client.get(f"/pypi/files/my-package/{WHEEL_NAME}.metadata")
        assert hashlib.sha256(sidecar.content).hexdigest() == advertised

    async def test_legacy_row_that_no_longer_matches_is_re_extracted(self, app_client):  # noqa: F811
        """An upstream row: the upstream's (correct) digest plus a decoded copy
        that no longer hashes to it. The wheel is re-read for exact bytes."""
        assert (await upload(app_client)).status_code == 200
        decoded = RAW_METADATA.decode("utf-8", "replace")
        await self._set_core_metadata({"sha256": RAW_SHA256, "_raw": decoded})

        sidecar = await app_client.get(f"/pypi/files/my-package/{WHEEL_NAME}.metadata")
        assert sidecar.content == RAW_METADATA

        stored = await self._stored_core_metadata()
        assert "_raw" not in stored
        assert base64.b64decode(stored["_raw_b64"]) == RAW_METADATA
        assert stored["sha256"] == RAW_SHA256


# --------------------------------------------------------------------------- #
# 4. Refused uploads leave no file behind
# --------------------------------------------------------------------------- #
class TestRefusedUploadLeavesNoBlob:
    async def test_digest_mismatch(self, app_client):  # noqa: F811
        response = await upload(app_client, sha256_digest="0" * 64)
        assert response.status_code == 400
        assert blob_files() == []

    async def test_cve_policy_refusal(self, app_client):  # noqa: F811
        # OSV is disabled in tests, so the inline scan comes back unscanned.
        async with db_module.session_scope() as session:
            session.add(
                Setting(
                    key=KEY_CVE_POLICY,
                    value={
                        "enabled": True,
                        "min_score": 7.0,
                        "max_score": 10.0,
                        "block_unscored": True,
                        "require_fix_available": False,
                    },
                )
            )
        await invalidate_policy_cache()
        response = await upload(app_client)
        assert response.status_code == 403
        assert blob_files() == []

    async def test_accepted_upload_is_stored(self, app_client):  # noqa: F811
        content = build_wheel()
        assert (await upload(app_client, content)).status_code == 200
        assert get_store().exists(hashlib.sha256(content).hexdigest())


# --------------------------------------------------------------------------- #
# 5. ETag / 304
# --------------------------------------------------------------------------- #
class TestConditionalRequests:
    async def _revalidates(self, client, path, headers=None):
        first = await client.get(path, headers=headers or {})
        assert first.status_code == 200
        etag = first.headers["etag"]
        assert etag.startswith('"') and not etag.startswith("W/")

        again = await client.get(path, headers={**(headers or {}), "if-none-match": etag})
        assert again.status_code == 304
        assert again.content == b""
        assert again.headers["etag"] == etag

        weak = await client.get(path, headers={**(headers or {}), "if-none-match": f"W/{etag}"})
        assert weak.status_code == 304

        stale = await client.get(path, headers={**(headers or {}), "if-none-match": '"nope"'})
        assert stale.status_code == 200
        assert stale.content == first.content
        return etag

    async def test_cargo_config_json(self, cargo_client):  # noqa: F811
        await self._revalidates(cargo_client, "/cargo/index/config.json")

    @respx.mock
    async def test_cargo_index_file(self, cargo_client):  # noqa: F811
        mock_cargo_upstream()
        first = await cargo_client.get("/cargo/index/le/ft/leftpad")
        assert first.headers["etag"] == f'"{hashlib.sha256(first.content).hexdigest()}"'
        await self._revalidates(cargo_client, "/cargo/index/le/ft/leftpad")

    @respx.mock
    async def test_cargo_404_is_unchanged(self, cargo_client):  # noqa: F811
        respx.get("https://index.upstream.test/no/pe/nope").mock(
            return_value=httpx.Response(404)
        )
        response = await cargo_client.get("/cargo/index/no/pe/nope", headers={"if-none-match": "*"})
        assert response.status_code == 404
        assert "etag" not in response.headers

    async def test_pypi_project_pages(self, app_client):  # noqa: F811
        assert (await upload(app_client)).status_code == 200
        path = "/pypi/simple/my-package/"
        html_tag = await self._revalidates(app_client, path)
        json_tag = await self._revalidates(app_client, path, {"accept": JSON_CONTENT_TYPE})
        vnd_tag = await self._revalidates(app_client, path, {"accept": HTML_CONTENT_TYPE})
        # Distinct representations, distinct validators.
        assert len({html_tag, json_tag, vnd_tag}) == 3

        # A JSON validator does not revalidate the HTML page.
        cross = await app_client.get(path, headers={"if-none-match": json_tag})
        assert cross.status_code == 200

    async def test_pypi_etag_tracks_the_body(self, app_client):  # noqa: F811
        """A new release changes the JSON body (PEP 700 ``versions``), so the
        ETag must change with it: it hashes the bytes served."""
        assert (await upload(app_client)).status_code == 200
        path, accept = "/pypi/simple/my-package/", {"accept": JSON_CONTENT_TYPE}
        before = (await app_client.get(path, headers=accept)).headers["etag"]
        async with db_module.session_scope() as session:
            package = (await session.execute(select(Package.id))).scalar_one()
            session.add(
                PackageVersion(
                    package_id=package,
                    version="2.0.0",
                    normalized_version="2.0.0",
                    is_local=True,
                    published_at=datetime.now(UTC),
                )
            )
        after = (await app_client.get(path, headers=accept)).headers["etag"]
        assert before != after


# --------------------------------------------------------------------------- #
# 6. CVE refresh invalidates rendered documents
# --------------------------------------------------------------------------- #
class TestCveRefreshInvalidation:
    async def test_refresh_invalidates_changed_packages_only(self, app_client, monkeypatch):  # noqa: F811
        from app import main
        from app.config import settings
        from app.services import osv

        for name in ("my-package", "other-package"):
            data, _ = upload_form(b"", name=name)
            wheel = f"{name.replace('-', '_')}-1.0.0-py3-none-any.whl"
            files = {"content": (wheel, build_wheel(), "application/octet-stream")}
            response = await app_client.post(
                "/pypi/legacy/", data=data, files=files, headers=basic_auth(app_client)
            )
            assert response.status_code == 200
        # Both scanned clean at upload time, long ago.
        async with db_module.session_scope() as session:
            await session.execute(
                update(PackageVersion).values(
                    scanned_at=datetime(2020, 1, 1, tzinfo=UTC), max_cvss=None
                )
            )

        async def fake_scan(self, ecosystem, items, timeout=None):
            return {
                (name, version): osv.ScanResult(
                    None,
                    name,
                    version,
                    cves=[],
                    # Only my-package gains a score.
                    max_score=9.8 if name == "my-package" else None,
                    scanned=True,
                )
                for name, version in items
            }

        invalidated: list[set] = []

        async def capture(targets):
            invalidated.append(set(targets))

        monkeypatch.setattr(settings, "osv_enabled", True)
        monkeypatch.setattr(osv.OsvScanner, "scan_versions", fake_scan)
        monkeypatch.setattr(osv, "invalidate_rendered_documents", capture)

        await main._cve_refresh_task()

        assert invalidated == [{("pypi", "my-package")}]
        async with db_module.session_scope() as session:
            scores = dict(
                (
                    await session.execute(
                        select(Package.name, PackageVersion.max_cvss).join(
                            PackageVersion, PackageVersion.package_id == Package.id
                        )
                    )
                ).all()
            )
        assert scores == {"my-package": 9.8, "other-package": None}

    async def test_small_batches_use_per_package_invalidation(self, monkeypatch):
        from app.services import osv, packages

        calls = []

        async def fake_invalidate(ecosystem, name):
            calls.append((ecosystem, name))

        monkeypatch.setattr(packages, "invalidate_package_cache", fake_invalidate)
        await osv.invalidate_rendered_documents({("pypi", "a"), ("npm", "b")})
        assert sorted(calls) == [("npm", "b"), ("pypi", "a")]

    async def test_large_batches_scan_once_and_touch_only_their_keys(self, monkeypatch):
        from app.core import cache
        from app.services import osv

        targets = {("npm", f"pkg{i}") for i in range(20)}
        keys = {
            b"pkg:npm:pkg1:full",
            b"pkg:npm:pkg1:abbrev",
            b"pkg:npm:pkg12:full",
            b"pkg:npm:pkg100:full",  # not a target, despite the shared prefix
            b"pkg:pypi:pkg1:html",  # other ecosystem
            b"pkg:npm:react:full",
        }

        class FakeRedis:
            scans = 0

            async def scan(self, cursor, match, count):
                FakeRedis.scans += 1
                assert match == "pkg:*"
                return 0, sorted(keys)

            async def delete(self, *doomed):
                for key in doomed:
                    keys.discard(key)

        monkeypatch.setattr(cache, "redis_client", lambda: FakeRedis())
        await osv.invalidate_rendered_documents(targets)
        assert FakeRedis.scans == 1
        assert keys == {
            b"pkg:npm:pkg100:full",
            b"pkg:pypi:pkg1:html",
            b"pkg:npm:react:full",
        }


def test_select_content_type_is_the_only_negotiator():
    """Every PyPI HTML response goes through the negotiated type."""
    import inspect

    from app.api import pypi

    source = inspect.getsource(pypi)
    assert "media_type=pypi_render.HTML_CONTENT_TYPE" not in source
    assert pypi_render.LEGACY_HTML_CONTENT_TYPE == "text/html"
