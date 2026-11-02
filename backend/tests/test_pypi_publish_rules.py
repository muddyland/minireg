"""PyPI upload rules exercised through the real ``/pypi/legacy/`` route.

Each test pins a way a publish-scoped credential could get a file into a
release, or a document, that it should not.
"""

from __future__ import annotations

import io
import zipfile
from datetime import UTC, datetime

from app import db as db_module
from app.models import Ecosystem, Package, PackageFile, PackageVersion, RetiredVersion, Setting
from app.services.policy import invalidate_policy_cache

from .test_integration import app_client, basic_auth  # noqa: F401

JSON = {"accept": "application/vnd.pypi.simple.v1+json"}


def build_wheel(name: str, version: str, *, metadata: str | None = None) -> bytes:
    dist = name.replace("-", "_")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(
            f"{dist}-{version}.dist-info/METADATA",
            metadata or f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n",
        )
        archive.writestr(f"{dist}/__init__.py", "")
    return buffer.getvalue()


async def upload(client, name, version, filename, content, **fields):
    data = {
        ":action": "file_upload",
        "protocol_version": "1",
        "name": name,
        "version": version,
        "metadata_version": "2.1",
        **fields,
    }
    files = {"content": (filename, content, "application/octet-stream")}
    return await client.post("/pypi/legacy/", data=data, files=files, headers=basic_auth(client))


async def upload_wheel(client, name, version, tag="py3-none-any", **fields):
    filename = f"{name.replace('-', '_')}-{version}-{tag}.whl"
    fields.setdefault("filetype", "bdist_wheel")
    return await upload(client, name, version, filename, build_wheel(name, version), **fields)


async def mirrored_release(name: str, version: str) -> None:
    """A cached upstream release inside a reserved private namespace."""
    async with db_module.session_scope() as session:
        session.add(Setting(key="publish_namespaces", value={"pypi": ["corp-*"]}))
        package = Package(
            ecosystem=Ecosystem.pypi,
            name=name,
            normalized_name=name,
            is_local=False,
            cached_at=datetime.now(UTC),
        )
        session.add(package)
        await session.flush()
        row = PackageVersion(
            package_id=package.id,
            version=version,
            normalized_version=version,
            is_local=False,
            metadata_json={},
        )
        session.add(row)
        await session.flush()
        session.add(
            PackageFile(
                version_id=row.id,
                filename=f"{name.replace('-', '_')}-{version}-py3-none-any.whl",
                sha256="a" * 64,
                size=10,
                packagetype="bdist_wheel",
            )
        )
    await invalidate_policy_cache()


# --------------------------------------------------------------------------- #
# PEP 440 equal versions are one release
# --------------------------------------------------------------------------- #
class TestEqualVersionsAreOneRelease:
    async def test_padded_version_cannot_join_a_mirrored_release(self, app_client):  # noqa: F811
        await mirrored_release("corp-lib", "2.0")
        tag = "cp312-cp312-manylinux_2_17_x86_64"

        for spelling in ("2.0", "2.0.0", "2.0.0.0"):
            response = await upload_wheel(app_client, "corp-lib", spelling, tag=tag)
            assert response.status_code == 403, (spelling, response.text)
            assert "mirrored from an upstream registry" in response.text

        doc = (await app_client.get("/pypi/simple/corp-lib/", headers=JSON)).json()
        assert [f["filename"] for f in doc["files"]] == ["corp_lib-2.0-py3-none-any.whl"]
        assert doc["versions"] == ["2.0"]

    async def test_equal_local_versions_share_one_release(self, app_client):  # noqa: F811
        first = await upload_wheel(app_client, "eqpkg", "1.0")
        assert first.status_code == 200, first.text
        second = await upload_wheel(app_client, "eqpkg", "1.0.0", tag="py2.py3-none-any")
        assert second.status_code == 200, second.text

        doc = (await app_client.get("/pypi/simple/eqpkg/", headers=JSON)).json()
        # One release, under the spelling it was first published with.
        assert doc["versions"] == ["1.0"]
        assert len(doc["files"]) == 2
        api = (await app_client.get("/pypi/eqpkg/json")).json()
        assert list(api["releases"]) == ["1.0"]
        assert len(api["releases"]["1.0"]) == 2

    async def test_one_sdist_rule_spans_equal_spellings(self, app_client):  # noqa: F811
        first = await upload(
            app_client, "sdpkg", "1.0", "sdpkg-1.0.tar.gz", b"sdist-1", filetype="sdist"
        )
        assert first.status_code == 200, first.text
        second = await upload(
            app_client, "sdpkg", "1.0.0", "sdpkg-1.0.0.tar.gz", b"sdist-2", filetype="sdist"
        )
        assert second.status_code == 400
        assert "Only one sdist" in second.text

    async def test_withdrawn_version_blocks_its_equal_spellings(self, app_client):  # noqa: F811
        async with db_module.session_scope() as session:
            session.add(
                RetiredVersion(
                    ecosystem=Ecosystem.pypi,
                    normalized_name="gone-pkg",
                    version="1.0",
                    normalized_version="1.0",
                )
            )
        response = await upload_wheel(app_client, "gone-pkg", "1.0.0")
        assert response.status_code == 409, response.text
        assert "withdrawn" in response.text
        # An unrelated version is still fine.
        assert (await upload_wheel(app_client, "gone-pkg", "1.0.1")).status_code == 200


# --------------------------------------------------------------------------- #
# Only wheels and .tar.gz sdists, with a filetype that agrees
# --------------------------------------------------------------------------- #
class TestDistributionTypes:
    async def test_second_sdist_cannot_pose_as_a_wheel(self, app_client):  # noqa: F811
        sdist = await upload(
            app_client, "ftpkg", "1.0", "ftpkg-1.0.tar.gz", b"sdist-1", filetype="sdist"
        )
        assert sdist.status_code == 200, sdist.text
        for filename, filetype, reason in (
            ("ftpkg-1.0.zip", "bdist_wheel", "only wheels"),
            ("ftpkg-1.0.zip", "sdist", "only wheels"),
            ("FTPkg-1.0.tar.gz", "bdist_wheel", "does not match"),
        ):
            response = await upload(
                app_client, "ftpkg", "1.0", filename, b"sdist-2", filetype=filetype
            )
            assert response.status_code == 400, (filename, filetype, response.text)
            assert reason in response.text

        api = (await app_client.get("/pypi/ftpkg/json")).json()
        assert [(f["filename"], f["packagetype"]) for f in api["releases"]["1.0"]] == [
            ("ftpkg-1.0.tar.gz", "sdist")
        ]

    async def test_eggs_and_non_pep440_versions_are_refused(self, app_client):  # noqa: F811
        egg = await upload(app_client, "eggpkg", "latest", "eggpkg-latest.egg", b"egg")
        assert egg.status_code == 400
        egg = await upload(app_client, "eggpkg", "1.0", "eggpkg-1.0-py3.12.egg", b"egg")
        assert egg.status_code == 400
        assert (await app_client.get("/pypi/simple/eggpkg/", headers=JSON)).status_code == 404
