"""PyPI upload rules exercised through the real ``/pypi/legacy/`` route.

Each test pins a way a publish-scoped credential could get a file into a
release, or a document, that it should not.
"""

from __future__ import annotations

import io
import zipfile
from datetime import UTC, datetime

from sqlalchemy import update

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


# --------------------------------------------------------------------------- #
# A wheel's own METADATA is held to the form
# --------------------------------------------------------------------------- #
def zip_of(members: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for path, text in members.items():
            archive.writestr(path, text)
    return buffer.getvalue()


class TestWheelMetadata:
    WHEEL = "mdpkg-1.0-py3-none-any.whl"

    async def _upload(self, client, content, **fields):
        return await upload(
            client, "mdpkg", "1.0", self.WHEEL, content, filetype="bdist_wheel", **fields
        )

    async def test_wheel_for_another_project_is_refused(self, app_client):  # noqa: F811
        content = build_wheel(
            "mdpkg", "1.0", metadata="Metadata-Version: 2.1\nName: requests\nVersion: 1.0\n"
        )
        response = await self._upload(app_client, content)
        assert response.status_code == 400
        assert "requests" in response.text
        sidecar = await app_client.get(f"/pypi/files/mdpkg/{self.WHEEL}.metadata")
        assert sidecar.status_code == 404

    async def test_wheel_for_another_version_is_refused(self, app_client):  # noqa: F811
        content = build_wheel(
            "mdpkg", "1.0", metadata="Metadata-Version: 2.1\nName: MDPkg\nVersion: 6.6.6\n"
        )
        response = await self._upload(app_client, content)
        assert response.status_code == 400
        assert "6.6.6" in response.text

    async def test_malformed_wheels_are_refused(self, app_client):  # noqa: F811
        meta = "Metadata-Version: 2.1\nName: mdpkg\nVersion: 1.0\n"
        cases = {
            "not a zip": b"not a zip at all",
            "no dist-info": zip_of({"mdpkg/__init__.py": ""}),
            "no METADATA": zip_of({"mdpkg-1.0.dist-info/WHEEL": "Wheel-Version: 1.0\n"}),
            "two dist-infos": zip_of(
                {
                    "mdpkg-1.0.dist-info/METADATA": meta,
                    "requests-1.0.dist-info/METADATA": meta.replace("mdpkg", "requests"),
                }
            ),
            "dist-info of another project": zip_of({"requests-1.0.dist-info/METADATA": meta}),
            "no Version": zip_of({"mdpkg-1.0.dist-info/METADATA": "Name: mdpkg\n"}),
        }
        for label, content in cases.items():
            response = await self._upload(app_client, content)
            assert response.status_code == 400, (label, response.text)
        assert (await app_client.get("/pypi/simple/mdpkg/", headers=JSON)).status_code == 404

    async def test_requires_python_comes_from_the_wheel(self, app_client):  # noqa: F811
        content = build_wheel(
            "mdpkg",
            "1.0",
            metadata=(
                "Metadata-Version: 2.1\nName: mdpkg\nVersion: 1.0.0\n"
                "Requires-Python: >=3.10\n"
            ),
        )
        # An equal spelling of the version in METADATA is fine.
        response = await self._upload(app_client, content, requires_python=">=2.7")
        assert response.status_code == 200, response.text

        doc = (await app_client.get("/pypi/simple/mdpkg/", headers=JSON)).json()
        assert doc["files"][0]["requires-python"] == ">=3.10"
        html = (await app_client.get("/pypi/simple/mdpkg/")).text
        assert 'data-requires-python="&gt;=3.10"' in html
        api = (await app_client.get("/pypi/mdpkg/json")).json()
        assert api["info"]["requires_python"] == ">=3.10"


# --------------------------------------------------------------------------- #
# Simple API details
# --------------------------------------------------------------------------- #
class TestSimpleApi:
    async def test_normalizing_redirect_keeps_the_query(self, app_client):  # noqa: F811
        response = await app_client.get("/pypi/simple/Foo_Bar/?format=json", follow_redirects=False)
        assert response.status_code == 301
        assert response.headers["location"].endswith("/pypi/simple/foo-bar/?format=json")
        bare = await app_client.get("/pypi/simple/Foo_Bar/", follow_redirects=False)
        assert bare.headers["location"].endswith("/pypi/simple/foo-bar/")

    async def test_redirected_format_query_still_negotiates_json(self, app_client):  # noqa: F811
        assert (await upload_wheel(app_client, "foo-bar", "1.0")).status_code == 200
        response = await app_client.get(
            "/pypi/simple/Foo_Bar/?format=json", follow_redirects=True
        )
        assert response.headers["content-type"].startswith("application/vnd.pypi.simple.v1+json")
        assert response.json()["name"] == "foo-bar"

    async def test_size_falls_back_to_the_cached_blob(self, app_client):  # noqa: F811
        content = build_wheel("sizepkg", "1.0")
        filename = "sizepkg-1.0-py3-none-any.whl"
        response = await upload(
            app_client, "sizepkg", "1.0", filename, content, filetype="bdist_wheel"
        )
        assert response.status_code == 200, response.text
        # A row cached before its size was recorded.
        async with db_module.session_scope() as session:
            await session.execute(update(PackageFile).values(size=None))

        doc = (await app_client.get("/pypi/simple/sizepkg/", headers=JSON)).json()
        assert doc["meta"]["api-version"] == "1.1"
        assert doc["files"][0]["size"] == len(content)
        api = (await app_client.get("/pypi/sizepkg/json")).json()
        assert api["releases"]["1.0"][0]["size"] == len(content)
