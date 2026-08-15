"""Upstream provider parsing and tiered routing."""

import httpx
import pytest
import respx

from app.models import Ecosystem, Upstream, UpstreamKind
from app.upstreams.base import UpstreamNotFound
from app.upstreams.gitlab_provider import GitLabNpmProvider, GitLabPyPIProvider
from app.upstreams.npm_provider import NpmProvider
from app.upstreams.pypi_provider import PyPIProvider


def make_upstream(**kwargs):
    defaults = {
        "id": 1,
        "name": "test-upstream",
        "ecosystem": Ecosystem.npm,
        "kind": UpstreamKind.npm,
        "url": "https://registry.example.com",
        "tier": 1,
        "priority": 100,
        "enabled": True,
        "auth_type": "none",
        "credential_enc": None,
        "timeout_seconds": 5.0,
        "verify_ssl": True,
        "healthy": True,
        "consecutive_failures": 0,
        "gitlab_project_id": None,
        "gitlab_group_id": None,
        "auth_header_name": None,
    }
    defaults.update(kwargs)
    return Upstream(**defaults)


PACKUMENT = {
    "_id": "lodash",
    "name": "lodash",
    "description": "Lodash modular utilities.",
    "dist-tags": {"latest": "4.17.21", "beta": "5.0.0-beta.1"},
    "time": {
        "created": "2011-04-24T18:12:20.808Z",
        "4.17.21": "2021-02-20T15:42:16.891Z",
    },
    "versions": {
        "4.17.21": {
            "name": "lodash",
            "version": "4.17.21",
            "description": "Lodash modular utilities.",
            "license": "MIT",
            "dependencies": {},
            "dist": {
                "shasum": "679591c564c3bffaae8454cf0b3df370c3d6911c",
                "integrity": "sha512-abc==",
                "tarball": "https://registry.example.com/lodash/-/lodash-4.17.21.tgz",
            },
        }
    },
}


class TestNpmProvider:
    @respx.mock
    async def test_parses_packument(self):
        respx.get("https://registry.example.com/lodash").mock(
            return_value=httpx.Response(200, json=PACKUMENT)
        )
        package = await NpmProvider(make_upstream()).fetch_package("lodash")

        assert package.name == "lodash"
        assert package.description == "Lodash modular utilities."
        assert package.dist_tags == {"latest": "4.17.21", "beta": "5.0.0-beta.1"}
        assert len(package.versions) == 1
        assert package.versions[0].version == "4.17.21"
        # The raw packument is preserved for 1:1 re-serving.
        assert package.raw == PACKUMENT

    @respx.mock
    async def test_extracts_tarball_and_digests(self):
        respx.get("https://registry.example.com/lodash").mock(
            return_value=httpx.Response(200, json=PACKUMENT)
        )
        package = await NpmProvider(make_upstream()).fetch_package("lodash")
        file = package.versions[0].files[0]
        assert file.filename == "lodash-4.17.21.tgz"
        assert file.hashes["sha1"] == "679591c564c3bffaae8454cf0b3df370c3d6911c"
        assert file.hashes["integrity"] == "sha512-abc=="

    @respx.mock
    async def test_404_raises_not_found(self):
        respx.get("https://registry.example.com/nope").mock(return_value=httpx.Response(404))
        with pytest.raises(UpstreamNotFound):
            await NpmProvider(make_upstream()).fetch_package("nope")

    @respx.mock
    async def test_scoped_name_is_url_encoded(self):
        route = respx.get("https://registry.example.com/@babel%2fcore").mock(
            return_value=httpx.Response(200, json={**PACKUMENT, "name": "@babel/core"})
        )
        await NpmProvider(make_upstream()).fetch_package("@babel/core")
        assert route.called

    @respx.mock
    async def test_search(self):
        respx.get("https://registry.example.com/-/v1/search").mock(
            return_value=httpx.Response(
                200,
                json={
                    "objects": [
                        {
                            "package": {
                                "name": "lodash",
                                "version": "4.17.21",
                                "description": "utilities",
                                "keywords": ["util"],
                            },
                            "searchScore": 0.99,
                        }
                    ],
                    "total": 1,
                },
            )
        )
        hits = await NpmProvider(make_upstream()).search("lodash")
        assert len(hits) == 1
        assert hits[0].name == "lodash"
        assert hits[0].score == pytest.approx(0.99)


PYPI_JSON = {
    "meta": {"api-version": "1.1"},
    "name": "requests",
    "versions": ["2.31.0"],
    "files": [
        {
            "filename": "requests-2.31.0-py3-none-any.whl",
            "url": "https://files.example.com/requests-2.31.0-py3-none-any.whl",
            "hashes": {"sha256": "a" * 64},
            "size": 62574,
            "requires-python": ">=3.7",
            "upload-time": "2023-05-22T15:12:44.000000Z",
            "core-metadata": {"sha256": "b" * 64},
        },
        {
            "filename": "requests-2.31.0.tar.gz",
            "url": "https://files.example.com/requests-2.31.0.tar.gz",
            "hashes": {"sha256": "c" * 64},
            "size": 110794,
            "yanked": "broken sdist",
        },
    ],
}

PYPI_HTML = """<!DOCTYPE html>
<html><head><meta name="pypi:repository-version" content="1.0"></head><body>
<a href="https://files.example.com/requests-2.31.0-py3-none-any.whl#sha256=aaaa"
   data-requires-python="&gt;=3.7"
   data-core-metadata="sha256=bbbb">requests-2.31.0-py3-none-any.whl</a><br>
<a href="https://files.example.com/requests-2.31.0.tar.gz#sha256=cccc"
   data-yanked="broken sdist">requests-2.31.0.tar.gz</a><br>
</body></html>
"""


def pypi_upstream(**kwargs):
    return make_upstream(
        ecosystem=Ecosystem.pypi,
        kind=UpstreamKind.pypi,
        url="https://pypi.example.com/simple",
        **kwargs,
    )


class TestPyPIProviderJson:
    @respx.mock
    async def test_parses_json_simple_api(self):
        respx.get("https://pypi.example.com/simple/requests/").mock(
            return_value=httpx.Response(
                200,
                json=PYPI_JSON,
                headers={"content-type": "application/vnd.pypi.simple.v1+json"},
            )
        )
        package = await PyPIProvider(pypi_upstream()).fetch_package("requests")
        assert len(package.versions) == 1
        version = package.versions[0]
        assert version.version == "2.31.0"
        assert len(version.files) == 2

    @respx.mock
    async def test_reads_size_and_requires_python(self):
        respx.get("https://pypi.example.com/simple/requests/").mock(
            return_value=httpx.Response(
                200,
                json=PYPI_JSON,
                headers={"content-type": "application/vnd.pypi.simple.v1+json"},
            )
        )
        package = await PyPIProvider(pypi_upstream()).fetch_package("requests")
        wheel = next(
            f for f in package.versions[0].files if f.filename.endswith(".whl")
        )
        assert wheel.size == 62574
        assert wheel.requires_python == ">=3.7"
        assert wheel.packagetype == "bdist_wheel"
        assert wheel.python_version == "py3"
        assert wheel.core_metadata == {"sha256": "b" * 64}
        assert wheel.upload_time is not None

    @respx.mock
    async def test_yanked_reason_is_preserved(self):
        respx.get("https://pypi.example.com/simple/requests/").mock(
            return_value=httpx.Response(
                200,
                json=PYPI_JSON,
                headers={"content-type": "application/vnd.pypi.simple.v1+json"},
            )
        )
        package = await PyPIProvider(pypi_upstream()).fetch_package("requests")
        sdist = next(f for f in package.versions[0].files if f.filename.endswith(".tar.gz"))
        assert sdist.yanked == "broken sdist"

    @respx.mock
    async def test_url_is_normalized_per_pep503(self):
        route = respx.get("https://pypi.example.com/simple/zope-interface/").mock(
            return_value=httpx.Response(
                200,
                json={"meta": {"api-version": "1.0"}, "name": "zope-interface", "files": []},
                headers={"content-type": "application/vnd.pypi.simple.v1+json"},
            )
        )
        # "Zope.Interface" must be requested as "zope-interface".
        await PyPIProvider(pypi_upstream()).fetch_package("Zope.Interface")
        assert route.called


class TestPyPIProviderHtml:
    @respx.mock
    async def test_parses_html_fallback(self):
        respx.get("https://pypi.example.com/simple/requests/").mock(
            return_value=httpx.Response(200, text=PYPI_HTML, headers={"content-type": "text/html"})
        )
        package = await PyPIProvider(pypi_upstream()).fetch_package("requests")
        assert len(package.versions) == 1
        assert len(package.versions[0].files) == 2

    @respx.mock
    async def test_reads_digest_from_url_fragment(self):
        respx.get("https://pypi.example.com/simple/requests/").mock(
            return_value=httpx.Response(200, text=PYPI_HTML, headers={"content-type": "text/html"})
        )
        package = await PyPIProvider(pypi_upstream()).fetch_package("requests")
        wheel = next(f for f in package.versions[0].files if f.filename.endswith(".whl"))
        assert wheel.hashes["sha256"] == "aaaa"
        # The fragment is stripped from the URL we will fetch.
        assert "#" not in wheel.url

    @respx.mock
    async def test_unescapes_requires_python_attribute(self):
        respx.get("https://pypi.example.com/simple/requests/").mock(
            return_value=httpx.Response(200, text=PYPI_HTML, headers={"content-type": "text/html"})
        )
        package = await PyPIProvider(pypi_upstream()).fetch_package("requests")
        wheel = next(f for f in package.versions[0].files if f.filename.endswith(".whl"))
        assert wheel.requires_python == ">=3.7"

    @respx.mock
    async def test_data_yanked_with_reason(self):
        respx.get("https://pypi.example.com/simple/requests/").mock(
            return_value=httpx.Response(200, text=PYPI_HTML, headers={"content-type": "text/html"})
        )
        package = await PyPIProvider(pypi_upstream()).fetch_package("requests")
        sdist = next(f for f in package.versions[0].files if f.filename.endswith(".tar.gz"))
        assert sdist.yanked == "broken sdist"

    @respx.mock
    async def test_data_yanked_empty_means_yanked(self):
        html = (
            '<html><body><a href="https://f.example.com/x-1.0.tar.gz#sha256=dd" '
            'data-yanked="">x-1.0.tar.gz</a></body></html>'
        )
        respx.get("https://pypi.example.com/simple/x/").mock(
            return_value=httpx.Response(200, text=html, headers={"content-type": "text/html"})
        )
        package = await PyPIProvider(pypi_upstream()).fetch_package("x")
        assert package.versions[0].files[0].yanked is True

    @respx.mock
    async def test_deprecated_dist_info_metadata_attribute_accepted(self):
        html = (
            '<html><body><a href="https://f.example.com/x-1.0-py3-none-any.whl" '
            'data-dist-info-metadata="sha256=ee">x-1.0-py3-none-any.whl</a></body></html>'
        )
        respx.get("https://pypi.example.com/simple/x/").mock(
            return_value=httpx.Response(200, text=html, headers={"content-type": "text/html"})
        )
        package = await PyPIProvider(pypi_upstream()).fetch_package("x")
        assert package.versions[0].files[0].core_metadata == {"sha256": "ee"}

    @respx.mock
    async def test_relative_urls_are_resolved(self):
        html = (
            '<html><body><a href="../../packages/x-1.0.tar.gz#sha256=ff">'
            "x-1.0.tar.gz</a></body></html>"
        )
        respx.get("https://pypi.example.com/simple/x/").mock(
            return_value=httpx.Response(200, text=html, headers={"content-type": "text/html"})
        )
        package = await PyPIProvider(pypi_upstream()).fetch_package("x")
        assert package.versions[0].files[0].url == "https://pypi.example.com/packages/x-1.0.tar.gz"


class TestGitLabProviders:
    def test_npm_url_construction_project_scope(self):
        upstream = make_upstream(
            kind=UpstreamKind.gitlab_npm,
            url="https://gitlab.example.com",
            gitlab_project_id="42",
        )
        provider = GitLabNpmProvider(upstream)
        assert (
            provider.package_url("@scope/pkg")
            == "https://gitlab.example.com/api/v4/projects/42/packages/npm/@scope%2fpkg"
        )

    def test_npm_url_construction_group_scope(self):
        upstream = make_upstream(
            kind=UpstreamKind.gitlab_npm,
            url="https://gitlab.example.com",
            gitlab_group_id="7",
        )
        assert (
            GitLabNpmProvider(upstream).package_url("lodash")
            == "https://gitlab.example.com/api/v4/groups/7/-/packages/npm/lodash"
        )

    def test_npm_url_instance_scope(self):
        upstream = make_upstream(kind=UpstreamKind.gitlab_npm, url="https://gitlab.example.com")
        assert (
            GitLabNpmProvider(upstream).package_url("lodash")
            == "https://gitlab.example.com/api/v4/packages/npm/lodash"
        )

    def test_api_root_is_not_doubled(self):
        upstream = make_upstream(
            kind=UpstreamKind.gitlab_npm,
            url="https://gitlab.example.com/api/v4",
            gitlab_project_id="42",
        )
        assert GitLabNpmProvider(upstream).api_root == "https://gitlab.example.com/api/v4"

    def test_pypi_url_uses_normalized_name(self):
        upstream = make_upstream(
            ecosystem=Ecosystem.pypi,
            kind=UpstreamKind.gitlab_pypi,
            url="https://gitlab.example.com",
            gitlab_project_id="42",
        )
        assert GitLabPyPIProvider(upstream).project_url("My.Package") == (
            "https://gitlab.example.com/api/v4/projects/42/packages/pypi/simple/my-package/"
        )

    def test_default_auth_header_is_private_token(self):
        from app.core.security import encrypt_credential

        upstream = make_upstream(
            kind=UpstreamKind.gitlab_npm,
            url="https://gitlab.example.com",
            auth_type="token_header",
            credential_enc=encrypt_credential("glpat-secret"),
        )
        assert GitLabNpmProvider(upstream).auth_headers() == {"PRIVATE-TOKEN": "glpat-secret"}

    def test_job_token_header(self):
        from app.core.security import encrypt_credential

        upstream = make_upstream(
            kind=UpstreamKind.gitlab_npm,
            url="https://gitlab.example.com",
            auth_type="job_token",
            credential_enc=encrypt_credential("ci-job-token"),
        )
        assert GitLabNpmProvider(upstream).auth_headers() == {"JOB-TOKEN": "ci-job-token"}

    @respx.mock
    async def test_npm_publish_forwards_document(self):
        route = respx.put(
            "https://gitlab.example.com/api/v4/projects/42/packages/npm/my-pkg"
        ).mock(return_value=httpx.Response(200, json={"ok": True}))
        upstream = make_upstream(
            kind=UpstreamKind.gitlab_npm,
            url="https://gitlab.example.com",
            gitlab_project_id="42",
            allow_publish=True,
        )
        ok, message = await GitLabNpmProvider(upstream).publish({"name": "my-pkg"}, "npm")
        assert ok is True
        assert route.called

    @respx.mock
    async def test_npm_publish_reports_conflict(self):
        respx.put("https://gitlab.example.com/api/v4/projects/42/packages/npm/my-pkg").mock(
            return_value=httpx.Response(409)
        )
        upstream = make_upstream(
            kind=UpstreamKind.gitlab_npm,
            url="https://gitlab.example.com",
            gitlab_project_id="42",
        )
        ok, message = await GitLabNpmProvider(upstream).publish({"name": "my-pkg"}, "npm")
        assert ok is False
        assert "already exists" in message

    async def test_publish_without_project_id_is_rejected(self):
        upstream = make_upstream(kind=UpstreamKind.gitlab_npm, url="https://gitlab.example.com")
        ok, message = await GitLabNpmProvider(upstream).publish({"name": "x"}, "npm")
        assert ok is False
        assert "project id" in message


class TestAuthHeaders:
    def test_bearer(self):
        from app.core.security import encrypt_credential

        upstream = make_upstream(auth_type="bearer", credential_enc=encrypt_credential("tok"))
        assert NpmProvider(upstream).auth_headers() == {"authorization": "Bearer tok"}

    def test_basic(self):
        import base64

        from app.core.security import encrypt_credential

        upstream = make_upstream(auth_type="basic", credential_enc=encrypt_credential("u:p"))
        expected = base64.b64encode(b"u:p").decode()
        assert NpmProvider(upstream).auth_headers() == {"authorization": f"Basic {expected}"}

    def test_none(self):
        assert NpmProvider(make_upstream()).auth_headers() == {}

    def test_credentials_are_encrypted_at_rest(self):
        from app.core.security import decrypt_credential, encrypt_credential

        ciphertext = encrypt_credential("super-secret")
        assert ciphertext is not None
        assert "super-secret" not in ciphertext
        assert decrypt_credential(ciphertext) == "super-secret"


class TestTierGrouping:
    def test_groups_ascending(self):
        from app.services.resolver import group_by_tier

        upstreams = [
            make_upstream(id=1, name="a", tier=2),
            make_upstream(id=2, name="b", tier=1),
            make_upstream(id=3, name="c", tier=1),
            make_upstream(id=4, name="d", tier=3),
        ]
        grouped = group_by_tier(upstreams)
        assert [tier for tier, _ in grouped] == [1, 2, 3]
        assert {u.name for u in grouped[0][1]} == {"b", "c"}

    def test_quarantine_after_repeated_failures(self):
        from datetime import UTC, datetime, timedelta

        from app.services.resolver import FAILURE_THRESHOLD, is_quarantined

        healthy = make_upstream(healthy=True, consecutive_failures=0)
        assert not is_quarantined(healthy)

        failing = make_upstream(
            healthy=False,
            consecutive_failures=FAILURE_THRESHOLD,
            last_check_at=datetime.now(UTC),
        )
        assert is_quarantined(failing)

        # After the probe interval it is retried, so recovery is automatic.
        stale = make_upstream(
            healthy=False,
            consecutive_failures=FAILURE_THRESHOLD,
            last_check_at=datetime.now(UTC) - timedelta(hours=1),
        )
        assert not is_quarantined(stale)
