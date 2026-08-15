"""npm registry API spec compliance.

Covers the packument formats (full and abbreviated), tarball URL rewriting,
and the publish document grammar.
"""

import base64

import pytest

from app.services.npm_publish import (
    PublishError,
    match_attachment,
    parse_publish_document,
)
from app.services.npm_render import (
    ABBREVIATED_CONTENT_TYPE,
    ABBREVIATED_VERSION_KEYS,
    render_packument,
    render_version_document,
    tarball_url,
    wants_abbreviated,
)

from .conftest import add_file, make_package

PACKAGE_JSON = {
    "name": "lodash",
    "version": "4.17.21",
    "description": "Lodash modular utilities.",
    "main": "lodash.js",
    "license": "MIT",
    "homepage": "https://lodash.com/",
    "keywords": ["modules", "util"],
    "dependencies": {"left-pad": "^1.0.0"},
    "devDependencies": {"mocha": "^8.0.0"},
    "peerDependencies": {},
    "engines": {"node": ">=8"},
    "bin": {"lodash": "./bin/lodash"},
    "cpu": ["x64"],
    "os": ["linux"],
    "funding": {"type": "opencollective", "url": "https://opencollective.com/lodash"},
    "scripts": {"test": "mocha"},
    "_npmUser": {"name": "jdalton"},
    "_nodeVersion": "14.16.0",
    "dist": {
        "shasum": "679591c564c3bffaae8454cf0b3df370c3d6911c",
        "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==",
        "tarball": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
        "fileCount": 1054,
        "unpackedSize": 1412415,
    },
}


class TestAcceptNegotiation:
    def test_install_v1_requests_abbreviated(self):
        assert wants_abbreviated(
            "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*"
        )

    def test_plain_json_requests_full(self):
        assert not wants_abbreviated("application/json")
        assert not wants_abbreviated("*/*")
        assert not wants_abbreviated(None)


class TestAbbreviatedPackument:
    @pytest.fixture
    def doc(self):
        package = make_package(versions=[("4.17.21", PACKAGE_JSON)], dist_tags={"latest": "4.17.21"})
        add_file(
            package.versions[0],
            "lodash-4.17.21.tgz",
            sha1="679591c564c3bffaae8454cf0b3df370c3d6911c",
            integrity=PACKAGE_JSON["dist"]["integrity"],
        )
        return render_packument(package, abbreviated=True)

    def test_has_exactly_four_top_level_keys(self, doc):
        # The abbreviated document is a closed set: name, modified,
        # dist-tags, versions. Anything else breaks npm's expectations.
        assert set(doc) == {"name", "modified", "dist-tags", "versions"}

    def test_version_keys_are_whitelisted(self, doc):
        version = doc["versions"]["4.17.21"]
        assert set(version) <= ABBREVIATED_VERSION_KEYS
        # Fields explicitly not in the whitelist must be gone.
        for dropped in ("description", "main", "license", "homepage", "keywords", "scripts", "_npmUser"):
            assert dropped not in version

    def test_whitelisted_fields_survive(self, doc):
        version = doc["versions"]["4.17.21"]
        for kept in ("name", "version", "dependencies", "devDependencies", "bin", "engines", "dist", "cpu", "os", "funding"):
            assert kept in version, f"{kept} should be preserved"

    def test_dist_tags_present(self, doc):
        assert doc["dist-tags"] == {"latest": "4.17.21"}

    def test_content_type_constant(self):
        assert ABBREVIATED_CONTENT_TYPE == "application/vnd.npm.install-v1+json"


class TestFullPackument:
    @pytest.fixture
    def doc(self):
        package = make_package(versions=[("4.17.21", PACKAGE_JSON)], dist_tags={"latest": "4.17.21"})
        package.description = "Lodash modular utilities."
        add_file(package.versions[0], "lodash-4.17.21.tgz", sha1="abc123")
        return render_packument(package, abbreviated=False)

    def test_required_top_level_fields(self, doc):
        for field in ("_id", "_rev", "name", "dist-tags", "versions", "time"):
            assert field in doc, f"full packument must include {field}"

    def test_id_is_the_package_name(self, doc):
        assert doc["_id"] == "lodash"

    def test_hoists_latest_version_fields(self, doc):
        # description/homepage/license/keywords are hoisted from `latest`.
        assert doc["description"] == "Lodash modular utilities."
        assert doc["license"] == "MIT"
        assert doc["homepage"] == "https://lodash.com/"
        assert doc["keywords"] == ["modules", "util"]

    def test_time_has_created_and_modified(self, doc):
        assert "created" in doc["time"]
        assert "modified" in doc["time"]
        assert "4.17.21" in doc["time"]

    def test_time_uses_iso_millisecond_z_format(self, doc):
        # npm's format: 2024-03-01T12:00:00.000Z
        stamp = doc["time"]["4.17.21"]
        assert stamp.endswith("Z")
        assert len(stamp) == len("2024-03-01T12:00:00.000Z")

    def test_full_version_keeps_non_whitelisted_fields(self, doc):
        version = doc["versions"]["4.17.21"]
        assert version["description"] == "Lodash modular utilities."
        assert version["main"] == "lodash.js"
        assert version["_id"] == "lodash@4.17.21"


class TestTarballRewriting:
    def test_url_points_at_this_registry(self):
        assert (
            tarball_url("lodash", "4.17.21")
            == "http://registry.test/npm/lodash/-/lodash-4.17.21.tgz"
        )

    def test_scoped_package_strips_scope_from_filename(self):
        # npm names the tarball without the scope but keeps it in the path.
        assert (
            tarball_url("@babel/core", "7.24.0")
            == "http://registry.test/npm/%40babel/core/-/core-7.24.0.tgz"
        )

    def test_packument_rewrites_upstream_tarball(self):
        package = make_package(versions=[("4.17.21", PACKAGE_JSON)], dist_tags={"latest": "4.17.21"})
        add_file(package.versions[0], "lodash-4.17.21.tgz", sha1="deadbeef")
        doc = render_packument(package, abbreviated=True)
        dist = doc["versions"]["4.17.21"]["dist"]
        assert dist["tarball"].startswith("http://registry.test/npm/")
        assert "registry.npmjs.org" not in dist["tarball"]

    def test_preserves_dist_passthrough_fields(self):
        package = make_package(versions=[("4.17.21", PACKAGE_JSON)], dist_tags={"latest": "4.17.21"})
        add_file(package.versions[0], "lodash-4.17.21.tgz", sha1="deadbeef")
        dist = render_packument(package, abbreviated=True)["versions"]["4.17.21"]["dist"]
        # fileCount/unpackedSize are not ours to invent or drop.
        assert dist["fileCount"] == 1054
        assert dist["unpackedSize"] == 1412415

    def test_uses_local_digests_over_upstream(self):
        package = make_package(versions=[("4.17.21", PACKAGE_JSON)], dist_tags={"latest": "4.17.21"})
        add_file(package.versions[0], "lodash-4.17.21.tgz", sha1="locally-computed-sha1")
        dist = render_packument(package, abbreviated=True)["versions"]["4.17.21"]["dist"]
        assert dist["shasum"] == "locally-computed-sha1"


class TestVersionDocument:
    def test_returns_bare_version_object(self):
        package = make_package(versions=[("4.17.21", PACKAGE_JSON)], dist_tags={"latest": "4.17.21"})
        add_file(package.versions[0], "lodash-4.17.21.tgz", sha1="abc")
        doc = render_version_document(package, package.versions[0])
        # Not a packument: no versions map, no dist-tags.
        assert "versions" not in doc
        assert "dist-tags" not in doc
        assert doc["name"] == "lodash"
        assert doc["version"] == "4.17.21"
        assert doc["_id"] == "lodash@4.17.21"


class TestLatestDerivation:
    def test_latest_falls_back_to_highest_semver(self):
        package = make_package(
            versions=[("1.0.0", {}), ("2.0.0", {}), ("1.5.0", {})], dist_tags=None
        )
        doc = render_packument(package, abbreviated=True)
        assert doc["dist-tags"]["latest"] == "2.0.0"

    def test_explicit_latest_tag_wins(self):
        package = make_package(
            versions=[("1.0.0", {}), ("2.0.0", {})], dist_tags={"latest": "1.0.0"}
        )
        doc = render_packument(package, abbreviated=True)
        assert doc["dist-tags"]["latest"] == "1.0.0"


# --------------------------------------------------------------------------- #
# Publish
# --------------------------------------------------------------------------- #
def make_publish_doc(name="my-pkg", version="1.0.0", tarball=b"fake-tarball-bytes", **overrides):
    doc = {
        "_id": name,
        "name": name,
        "description": "a package",
        "dist-tags": {"latest": version},
        "versions": {
            version: {
                "name": name,
                "version": version,
                "dist": {"shasum": "abc", "tarball": f"http://x/{name}/-/{name}-{version}.tgz"},
            }
        },
        "_attachments": {
            f"{name}-{version}.tgz": {
                "content_type": "application/octet-stream",
                "data": base64.b64encode(tarball).decode(),
                "length": len(tarball),
            }
        },
        "access": None,
    }
    doc.update(overrides)
    return doc


class TestPublishDocumentParsing:
    def test_parses_a_normal_publish(self):
        parsed = parse_publish_document(make_publish_doc(), "my-pkg")
        assert parsed.name == "my-pkg"
        assert parsed.intent == "publish"
        assert list(parsed.versions) == ["1.0.0"]
        assert parsed.dist_tags == {"latest": "1.0.0"}
        assert parsed.attachments["my-pkg-1.0.0.tgz"].data == b"fake-tarball-bytes"

    def test_scoped_package(self):
        doc = make_publish_doc(name="@scope/pkg")
        # npm names the attachment without the scope.
        doc["_attachments"] = {
            "pkg-1.0.0.tgz": doc["_attachments"].pop("@scope/pkg-1.0.0.tgz")
        }
        parsed = parse_publish_document(doc, "@scope/pkg")
        assert parsed.name == "@scope/pkg"
        assert match_attachment(parsed, "1.0.0") is not None

    def test_rejects_name_path_mismatch(self):
        with pytest.raises(PublishError, match="does not match the request path"):
            parse_publish_document(make_publish_doc(name="a"), "b")

    def test_rejects_invalid_package_name(self):
        with pytest.raises(PublishError, match="invalid package name"):
            parse_publish_document(make_publish_doc(name="Uppercase"), "Uppercase")

    def test_rejects_invalid_semver(self):
        with pytest.raises(PublishError, match="not a valid semver"):
            parse_publish_document(make_publish_doc(version="1.0"), "my-pkg")

    def test_rejects_version_key_metadata_mismatch(self):
        doc = make_publish_doc()
        doc["versions"]["1.0.0"]["version"] = "2.0.0"
        with pytest.raises(PublishError, match="does not match its metadata version"):
            parse_publish_document(doc, "my-pkg")

    def test_rejects_semver_shaped_dist_tag(self):
        # npm forbids this: `pkg@1.0.0` would become ambiguous.
        doc = make_publish_doc()
        doc["dist-tags"]["1.2.3"] = "1.0.0"
        with pytest.raises(PublishError, match="must not be a valid semver"):
            parse_publish_document(doc, "my-pkg")

    def test_rejects_bad_base64(self):
        doc = make_publish_doc()
        doc["_attachments"]["my-pkg-1.0.0.tgz"]["data"] = "not!valid!base64!"
        with pytest.raises(PublishError, match="not valid base64"):
            parse_publish_document(doc, "my-pkg")

    def test_rejects_length_mismatch(self):
        doc = make_publish_doc()
        doc["_attachments"]["my-pkg-1.0.0.tgz"]["length"] = 99999
        with pytest.raises(PublishError, match="length mismatch"):
            parse_publish_document(doc, "my-pkg")

    def test_rejects_non_object_body(self):
        with pytest.raises(PublishError, match="must be a JSON object"):
            parse_publish_document([1, 2, 3], "my-pkg")


class TestPublishIntentDetection:
    def test_attachment_means_publish(self):
        assert parse_publish_document(make_publish_doc(), "my-pkg").intent == "publish"

    def test_versions_without_attachment_means_deprecate(self):
        doc = make_publish_doc()
        doc["_attachments"] = {}
        doc["versions"]["1.0.0"]["deprecated"] = "use v2 instead"
        parsed = parse_publish_document(doc, "my-pkg")
        assert parsed.intent == "deprecate"
        assert parsed.deprecations == {"1.0.0": "use v2 instead"}

    def test_empty_document_means_unpublish(self):
        doc = {"_id": "my-pkg", "name": "my-pkg", "versions": {}, "_attachments": {}}
        assert parse_publish_document(doc, "my-pkg").intent == "unpublish"


class TestAttachmentMatching:
    def test_matches_by_conventional_name(self):
        parsed = parse_publish_document(make_publish_doc(), "my-pkg")
        assert match_attachment(parsed, "1.0.0").filename == "my-pkg-1.0.0.tgz"

    def test_matches_by_dist_tarball_basename(self):
        doc = make_publish_doc()
        payload = doc["_attachments"].pop("my-pkg-1.0.0.tgz")
        doc["_attachments"]["oddly-named.tgz"] = payload
        doc["versions"]["1.0.0"]["dist"]["tarball"] = "http://x/my-pkg/-/oddly-named.tgz"
        parsed = parse_publish_document(doc, "my-pkg")
        assert match_attachment(parsed, "1.0.0").filename == "oddly-named.tgz"

    def test_no_match_returns_none(self):
        doc = make_publish_doc()
        doc["_attachments"] = {
            "a-9.9.9.tgz": doc["_attachments"].pop("my-pkg-1.0.0.tgz"),
            "b-9.9.9.tgz": {"data": base64.b64encode(b"x").decode(), "length": 1},
        }
        parsed = parse_publish_document(doc, "my-pkg")
        assert match_attachment(parsed, "1.0.0") is None


class TestScopedPathSplitting:
    @pytest.mark.parametrize(
        "path,name,version",
        [
            ("lodash", "lodash", None),
            ("lodash/4.17.21", "lodash", "4.17.21"),
            ("lodash/latest", "lodash", "latest"),
            ("@babel/core", "@babel/core", None),
            ("@babel%2fcore", "@babel/core", None),
            ("@babel%2Fcore", "@babel/core", None),
            ("@babel/core/7.24.0", "@babel/core", "7.24.0"),
        ],
    )
    def test_splits_correctly(self, path, name, version):
        from app.api.npm import split_package_path

        assert split_package_path(path) == (name, version)

    @pytest.mark.parametrize("path", ["", "/", "@scope", "a/b/c/d"])
    def test_rejects_unparseable(self, path):
        from app.api.npm import split_package_path

        assert split_package_path(path) is None
