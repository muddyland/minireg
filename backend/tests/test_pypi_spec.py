"""PyPI Simple API spec compliance.

PEP 503 (HTML), PEP 592 (yanked), PEP 629 (repository version), PEP 691 (JSON),
PEP 700 (versions/size/upload-time), PEP 714 (core-metadata), and the legacy
upload endpoint's validation rules.
"""

import io
import re
import zipfile
from datetime import UTC, datetime

import pytest

from app.models import Ecosystem
from app.services.pypi_publish import (
    UploadError,
    extract_wheel_metadata,
    parse_upload,
    verify_digests,
)
from app.services.pypi_render import (
    API_VERSION,
    HTML_CONTENT_TYPE,
    JSON_CONTENT_TYPE,
    file_url,
    render_index_html,
    render_index_json,
    render_project_html,
    render_project_json,
    select_content_type,
)

from .conftest import add_file, make_package


def make_pypi_package(name="my-package", files=None):
    package = make_package(
        name=name,
        ecosystem=Ecosystem.pypi,
        versions=[("1.0.0", {}), ("2.0.0", {})],
    )
    package.normalized_name = "my-package"
    defaults = [
        (0, "my_package-1.0.0-py3-none-any.whl", {"packagetype": "bdist_wheel"}),
        (0, "my_package-1.0.0.tar.gz", {"packagetype": "sdist"}),
        (1, "my_package-2.0.0-py3-none-any.whl", {"packagetype": "bdist_wheel"}),
    ]
    for index, filename, extra in files if files is not None else defaults:
        add_file(
            package.versions[index],
            filename,
            sha256="a" * 64,
            size=1024,
            upload_time=datetime(2024, 3, 1, 12, 0, 0, tzinfo=UTC),
            **extra,
        )
    return package


class TestContentNegotiation:
    """PEP 691 section: Content-Types."""

    def test_json_content_type_string(self):
        assert JSON_CONTENT_TYPE == "application/vnd.pypi.simple.v1+json"

    def test_html_content_type_string(self):
        assert HTML_CONTENT_TYPE == "application/vnd.pypi.simple.v1+html"

    @pytest.mark.parametrize(
        "accept,expected",
        [
            ("application/vnd.pypi.simple.v1+json", JSON_CONTENT_TYPE),
            ("application/vnd.pypi.simple.latest+json", JSON_CONTENT_TYPE),
            ("application/vnd.pypi.simple.v1+html", HTML_CONTENT_TYPE),
            ("text/html", HTML_CONTENT_TYPE),
            ("*/*", HTML_CONTENT_TYPE),
            (None, HTML_CONTENT_TYPE),
        ],
    )
    def test_accept_header(self, accept, expected):
        assert select_content_type(accept) == expected

    def test_q_values_are_honoured(self):
        # JSON has the higher q, so it wins despite coming second.
        accept = "text/html;q=0.2, application/vnd.pypi.simple.v1+json;q=0.9"
        assert select_content_type(accept) == JSON_CONTENT_TYPE

    def test_format_parameter_overrides_accept(self):
        assert select_content_type("text/html", "application/vnd.pypi.simple.v1+json") == (
            JSON_CONTENT_TYPE
        )
        assert select_content_type("application/vnd.pypi.simple.v1+json", "html") == (
            HTML_CONTENT_TYPE
        )


class TestJsonProjectPage:
    """PEP 691 + PEP 700."""

    @pytest.fixture
    def doc(self):
        return render_project_json(make_pypi_package())

    def test_meta_api_version(self, doc):
        # PEP 700 requires >= 1.1 for the versions key we emit.
        assert doc["meta"]["api-version"] == API_VERSION
        assert tuple(int(p) for p in API_VERSION.split(".")) >= (1, 1)

    def test_name_is_normalized(self, doc):
        assert doc["name"] == "my-package"

    def test_required_file_keys(self, doc):
        for entry in doc["files"]:
            # PEP 691: filename, url, hashes are required.
            assert "filename" in entry
            assert "url" in entry
            assert "hashes" in entry
            assert isinstance(entry["hashes"], dict)
            # PEP 700: size is required.
            assert "size" in entry
            assert isinstance(entry["size"], int)

    def test_versions_key_present_and_sorted(self, doc):
        # PEP 700 mandatory `versions`, logically a set.
        assert doc["versions"] == ["1.0.0", "2.0.0"]
        assert len(doc["versions"]) == len(set(doc["versions"]))

    def test_upload_time_format(self, doc):
        # PEP 700: yyyy-mm-ddThh:mm:ssZ
        for entry in doc["files"]:
            assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", entry["upload-time"])

    def test_urls_point_at_this_registry(self, doc):
        for entry in doc["files"]:
            assert entry["url"].startswith("http://registry.test/pypi/files/")

    def test_yanked_absent_when_not_yanked(self, doc):
        for entry in doc["files"]:
            assert "yanked" not in entry


class TestPep592Yanked:
    def test_yanked_true_without_reason(self):
        package = make_pypi_package()
        package.versions[0].files[0].yanked = True
        entry = render_project_json(package)["files"][0]
        assert entry["yanked"] is True

    def test_yanked_string_when_reason_given(self):
        package = make_pypi_package()
        package.versions[0].files[0].yanked = True
        package.versions[0].files[0].yanked_reason = "security issue"
        entry = render_project_json(package)["files"][0]
        assert entry["yanked"] == "security issue"

    def test_html_data_yanked_empty_attribute(self):
        package = make_pypi_package()
        package.versions[0].files[0].yanked = True
        html = render_project_html(package)
        assert 'data-yanked=""' in html

    def test_html_data_yanked_carries_reason(self):
        package = make_pypi_package()
        package.versions[0].files[0].yanked = True
        package.versions[0].files[0].yanked_reason = "broken build"
        assert 'data-yanked="broken build"' in render_project_html(package)


class TestPep714CoreMetadata:
    def test_json_emits_both_keys(self):
        package = make_pypi_package()
        package.versions[0].files[0].core_metadata = {"sha256": "b" * 64}
        entry = render_project_json(package)["files"][0]
        # PEP 714: emit core-metadata, keep dist-info-metadata for old clients.
        assert entry["core-metadata"] == {"sha256": "b" * 64}
        assert entry["dist-info-metadata"] == {"sha256": "b" * 64}

    def test_json_boolean_form(self):
        package = make_pypi_package()
        package.versions[0].files[0].core_metadata = {"available": True}
        entry = render_project_json(package)["files"][0]
        assert entry["core-metadata"] is True

    def test_html_emits_both_attributes(self):
        package = make_pypi_package()
        package.versions[0].files[0].core_metadata = {"sha256": "b" * 64}
        html = render_project_html(package)
        assert f'data-core-metadata="sha256={"b" * 64}"' in html
        assert f'data-dist-info-metadata="sha256={"b" * 64}"' in html

    def test_absent_when_unavailable(self):
        entry = render_project_json(make_pypi_package())["files"][0]
        assert "core-metadata" not in entry
        assert "dist-info-metadata" not in entry


class TestPep503Html:
    @pytest.fixture
    def html(self):
        return render_project_html(make_pypi_package())

    def test_pep629_repository_version_meta_tag(self, html):
        assert f'<meta name="pypi:repository-version" content="{API_VERSION}">' in html

    def test_digest_is_in_url_fragment(self, html):
        # PEP 503: <a href="...#sha256=...">
        assert f'#sha256={"a" * 64}' in html

    def test_anchor_text_is_the_filename(self, html):
        assert ">my_package-1.0.0-py3-none-any.whl</a>" in html

    def test_requires_python_is_html_escaped(self):
        package = make_pypi_package()
        package.versions[0].files[0].requires_python = ">=3.8,<4.0"
        html = render_project_html(package)
        # PEP 503 requires escaping; a raw > would break the tag.
        assert "data-requires-python=\"&gt;=3.8,&lt;4.0\"" in html
        assert 'data-requires-python=">=3.8' not in html

    def test_index_lists_normalized_names(self):
        html = render_index_html(["Foo.Bar", "zope.interface"])
        assert '<a href="foo-bar/">foo-bar</a>' in html
        assert '<a href="zope-interface/">zope-interface</a>' in html


class TestJsonIndex:
    def test_shape(self):
        doc = render_index_json(["Foo.Bar", "requests"])
        assert doc["meta"]["api-version"] == API_VERSION
        assert doc["projects"] == [{"name": "foo-bar"}, {"name": "requests"}]


class TestFileUrls:
    def test_uses_normalized_project_name(self):
        assert (
            file_url("Foo.Bar", "foo_bar-1.0.tar.gz")
            == "http://registry.test/pypi/files/foo-bar/foo_bar-1.0.tar.gz"
        )


# --------------------------------------------------------------------------- #
# Upload
# --------------------------------------------------------------------------- #
def make_form(**overrides):
    form = {
        ":action": "file_upload",
        "protocol_version": "1",
        "name": "my-package",
        "version": "1.0.0",
        "filetype": "bdist_wheel",
        "pyversion": "py3",
        "metadata_version": "2.1",
        "summary": "A package",
        "md5_digest": "",
        "sha256_digest": "",
        "blake2_256_digest": "",
    }
    form.update(overrides)
    return {k: v for k, v in form.items() if v != ""}


class TestUploadValidation:
    def test_accepts_a_valid_wheel_upload(self):
        parsed = parse_upload(
            make_form(), "my_package-1.0.0-py3-none-any.whl", b"data", "application/octet-stream"
        )
        assert parsed.name == "my-package"
        assert parsed.version == "1.0.0"
        assert parsed.filetype == "bdist_wheel"
        assert parsed.normalized_name == "my-package"

    def test_accepts_an_sdist(self):
        parsed = parse_upload(
            make_form(filetype="sdist"), "my_package-1.0.0.tar.gz", b"data", "application/gzip"
        )
        assert parsed.filetype == "sdist"
        assert parsed.pyversion == "py3"

    def test_infers_filetype_from_filename(self):
        form = make_form()
        del form["filetype"]
        parsed = parse_upload(form, "my_package-1.0.0.tar.gz", b"data", "x")
        assert parsed.filetype == "sdist"

    def test_rejects_missing_name(self):
        form = make_form()
        del form["name"]
        with pytest.raises(UploadError, match="'name' is required"):
            parse_upload(form, "my_package-1.0.0-py3-none-any.whl", b"d", "x")

    def test_rejects_missing_version(self):
        form = make_form()
        del form["version"]
        with pytest.raises(UploadError, match="'version' is required"):
            parse_upload(form, "my_package-1.0.0-py3-none-any.whl", b"d", "x")

    def test_rejects_invalid_project_name(self):
        with pytest.raises(UploadError, match="not a valid project name"):
            parse_upload(make_form(name="-bad-"), "bad-1.0.0.tar.gz", b"d", "x")

    def test_rejects_filename_name_mismatch(self):
        with pytest.raises(UploadError, match="does not match the declared project name"):
            parse_upload(make_form(), "other_package-1.0.0-py3-none-any.whl", b"d", "x")

    def test_rejects_filename_version_mismatch(self):
        with pytest.raises(UploadError, match="does not match the declared version"):
            parse_upload(make_form(), "my_package-9.9.9-py3-none-any.whl", b"d", "x")

    def test_accepts_normalized_name_variants_in_filename(self):
        # my_package vs my-package: PEP 503 says these are the same project.
        parsed = parse_upload(
            make_form(name="My.Package"), "my_package-1.0.0-py3-none-any.whl", b"d", "x"
        )
        assert parsed.normalized_name == "my-package"

    def test_rejects_unsupported_extension(self):
        with pytest.raises(UploadError, match="unsupported distribution type"):
            parse_upload(make_form(), "my_package-1.0.0.rpm", b"d", "x")

    def test_rejects_empty_content(self):
        with pytest.raises(UploadError, match="empty"):
            parse_upload(make_form(), "my_package-1.0.0-py3-none-any.whl", b"", "x")

    def test_rejects_bad_filename_characters(self):
        with pytest.raises(UploadError, match="invalid characters"):
            parse_upload(make_form(), "../../etc/passwd.tar.gz", b"d", "x")

    def test_rejects_invalid_filetype(self):
        with pytest.raises(UploadError, match="invalid filetype"):
            parse_upload(
                make_form(filetype="bogus"), "my_package-1.0.0-py3-none-any.whl", b"d", "x"
            )

    def test_unknown_is_treated_as_absent(self):
        parsed = parse_upload(
            make_form(summary="UNKNOWN"), "my_package-1.0.0-py3-none-any.whl", b"d", "x"
        )
        assert parsed.summary is None

    def test_multivalued_fields_collect(self):
        form = make_form(
            classifiers=["Programming Language :: Python", "License :: OSI Approved :: MIT License"],
            requires_dist=["requests>=2.0"],
        )
        parsed = parse_upload(form, "my_package-1.0.0-py3-none-any.whl", b"d", "x")
        assert len(parsed.classifiers) == 2
        assert parsed.requires_dist == ["requests>=2.0"]

    def test_keywords_split_on_commas(self):
        parsed = parse_upload(
            make_form(keywords="web,api, http"), "my_package-1.0.0-py3-none-any.whl", b"d", "x"
        )
        assert parsed.keyword_list == ["web", "api", "http"]


class TestDigestVerification:
    class _Stored:
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        blake2b_256 = "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"

    def test_accepts_matching_digests(self):
        parsed = parse_upload(
            make_form(md5_digest=self._Stored.md5, sha256_digest=self._Stored.sha256),
            "my_package-1.0.0-py3-none-any.whl",
            b"d",
            "x",
        )
        verify_digests(parsed, self._Stored())  # must not raise

    def test_rejects_mismatched_sha256(self):
        parsed = parse_upload(
            make_form(sha256_digest="f" * 64), "my_package-1.0.0-py3-none-any.whl", b"d", "x"
        )
        with pytest.raises(UploadError, match="sha256 digest mismatch"):
            verify_digests(parsed, self._Stored())

    def test_rejects_mismatched_md5(self):
        parsed = parse_upload(
            make_form(md5_digest="0" * 32), "my_package-1.0.0-py3-none-any.whl", b"d", "x"
        )
        with pytest.raises(UploadError, match="md5 digest mismatch"):
            verify_digests(parsed, self._Stored())

    def test_no_declared_digest_is_accepted(self):
        parsed = parse_upload(make_form(), "my_package-1.0.0-py3-none-any.whl", b"d", "x")
        verify_digests(parsed, self._Stored())


class TestWheelMetadataExtraction:
    def _build_wheel(self, metadata: str) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("my_package-1.0.0.dist-info/METADATA", metadata)
            archive.writestr("my_package/__init__.py", "")
        return buffer.getvalue()

    def test_extracts_metadata(self):
        wheel = self._build_wheel(
            "Metadata-Version: 2.1\nName: my-package\nVersion: 1.0.0\n"
            "Requires-Dist: requests\nRequires-Dist: click\n"
        )
        metadata = extract_wheel_metadata(wheel, "my_package-1.0.0-py3-none-any.whl")
        assert metadata["name"] == "my-package"
        assert metadata["version"] == "1.0.0"
        assert metadata["requires_dist"] == ["requests", "click"]
        assert "Metadata-Version: 2.1" in metadata["_raw"]

    def test_returns_none_for_non_wheel(self):
        assert extract_wheel_metadata(b"data", "my_package-1.0.0.tar.gz") is None

    def test_returns_none_for_corrupt_zip(self):
        assert extract_wheel_metadata(b"not a zip", "my_package-1.0.0-py3-none-any.whl") is None
