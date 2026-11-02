"""Spec compliance: PEP 503/440 normalization, wheel/sdist filename grammar,
npm name validation and semver 2.0.0 precedence."""

import pytest

from app.core.naming import (
    is_valid_npm_name,
    is_valid_pypi_name,
    is_valid_semver,
    max_semver,
    normalize_npm_name,
    normalize_pypi_name,
    normalize_pypi_version,
    npm_name_to_path,
    npm_path_to_name,
    npm_scope,
    npm_tarball_filename,
    parse_dist_filename,
    pypi_versions_equal,
    sort_pypi_versions,
    sort_semver,
)


class TestPEP503Normalization:
    """PEP 503: re.sub(r'[-_.]+', '-', name).lower()"""

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("Foo", "foo"),
            ("Foo.Bar", "foo-bar"),
            ("Foo_Bar", "foo-bar"),
            ("Foo--Bar", "foo-bar"),
            ("Foo..Bar", "foo-bar"),
            ("foo_.-_bar", "foo-bar"),
            ("zope.interface", "zope-interface"),
            ("Django", "django"),
            ("ruamel.yaml", "ruamel-yaml"),
            ("typing_extensions", "typing-extensions"),
            ("A", "a"),
            ("backports.functools_lru_cache", "backports-functools-lru-cache"),
        ],
    )
    def test_normalization(self, raw, expected):
        assert normalize_pypi_name(raw) == expected

    def test_is_idempotent(self):
        for raw in ["Foo.Bar", "a_b_c", "X--Y", "zope.interface"]:
            once = normalize_pypi_name(raw)
            assert normalize_pypi_name(once) == once

    @pytest.mark.parametrize(
        "name,valid",
        [
            ("requests", True),
            ("zope.interface", True),
            ("my-package_1", True),
            ("A", True),
            ("", False),
            ("-leading", False),
            ("trailing-", False),
            (".dotted", False),
            ("has space", False),
            ("has/slash", False),
        ],
    )
    def test_pep508_name_grammar(self, name, valid):
        assert is_valid_pypi_name(name) is valid


class TestPEP440Versions:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("1.0", "1.0"),
            ("1.0.0", "1.0.0"),
            ("1.0.0.post1", "1.0.0.post1"),
            ("1.0.0-1", "1.0.0.post1"),
            ("1.0.0a1", "1.0.0a1"),
            ("1.0.0-alpha1", "1.0.0a1"),
            ("1.0.0.dev0", "1.0.0.dev0"),
            ("v1.0.0", "1.0.0"),
            ("1.0.0+local.1", "1.0.0+local.1"),
            ("1!2.0", "1!2.0"),
        ],
    )
    def test_canonical_form(self, raw, expected):
        assert normalize_pypi_version(raw) == expected

    def test_non_pep440_falls_back_not_raises(self):
        # Legacy upstream files must stay reachable even with junk versions.
        assert normalize_pypi_version("not-a-version") == "not-a-version"

    @pytest.mark.parametrize(
        ("a", "b", "equal"),
        [
            ("2.0", "2.0.0", True),
            ("2", "2.0.0.0", True),
            ("v1.0", "1.0.0", True),
            ("1.0+local", "1.0.0+local", True),
            ("1.0", "1.0.1", False),
            ("1.0", "1.0.post0", False),
            ("1.0", "1.0+local", False),
            ("not-a-version", "not-a-version", True),
            ("not-a-version", "1.0", False),
        ],
    )
    def test_equality_ignores_trailing_zeros(self, a, b, equal):
        # The storage key keeps them, so "is this the same release" cannot be
        # answered by comparing keys.
        assert pypi_versions_equal(a, b) is equal
        assert pypi_versions_equal(b, a) is equal

    def test_ordering(self):
        versions = ["1.0", "1.0.1", "0.9", "2.0a1", "2.0", "1.0.post1", "1.0.dev1"]
        assert sort_pypi_versions(versions) == [
            "0.9",
            "1.0.dev1",
            "1.0",
            "1.0.post1",
            "1.0.1",
            "2.0a1",
            "2.0",
        ]


class TestDistFilenameParsing:
    @pytest.mark.parametrize(
        "filename,name,version,ptype",
        [
            ("requests-2.31.0-py3-none-any.whl", "requests", "2.31.0", "bdist_wheel"),
            ("requests-2.31.0.tar.gz", "requests", "2.31.0", "sdist"),
            (
                "numpy-1.26.4-cp312-cp312-manylinux_2_17_x86_64.whl",
                "numpy",
                "1.26.4",
                "bdist_wheel",
            ),
            ("zope.interface-6.1.tar.gz", "zope-interface", "6.1", "sdist"),
            ("my_pkg-1.0.0-1-py3-none-any.whl", "my-pkg", "1.0.0", "bdist_wheel"),
        ],
    )
    def test_parses(self, filename, name, version, ptype):
        parsed = parse_dist_filename(filename)
        assert parsed is not None
        got_name, got_version, got_type = parsed
        assert normalize_pypi_name(got_name) == normalize_pypi_name(name)
        assert got_version == version
        assert got_type == ptype

    def test_rejects_garbage(self):
        assert parse_dist_filename("not-a-package") is None
        assert parse_dist_filename("noversion.whl") is None

    def test_egg_needs_a_real_version(self):
        # Upstream indexes still list eggs; one whose "version" is not PEP 440
        # is not a release and must not become one.
        assert parse_dist_filename("eggpkg-latest.egg") is None
        assert parse_dist_filename("eggpkg-1.0-py2.7.egg") == ("eggpkg", "1.0", "bdist_egg")


class TestNpmNames:
    @pytest.mark.parametrize(
        "name,valid",
        [
            ("lodash", True),
            ("@scope/pkg", True),
            ("@babel/core", True),
            ("some-package", True),
            ("some.package", True),
            ("some_package", True),
            ("", False),
            (".leading-dot", False),
            ("_leading-underscore", False),
            ("Uppercase", False),
            ("has space", False),
            ("has~tilde", False),
            ("has'quote", False),
            ("node_modules", False),
            ("favicon.ico", False),
            ("a" * 215, False),
        ],
    )
    def test_validation(self, name, valid):
        ok, _ = is_valid_npm_name(name)
        assert ok is valid

    def test_length_boundary(self):
        assert is_valid_npm_name("a" * 214)[0] is True
        assert is_valid_npm_name("a" * 215)[0] is False

    def test_scope_extraction(self):
        assert npm_scope("@babel/core") == "babel"
        assert npm_scope("lodash") is None

    def test_path_roundtrip(self):
        assert npm_name_to_path("@scope/pkg") == "@scope%2fpkg"
        assert npm_path_to_name("@scope%2fpkg") == "@scope/pkg"
        assert npm_path_to_name("@scope%2Fpkg") == "@scope/pkg"
        assert npm_path_to_name("lodash") == "lodash"

    def test_tarball_filename_strips_scope(self):
        # npm names the tarball without the scope segment.
        assert npm_tarball_filename("@babel/core", "7.0.0") == "core-7.0.0.tgz"
        assert npm_tarball_filename("lodash", "4.17.21") == "lodash-4.17.21.tgz"

    def test_lookup_is_case_sensitive(self):
        # registry.npmjs.org: JSONStream and jsonstream are two packages.
        assert normalize_npm_name("JSONStream") == "JSONStream"
        assert normalize_npm_name("JSONStream") != normalize_npm_name("jsonstream")
        assert normalize_npm_name(" lodash ") == "lodash"


class TestSemver:
    @pytest.mark.parametrize(
        "version,valid",
        [
            ("1.0.0", True),
            ("0.0.1", True),
            ("1.0.0-alpha", True),
            ("1.0.0-alpha.1", True),
            ("1.0.0+build.1", True),
            ("1.0.0-alpha+build", True),
            ("1.0", False),
            ("v1.0.0", False),
            ("01.0.0", False),
            ("1.0.0-", False),
        ],
    )
    def test_validation(self, version, valid):
        assert is_valid_semver(version) is valid

    def test_precedence_from_spec_section_11(self):
        # semver.org 11.4: 1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-alpha.beta
        #   < 1.0.0-beta < 1.0.0-beta.2 < 1.0.0-beta.11 < 1.0.0-rc.1 < 1.0.0
        ordered = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
        ]
        assert sort_semver(list(reversed(ordered))) == ordered

    def test_numeric_identifiers_compare_numerically(self):
        # beta.11 > beta.2 numerically, not lexically.
        assert sort_semver(["1.0.0-beta.11", "1.0.0-beta.2"]) == [
            "1.0.0-beta.2",
            "1.0.0-beta.11",
        ]

    def test_major_minor_patch_ordering(self):
        assert sort_semver(["1.10.0", "1.9.0", "1.2.0"]) == ["1.2.0", "1.9.0", "1.10.0"]

    def test_latest_prefers_stable_over_prerelease(self):
        assert max_semver(["1.0.0", "2.0.0-beta.1"]) == "1.0.0"

    def test_latest_falls_back_to_prerelease_when_only_prereleases(self):
        assert max_semver(["2.0.0-beta.1", "2.0.0-alpha.1"]) == "2.0.0-beta.1"

    def test_latest_of_empty_is_none(self):
        assert max_semver([]) is None
