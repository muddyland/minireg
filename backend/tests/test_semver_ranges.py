"""node-semver range compatibility.

The inclusion/exclusion tables below are taken from node-semver's own
test fixtures (test/fixtures/range-include.js and range-exclude.js), so a
passing run means our ranges agree with npm's on the cases npm itself
regression-tests.
"""

import itertools

import pytest

from app.core.semver import (
    InvalidRange,
    SemVer,
    compare,
    is_valid_range,
    max_satisfying,
    parse_range,
    satisfies,
)


class TestVersionParsing:
    def test_basic(self):
        v = SemVer.parse("1.2.3")
        assert (v.major, v.minor, v.patch) == (1, 2, 3)
        assert v.prerelease == ()
        assert v.build is None

    def test_prerelease_and_build(self):
        v = SemVer.parse("1.2.3-alpha.1+build.5")
        assert v.prerelease == ("alpha", 1)
        assert v.build == "build.5"
        assert v.is_prerelease

    def test_leading_v_is_tolerated(self):
        assert SemVer.parse("v1.2.3").tuple == (1, 2, 3)
        assert SemVer.parse("=1.2.3").tuple == (1, 2, 3)

    @pytest.mark.parametrize("bad", ["1.2", "1", "", "1.2.3.4", "a.b.c", "01.2.3", "1.2.3-"])
    def test_rejects_invalid(self, bad):
        assert SemVer.parse(bad) is None


class TestPrecedence:
    def test_build_metadata_is_ignored(self):
        # semver 2.0.0 section 10: build metadata does not affect precedence.
        assert compare("1.2.3+build.1", "1.2.3+build.2") == 0
        assert SemVer.parse("1.2.3+a").equivalent(SemVer.parse("1.2.3+b"))

    def test_spec_section_11_ordering(self):
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
        for lower, higher in itertools.pairwise(ordered):
            assert compare(lower, higher) == -1, f"{lower} should sort below {higher}"

    def test_numeric_identifiers_compare_numerically(self):
        assert compare("1.0.0-beta.2", "1.0.0-beta.11") == -1

    def test_numeric_ranks_below_alphanumeric(self):
        assert compare("1.0.0-1", "1.0.0-alpha") == -1

    def test_longer_prerelease_wins_ties(self):
        assert compare("1.0.0-alpha", "1.0.0-alpha.1") == -1


# --------------------------------------------------------------------------- #
# node-semver fixtures
# --------------------------------------------------------------------------- #
INCLUDE = [
    ("1.0.0 - 2.0.0", "1.2.3"),
    ("^1.2.3+build", "1.2.3"),
    ("^1.2.3+build", "1.3.0"),
    ("1.2.3-pre+asdf - 2.4.3-pre+asdf", "1.2.3"),
    (">=*", "0.2.4"),
    ("", "1.0.0"),
    ("*", "1.2.3"),
    (">=1.0.0", "1.0.0"),
    (">=1.0.0", "1.0.1"),
    (">=1.0.0", "1.1.0"),
    (">1.0.0", "1.0.1"),
    (">1.0.0", "1.1.0"),
    ("<=2.0.0", "2.0.0"),
    ("<=2.0.0", "1.9999.9999"),
    ("<=2.0.0", "0.2.9"),
    ("<2.0.0", "1.9999.9999"),
    ("<2.0.0", "0.2.9"),
    (">= 1.0.0", "1.0.0"),
    (">=  1.0.0", "1.0.1"),
    (">=   1.0.0", "1.1.0"),
    ("> 1.0.0", "1.0.1"),
    (">  1.0.0", "1.1.0"),
    ("<=   2.0.0", "2.0.0"),
    ("<= 2.0.0", "1.9999.9999"),
    ("<=  2.0.0", "0.2.9"),
    ("<    2.0.0", "1.9999.9999"),
    ("<\t2.0.0", "0.2.9"),
    (">=0.1.97", "0.1.97"),
    ("0.1.20 || 1.2.4", "1.2.4"),
    (">=0.2.3 || <0.0.1", "0.0.0"),
    (">=0.2.3 || <0.0.1", "0.2.3"),
    (">=0.2.3 || <0.0.1", "0.2.4"),
    ("||", "1.3.4"),
    ("2.x.x", "2.1.3"),
    ("1.2.x", "1.2.3"),
    ("1.2.x || 2.x", "2.1.3"),
    ("1.2.x || 2.x", "1.2.3"),
    ("x", "1.2.3"),
    ("2.*.*", "2.1.3"),
    ("1.2.*", "1.2.3"),
    ("1.2.* || 2.*", "2.1.3"),
    ("1.2.* || 2.*", "1.2.3"),
    ("*", "1.2.3"),
    ("2", "2.1.2"),
    ("2.3", "2.3.1"),
    ("~0.0.1", "0.0.1"),
    ("~0.0.1", "0.0.2"),
    ("~x", "0.0.9"),
    ("~2.4", "2.4.0"),
    ("~2.4", "2.4.5"),
    ("~>3.2.1", "3.2.2"),
    ("~1", "1.2.3"),
    ("~>1", "1.2.3"),
    ("~1.0", "1.0.2"),
    ("~ 1.0", "1.0.2"),
    ("~ 1.0.3", "1.0.12"),
    (">=1", "1.0.0"),
    (">= 1", "1.0.0"),
    ("<1.2", "1.1.1"),
    ("< 1.2", "1.1.1"),
    ("~v0.5.4-pre", "0.5.5"),
    ("~v0.5.4-pre", "0.5.4"),
    ("=0.7.x", "0.7.2"),
    ("<=0.7.x", "0.7.2"),
    (">=0.7.x", "0.7.2"),
    ("<=0.7.x", "0.6.2"),
    ("~1.2.1 >=1.2.3", "1.2.3"),
    ("~1.2.1 =1.2.3", "1.2.3"),
    ("~1.2.1 1.2.3", "1.2.3"),
    ("~1.2.1 >=1.2.3 1.2.3", "1.2.3"),
    ("~1.2.1 1.2.3 >=1.2.3", "1.2.3"),
    (">=1.2.1 1.2.3", "1.2.3"),
    ("1.2.3 >=1.2.1", "1.2.3"),
    (">=1.2.3 >=1.2.1", "1.2.3"),
    (">=1.2.1 >=1.2.3", "1.2.3"),
    (">=1.2", "1.2.8"),
    ("^1.2.3", "1.8.1"),
    ("^0.1.2", "0.1.2"),
    ("^0.1", "0.1.2"),
    ("^0.0.1", "0.0.1"),
    ("^1.2", "1.4.2"),
    ("^1.2 ^1", "1.4.2"),
    ("^1.2.3-alpha", "1.2.3-pre"),
    ("^1.2.0-alpha", "1.2.0-pre"),
    ("^0.0.1-alpha", "0.0.1-beta"),
    ("^0.0.1-alpha", "0.0.1"),
    ("^0.1.1-alpha", "0.1.1-beta"),
    ("^x", "1.2.3"),
    ("x - 1.0.0", "0.9.7"),
    ("x - 1.x", "0.9.7"),
    ("1.0.0 - x", "1.9.7"),
    ("1.x - x", "1.9.7"),
    ("<=7.x", "7.9.9"),
    ("2.x", "2.0.0"),
    ("<1.0.0", "0.9.9"),
]

EXCLUDE = [
    ("1.0.0 - 2.0.0", "2.2.3"),
    ("1.2.3+asdf - 2.4.3+asdf", "1.2.3-pre.2"),
    ("1.2.3+asdf - 2.4.3+asdf", "2.4.3-alpha"),
    ("^1.2.3+build", "2.0.0"),
    ("^1.2.3+build", "1.2.0"),
    ("^1.2.3", "1.2.3-pre"),
    ("^1.2", "1.2.0-pre"),
    (">1.2", "1.3.0-beta"),
    ("<=1.2.3", "1.2.3-beta"),
    ("^1.2.3", "1.2.3-beta"),
    ("=0.7.x", "0.7.0-asdf"),
    (">=0.7.x", "0.7.0-asdf"),
    ("<=0.7.x", "0.7.0-asdf"),
    ("1", "1.0.0beta"),
    ("<1", "1.0.0"),
    (">=1.2", "1.1.1"),
    ("1", "2.0.0beta"),
    ("~v0.5.4-beta", "0.5.4-alpha"),
    ("=0.7.x", "0.8.2"),
    (">=0.7.x", "0.6.2"),
    ("<0.7.x", "0.7.2"),
    ("<1.2.3", "1.2.3-beta"),
    ("=1.2.3", "1.2.3-beta"),
    (">1.2", "1.2.8"),
    ("^0.0.1", "0.0.2-alpha"),
    ("^0.0.1", "0.0.2"),
    ("^1.2.3", "2.0.0-alpha"),
    ("^1.2.3", "1.2.2"),
    ("^1.2", "1.1.9"),
    ("2.x", "3.0.0"),
    ("1.2.x", "1.3.0"),
    ("~1.2.3", "1.3.0"),
    ("~1.2.3", "1.2.2"),
    (">=1.0.0", "0.9.9"),
    ("<1.0.0", "1.0.0"),
]


class TestNodeSemverInclusions:
    @pytest.mark.parametrize("range_str,version", INCLUDE)
    def test_satisfies(self, range_str, version):
        assert satisfies(version, range_str) is True, (
            f"{version} should satisfy {range_str!r} "
            f"(desugars to {parse_range(range_str)})"
        )


class TestNodeSemverExclusions:
    @pytest.mark.parametrize("range_str,version", EXCLUDE)
    def test_does_not_satisfy(self, range_str, version):
        assert satisfies(version, range_str) is False, (
            f"{version} should NOT satisfy {range_str!r} "
            f"(desugars to {parse_range(range_str)})"
        )


class TestDesugaring:
    """Spot-check the documented expansions from the node-semver README."""

    @pytest.mark.parametrize(
        "range_str,expected",
        [
            ("^1.2.3", ">=1.2.3 <2.0.0-0"),
            ("^0.2.3", ">=0.2.3 <0.3.0-0"),
            ("^0.0.3", ">=0.0.3 <0.0.4-0"),
            ("^1.2.x", ">=1.2.0 <2.0.0-0"),
            ("^0.0.x", ">=0.0.0 <0.1.0-0"),
            ("^1.x", ">=1.0.0 <2.0.0-0"),
            ("^0.x", ">=0.0.0 <1.0.0-0"),
            ("~1.2.3", ">=1.2.3 <1.3.0-0"),
            ("~1.2", ">=1.2.0 <1.3.0-0"),
            ("~1", ">=1.0.0 <2.0.0-0"),
            ("~0.2.3", ">=0.2.3 <0.3.0-0"),
            ("1.2.x", ">=1.2.0 <1.3.0-0"),
            ("1.x", ">=1.0.0 <2.0.0-0"),
            ("1.2.3 - 2.3.4", ">=1.2.3 <=2.3.4"),
            ("1.2 - 2.3.4", ">=1.2.0 <=2.3.4"),
            ("1.2.3 - 2.3", ">=1.2.3 <2.4.0-0"),
            ("1.2.3 - 2", ">=1.2.3 <3.0.0-0"),
        ],
    )
    def test_expansion(self, range_str, expected):
        assert str(parse_range(range_str)) == expected

    def test_upper_bounds_carry_the_prerelease_floor(self):
        # Without the -0, `2.0.0-alpha` would sort under `2.0.0` and leak
        # through a `^1.2.3` range.
        assert str(parse_range("^1.2.3")).endswith("<2.0.0-0")
        assert satisfies("2.0.0-alpha", "^1.2.3") is False


class TestPrereleaseOptIn:
    def test_prerelease_excluded_by_default(self):
        assert satisfies("1.2.4-alpha", "^1.2.3") is False
        assert satisfies("1.5.0-beta.1", ">=1.0.0 <2.0.0") is False

    def test_prerelease_allowed_when_a_bound_names_the_same_tuple(self):
        assert satisfies("1.2.3-beta", "^1.2.3-alpha") is True
        assert satisfies("1.2.3-beta", ">=1.2.3-alpha <2.0.0") is True

    def test_prerelease_of_a_different_tuple_still_excluded(self):
        # ^1.2.3-alpha desugars to >=1.2.3-alpha <2.0.0-0; 1.9.0-beta is inside
        # the arithmetic but names a different tuple, so it does not qualify.
        assert satisfies("1.9.0-beta", "^1.2.3-alpha") is False

    def test_include_prerelease_opens_it_up(self):
        assert satisfies("1.2.4-alpha", "^1.2.3", include_prerelease=True) is True
        assert satisfies("1.5.0-beta.1", ">=1.0.0 <2.0.0", include_prerelease=True) is True
        assert satisfies("1.0.0-alpha", "1.x", include_prerelease=True) is True

    def test_include_prerelease_does_not_break_arithmetic(self):
        # Still below the lower bound, opt-in or not.
        assert satisfies("1.2.3-pre", ">=1.2.3", include_prerelease=True) is False
        # Still at or above the -0 upper bound.
        assert satisfies("2.0.0-alpha", "^1.2.3", include_prerelease=True) is False


class TestRangeValidation:
    @pytest.mark.parametrize(
        "range_str",
        ["*", "", "1.2.3", "^1.2.3", "~1.2", ">=1.0.0 <2.0.0", "1.x || >=2.5.0", "1.2.3 - 2.3.4"],
    )
    def test_valid(self, range_str):
        assert is_valid_range(range_str) is True

    @pytest.mark.parametrize(
        "range_str", ["not-a-range", ">=blah", "^^1.2.3", "1.2.3 - ", "><1.2.3"]
    )
    def test_invalid(self, range_str):
        assert is_valid_range(range_str) is False

    def test_parse_raises_on_invalid(self):
        with pytest.raises(InvalidRange):
            parse_range("garbage!!")

    def test_satisfies_never_raises(self):
        assert satisfies("1.2.3", "garbage!!") is False
        assert satisfies("not-a-version", "^1.0.0") is False


class TestMaxSatisfying:
    def test_picks_the_highest_match(self):
        versions = ["1.0.0", "1.2.0", "1.2.5", "2.0.0"]
        assert max_satisfying(versions, "^1.0.0") == "1.2.5"
        assert max_satisfying(versions, "^2.0.0") == "2.0.0"
        assert max_satisfying(versions, "~1.2.0") == "1.2.5"

    def test_none_when_nothing_matches(self):
        assert max_satisfying(["1.0.0"], "^2.0.0") is None

    def test_ignores_unparseable_versions(self):
        assert max_satisfying(["1.0.0", "garbage"], "*") == "1.0.0"


class TestRealWorldBlockingScenarios:
    """The cases an admin writing a block rule actually cares about."""

    def test_block_everything_below_a_patched_version(self):
        # The classic "upgrade past the CVE" rule.
        for vulnerable in ["4.17.0", "4.17.20", "1.0.0", "4.17.20-rc.1"]:
            assert satisfies(vulnerable, "<4.17.21", include_prerelease=True) is True
        assert satisfies("4.17.21", "<4.17.21", include_prerelease=True) is False
        assert satisfies("5.0.0", "<4.17.21", include_prerelease=True) is False

    def test_block_a_single_bad_release(self):
        assert satisfies("3.3.6", "3.3.6") is True
        assert satisfies("3.3.5", "3.3.6") is False

    def test_block_a_compromised_window(self):
        # event-stream: only 3.3.6 shipped the payload.
        rule = ">=3.3.6 <3.3.7"
        assert satisfies("3.3.6", rule) is True
        assert satisfies("3.3.5", rule) is False
        assert satisfies("3.3.7", rule) is False

    def test_block_a_whole_major_line(self):
        assert satisfies("1.0.0", "1.x", include_prerelease=True) is True
        assert satisfies("1.99.99", "1.x", include_prerelease=True) is True
        assert satisfies("2.0.0", "1.x", include_prerelease=True) is False

    def test_block_two_disjoint_windows(self):
        rule = "<2.6.9 || >=3.0.0 <3.0.2"
        assert satisfies("2.6.8", rule) is True
        assert satisfies("3.0.1", rule) is True
        assert satisfies("2.6.9", rule) is False
        assert satisfies("3.0.2", rule) is False

    def test_prereleases_of_a_blocked_line_are_blocked(self):
        # A block list must not leak a prerelease of a version it blocks.
        assert satisfies("1.5.0-beta.1", ">=1.0.0 <2.0.0", include_prerelease=True) is True
