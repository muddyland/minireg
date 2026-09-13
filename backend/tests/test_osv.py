"""CVSS scoring and OSV record handling.

Reference vectors and their expected base scores come from the FIRST.org CVSS
v3.1 specification examples and published NVD entries.
"""

import pytest

from app.services.osv import (
    CVE_RE,
    best_severity,
    extract_cve,
    fixed_version_for,
    parse_cvss_vector,
    severity_label,
)


class TestCvss31BaseScore:
    @pytest.mark.parametrize(
        "vector,expected",
        [
            # Full compromise, network, no privileges -> critical.
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            # Scope change pushes the same metrics to the ceiling.
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
            # Availability-only DoS.
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
            # Local privilege escalation.
            ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
            # Reflected XSS.
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
            # High attack complexity, user interaction, low confidentiality.
            ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),
            # No impact at all scores zero.
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ],
    )
    def test_reference_vectors(self, vector, expected):
        assert parse_cvss_vector(vector) == pytest.approx(expected, abs=0.05)

    def test_cvss30_prefix_also_parses(self):
        assert parse_cvss_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == pytest.approx(
            9.8, abs=0.05
        )

    def test_malformed_vector_returns_none(self):
        assert parse_cvss_vector("CVSS:3.1/AV:X/AC:L") is None
        assert parse_cvss_vector("") is None
        assert parse_cvss_vector("garbage") is None


class TestCvss2BaseScore:
    @pytest.mark.parametrize(
        "vector,expected",
        [
            ("AV:N/AC:L/Au:N/C:C/I:C/A:C", 10.0),
            ("AV:N/AC:L/Au:N/C:P/I:N/A:N", 5.0),
            ("AV:L/AC:H/Au:N/C:C/I:C/A:C", 6.2),
        ],
    )
    def test_reference_vectors(self, vector, expected):
        assert parse_cvss_vector(vector) == pytest.approx(expected, abs=0.1)


class TestSeverityBands:
    @pytest.mark.parametrize(
        "score,label",
        [
            (0.0, "none"),
            (0.1, "low"),
            (3.9, "low"),
            (4.0, "medium"),
            (6.9, "medium"),
            (7.0, "high"),
            (8.9, "high"),
            (9.0, "critical"),
            (10.0, "critical"),
        ],
    )
    def test_first_org_qualitative_scale(self, score, label):
        assert severity_label(score) == label

    def test_none_score_has_no_label(self):
        assert severity_label(None) is None


class TestCveExtraction:
    def test_cve_regex(self):
        assert CVE_RE.match("CVE-2021-44228")
        assert CVE_RE.match("CVE-2024-123456")
        assert not CVE_RE.match("GHSA-jfh8-c2jp-5v3q")
        assert not CVE_RE.match("CVE-21-4422")

    def test_extracts_from_id(self):
        assert extract_cve({"id": "CVE-2021-44228"}) == "CVE-2021-44228"

    def test_extracts_from_aliases(self):
        record = {"id": "GHSA-jfh8-c2jp-5v3q", "aliases": ["CVE-2021-44228"]}
        assert extract_cve(record) == "CVE-2021-44228"

    def test_returns_none_for_non_cve_records(self):
        # CVE-only policy: a GHSA or MAL record with no CVE alias is ignored.
        assert extract_cve({"id": "GHSA-xxxx-yyyy-zzzz", "aliases": ["GHSA-other"]}) is None
        assert extract_cve({"id": "MAL-2024-1234"}) is None

    def test_normalizes_case(self):
        assert extract_cve({"id": "cve-2021-44228"}) == "CVE-2021-44228"


class TestBestSeverity:
    def test_prefers_exactly_computed_v3_over_approximated_v4(self):
        # v3 is computed from the published equations; v4 is approximated
        # (its real model is a lookup table). When a record carries both, the
        # score we can stand behind wins -- even though v4 is the newer format.
        record = {
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
                {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/VC:H/VI:H/VA:H"},
            ]
        }
        score, stype, _vector = best_severity(record)
        assert stype == "CVSS_V3"
        assert score == pytest.approx(7.5, abs=0.05)

    def test_uses_v3_when_only_v3_present(self):
        record = {
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
            ]
        }
        score, stype, vector = best_severity(record)
        assert score == pytest.approx(9.8, abs=0.05)
        assert stype == "CVSS_V3"
        assert vector.startswith("CVSS:3.1")

    def test_falls_back_to_database_specific_cvss(self):
        record = {
            "severity": [],
            "database_specific": {
                "cvss": {"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
            },
        }
        score, _, _ = best_severity(record)
        assert score == pytest.approx(9.8, abs=0.05)

    def test_accepts_bare_numeric_score(self):
        record = {"severity": [{"type": "CVSS_V3", "score": "7.5"}]}
        score, _, _ = best_severity(record)
        assert score == pytest.approx(7.5)

    def test_no_severity_returns_none(self):
        assert best_severity({}) == (None, None, None)
        assert best_severity({"severity": []}) == (None, None, None)


class TestFixedVersion:
    def test_finds_first_fixed_event(self):
        record = {
            "affected": [
                {
                    "package": {"name": "lodash", "ecosystem": "npm"},
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [{"introduced": "0"}, {"fixed": "4.17.21"}],
                        }
                    ],
                }
            ]
        }
        assert fixed_version_for(record, "lodash", "npm") == "4.17.21"

    def test_ignores_other_packages(self):
        record = {
            "affected": [
                {
                    "package": {"name": "other-pkg", "ecosystem": "npm"},
                    "ranges": [{"events": [{"fixed": "1.0.0"}]}],
                }
            ]
        }
        assert fixed_version_for(record, "lodash", "npm") is None

    def test_no_fix_returns_none(self):
        record = {
            "affected": [
                {
                    "package": {"name": "lodash", "ecosystem": "npm"},
                    "ranges": [{"events": [{"introduced": "0"}]}],
                }
            ]
        }
        assert fixed_version_for(record, "lodash", "npm") is None


class TestCvss4Approximation:
    """v4 is approximated, so these guard the properties that must hold even
    when the exact score does not."""

    def test_subsequent_system_impact_is_not_ignored(self):
        # Real vector from CVE-2024-43796 (express XSS): nothing happens to the
        # component itself, but downstream systems are affected. Reading only
        # VC/VI/VA scored this 0.0 and presented a live vulnerability as clean.
        vector = "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:L"
        score = parse_cvss_vector(vector)
        assert score is not None
        assert score > 0, "a vector with subsequent impact must not score zero"
        assert severity_label(score) in ("low", "medium")

    def test_genuinely_impactless_vector_still_scores_zero(self):
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
        assert parse_cvss_vector(vector) == 0.0

    def test_full_impact_is_critical(self):
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"
        assert severity_label(parse_cvss_vector(vector)) == "critical"

    def test_attack_requirements_lower_the_score(self):
        without = parse_cvss_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H")
        with_at = parse_cvss_vector("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H")
        assert with_at < without

    def test_any_declared_impact_clears_the_low_floor(self):
        from app.services.osv import LOW_FLOOR

        # Hardest possible vector that still declares some impact.
        vector = "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
        assert parse_cvss_vector(vector) >= LOW_FLOOR

    def test_exact_v3_is_preferred_over_approximated_v4(self):
        record = {
            "severity": [
                {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"},
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
            ]
        }
        score, stype, _vector = best_severity(record)
        assert stype == "CVSS_V3", "an exact score must win over an approximated one"
        assert score == pytest.approx(6.1, abs=0.05)

    def test_v4_used_when_it_is_the_only_vector(self):
        record = {
            "severity": [
                {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"}
            ]
        }
        _score, stype, _vector = best_severity(record)
        assert stype == "CVSS_V4"


class TestAdvisoryUpsertOrdering:
    """Concurrent scans must take row locks in the same order.

    The hourly refresh now drains for minutes rather than doing a single
    batch, so it overlaps with an admin-triggered scan far more often. Both
    upsert into `vulnerabilities`; iterating a set meant each process picked
    its own order, and Postgres deadlocked.
    """

    def test_hydrate_iterates_ids_in_sorted_order(self):
        import inspect

        from app.services.osv import OsvScanner

        source = inspect.getsource(OsvScanner._hydrate)
        assert "sorted(missing)" in source, (
            "advisory ids must be hydrated in a deterministic order, or two "
            "concurrent scans can deadlock upserting the same rows"
        )
        # And the upserts must follow that order, not the set's.
        assert source.index("sorted(missing)") < source.index("_upsert_vulnerability")
