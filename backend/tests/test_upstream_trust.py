"""What the fetcher will and will not connect to, and who may answer for a name.

Artifact URLs come out of upstream metadata, so they are attacker-chosen the
moment an upstream is hostile, spoofed, or simply wrong.
"""

from __future__ import annotations

import pytest

from app.models import Ecosystem, Upstream, UpstreamKind
from app.services.resolver import claimants_for
from app.upstreams.netguard import BlockedUrl, check_fetchable, same_origin


def _upstream(name, url, patterns=None, tier=1):
    return Upstream(
        name=name,
        ecosystem=Ecosystem.npm,
        kind=UpstreamKind.npm,
        url=url,
        tier=tier,
        name_patterns=patterns or [],
    )


class TestArtifactUrlGuard:
    def test_the_upstreams_own_host_is_allowed(self):
        check_fetchable(
            "https://npm.internal.test/pkg.tgz", upstream_url="https://npm.internal.test"
        )

    def test_allowlisted_cdn_is_allowed(self):
        # Real registries serve files from a different host than their API.
        check_fetchable(
            "https://files.pythonhosted.org/x.whl", upstream_url="https://pypi.org/simple"
        )

    @pytest.mark.parametrize(
        "url,expect",
        [
            ("https://evil.example/payload.tgz", "not an allowed artifact host"),
            ("file:///etc/passwd", "non-HTTP URL"),
            ("ftp://host/x", "non-HTTP URL"),
        ],
    )
    def test_foreign_and_non_http_urls_are_refused(self, url, expect):
        with pytest.raises(BlockedUrl) as caught:
            check_fetchable(url, upstream_url="https://pypi.org/simple")
        assert expect in str(caught.value)

    def test_cloud_metadata_service_is_refused(self, monkeypatch):
        """The classic SSRF target. Anonymous reads are on by default, so a
        successful fetch would be served straight back out as a package."""
        from app.config import settings

        monkeypatch.setattr(settings, "upstream_allow_private_addresses", False)
        monkeypatch.setattr(
            settings, "upstream_artifact_hosts", "169.254.169.254,pypi.org"
        )
        with pytest.raises(BlockedUrl) as caught:
            check_fetchable(
                "https://169.254.169.254/latest/meta-data/iam/security-credentials/",
                upstream_url="https://pypi.org/simple",
            )
        assert "private or link-local" in str(caught.value)

    def test_plaintext_http_is_refused_by_default(self, monkeypatch):
        from app.config import settings

        monkeypatch.setattr(settings, "upstream_allow_plaintext_http", False)
        with pytest.raises(BlockedUrl):
            check_fetchable(
                "http://files.pythonhosted.org/x.whl", upstream_url="https://pypi.org"
            )


class TestCredentialScoping:
    @pytest.mark.parametrize(
        "a,b,expected",
        [
            ("https://gitlab.test/x", "https://gitlab.test", True),
            ("https://gitlab.test:443/x", "https://gitlab.test", True),
            # GitLab 302s package downloads to object storage; the token must
            # not follow it there.
            ("https://storage.test/x", "https://gitlab.test", False),
            ("http://gitlab.test/x", "https://gitlab.test", False),
        ],
    )
    def test_same_origin(self, a, b, expected):
        assert same_origin(a, b) is expected


class TestNamespaceClaims:
    def test_a_claimed_namespace_excludes_everyone_else(self):
        internal = _upstream("internal", "https://npm.internal.test", ["@corp/*"])
        public = _upstream("public", "https://registry.npmjs.org", tier=2)

        chosen = claimants_for([internal, public], "@corp/secrets", Ecosystem.npm)
        assert [u.name for u in chosen] == ["internal"]

    def test_unclaimed_names_go_to_the_general_pool(self):
        internal = _upstream("internal", "https://npm.internal.test", ["@corp/*"])
        public = _upstream("public", "https://registry.npmjs.org", tier=2)

        chosen = claimants_for([internal, public], "lodash", Ecosystem.npm)
        assert [u.name for u in chosen] == ["public"]

    def test_claims_are_matched_against_the_normalized_name(self):
        internal = _upstream("internal", "https://npm.internal.test", ["@CORP/*"])
        chosen = claimants_for([internal], "@corp/thing", Ecosystem.npm)
        assert [u.name for u in chosen] == ["internal"]
