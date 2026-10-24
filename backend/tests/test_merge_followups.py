"""Fixes that only became visible once the review branches were merged."""

from types import SimpleNamespace

import pytest

from app.api import cargo, npm, pypi


@pytest.mark.parametrize("module", [npm, pypi, cargo])
def test_artifact_etag_never_renders_none(module):
    # Mid-download streams have no blob digest yet.
    streaming = SimpleNamespace(blob_sha256=None, sha256=None)
    assert module._artifact_etag(streaming) == {}

    recorded = SimpleNamespace(blob_sha256=None, sha256="ab" * 32)
    assert module._artifact_etag(recorded) == {"etag": f'"{"ab" * 32}"'}

    cached = SimpleNamespace(blob_sha256="cd" * 32, sha256="ab" * 32)
    assert module._artifact_etag(cached) == {"etag": f'"{"cd" * 32}"'}
