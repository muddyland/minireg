"""Container image support: an OCI distribution registry at ``/v2``.

Images are a separate feature from the npm/PyPI/cargo package model. They
have their own tables (``docker_*`` in ``app.models``), routes (``/v2``),
upstream client and vulnerability pipeline (Trivy, via the scanner worker).
They share the content-addressed blob store, the upstream rows, the audit
log, the download log and the token system.
"""
