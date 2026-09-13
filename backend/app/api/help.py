"""In-app documentation.

The registry is frequently deployed somewhere with no route to the internet
and no access to the repository it was built from, so "read the docs" cannot
mean "go and find them elsewhere". The markdown ships inside the image and is
served from here; the UI renders it.

Only the files discovered on disk at request time can be served. The slug is
matched against that set rather than being joined onto a path, so there is no
traversal to defend against.
"""

from __future__ import annotations

import functools
import logging
import re
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status

from ..core.deps import Identity, require_user

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/help", tags=["help"])

#: Reading order, which is not alphabetical. Anything on disk but missing from
#: this list still appears, after these.
PREFERRED_ORDER = [
    "installation",
    "usage",
    "cli",
    "configuration",
    "policy",
    "operations",
    "troubleshooting",
    "api",
    "architecture",
]

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


def docs_dir() -> Path | None:
    """Where the markdown lives.

    Two layouts: inside the image the docs sit next to the package, and in a
    source checkout they are at the repository root.
    """
    here = Path(__file__).resolve().parent.parent  # app/
    for candidate in (here / "docs", here.parent.parent / "docs"):
        if candidate.is_dir():
            return candidate
    return None


#: Line prefixes that are structure rather than prose.
_NOT_PROSE = ("#", "|", "---", "<", "- ", "* ", "> ", "!", "1.")


def _title_and_summary(text: str) -> tuple[str, str | None]:
    """First heading, and the first real paragraph under it.

    Fenced blocks are skipped wholesale. Several of these pages open with a
    command or an ASCII diagram, and quoting that as the summary tells a
    reader nothing about the page.
    """
    title = ""
    summary_lines: list[str] = []
    in_fence = False

    for line in text.splitlines():
        stripped = line.strip()

        if stripped.startswith("```"):
            in_fence = not in_fence
            if summary_lines:
                break
            continue
        if in_fence:
            continue

        if not title:
            if stripped.startswith("# "):
                title = stripped[2:].strip()
            continue

        if not stripped:
            if summary_lines:
                break
            continue
        if stripped.startswith(_NOT_PROSE):
            if summary_lines:
                break
            continue
        summary_lines.append(stripped)

    summary = _strip_inline_markdown(" ".join(summary_lines)) or None
    if summary and len(summary) > 200:
        summary = summary[:197].rstrip(" ,.;:") + "..."
    return title, summary


def _strip_inline_markdown(text: str) -> str:
    """Flatten a line of markdown to plain text.

    The summary is rendered as a one-line label in a list, not as markdown, so
    leaving the source syntax in it shows readers `**Client setup**` and
    backticked identifiers verbatim.
    """
    # Links and images: keep the label, drop the target.
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = text.replace("`", "")
    # Emphasis, longest marker first so ** is not left as a stray *.
    for marker in ("***", "**", "__", "*"):
        text = text.replace(marker, "")
    return " ".join(text.split())


@functools.lru_cache(maxsize=1)
def _index() -> list[dict]:
    """Slug, title and summary for every page. Cached: the files are baked
    into the image and cannot change while the process runs."""
    directory = docs_dir()
    if directory is None:
        log.warning("no docs directory found; in-app help will be empty")
        return []

    pages: list[dict] = []
    for path in sorted(directory.glob("*.md")):
        slug = path.stem.lower()
        if not _SLUG_RE.match(slug):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            log.warning("could not read %s: %s", path, exc)
            continue
        title, summary = _title_and_summary(text)
        pages.append(
            {
                "slug": slug,
                "title": title or slug.replace("-", " ").title(),
                "summary": summary,
            }
        )

    order = {slug: i for i, slug in enumerate(PREFERRED_ORDER)}
    pages.sort(key=lambda p: (order.get(p["slug"], len(order)), p["slug"]))
    return pages


@router.get("/pages")
async def list_pages(identity: Identity = Depends(require_user)) -> dict:
    return {"pages": _index()}


@router.get("/pages/{slug}")
async def get_page(slug: str, identity: Identity = Depends(require_user)) -> dict:
    directory = docs_dir()
    known = {page["slug"]: page for page in _index()}
    page = known.get(slug.lower())
    if page is None or directory is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such page")

    # Built from the slug we just matched against the on-disk listing, so this
    # can only ever name a file the index already found.
    path = directory / f"{page['slug']}.md"
    try:
        markdown = path.read_text(encoding="utf-8")
    except OSError as exc:
        log.error("could not read documentation page %s: %s", path, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="documentation page could not be read",
        ) from exc
    return {**page, "markdown": markdown}
