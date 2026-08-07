"""
Markdown -> HTML -> PDF, deterministically.

Why the middle step exists
--------------------------
Markdown is a *syntax*, not a document. Handing its source text to a PDF writer and
asking for line breaks produces a transcript of the syntax, not a rendering of it:
headings arrive as `## 1. Summary`, tables as pipe-delimited soup, emphasis as
asterisks. Parsing to HTML first yields a real document tree — headings, table cells,
list items, code blocks — which CSS Paged Media then lays out with page breaks,
repeating table headers, running headers and page numbers.

Why not an AI pass
------------------
Rendering here is deterministic by requirement, not by preference. These are evidence
documents: the same Markdown must produce the same PDF on every run, or a reader cannot
tell an edited finding from a re-rendered one. A model may help *author* the Markdown
upstream, where its output is diffable. It has no place between the Markdown and the
page.

Security posture
----------------
`html: False` on the parser is load-bearing. Report bodies routinely contain
LLM-generated text; raw HTML passthrough would let that text inject markup, remote
images (a tracking-pixel exfil channel) and CSS into a document that is then forwarded
to leadership. Inline HTML is escaped and shown as text. For the same reason the
renderer runs with a URL fetcher that refuses every non-local asset — a PDF build must
never make a network request.
"""

from __future__ import annotations

import datetime as _dt
import html
import io
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

_ASSETS = Path(__file__).parent / "assets"
_STYLESHEET = _ASSETS / "report.css"

# WeasyPrint subsets its embedded fonts with fontTools, which stamps the current time into
# each subset's `head.created`/`head.modified`. Two renders of the same document a second
# apart therefore differ inside the font program — same object length, different bytes,
# nothing visible on the page. Reproducibility is a stated property of these documents (it
# is what lets a reader tell a re-export from an edited finding), so it cannot depend on
# two calls landing in the same second.
#
# SOURCE_DATE_EPOCH is the ecosystem-wide switch for this and fontTools reads it directly.
# Set at import rather than around each render: a worker renders on several threads, and a
# set/restore pair would have one request clear the variable out from under another. The
# value is arbitrary as long as it never moves; `setdefault` leaves an outer build
# system's choice in place.
#
# 2020-01-01, not 0 and not 1980-01-01. Python 3.14's `zipfile` reads the same variable
# and a DOCX is a zip, whose DOS-format timestamp cannot express a year before 1980: an
# epoch of 0 makes every `markdown_to_docx` call die in `struct.pack` with "'H' format
# requires 0 <= number". `zipfile` converts through `time.localtime`, so 1980-01-01 UTC
# fails the same way anywhere west of Greenwich. A date comfortably inside the range
# avoids both, and the failure it avoids surfaces two modules away in a format this one
# does not produce, only on a Python new enough to honor the variable.
os.environ.setdefault("SOURCE_DATE_EPOCH", "1577836800")

# A table wider than this gets a condensed type size so it stops overflowing the
# text block. Chosen from the real corpus: the zero-day arbitration tables run 3-4
# columns and read fine; the hunt-evidence tables run 5+ and did not.
_WIDE_TABLE_COLUMNS = 5

# Headings deeper than this are omitted from the table of contents. h4+ in these
# reports are sub-points, and listing them makes the TOC longer than the section.
_TOC_MAX_LEVEL = 3

# h1 is included because a three-part report uses h1 for its parts, and a contents page
# that omits "Part 1 / Part 2 / Part 3" hides the document's structure — the one thing a
# reader opening it for the second time is looking for. A single leading h1 repeating
# the cover title is already removed by `_strip_leading_h1` before this runs.
_TOC_MIN_LEVEL = 1


class MarkdownRenderError(RuntimeError):
    """Raised when a document cannot be rendered. Carries a message fit for an API."""


@dataclass
class DocumentMeta:
    """
    Cover page and running furniture.

    `fields` are rendered as a definition list on the cover in the order given, so the
    caller controls precedence. `classification` prints in the footer of every page
    including the cover; it is the marking a reader checks before forwarding, so it is
    never omitted and defaults to the most restrictive sensible value.
    """

    title: str
    subtitle: Optional[str] = None
    fields: List[Tuple[str, str]] = field(default_factory=list)
    classification: str = "Confidential — Internal Use Only"
    footer_note: Optional[str] = None
    generated: Optional[str] = None
    cover: bool = True
    toc: bool = True

    def resolved_generated(self) -> str:
        if self.generated:
            return self.generated
        return _dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")


# --------------------------------------------------------------------------- #
# Front matter
# --------------------------------------------------------------------------- #

_FRONT_MATTER = re.compile(r"\A---[ \t]*\r?\n(.*?)\r?\n---[ \t]*\r?\n", re.DOTALL)


def split_front_matter(text: str) -> Tuple[Dict[str, Any], str]:
    """
    Split optional YAML front matter from a Markdown document.

    Returns ``({}, text)`` unchanged when there is no front matter, when PyYAML is
    unavailable, or when the block does not parse. A malformed header is not worth
    failing a render over — the body is still the document.
    """
    match = _FRONT_MATTER.match(text)
    if not match:
        return {}, text
    try:
        import yaml
    except ImportError:  # pragma: no cover - yaml is a transitive dependency
        return {}, text
    try:
        data = yaml.safe_load(match.group(1)) or {}
    except Exception:
        logger.warning("Front matter did not parse as YAML; treating it as body text")
        return {}, text
    if not isinstance(data, dict):
        return {}, text
    return data, text[match.end():]


def meta_from_front_matter(data: Dict[str, Any], fallback_title: str) -> DocumentMeta:
    """Build a DocumentMeta from a front-matter mapping, ignoring unknown keys."""
    fields: List[Tuple[str, str]] = []
    raw_fields = data.get("fields")
    if isinstance(raw_fields, dict):
        fields = [(str(k), str(v)) for k, v in raw_fields.items()]
    elif isinstance(raw_fields, list):
        for item in raw_fields:
            if isinstance(item, dict) and len(item) == 1:
                (k, v), = item.items()
                fields.append((str(k), str(v)))

    meta = DocumentMeta(
        title=str(data.get("title") or fallback_title),
        subtitle=_opt_str(data.get("subtitle")),
        fields=fields,
        footer_note=_opt_str(data.get("footer_note")),
        generated=_opt_str(data.get("generated")),
    )
    if data.get("classification") is not None:
        meta.classification = str(data["classification"])
    if data.get("cover") is not None:
        meta.cover = bool(data["cover"])
    if data.get("toc") is not None:
        meta.toc = bool(data["toc"])
    return meta


def _opt_str(value: Any) -> Optional[str]:
    return None if value is None else str(value)


# --------------------------------------------------------------------------- #
# Markdown -> HTML
# --------------------------------------------------------------------------- #

def _highlight(code: str, lang: str, _attrs: str) -> str:
    """
    Pygments highlighter for fenced blocks.

    Returns "" on any failure, which tells markdown-it to fall back to its own escaped
    <pre><code>. An unknown language must degrade to plain monospace, never to a
    traceback in the middle of a report build.
    """
    if not lang:
        return ""
    try:
        from pygments import highlight
        from pygments.formatters import HtmlFormatter
        from pygments.lexers import get_lexer_by_name
        from pygments.util import ClassNotFound
    except ImportError:
        return ""
    try:
        lexer = get_lexer_by_name(lang, stripall=False)
    except ClassNotFound:
        return ""
    except Exception:
        return ""
    return highlight(code, lexer, HtmlFormatter(nowrap=False, cssclass="highlight"))


def _build_parser():
    from markdown_it import MarkdownIt

    md = MarkdownIt(
        "commonmark",
        {
            # Load-bearing: report bodies are LLM-generated. See module docstring.
            "html": False,
            "linkify": False,
            "typographer": True,
            "highlight": _highlight,
        },
    )
    # Tables and strikethrough are core rules in markdown-it-py, disabled by the
    # commonmark preset. Enabling them here keeps the dependency set at one parser.
    md.enable(["table", "strikethrough"])
    return md


_SLUG_STRIP = re.compile(r"[^\w\s-]")
_SLUG_SPACE = re.compile(r"[-\s]+")


def _slugify(text: str, seen: Dict[str, int]) -> str:
    base = _SLUG_STRIP.sub("", text.strip().lower())
    base = _SLUG_SPACE.sub("-", base).strip("-") or "section"
    count = seen.get(base, 0)
    seen[base] = count + 1
    return base if count == 0 else f"{base}-{count}"


@dataclass
class _Heading:
    level: int
    text: str
    anchor: str


def _annotate_headings(tokens: Sequence[Any]) -> List[_Heading]:
    """
    Give every heading a stable anchor id and collect the outline.

    Mutates the token stream in place (markdown-it's intended extension point) so the
    same ids appear in the body and in the TOC's ``target-counter`` references.
    """
    headings: List[_Heading] = []
    seen: Dict[str, int] = {}
    for index, token in enumerate(tokens):
        if token.type != "heading_open":
            continue
        inline = tokens[index + 1] if index + 1 < len(tokens) else None
        text = (inline.content if inline is not None else "").strip()
        anchor = _slugify(text, seen)
        token.attrSet("id", anchor)
        headings.append(_Heading(level=int(token.tag[1:]), text=text, anchor=anchor))
    return headings


def _tag_wide_tables(tokens: Sequence[Any]) -> None:
    """Mark tables past the column threshold so the stylesheet can condense them."""
    for index, token in enumerate(tokens):
        if token.type != "table_open":
            continue
        columns = 0
        for probe in tokens[index + 1:]:
            if probe.type == "th_open":
                columns += 1
            elif probe.type == "tr_close":
                break
        if columns >= _WIDE_TABLE_COLUMNS:
            existing = token.attrGet("class") or ""
            token.attrSet("class", (existing + " wide").strip())


def _render_toc(headings: Iterable[_Heading]) -> str:
    items = [h for h in headings if _TOC_MIN_LEVEL <= h.level <= _TOC_MAX_LEVEL]
    if not items:
        return ""
    rows = "\n".join(
        f'<li class="toc-l{h.level}"><a href="#{html.escape(h.anchor, quote=True)}">'
        f'<span class="toc-text">{html.escape(h.text)}</span></a></li>'
        for h in items
    )
    return (
        '<nav class="toc" id="toc">\n'
        "<h2>Contents</h2>\n"
        f"<ul>\n{rows}\n</ul>\n"
        "</nav>\n"
    )


def _render_cover(meta: DocumentMeta) -> str:
    rows = "\n".join(
        f'<div class="cover-field"><dt>{html.escape(str(k))}</dt>'
        f"<dd>{html.escape(str(v))}</dd></div>"
        for k, v in meta.fields
        if str(v).strip()
    )
    subtitle = (
        f'<p class="cover-subtitle">{html.escape(meta.subtitle)}</p>'
        if meta.subtitle
        else ""
    )
    return (
        '<section class="cover">\n'
        '<div class="cover-mark">{cls}</div>\n'
        '<h1 class="cover-title">{title}</h1>\n'
        "{subtitle}\n"
        '<dl class="cover-meta">\n{rows}\n'
        '<div class="cover-field"><dt>Generated</dt><dd>{gen}</dd></div>\n'
        "</dl>\n"
        "</section>\n"
    ).format(
        cls=html.escape(meta.classification),
        title=html.escape(meta.title),
        subtitle=subtitle,
        rows=rows,
        gen=html.escape(meta.resolved_generated()),
    )


def _strip_leading_h1(tokens: List[Any], title: str) -> None:
    """
    Drop a body-leading H1 that merely repeats the cover title.

    Authored reports open with their own title. Printing it again immediately under the
    cover reads as a duplication bug, so it is removed — but only when it actually
    matches, never blind.
    """
    for index, token in enumerate(tokens):
        if token.type in ("front_matter",):
            continue
        if token.type != "heading_open" or token.tag != "h1":
            return
        inline = tokens[index + 1] if index + 1 < len(tokens) else None
        text = (inline.content if inline is not None else "").strip()
        if _slugify(text, {}) == _slugify(title, {}):
            del tokens[index:index + 3]
        return


# --------------------------------------------------------------------------- #
# Emoji presentation
# --------------------------------------------------------------------------- #

# The codepoints report.css fences behind its "Report Emoji" faces. This list and the two
# `unicode-range` declarations there are one decision written twice; a codepoint in one and
# not the other renders from whatever the system happens to offer, which is the failure
# this whole mechanism exists to prevent.
_EMOJI_RANGES: Tuple[Tuple[int, int], ...] = (
    (0x203C, 0x203C), (0x2049, 0x2049), (0x20E3, 0x20E3), (0x2122, 0x2122),
    (0x2139, 0x2139), (0x2194, 0x21AA), (0x231A, 0x231B), (0x2328, 0x2328),
    (0x23CF, 0x23FA), (0x24C2, 0x24C2), (0x25AA, 0x25FE), (0x2600, 0x27BF),
    (0x2934, 0x2935), (0x2B00, 0x2BFF), (0x3030, 0x3030), (0x303D, 0x303D),
    (0x3297, 0x3297), (0x3299, 0x3299), (0x1F000, 0x1FAFF),
)

_ZWJ = 0x200D
_KEYCAP = 0x20E3
_VS15 = "︎"
_VS16 = 0xFE0F
_VARIATION_SELECTORS = frozenset(range(0xFE00, 0xFE10))
_REGIONAL_INDICATORS = range(0x1F1E6, 0x1F200)


def _is_fenced_emoji(codepoint: int) -> bool:
    return any(low <= codepoint <= high for low, high in _EMOJI_RANGES)


def _force_text_presentation(text: str) -> str:
    """
    Ask for the monochrome form of every emoji the stylesheet fences.

    Pango decides which font shapes a run before CSS is consulted: a codepoint whose
    default is emoji presentation goes to a color emoji font whatever the stack says. On
    Linux that font is Noto Color Emoji, whose glyphs are CBDT bitmaps — WeasyPrint embeds
    them and draws nothing, so the mark occupies its width and shows blank. Appending
    U+FE0E (VARIATION SELECTOR-15, "text presentation") moves the run back onto the
    stylesheet's fenced outline faces, which is the only way found to get ink.

    U+FE0F is rewritten rather than added to, so ⚠️ (U+26A0 U+FE0F) does not end up
    carrying both selectors. Sequences that a selector would break are left alone: keycaps,
    regional-indicator pairs, and any codepoint adjacent to a zero-width joiner.
    """
    if not text:
        return text
    out: List[str] = []
    for index, char in enumerate(text):
        codepoint = ord(char)
        if codepoint == _VS16:
            out.append(_VS15)
            continue
        out.append(char)
        if not _is_fenced_emoji(codepoint):
            continue
        if codepoint in (_KEYCAP, _ZWJ) or codepoint in _REGIONAL_INDICATORS:
            continue
        following = ord(text[index + 1]) if index + 1 < len(text) else None
        preceding = ord(text[index - 1]) if index else None
        if following in (_ZWJ, _KEYCAP) or following in _VARIATION_SELECTORS:
            continue
        if preceding == _ZWJ:
            continue
        out.append(_VS15)
    return "".join(out)


def _force_text_presentation_in_tokens(tokens: Sequence[Any]) -> None:
    """
    Apply `_force_text_presentation` to prose, and only to prose.

    Code spans and fenced blocks are evidence — a reader copies a command or a log line
    out of them — so they keep their bytes. Walking the token stream rather than the
    rendered HTML is what makes that distinction possible: `code_inline`, `fence` and
    `code_block` are separate token types and are simply not visited.
    """
    for token in tokens:
        if token.type != "inline" or not token.children:
            continue
        for child in token.children:
            if child.type == "text":
                child.content = _force_text_presentation(child.content)
        # Heading outlines and the TOC are built from the inline token's own content,
        # so it needs the same treatment or the contents page loses the marks the body kept.
        token.content = _force_text_presentation(token.content)


def _pygments_css() -> str:
    try:
        from pygments.formatters import HtmlFormatter
    except ImportError:
        return ""
    return HtmlFormatter(style="friendly").get_style_defs(".highlight")


def markdown_to_html(
    markdown_text: str,
    meta: Optional[DocumentMeta] = None,
    *,
    standalone: bool = True,
    embed_css: bool = True,
    emoji_text_presentation: bool = False,
) -> str:
    """
    Render Markdown to an HTML document.

    ``standalone=False`` returns the body fragment only (no cover, TOC or <head>),
    which is what a caller wants when embedding the result in an existing page.

    ``emoji_text_presentation`` forces the monochrome form of the stylesheet's fenced
    emoji. It defaults off because it is a workaround for how Pango picks a font, and a
    browser does not have that problem: HTML served to a reader should keep the color
    marks. The PDF path turns it on. See `_force_text_presentation`.
    """
    try:
        parser = _build_parser()
    except ImportError as exc:  # pragma: no cover - dependency is declared
        raise MarkdownRenderError(
            "Markdown rendering requires markdown-it-py. Install with: "
            "pip install markdown-it-py"
        ) from exc

    front_matter, body = split_front_matter(markdown_text or "")
    if meta is None:
        meta = meta_from_front_matter(front_matter, fallback_title="Report")

    env: Dict[str, Any] = {}
    tokens = parser.parse(body, env)
    _strip_leading_h1(tokens, meta.title)
    if emoji_text_presentation:
        # Before the outline is collected, so the TOC entries carry the same text as the
        # headings they point at. `_slugify` drops the selector, so anchors are unchanged.
        _force_text_presentation_in_tokens(tokens)
    headings = _annotate_headings(tokens)
    _tag_wide_tables(tokens)
    rendered = parser.renderer.render(tokens, parser.options, env)

    if not standalone:
        return rendered

    css = ""
    if embed_css:
        try:
            css = _STYLESHEET.read_text(encoding="utf-8")
        except OSError as exc:
            raise MarkdownRenderError(f"Report stylesheet is missing: {exc}") from exc
        css = css + "\n" + _pygments_css()

    parts = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        f"<title>{html.escape(meta.title)}</title>",
        # Bound to the running header/footer via CSS `string-set` on these elements.
        f'<meta name="classification" content="{html.escape(meta.classification, quote=True)}">',
        f"<style>{css}</style>" if embed_css else "",
        "</head>",
        '<body class="report">',
        f'<div class="running-title" aria-hidden="true">{html.escape(meta.title)}</div>',
        f'<div class="running-mark" aria-hidden="true">{html.escape(meta.classification)}</div>',
    ]
    if meta.cover:
        parts.append(_render_cover(meta))
    if meta.toc:
        parts.append(_render_toc(headings))
    parts.append('<main class="body">')
    parts.append(rendered)
    parts.append("</main>")
    if meta.footer_note:
        parts.append(
            f'<p class="footer-note">{html.escape(meta.footer_note)}</p>'
        )
    parts.append("</body></html>")
    return "\n".join(p for p in parts if p)


# --------------------------------------------------------------------------- #
# HTML -> PDF
# --------------------------------------------------------------------------- #

def _offline_url_fetcher(url: str, *args, **kwargs):
    """
    Resolve only local assets; refuse the network.

    A report build that reaches out is both a latency risk and a disclosure one — an
    attacker-supplied image URL in report text would turn every PDF export into a
    callback carrying the exporter's IP. Local files stay available so a future
    template can embed a logo.
    """
    from weasyprint.urls import default_url_fetcher

    if url.startswith(("file:", "data:")):
        return default_url_fetcher(url, *args, **kwargs)
    raise ValueError(f"Refusing to fetch remote asset during PDF render: {url}")


def markdown_to_pdf(
    markdown_text: str,
    meta: Optional[DocumentMeta] = None,
) -> bytes:
    """Render Markdown to PDF bytes."""
    try:
        from weasyprint import HTML
        from weasyprint.text.fonts import FontConfiguration
    except ImportError as exc:
        raise MarkdownRenderError(
            "PDF generation requires WeasyPrint and its system libraries "
            "(pango, cairo). Install with: pip install weasyprint"
        ) from exc

    document_html = markdown_to_html(markdown_text, meta, emoji_text_presentation=True)
    buffer = io.BytesIO()
    try:
        # A fresh font configuration per render, not the shared default. `@font-face`
        # registrations accumulate in whichever configuration is used, so on the default
        # one a document's bytes depend on what the process rendered before it: in the
        # API worker, on which reports happened to be exported earlier. The output stayed
        # correct and stopped being reproducible, which is the property that lets a reader
        # tell a re-exported finding from an edited one.
        HTML(
            string=document_html,
            base_url=str(_ASSETS),
            url_fetcher=_offline_url_fetcher,
        ).write_pdf(buffer, font_config=FontConfiguration())
    except Exception as exc:
        logger.exception("WeasyPrint failed to write the PDF")
        raise MarkdownRenderError(f"PDF layout failed: {exc}") from exc
    return buffer.getvalue()


def render_file(
    source: Path | str,
    output: Path | str,
    *,
    meta: Optional[DocumentMeta] = None,
    fmt: Optional[str] = None,
) -> Path:
    """
    Render a Markdown file to PDF, HTML or DOCX on disk.

    Format is taken from `fmt` when given, otherwise from the output suffix.
    Front matter in the source supplies the metadata unless `meta` overrides it.
    """
    source = Path(source)
    output = Path(output)
    text = source.read_text(encoding="utf-8")

    if meta is None:
        front_matter, _ = split_front_matter(text)
        meta = meta_from_front_matter(
            front_matter,
            fallback_title=_title_from_markdown(text) or source.stem,
        )

    resolved = (fmt or output.suffix.lstrip(".")).lower()
    output.parent.mkdir(parents=True, exist_ok=True)
    if resolved == "pdf":
        output.write_bytes(markdown_to_pdf(text, meta))
    elif resolved in ("html", "htm"):
        output.write_text(markdown_to_html(text, meta), encoding="utf-8")
    elif resolved == "docx":
        # Imported here: md_to_docx imports this module at load time.
        from .md_to_docx import markdown_to_docx

        output.write_bytes(markdown_to_docx(text, meta))
    else:
        raise MarkdownRenderError(f"Unsupported output format: {resolved!r}")
    return output


_H1 = re.compile(r"^#\s+(.+?)\s*$", re.MULTILINE)


def _title_from_markdown(text: str) -> Optional[str]:
    _, body = split_front_matter(text)
    match = _H1.search(body)
    return match.group(1).strip() if match else None
