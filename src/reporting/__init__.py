"""
Document rendering for AuditGH reports.

Every report this system produces is authored in Markdown. This package owns the
single path from that Markdown to a paginated document:

    Markdown  ->  HTML (semantic, sanitized)  ->  PDF (CSS Paged Media)
    Markdown  ->  DOCX (same token stream, python-docx elements)

There is deliberately one renderer. The previous arrangement had three independent
PDF writers (two zero-day export endpoints and a dead `pdf_generator` module), each
hand-assembling reportlab flowables, and each with its own idea of what a report looks
like. Two of them pushed raw Markdown into a single text run, so headings, tables and
emphasis reached the reader as literal `##`, `|---|---|` and `**`.

`briefing` supplies the structure those documents are written in: one reader opening
the same report with three different questions, so Part 1 answers "what do I tell my
manager", Part 2 "what do I do and in what order", and Part 3 "prove it, and tell me
exactly what to touch". Priority order and every figure are computed in code; only the
wording may come from a model, and only at analysis time.

Public surface:
    DocumentMeta        cover-page and running-furniture metadata
    markdown_to_html    Markdown -> standalone HTML document
    markdown_to_pdf     Markdown -> PDF bytes
    markdown_to_docx    Markdown -> DOCX bytes
    render_file         Markdown file -> PDF/HTML/DOCX file on disk
    Briefing, Finding   the three-part report model
    author_briefing     Parts 1 and 2, model-written where available
    compose_document    Briefing + evidence -> three-part Markdown
"""

from .md_to_pdf import (  # noqa: F401
    DocumentMeta,
    MarkdownRenderError,
    markdown_to_html,
    markdown_to_pdf,
    meta_from_front_matter,
    render_file,
    split_front_matter,
)
from .md_to_docx import markdown_to_docx  # noqa: F401
from .briefing import (  # noqa: F401
    ActionItem,
    Briefing,
    BriefingRejected,
    Finding,
    author_briefing,
    briefing_from_dict,
    briefing_to_dict,
    compose_document,
    deterministic_briefing,
    findings_from_scan,
    findings_from_zda,
)

__all__ = [
    "DocumentMeta",
    "MarkdownRenderError",
    "markdown_to_html",
    "markdown_to_pdf",
    "markdown_to_docx",
    "meta_from_front_matter",
    "render_file",
    "split_front_matter",
    "ActionItem",
    "Briefing",
    "BriefingRejected",
    "Finding",
    "author_briefing",
    "briefing_from_dict",
    "briefing_to_dict",
    "compose_document",
    "deterministic_briefing",
    "findings_from_scan",
    "findings_from_zda",
]
