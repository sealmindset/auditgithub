#!/usr/bin/env python3
"""
Render a Markdown file to a formatted PDF, HTML or DOCX.

Uses the same renderer and stylesheet as the API's report exports, so a playbook rendered
here and an analysis exported from the UI are the same document class. That is the point
of the CLI: the hunt corpus (`docs/playbooks/*.md`, `handoff.md`, the round-2 hunt
reports) is Markdown that gets forwarded to people who do not read Markdown.

Examples
--------
    scripts/report/md2pdf.py docs/playbooks/supply-chain-hunt-ttp.md
    scripts/report/md2pdf.py handoff.md -o /tmp/handoff.pdf --title "Session Handoff"
    scripts/report/md2pdf.py docs/playbooks/*.md --outdir /tmp/pdf
    scripts/report/md2pdf.py report.md -o report.html --field Owner "Security Eng"

Metadata may also be supplied as YAML front matter in the source file:

    ---
    title: Supply Chain Hunt
    subtitle: npm / CHAINDROP
    classification: Confidential — Internal Use Only
    fields:
      Estate: Sleep Number
      Analyst: R. Vance
    ---
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from src.reporting import (  # noqa: E402
    DocumentMeta,
    MarkdownRenderError,
    meta_from_front_matter,
    render_file,
    split_front_matter,
)
from src.reporting.md_to_pdf import _title_from_markdown  # noqa: E402

_FORMATS = ("pdf", "html", "docx")


def _parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render Markdown to a formatted PDF, HTML or DOCX.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("sources", nargs="+", type=Path, help="Markdown file(s) to render")
    parser.add_argument("-o", "--output", type=Path,
                        help="Output path. Only valid with a single source.")
    parser.add_argument("--outdir", type=Path,
                        help="Directory for outputs; names follow the source stems.")
    parser.add_argument("-f", "--format", choices=_FORMATS,
                        help="Output format. Defaults to the output suffix, else pdf.")
    parser.add_argument("--title", help="Document title. Overrides front matter and H1.")
    parser.add_argument("--subtitle", help="Document subtitle.")
    parser.add_argument("--classification",
                        help="Marking printed on the cover and in every page footer.")
    parser.add_argument("--field", nargs=2, action="append", metavar=("NAME", "VALUE"),
                        default=[], help="Add a cover-page field. Repeatable.")
    parser.add_argument("--no-cover", action="store_true", help="Omit the cover page.")
    parser.add_argument("--no-toc", action="store_true", help="Omit the table of contents.")
    parser.add_argument("--generated",
                        help="Override the generated timestamp. Use for reproducible "
                             "output — the default is the current local time, which "
                             "makes two renders of one source differ.")
    args = parser.parse_args(argv)

    if args.output and len(args.sources) > 1:
        parser.error("--output takes a single source; use --outdir for several")
    if args.output and args.outdir:
        parser.error("--output and --outdir are mutually exclusive")
    return args


def _build_meta(args: argparse.Namespace, source: Path, text: str) -> DocumentMeta:
    """Front matter first, CLI flags on top — the flag is the more specific instruction."""
    front_matter, _ = split_front_matter(text)
    meta = meta_from_front_matter(
        front_matter,
        fallback_title=_title_from_markdown(text) or source.stem.replace("-", " ").title(),
    )
    if args.title:
        meta.title = args.title
    if args.subtitle:
        meta.subtitle = args.subtitle
    if args.classification:
        meta.classification = args.classification
    if args.generated:
        meta.generated = args.generated
    meta.fields = list(meta.fields) + [(name, value) for name, value in args.field]
    if args.no_cover:
        meta.cover = False
    if args.no_toc:
        meta.toc = False
    return meta


def _resolve_output(args: argparse.Namespace, source: Path, fmt: str) -> Path:
    if args.output:
        return args.output
    directory = args.outdir or source.parent
    return directory / f"{source.stem}.{fmt}"


def main(argv=None) -> int:
    args = _parse_args(argv)
    fmt = args.format or (
        args.output.suffix.lstrip(".").lower() if args.output else "pdf"
    )
    if fmt not in _FORMATS:
        print(f"error: unsupported format {fmt!r}; choose from {', '.join(_FORMATS)}",
              file=sys.stderr)
        return 2

    failures = 0
    for source in args.sources:
        if not source.is_file():
            print(f"error: {source} is not a file", file=sys.stderr)
            failures += 1
            continue
        try:
            text = source.read_text(encoding="utf-8")
            output = _resolve_output(args, source, fmt)
            render_file(source, output, meta=_build_meta(args, source, text), fmt=fmt)
            print(f"{source} -> {output}")
        except (MarkdownRenderError, OSError, UnicodeDecodeError) as exc:
            print(f"error: {source}: {exc}", file=sys.stderr)
            failures += 1

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
