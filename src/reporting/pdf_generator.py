"""
Scan-report documents.

Historically this module carried a reportlab writer that was never finished and never
imported — its own header admitted as much ("adding a heavy PDF dependency might
complicate the environment"). It now builds Markdown and hands it to the shared renderer,
so a scan report looks like every other document this system produces and gains the
cover page, running header, table of contents and repeating table headers for free.

`ReportGenerator` keeps its previous signature so any caller written against it still
works, but `generate_scan_report` now genuinely produces a PDF rather than silently
writing Markdown beside it.

A scan report is read by the same person, with the same three questions, as a zero-day
analysis, so it is built in the same three parts (see `briefing`). The scanner detail
that used to be the whole document becomes Part 3.1 — it is still there in full, but it
is no longer the first thing a reader who owns the response has to wade through.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Sequence

from .md_to_pdf import (
    DocumentMeta,
    MarkdownRenderError,
    markdown_to_html,
    markdown_to_pdf,
)

logger = logging.getLogger(__name__)

# Order matters: a report is read top-down and the reader must meet the worst finding
# first. Anything with an unrecognized severity is counted under "other" rather than
# dropped, because a finding that vanishes from the summary is worse than a miscategorized
# one.
_SEVERITIES = ("critical", "high", "medium", "low", "info")


def _severity(finding: Dict[str, Any]) -> str:
    value = str(finding.get("severity") or "").strip().lower()
    return value if value in _SEVERITIES else "other"


def _escape(value: Any) -> str:
    """Escape a scan value for Markdown prose. Scan data is not authored Markdown."""
    text = "" if value is None else str(value)
    for char in ("\\", "`", "*", "_", "[", "]", "|"):
        text = text.replace(char, "\\" + char)
    return text


def _cell(value: Any) -> str:
    return " ".join(_escape(value).split())


def build_scan_markdown(
    scan_data: Dict[str, Any],
    findings: Sequence[Dict[str, Any]],
    *,
    briefed: bool = True,
) -> str:
    """
    Render a scan result as a Markdown document.

    `briefed=True` produces the three-part document: situation, ordered plan, then the
    scanner detail as evidence. `briefed=False` returns the evidence alone, which is what
    a caller embedding this inside a larger document wants.
    """
    if not briefed:
        return _scan_evidence_markdown(scan_data, findings)

    from .briefing import (
        briefing_from_dict,
        compose_document,
        deterministic_briefing,
        findings_from_scan,
    )

    model = findings_from_scan(findings)
    # Authoring is an analysis-time job, never a render-time one: a report re-exported
    # next month must come out identical to the one filed today, and a model call here
    # would make the document a function of when it was printed.
    stored = scan_data.get("briefing")
    briefing = briefing_from_dict(stored, model) if isinstance(stored, dict) else None
    if briefing is None:
        briefing = deterministic_briefing(model, scan_data)

    return compose_document(
        briefing,
        model,
        evidence_body=_scan_evidence_markdown(scan_data, findings),
    )


def _scan_evidence_markdown(
    scan_data: Dict[str, Any],
    findings: Sequence[Dict[str, Any]],
) -> str:
    """The scanner detail, in full and unsummarized. Part 3.1 of the briefed document."""
    counts = {name: 0 for name in _SEVERITIES}
    counts["other"] = 0
    for finding in findings:
        counts[_severity(finding)] += 1

    lines: List[str] = ["## Summary", ""]
    lines.append(f"**{len(findings)}** finding(s) recorded for this scan.")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | --- |")
    for name in _SEVERITIES:
        lines.append(f"| {name.capitalize()} | {counts[name]} |")
    if counts["other"]:
        lines.append(f"| Unclassified | {counts['other']} |")
    lines.append("")

    lines.append("## Detailed Findings")
    lines.append("")
    if not findings:
        lines.append("No findings were recorded for this scan.")
        lines.append("")
        return "\n".join(lines)

    # Grouped by severity so the reader is not asked to re-sort the document mentally.
    ordered = sorted(
        findings,
        key=lambda f: (_SEVERITIES + ("other",)).index(_severity(f)),
    )
    for finding in ordered:
        title = _escape(finding.get("title")) or "Untitled finding"
        lines.append(f"### {title}")
        lines.append("")
        lines.append(f"**Severity:** {_escape(finding.get('severity') or 'unclassified')}")
        lines.append("")
        path = finding.get("file_path")
        if path:
            line_no = finding.get("line_number") or finding.get("line")
            location = f"`{_cell(path)}`" + (f" line {_cell(line_no)}" if line_no else "")
            lines.append(f"**Location:** {location}")
            lines.append("")
        description = str(finding.get("description") or "").strip()
        if description:
            lines.append(_escape(description))
            lines.append("")
        remediation = str(finding.get("remediation") or "").strip()
        if remediation:
            lines.append(f"**Remediation:** {_escape(remediation)}")
            lines.append("")
    return "\n".join(lines)


class ReportGenerator:
    """Generate scan reports as PDF (or any format the shared renderer supports)."""

    def generate_scan_report(
        self,
        scan_data: Dict[str, Any],
        findings: List[Dict[str, Any]],
        output_path: str,
    ) -> bool:
        """
        Write a scan report to `output_path`.

        Returns True on success. The format follows the output suffix (`.pdf`, `.html`
        or `.md`). The old fallback that quietly wrote Markdown to a *different* path
        when reportlab was missing is gone — it produced a file the caller never asked
        for and then reported success.
        """
        repo = scan_data.get("repo_name") or scan_data.get("repository") or "repository"
        meta = DocumentMeta(
            title=f"Security Scan Report — {repo}",
            subtitle=str(scan_data.get("subtitle") or "") or None,
            fields=[
                ("Repository", str(repo)),
                ("Scan ID", str(scan_data.get("scan_id") or "—")),
                ("Scanners", ", ".join(str(s) for s in (scan_data.get("scanners") or []))),
            ],
            generated=datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z"),
        )

        markdown = build_scan_markdown(scan_data, findings)
        destination = Path(output_path)
        suffix = destination.suffix.lstrip(".").lower()
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            if suffix == "pdf":
                destination.write_bytes(markdown_to_pdf(markdown, meta))
            elif suffix in ("html", "htm"):
                destination.write_text(markdown_to_html(markdown, meta), encoding="utf-8")
            elif suffix == "md":
                destination.write_text(markdown, encoding="utf-8")
            else:
                raise MarkdownRenderError(f"Unsupported report format: {suffix!r}")
            logger.info("Scan report written to %s", output_path)
            return True
        except (MarkdownRenderError, OSError) as exc:
            logger.error("Failed to generate scan report: %s", exc)
            return False
