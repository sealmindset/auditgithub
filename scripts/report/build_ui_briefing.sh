#!/usr/bin/env bash
# Render the UI design-system briefing, its deck, and the technical companion.
#
# The markdown is the source of truth; the PDF and PPTX are build products that are
# committed so readers without a toolchain can open them. Re-run this after editing any
# of the markdown, and commit what changes.
#
# Requires: pandoc and weasyprint (both from homebrew). No LaTeX needed - weasyprint is
# the PDF engine, which is why the styling lives in CSS rather than a template.
#
#   ./scripts/report/build_ui_briefing.sh
set -euo pipefail

cd "$(dirname "$0")/../.."
DOCS="docs/playbooks"
CSS="scripts/report"
STEM="$DOCS/ui-design-system"

for tool in pandoc weasyprint; do
  command -v "$tool" >/dev/null || { echo "missing: $tool (brew install $tool)" >&2; exit 1; }
done

# The named appendix is generated from the two committed auditors, never edited by hand.
# It carries no YAML front matter for that reason.
python3 "$CSS/build_ui_appendix.py"
APPENDIX="$STEM-appendix.md"

# The briefing. -f gfm because the markdown is written to read well on GitHub too.
# pagetitle rather than title: the document already carries its own H1, and setting
# `title` would render it a second time above that.
echo "briefing -> pdf"
pandoc "$STEM-plain-language.md" "$APPENDIX" \
  -f gfm -t pdf \
  --pdf-engine=weasyprint \
  --css="$CSS/briefing.css" \
  -M pagetitle="The AuditGH Screen - A Plain-Language Briefing" \
  -o "$STEM-plain-language.pdf" 2>&1 | grep -v '^WARNING: Ignored' || true

# The technical companion gets the same treatment: the people who need the detail are not
# all working from a checkout.
echo "companion -> pdf"
pandoc "$STEM-report.md" "$APPENDIX" \
  -f gfm -t pdf \
  --pdf-engine=weasyprint \
  --css="$CSS/briefing.css" \
  -M pagetitle="AuditGH Web UI - Design System Overhaul: Technical Companion" \
  -o "$STEM-report.pdf" 2>&1 | grep -v '^WARNING: Ignored' || true

# The deck, twice: PowerPoint for presenting, PDF for forwarding.
# Keep any trailing prose ABOVE a table on a slide - pandoc gives a table its own
# pptx slide and pushes whatever follows onto an untitled orphan slide.
echo "slides -> pptx"
pandoc "$STEM-slides.md" \
  -f markdown -t pptx --slide-level=2 \
  -o "$STEM-slides.pptx"

# The PDF of the deck prints the speaker notes under each slide on purpose: it gets
# forwarded to people who were not in the room, and the notes are what make the
# slides stand on their own.
echo "slides -> pdf"
pandoc "$STEM-slides.md" \
  -f markdown -t pdf --standalone \
  --pdf-engine=weasyprint \
  --css="$CSS/slides.css" \
  -o "$STEM-slides.pdf" 2>&1 | grep -v '^WARNING: Ignored' || true

echo
ls -lh "$STEM"-*.pdf "$STEM"-*.pptx
