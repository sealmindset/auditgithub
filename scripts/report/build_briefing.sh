#!/usr/bin/env bash
# Render the plain-language supply-chain briefing and its deck.
#
# The markdown is the source of truth; the PDF and PPTX are build products that are
# committed so non-technical readers can open them without a toolchain. Re-run this
# after editing either markdown file, and commit what changes.
#
# Requires: pandoc and weasyprint (both from homebrew). No LaTeX needed - weasyprint
# is the PDF engine, which is why the styling lives in CSS rather than a template.
#
#   ./scripts/report/build_briefing.sh
set -euo pipefail

cd "$(dirname "$0")/../.."
DOCS="docs/playbooks"
CSS="scripts/report"

for tool in pandoc weasyprint; do
  command -v "$tool" >/dev/null || { echo "missing: $tool (brew install $tool)" >&2; exit 1; }
done

# The named appendix is generated from the collector artifacts, never edited by hand, and
# concatenated onto both deliverables. It carries no YAML front matter for that reason.
python3 "$CSS/build_appendix.py"
APPENDIX="$DOCS/npm-supply-chain-exposure-appendix.md"

# The briefing. -f gfm because the markdown is written to read well on GitHub too.
# pagetitle rather than title: the document already carries its own H1, and setting
# `title` would render it a second time above that.
echo "briefing -> pdf"
pandoc "$DOCS/npm-supply-chain-exposure-plain-language.md" "$APPENDIX" \
  -f gfm -t pdf \
  --pdf-engine=weasyprint \
  --css="$CSS/briefing.css" \
  -M pagetitle="Software Supply Chain - A Plain-Language Briefing" \
  -o "$DOCS/npm-supply-chain-exposure-plain-language.pdf" 2>&1 | grep -v '^WARNING: Ignored' || true

# The deck, twice: PowerPoint for presenting, PDF for forwarding.
# Keep any trailing prose ABOVE a table on a slide - pandoc gives a table its own
# pptx slide and pushes whatever follows onto an untitled orphan slide.
echo "slides -> pptx"
pandoc "$DOCS/npm-supply-chain-exposure-slides.md" "$APPENDIX" \
  -f markdown -t pptx --slide-level=2 \
  -o "$DOCS/npm-supply-chain-exposure-slides.pptx"

# The PDF of the deck prints the speaker notes under each slide on purpose: it gets
# forwarded to people who were not in the room, and the notes are what make the
# slides stand on their own.
echo "slides -> pdf"
pandoc "$DOCS/npm-supply-chain-exposure-slides.md" "$APPENDIX" \
  -f markdown -t pdf --standalone \
  --pdf-engine=weasyprint \
  --css="$CSS/slides.css" \
  -o "$DOCS/npm-supply-chain-exposure-slides.pdf" 2>&1 | grep -v '^WARNING: Ignored' || true

echo
ls -lh "$DOCS"/npm-supply-chain-exposure-*.pdf "$DOCS"/npm-supply-chain-exposure-*.pptx
