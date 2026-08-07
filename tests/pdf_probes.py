"""
Reading facts back out of a rendered PDF.

WeasyPrint packs most object definitions into deflated `/ObjStm` streams, so grepping a
PDF as plaintext finds neither `/BaseFont` nor `/Type /Page`. That looks exactly like a
document with no fonts and no pages, and it is how the first versions of the font and
page-count assertions both failed against perfectly good output. Inflate first.
"""

import io
import re
import zlib


def pdf_objects(pdf: bytes) -> bytes:
    """A PDF's object definitions as searchable bytes, compressed ones included."""
    parts = [pdf]
    for match in re.finditer(rb"stream\r?\n", pdf):
        start = match.end()
        end = pdf.find(b"endstream", start)
        try:
            parts.append(zlib.decompress(pdf[start:end]))
        except zlib.error:
            continue  # not a deflate stream (an image, or already plaintext)
    return b"\n".join(parts)


def embedded_fonts(pdf: bytes) -> set:
    """The font families a PDF embeds, minus the random per-build subset tag."""
    names = re.findall(rb"/BaseFont\s*/([A-Za-z0-9+\-]+)", pdf_objects(pdf))
    return {n.decode("ascii", "replace").split("+")[-1] for n in names}


def page_count(pdf: bytes) -> int:
    # `/Type /Page` and not `/Type /Pages`, which is the tree node rather than a leaf.
    return len(re.findall(rb"/Type\s*/Page[^s]", pdf_objects(pdf)))


def bitmap_only_fonts(pdf: bytes) -> set:
    """
    Embedded fonts whose glyphs are color bitmaps rather than outlines.

    WeasyPrint embeds a CBDT/sbix font quite happily and then draws nothing from it: the
    glyph keeps its advance width and the reader sees a gap. Nothing about that is
    visible in the byte count, the page count or `pdftotext`, so this is the probe that
    distinguishes "the mark rendered" from "the mark was silently omitted".
    """
    from fontTools.ttLib import TTFont

    found = set()
    for stream in _font_programs(pdf):
        try:
            font = TTFont(io.BytesIO(stream), fontNumber=0, lazy=True)
        except Exception:
            continue  # not a TrueType/OpenType program (Type1, or a subset we cannot parse)
        tables = set(font.keys())
        if tables & {"CBDT", "sbix"} and not tables & {"glyf", "CFF ", "CFF2"}:
            found.add(_font_name(font))
    return found


def _font_programs(pdf: bytes):
    """The inflated FontFile2/FontFile3 streams a PDF carries."""
    for match in re.finditer(rb"stream\r?\n", pdf):
        start = match.end()
        end = pdf.find(b"endstream", start)
        try:
            data = zlib.decompress(pdf[start:end])
        except zlib.error:
            continue
        if data[:4] in (b"\x00\x01\x00\x00", b"true", b"ttcf", b"OTTO"):
            yield data


def _font_name(font) -> str:
    try:
        for record in font["name"].names:
            if record.nameID == 6:
                return str(record)
    except Exception:
        pass
    return "<unnamed>"


def discarded_declarations(render) -> list:
    """
    Run `render` and return the stylesheet declarations WeasyPrint threw away.

    An unsupported declaration is a warning on stderr, never an error, so a stylesheet
    can rot one property at a time while every render still "succeeds".
    """
    import logging

    records = []

    class Capture(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    logger = logging.getLogger("weasyprint")
    handler = Capture(level=logging.WARNING)
    logger.addHandler(handler)
    try:
        render()
    finally:
        logger.removeHandler(handler)

    return [m for m in records if "Ignored" in m or "invalid value" in m]
