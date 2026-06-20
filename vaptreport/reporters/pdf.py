"""Render a Report to PDF by converting the HTML report with WeasyPrint.

Supports custom templates (``template_path``) so the PDF can use a company's
own branding/layout. WeasyPrint is an optional dependency; install with
``pip install 'vapt-report-generator[pdf]'``.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Optional

from ..models import Report
from .html import render_string


def _render_with_pdf_cover(report: Report, output: str, cover_pdf: str) -> str:
    """A flat PDF can't be field-filled, but we can still *use* it: take its
    first page as the report cover/letterhead and append our rendered findings.

    This is the honest best-effort for a PDF "template" — the company's cover
    page is preserved, and the findings follow in the default styling. For true
    field-by-field filling, use a .docx or .html.j2 template instead.
    """
    from pypdf import PdfReader, PdfWriter
    from weasyprint import HTML

    body_bytes = HTML(string=render_string(report, None)).write_pdf()

    writer = PdfWriter()
    cover = PdfReader(cover_pdf)
    if cover.pages:
        writer.add_page(cover.pages[0])  # first page = cover/letterhead
    for page in PdfReader(io.BytesIO(body_bytes)).pages:
        writer.add_page(page)
    with open(output, "wb") as fh:
        writer.write(fh)
    return output


def render(report: Report, output: str, template_path: Optional[str] = None) -> str:
    try:
        from weasyprint import HTML
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "PDF output requires WeasyPrint. Install it with:\n"
            "    pip install 'vapt-report-generator[pdf]'\n"
            "(WeasyPrint also needs system libraries: see its install docs.)"
        ) from exc

    # A PDF template: reuse its cover page rather than treating it as Jinja2.
    if template_path and template_path.lower().endswith(".pdf"):
        if not Path(template_path).exists():
            raise FileNotFoundError(f"Template not found: {template_path}")
        return _render_with_pdf_cover(report, output, template_path)

    HTML(string=render_string(report, template_path)).write_pdf(output)
    return output
