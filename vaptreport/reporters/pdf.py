"""Render a Report to PDF by converting the HTML report with WeasyPrint.

Supports custom templates (``template_path``) so the PDF can use a company's
own branding/layout. WeasyPrint is an optional dependency; install with
``pip install 'vapt-report-generator[pdf]'``.
"""

from __future__ import annotations

from typing import Optional

from ..models import Report
from .html import render_string


def render(report: Report, output: str, template_path: Optional[str] = None) -> str:
    try:
        from weasyprint import HTML
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "PDF output requires WeasyPrint. Install it with:\n"
            "    pip install 'vapt-report-generator[pdf]'\n"
            "(WeasyPrint also needs system libraries: see its install docs.)"
        ) from exc

    HTML(string=render_string(report, template_path)).write_pdf(output)
    return output
