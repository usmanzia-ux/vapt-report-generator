"""Output reporters that render a Report into a file."""

from __future__ import annotations

from typing import Optional

from ..models import Report
from . import excel as _excel
from . import html as _html


def render(
    report: Report,
    fmt: str,
    output: str,
    template: Optional[str] = None,
) -> str:
    """Render ``report`` to ``output`` in the requested ``fmt``.

    Supported formats: ``pdf``, ``html``, ``docx``, ``xlsx``. A custom
    ``template`` applies to ``pdf``/``html`` (an HTML/Jinja2 file) and ``docx``
    (a .docx company template filled with docxtpl). Returns the output path.
    """
    fmt = fmt.lower()
    if fmt == "html":
        return _html.render(report, output, template_path=template)
    if fmt == "pdf":
        from . import pdf as _pdf  # lazy: weasyprint is an optional dependency

        return _pdf.render(report, output, template_path=template)
    if fmt in ("docx", "word"):
        from . import docx as _docx  # lazy: python-docx is an optional dependency

        return _docx.render(report, output, template_path=template)
    if fmt in ("xlsx", "excel"):
        if template:
            raise ValueError("Custom templates are not supported for xlsx output.")
        return _excel.render(report, output)
    raise ValueError(f"Unknown format '{fmt}'. Choose: pdf, html, docx, xlsx")


__all__ = ["render"]
