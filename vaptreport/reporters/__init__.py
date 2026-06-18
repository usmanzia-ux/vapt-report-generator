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

    Supported formats: ``pdf``, ``html``, ``xlsx``. A custom ``template`` (an
    HTML/Jinja2 file) applies to the ``pdf`` and ``html`` formats. Returns the
    output path.
    """
    fmt = fmt.lower()
    if fmt == "html":
        return _html.render(report, output, template_path=template)
    if fmt == "pdf":
        from . import pdf as _pdf  # lazy: weasyprint is an optional dependency

        return _pdf.render(report, output, template_path=template)
    if fmt in ("xlsx", "excel"):
        if template:
            raise ValueError("Custom templates are not supported for xlsx output.")
        return _excel.render(report, output)
    raise ValueError(f"Unknown format '{fmt}'. Choose: pdf, html, xlsx")


__all__ = ["render"]
