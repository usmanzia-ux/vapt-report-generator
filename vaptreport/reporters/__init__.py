"""Output reporters that render a Report into a file."""

from __future__ import annotations

from ..models import Report
from . import excel as _excel
from . import html as _html


def render(report: Report, fmt: str, output: str) -> str:
    """Render ``report`` to ``output`` in the requested ``fmt``.

    Supported formats: ``html``, ``pdf``, ``xlsx``. Returns the output path.
    """
    fmt = fmt.lower()
    if fmt == "html":
        return _html.render(report, output)
    if fmt == "pdf":
        from . import pdf as _pdf  # lazy: weasyprint is an optional dependency

        return _pdf.render(report, output)
    if fmt in ("xlsx", "excel"):
        return _excel.render(report, output)
    raise ValueError(f"Unknown format '{fmt}'. Choose: html, pdf, xlsx")


__all__ = ["render"]
