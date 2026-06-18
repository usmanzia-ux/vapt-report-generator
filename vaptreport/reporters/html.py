"""Render a Report to a standalone HTML file via Jinja2."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models import Report

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_string(report: Report) -> str:
    """Return the rendered HTML as a string (used by the PDF reporter too)."""
    template = _env().get_template("report.html.j2")
    return template.render(report=report)


def render(report: Report, output: str) -> str:
    Path(output).write_text(render_string(report), encoding="utf-8")
    return output
