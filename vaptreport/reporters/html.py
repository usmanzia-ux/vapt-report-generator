"""Render a Report to a standalone HTML file via Jinja2.

A custom template may be supplied (``template_path``) so the report can match a
company's own branding/layout instead of the bundled generic theme.

Autoescaping is forced ON: findings come from untrusted scanner output and may
contain HTML/JS payloads (e.g. an XSS proof-of-concept in an evidence field).
Without escaping, opening the report in a browser would execute that payload.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader

from ..models import Report

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
_DEFAULT_TEMPLATE = "report.html.j2"


def _env(search_dir: Path) -> Environment:
    return Environment(
        loader=FileSystemLoader(str(search_dir)),
        autoescape=True,  # force-on: report data is untrusted
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_string(report: Report, template_path: Optional[str] = None) -> str:
    """Return the rendered HTML as a string (also used by the PDF reporter).

    If ``template_path`` is given, that file is used as the Jinja2 template;
    otherwise the bundled generic template is used.
    """
    if template_path:
        p = Path(template_path)
        if not p.exists():
            raise FileNotFoundError(f"Template not found: {template_path}")
        env = _env(p.resolve().parent)
        template = env.get_template(p.name)
    else:
        env = _env(_TEMPLATE_DIR)
        template = env.get_template(_DEFAULT_TEMPLATE)
    return template.render(report=report)


def render(report: Report, output: str, template_path: Optional[str] = None) -> str:
    Path(output).write_text(render_string(report, template_path), encoding="utf-8")
    return output
