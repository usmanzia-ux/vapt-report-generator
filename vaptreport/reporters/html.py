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


def _validate_template(path: Path) -> None:
    """Fail early with a clear message if the template isn't a text/Jinja2 file.

    A custom template must be an HTML/Jinja2 source file. Users sometimes pass a
    finished document (commonly a ``.pdf`` of their company report) expecting it
    to be used as the layout — but a PDF is rendered output, not a reusable
    template, and feeding it to Jinja2 only produces a cryptic UTF-8 decode
    crash. Detect that here and explain what's actually needed.
    """
    raw = path.read_bytes()
    if raw[:5] == b"%PDF-":
        raise ValueError(
            f"template '{path.name}' is a PDF, but --template needs an HTML/Jinja2 "
            "file (.html or .html.j2). A PDF is a finished document, not a reusable "
            "layout, so it can't be used as a template. Build one from "
            "examples/custom_template.html.j2 (copy it, restyle to your branding)."
        )
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(
            f"template '{path.name}' is not a UTF-8 text file. --template needs an "
            "HTML/Jinja2 template (.html/.html.j2), not a binary document. "
            "See examples/custom_template.html.j2 for a starting point."
        ) from None


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
        _validate_template(p)
        env = _env(p.resolve().parent)
        template = env.get_template(p.name)
    else:
        env = _env(_TEMPLATE_DIR)
        template = env.get_template(_DEFAULT_TEMPLATE)
    return template.render(report=report)


def render(report: Report, output: str, template_path: Optional[str] = None) -> str:
    Path(output).write_text(render_string(report, template_path), encoding="utf-8")
    return output
