"""Render a Report to a Microsoft Word (.docx) document.

Two modes:

* **Default layout** — when no template is given, a clean professional report is
  built from scratch with ``python-docx`` (cover, metadata, severity summary,
  findings table, and a detailed section per finding).

* **Bring-your-own template** — when the user supplies their own ``.docx``
  company template, it is filled with ``docxtpl``. This is the real
  "use my company template, fill every field" workflow: the template holds
  Jinja2 placeholders (``{{ client }}``, ``{% for f in findings %}`` …) and we
  render the findings straight into the company's own layout. See
  ``examples/company_template.docx`` notes in the README for the placeholders.

python-docx / docxtpl are optional; install with
``pip install 'vapt-report-generator[docx]'``.
"""

from __future__ import annotations

from typing import Optional

from ..models import Report

# Severity → RGB accent used in the default layout.
_SEV_RGB = {
    "Critical": (176, 0, 32),
    "High": (211, 84, 0),
    "Medium": (184, 134, 11),
    "Low": (46, 125, 50),
    "Informational": (96, 125, 139),
}


def _context(report: Report) -> dict:
    """Flat, template-friendly context exposed to a user's docx template."""
    return {
        "report": report,
        "client": report.client,
        "title": report.title,
        "assessor": report.assessor,
        "date": report.assessment_date,
        "standard": report.standard,
        "scope": report.scope,
        "risk_rating": report.risk_rating(),
        "counts": report.severity_counts(),
        "findings": report.findings,
        "total": len(report.findings),
    }


def _template_has_placeholders(template_path: str) -> bool:
    """True if the .docx contains any Jinja2 tags ({{ }} or {% %}).

    A template with no tags has nothing to fill — docxtpl would just copy it.
    We scan body paragraphs, tables, and headers/footers (run text is rejoined
    by python-docx, so split tags are still detected)."""
    from docx import Document

    doc = Document(template_path)

    def _iter_text():
        for p in doc.paragraphs:
            yield p.text
        for t in doc.tables:
            for row in t.rows:
                for cell in row.cells:
                    for p in cell.paragraphs:
                        yield p.text
        for section in doc.sections:
            for hf in (section.header, section.footer):
                for p in hf.paragraphs:
                    yield p.text

    blob = "\n".join(_iter_text())
    return "{{" in blob or "{%" in blob


def _render_template(report: Report, output: str, template_path: str) -> str:
    """Fill a user-supplied .docx company template with the report data."""
    try:
        from docxtpl import DocxTemplate
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "DOCX output requires python-docx + docxtpl. Install with:\n"
            "    pip install 'vapt-report-generator[docx]'"
        ) from exc

    if not _template_has_placeholders(template_path):
        from pathlib import Path

        raise ValueError(
            f"template '{Path(template_path).name}' contains no placeholders, so "
            "there is nothing to fill — the output would just be a copy of your "
            "template. A .docx template must contain Jinja2 placeholders telling "
            "the tool where each value goes, e.g. {{ client }}, {{ date }}, and a "
            "findings loop:\n"
            "    {% for f in findings %}\n"
            "    {{ f.finding_id }} - {{ f.title }} [{{ f.severity.value }}]\n"
            "    {{ f.description }}\n"
            "    {% endfor %}\n"
            "Copy examples/company_template.docx (already tagged) and restyle it, "
            "or add these tags into your own template."
        )

    doc = DocxTemplate(template_path)
    doc.render(_context(report))
    doc.save(output)
    return output


def _render_default(report: Report, output: str) -> str:
    """Build a professional report from scratch (no template needed)."""
    try:
        from docx import Document
        from docx.enum.text import WD_ALIGN_PARAGRAPH
        from docx.shared import Pt, RGBColor
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "DOCX output requires python-docx. Install with:\n"
            "    pip install 'vapt-report-generator[docx]'"
        ) from exc

    doc = Document()

    # ---- Cover ----
    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = title.add_run(report.title)
    run.bold = True
    run.font.size = Pt(24)

    sub = doc.add_paragraph()
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sub.add_run(f"Prepared for: {report.client}").font.size = Pt(14)

    doc.add_paragraph()  # spacer

    meta = doc.add_table(rows=0, cols=2)
    meta.style = "Light Grid Accent 1"
    counts = report.severity_counts()
    for k, v in [
        ("Overall Risk", report.risk_rating()),
        ("Assessor", report.assessor),
        ("Date", report.assessment_date),
        ("Standard", report.standard),
        ("Findings", str(len(report.findings))),
        ("Scope", ", ".join(report.scope) if report.scope else "—"),
    ]:
        cells = meta.add_row().cells
        cells[0].text = k
        cells[1].text = v
        cells[0].paragraphs[0].runs[0].bold = True

    # ---- Summary ----
    doc.add_heading("Findings Summary", level=1)
    summary = doc.add_table(rows=1, cols=4)
    summary.style = "Light List Accent 1"
    hdr = summary.rows[0].cells
    for i, h in enumerate(("ID", "Finding", "Severity", "CVSS")):
        hdr[i].text = h
        hdr[i].paragraphs[0].runs[0].bold = True
    for f in report.findings:
        c = summary.add_row().cells
        c[0].text = f.finding_id
        c[1].text = f.title
        c[2].text = f.severity.value
        c[3].text = f"{f.cvss_score:.1f}" if f.cvss_score is not None else "—"
        rgb = _SEV_RGB.get(f.severity.value)
        if rgb and c[2].paragraphs[0].runs:
            c[2].paragraphs[0].runs[0].font.color.rgb = RGBColor(*rgb)

    # ---- Detailed findings ----
    doc.add_heading("Detailed Findings", level=1)
    for f in report.findings:
        h = doc.add_heading(level=2)
        run = h.add_run(f"{f.finding_id} — {f.title} [{f.severity.value}]")
        rgb = _SEV_RGB.get(f.severity.value)
        if rgb:
            run.font.color.rgb = RGBColor(*rgb)

        bits = []
        if f.cvss_score is not None:
            bits.append(f"CVSS {f.cvss_score:.1f}")
        if f.cwe:
            bits.append(f.cwe)
        if f.cve:
            bits.append(", ".join(f.cve))
        bits.append(f"Source: {f.source}")
        doc.add_paragraph(" · ".join(bits)).italic = True

        if f.targets:
            p = doc.add_paragraph()
            p.add_run("Targets: ").bold = True
            p.add_run(", ".join(t.label() for t in f.targets))
        if f.description:
            doc.add_paragraph().add_run("Description").bold = True
            doc.add_paragraph(f.description)
        if f.evidence:
            doc.add_paragraph().add_run("Evidence").bold = True
            ev = doc.add_paragraph(f.evidence)
            ev.style = doc.styles["Intense Quote"] if "Intense Quote" in [s.name for s in doc.styles] else ev.style
        if f.remediation:
            doc.add_paragraph().add_run("Remediation").bold = True
            doc.add_paragraph(f.remediation)
        if f.references:
            doc.add_paragraph().add_run("References").bold = True
            for ref in f.references:
                doc.add_paragraph(ref, style="List Bullet")

    doc.save(output)
    return output


def render(report: Report, output: str, template_path: Optional[str] = None) -> str:
    """Render ``report`` to a .docx file.

    If ``template_path`` is a ``.docx`` file it is filled via docxtpl; otherwise
    a default professional layout is generated.
    """
    if template_path:
        from pathlib import Path

        if not Path(template_path).exists():
            raise FileNotFoundError(f"Template not found: {template_path}")
        if not template_path.lower().endswith(".docx"):
            raise ValueError(
                f"For DOCX output a custom template must be a .docx file, not "
                f"'{Path(template_path).name}'. A .docx template holds the "
                "placeholders ({{ client }}, {% for f in findings %} …) that get "
                "filled. See the README for the template field reference."
            )
        return _render_template(report, output, template_path)
    return _render_default(report, output)
