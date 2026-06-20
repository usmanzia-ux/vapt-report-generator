"""Render a Report to a Microsoft Word (.docx) document.

Three modes, chosen automatically:

* **Default layout** — no template given: a clean professional report is built
  from scratch with ``python-docx``.

* **Tagged template (precise fill)** — the user's ``.docx`` contains Jinja2
  placeholders (``{{ client }}``, ``{% for f in findings %}`` …). It is filled
  with ``docxtpl`` straight into the company's own layout. Best control.

* **Branding shell (any template)** — the user's ``.docx`` has *no* tags (a
  normal company report template). We keep the whole document — cover, intro,
  methodology, header/footer, fonts, branding — and **append** the generated
  findings as a new section, rendered in the document's own styles. This is what
  makes "bring any company template" work without hand-tagging anything.

python-docx / docxtpl are optional; install with
``pip install 'vapt-report-generator[docx]'``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from ..models import Report

# Severity → RGB accent.
_SEV_RGB = {
    "Critical": (176, 0, 32),
    "High": (211, 84, 0),
    "Medium": (184, 134, 11),
    "Low": (46, 125, 50),
    "Informational": (96, 125, 139),
}

# Table styles we'd like, in order; we fall back to whatever the document has.
_SUMMARY_STYLES = ("Light List Accent 1", "Light List", "Table Grid")
_META_STYLES = ("Light Grid Accent 1", "Light Grid", "Table Grid")


def _context(report: Report) -> dict:
    """Flat, template-friendly context exposed to a user's tagged docx template."""
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

    Run text is rejoined by python-docx, so tags split across runs are detected.
    """
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


def _pick_table_style(doc, names):
    available = {s.name for s in doc.styles}
    for n in names:
        if n in available:
            return n
    return None


def _build_findings_body(doc, report) -> None:
    """Append the summary table + per-finding details into ``doc`` using its
    own styles (so it inherits the template's theme/branding)."""
    from docx.shared import RGBColor

    # ---- Summary table ----
    doc.add_heading("Summary of Vulnerability Findings", level=1)
    summary = doc.add_table(rows=1, cols=4)
    style = _pick_table_style(doc, _SUMMARY_STYLES)
    if style:
        summary.style = style
    hdr = summary.rows[0].cells
    for i, h in enumerate(("ID", "Finding", "Severity", "CVSS")):
        hdr[i].text = h
        if hdr[i].paragraphs[0].runs:
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

    # ---- Per-finding detail ----
    doc.add_heading("Vulnerability Technical Details", level=1)
    for f in report.findings:
        h = doc.add_heading(level=2)
        run = h.add_run(f"{f.finding_id} — {f.title} [{f.severity.value}]")
        rgb = _SEV_RGB.get(f.severity.value)
        if rgb:
            run.font.color.rgb = RGBColor(*rgb)

        bits = []
        if f.cvss_score is not None:
            bits.append(f"CVSS {f.cvss_score:.1f}")
        if f.cvss_vector:
            bits.append(f.cvss_vector)
        if f.cwe:
            bits.append(f.cwe)
        if f.cve:
            bits.append(", ".join(f.cve))
        bits.append(f"Source: {f.source}")
        doc.add_paragraph(" · ".join(bits))

        if f.targets:
            p = doc.add_paragraph()
            p.add_run("Affected: ").bold = True
            p.add_run(", ".join(t.label() for t in f.targets))
        if f.description:
            doc.add_paragraph().add_run("Vulnerability Description:").bold = True
            doc.add_paragraph(f.description)
        if f.evidence:
            doc.add_paragraph().add_run("Proof of Concept / Evidence:").bold = True
            doc.add_paragraph(f.evidence)
        if f.remediation:
            doc.add_paragraph().add_run("Recommendation:").bold = True
            doc.add_paragraph(f.remediation)
        if f.references:
            doc.add_paragraph().add_run("References:").bold = True
            for ref in f.references:
                try:
                    doc.add_paragraph(ref, style="List Bullet")
                except KeyError:
                    doc.add_paragraph(f"• {ref}")


def _render_default(report: Report, output: str) -> str:
    """Build a professional report from scratch (no template needed)."""
    try:
        from docx import Document
        from docx.enum.text import WD_ALIGN_PARAGRAPH
        from docx.shared import Pt
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "DOCX output requires python-docx. Install with:\n"
            "    pip install 'vapt-report-generator[docx]'"
        ) from exc

    doc = Document()

    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = title.add_run(report.title)
    run.bold = True
    run.font.size = Pt(24)

    sub = doc.add_paragraph()
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sub.add_run(f"Prepared for: {report.client}").font.size = Pt(14)
    doc.add_paragraph()

    meta = doc.add_table(rows=0, cols=2)
    style = _pick_table_style(doc, _META_STYLES)
    if style:
        meta.style = style
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
        if cells[0].paragraphs[0].runs:
            cells[0].paragraphs[0].runs[0].bold = True

    _build_findings_body(doc, report)
    doc.save(output)
    return output


def _render_branding_shell(report: Report, output: str, template_path: str) -> str:
    """Use an untagged company template as a branded shell: keep all of its
    content/styling and append the generated findings as a new section."""
    from docx import Document
    from docx.enum.text import WD_BREAK

    doc = Document(template_path)
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)  # start on a fresh page
    _build_findings_body(doc, report)
    doc.save(output)
    return output


def _render_template(report: Report, output: str, template_path: str) -> str:
    """Fill a tagged .docx company template with the report data via docxtpl."""
    try:
        from docxtpl import DocxTemplate
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "DOCX output requires python-docx + docxtpl. Install with:\n"
            "    pip install 'vapt-report-generator[docx]'"
        ) from exc

    doc = DocxTemplate(template_path)
    doc.render(_context(report))
    doc.save(output)
    return output


def render(report: Report, output: str, template_path: Optional[str] = None) -> str:
    """Render ``report`` to a .docx file.

    * no template            → default professional layout
    * template WITH {{ }} tags → precise fill via docxtpl
    * template WITHOUT tags    → branding shell: keep it, append the findings
    """
    if not template_path:
        return _render_default(report, output)

    if not Path(template_path).exists():
        raise FileNotFoundError(f"Template not found: {template_path}")
    if not template_path.lower().endswith(".docx"):
        raise ValueError(
            f"For DOCX output a custom template must be a .docx file, not "
            f"'{Path(template_path).name}'."
        )

    if _template_has_placeholders(template_path):
        return _render_template(report, output, template_path)
    return _render_branding_shell(report, output, template_path)
