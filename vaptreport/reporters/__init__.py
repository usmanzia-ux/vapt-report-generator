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
        # A .docx template can't render to PDF directly — build the docx in the
        # company format, then convert it to PDF via LibreOffice.
        if template and template.lower().endswith(".docx"):
            return _pdf_from_docx(report, output, template)
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


def _pdf_from_docx(report: Report, output: str, template: str) -> str:
    """Build the report as a .docx in the company template, then convert it to PDF
    with LibreOffice. A *branded* PDF needs a converter (LibreOffice or Word) —
    there is no pure-Python way. If LibreOffice is missing or fails, we save the
    branded .docx next to the requested PDF and tell the user to use Word's
    'Save As → PDF' so they always get a usable, branded file."""
    import shutil
    import subprocess
    import tempfile
    from pathlib import Path

    from . import docx as _docx

    def _save_docx_fallback(reason: str) -> str:
        alt = str(Path(output).with_suffix(".docx"))
        _docx.render(report, alt, template_path=template)
        raise RuntimeError(
            f"{reason}\n"
            f"A branded PDF needs LibreOffice or Microsoft Word to do the "
            f"conversion — there's no way around that.\n"
            f"  ✓ I saved your branded Word report at: {alt}\n"
            f"  → Open it in Word/LibreOffice and use File → Save As → PDF.\n"
            f"  (Or install LibreOffice: sudo apt install libreoffice, then retry.)"
        )

    soffice = shutil.which("soffice") or shutil.which("libreoffice")
    if not soffice:
        return _save_docx_fallback("LibreOffice isn't installed, so I can't make the PDF directly.")

    with tempfile.TemporaryDirectory() as tmp:
        docx_path = str(Path(tmp) / "report.docx")
        _docx.render(report, docx_path, template_path=template)

        # Use an isolated LibreOffice profile so the conversion works even when a
        # LibreOffice window is already open (otherwise it fails on a profile lock).
        profile = Path(tmp) / "lo_profile"
        cmd = [
            soffice, "--headless", "--norestore", "--nolockcheck",
            f"-env:UserInstallation=file://{profile}",
            "--convert-to", "pdf:writer_pdf_Export", "--outdir", tmp, docx_path,
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=300)
        except Exception as exc:  # noqa: BLE001
            return _save_docx_fallback(f"LibreOffice could not be run ({exc}).")
        produced = Path(tmp) / "report.pdf"
        if proc.returncode != 0 or not produced.exists():
            detail = (proc.stderr or proc.stdout or b"").decode("utf-8", "replace").strip()
            return _save_docx_fallback(
                f"LibreOffice failed to convert the report to PDF ({detail or 'no output'})."
            )
        shutil.copyfile(produced, output)
    return output


__all__ = ["render"]
