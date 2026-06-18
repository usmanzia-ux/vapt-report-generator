"""Input parsers that convert scanner output into a list of Findings."""

from __future__ import annotations

from pathlib import Path
from typing import List

from ..models import Finding
from . import acunetix_pdf as _acunetix_pdf
from . import findings as _findings
from . import nessus as _nessus
from . import nmap as _nmap


def detect_and_parse(path: str) -> List[Finding]:
    """Auto-detect the input format from extension / content and parse it."""
    p = Path(path)
    suffix = p.suffix.lower()

    if suffix == ".nessus":
        return _nessus.parse(path)
    if suffix in (".json", ".yaml", ".yml"):
        return _findings.parse(path)
    if suffix == ".pdf":
        text = _acunetix_pdf._extract_text(path)
        if "Acunetix" not in text[:4000]:
            raise ValueError(
                f"'{path}' is a PDF but does not look like an Acunetix report. "
                f"Only Acunetix Developer Report PDFs are supported; for other "
                f"scanners use their XML/JSON export or the findings JSON format."
            )
        return _acunetix_pdf.parse_text(text)
    if suffix == ".xml":
        # Distinguish Nmap from Nessus by a cheap content sniff.
        head = p.read_text(errors="ignore")[:2048].lower()
        if "nmaprun" in head:
            return _nmap.parse(path)
        if "nessusclientdata" in head or "policy" in head:
            return _nessus.parse(path)
        return _nmap.parse(path)  # default for unknown XML

    raise ValueError(
        f"Unsupported input '{path}'. Expected .xml (Nmap/Nessus), "
        f".nessus, .pdf (Acunetix), .json, .yaml or .yml"
    )


__all__ = ["detect_and_parse"]
