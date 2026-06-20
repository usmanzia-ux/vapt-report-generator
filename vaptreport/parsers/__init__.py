"""Input parsers that convert scanner output into a list of Findings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from ..models import Finding
from . import acunetix_pdf as _acunetix_pdf
from . import burp as _burp
from . import findings as _findings
from . import nessus as _nessus
from . import nmap as _nmap
from . import nuclei as _nuclei
from . import zap as _zap


def _sniff_json(path: str) -> str:
    """Return which JSON dialect a .json/.jsonl file is: zap | nuclei | findings."""
    text = Path(path).read_text(encoding="utf-8").strip()
    if not text:
        return "findings"
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return "nuclei"  # multiple objects => JSON-Lines (Nuclei)

    if isinstance(data, dict):
        if "site" in data:                       # ZAP report
            return "zap"
        if "findings" in data or "report" in data:
            return "findings"
        if "template-id" in data or "template" in data:
            return "nuclei"
        return "findings"
    if isinstance(data, list) and data:
        first = data[0]
        if isinstance(first, dict):
            if "template-id" in first or "template" in first or "matched-at" in first:
                return "nuclei"
            if "title" in first:
                return "findings"
    return "findings"


def _sniff_xml(path: str) -> str:
    """Return which XML dialect: nmap | nessus | burp | zap."""
    head = Path(path).read_text(errors="ignore")[:4096].lower()
    if "nmaprun" in head:
        return "nmap"
    if "nessusclientdata" in head:
        return "nessus"
    if "owaspzapreport" in head:
        return "zap"
    if "<issues" in head or "burpversion" in head:
        return "burp"
    return "nmap"  # default for unknown XML


def detect_and_parse(path: str) -> List[Finding]:
    """Auto-detect the input format from extension / content and parse it."""
    p = Path(path)
    suffix = p.suffix.lower()

    if suffix == ".nessus":
        return _nessus.parse(path)

    if suffix == ".jsonl":
        return _nuclei.parse(path)

    if suffix in (".json", ".yaml", ".yml"):
        if suffix in (".yaml", ".yml"):
            return _findings.parse(path)
        dialect = _sniff_json(path)
        return {
            "zap": _zap.parse_json,
            "nuclei": _nuclei.parse,
            "findings": _findings.parse,
        }[dialect](path)

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
        dialect = _sniff_xml(path)
        return {
            "nmap": _nmap.parse,
            "nessus": _nessus.parse,
            "burp": _burp.parse,
            "zap": _zap.parse_xml,
        }[dialect](path)

    raise ValueError(
        f"Unsupported input '{path}'. Expected .xml (Nmap/Nessus/Burp/ZAP), "
        f".nessus, .pdf (Acunetix), .jsonl (Nuclei), .json (Nuclei/ZAP/findings), "
        f".yaml or .yml"
    )


__all__ = ["detect_and_parse"]
