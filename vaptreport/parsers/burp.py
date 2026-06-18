"""Parser for Burp Suite XML issue exports (``<issues>`` root element).

Burp reports one ``<issue>`` per affected location, so identical issues across
paths are merged into a single finding with the affected targets aggregated.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

from ..models import Finding, Severity, Target
from ._util import extract_urls, strip_html, target_from_uri

_CWE_RE = re.compile(r"CWE-\d+")
_SEV = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "information": Severity.INFO,
    "informational": Severity.INFO,
    "false positive": Severity.INFO,
}


def _text(issue: ET.Element, tag: str) -> str:
    el = issue.find(tag)
    return (el.text or "").strip() if el is not None else ""


def parse(path: str) -> List[Finding]:
    root = ET.parse(path).getroot()
    merged: Dict[str, Finding] = {}

    for issue in root.findall("issue"):
        name = _text(issue, "name") or "Burp Issue"
        itype = _text(issue, "type") or name
        host_el = issue.find("host")
        host_url = (host_el.text or "").strip() if host_el is not None else ""
        target = target_from_uri(host_url)
        # Note the specific path in the target via service label if present.
        path_txt = _text(issue, "path")

        key = f"{itype}|{name}"
        if key in merged:
            merged[key].targets.append(target)
            continue

        background = strip_html(_text(issue, "issueBackground"))
        detail = strip_html(_text(issue, "issueDetail"))
        remediation = strip_html(_text(issue, "remediationBackground"))
        vuln_class = _text(issue, "vulnerabilityClassifications")
        cwe = _CWE_RE.search(vuln_class)

        evidence_bits = [b for b in (f"Path: {path_txt}" if path_txt else "", detail) if b]

        merged[key] = Finding(
            title=name,
            severity=_SEV.get(_text(issue, "severity").lower(), Severity.INFO),
            description="\n\n".join(b for b in (background, detail) if b),
            targets=[target],
            cwe=cwe.group(0) if cwe else None,
            remediation=remediation,
            references=extract_urls(background + " " + vuln_class),
            evidence="\n".join(evidence_bits),
            source="burp",
        )

    return list(merged.values())
