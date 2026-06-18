"""Parser for Tenable Nessus ``.nessus`` (XML) export files.

Each ``ReportItem`` becomes a Finding. Nessus reports one item per host/port,
so identical plugins across hosts are merged into a single finding with the
affected targets aggregated.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Dict, List, Tuple

from ..models import Finding, Severity, Target

# Nessus severity integer -> our Severity. (4=Critical … 0=Info)
_NESSUS_SEV = {
    "4": Severity.CRITICAL,
    "3": Severity.HIGH,
    "2": Severity.MEDIUM,
    "1": Severity.LOW,
    "0": Severity.INFO,
}


def _text(item: ET.Element, tag: str) -> str:
    el = item.find(tag)
    return el.text.strip() if el is not None and el.text else ""


def parse(path: str) -> List[Finding]:
    tree = ET.parse(path)
    root = tree.getroot()

    # Merge by plugin so we don't emit one finding per host.
    merged: Dict[str, Finding] = {}
    cvss_seen: Dict[str, Tuple[float, str]] = {}

    for host in root.iter("ReportHost"):
        host_name = host.get("name", "unknown")

        for item in host.findall("ReportItem"):
            plugin_id = item.get("pluginID", "")
            plugin_name = item.get("pluginName", "Unnamed Nessus Finding")
            severity = _NESSUS_SEV.get(item.get("severity", "0"), Severity.INFO)

            # Skip the noisy informational plugin "0" general items unless useful.
            port = item.get("port")
            svc = item.get("svc_name")
            target = Target(
                host=host_name,
                port=int(port) if port and port != "0" else None,
                service=svc or None,
            )

            cvss_vector = _text(item, "cvss3_vector") or _text(item, "cvss_vector") or None
            cvss_score = _text(item, "cvss3_base_score") or _text(item, "cvss_base_score")
            score_val = float(cvss_score) if cvss_score else None

            cve = [el.text.strip() for el in item.findall("cve") if el.text]
            cwe = _text(item, "cwe") or None

            if plugin_id in merged:
                merged[plugin_id].targets.append(target)
                merged[plugin_id].cve = sorted(set(merged[plugin_id].cve) | set(cve))
                continue

            finding = Finding(
                title=plugin_name,
                severity=severity,
                description=_text(item, "description") or _text(item, "synopsis"),
                targets=[target],
                cvss_score=score_val,
                cvss_vector=cvss_vector,
                cwe=f"CWE-{cwe}" if cwe and not cwe.startswith("CWE") else cwe,
                cve=cve,
                remediation=_text(item, "solution"),
                references=[
                    r.text.strip()
                    for r in item.findall("see_also")
                    if r.text
                ],
                evidence=_text(item, "plugin_output"),
                source="nessus",
            )
            merged[plugin_id] = finding

    return list(merged.values())
