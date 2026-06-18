"""Parser for OWASP ZAP reports (JSON or XML export).

ZAP already aggregates each alert across its instances, so one ``alert`` becomes
one finding with all instance URIs captured as targets/evidence.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List

from ..models import Finding, Severity, Target
from ._util import extract_urls, strip_html, target_from_uri

# ZAP riskcode: 3=High, 2=Medium, 1=Low, 0=Informational
_RISK = {"3": Severity.HIGH, "2": Severity.MEDIUM, "1": Severity.LOW, "0": Severity.INFO}
_MAX_INSTANCES = 25


def _cwe(value) -> str | None:
    s = str(value).strip() if value is not None else ""
    return f"CWE-{s}" if s and s not in ("-1", "0") else None


def _finding_from_alert(alert: dict, host: str, port) -> Finding:
    instances = alert.get("instances", []) or []
    targets, evidence = [], []
    for inst in instances[:_MAX_INSTANCES]:
        uri = inst.get("uri", "")
        targets.append(target_from_uri(uri, fallback_host=host, fallback_port=port))
        line = f"{inst.get('method', '')} {uri}".strip()
        if inst.get("param"):
            line += f" [param: {inst['param']}]"
        if inst.get("evidence"):
            line += f" -> {inst['evidence']}"
        evidence.append(line)
    if not targets:
        targets = [target_from_uri("", fallback_host=host, fallback_port=port)]

    return Finding(
        title=alert.get("alert") or alert.get("name") or "ZAP Alert",
        severity=_RISK.get(str(alert.get("riskcode", "0")), Severity.INFO),
        description=strip_html(alert.get("desc", "")),
        targets=targets,
        cwe=_cwe(alert.get("cweid")),
        remediation=strip_html(alert.get("solution", "")),
        references=extract_urls(alert.get("reference", "")),
        evidence="\n".join(evidence),
        source="zap",
    )


def parse_json(path: str) -> List[Finding]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    findings: List[Finding] = []
    for site in data.get("site", []):
        host = site.get("@host") or site.get("@name", "")
        port = site.get("@port")
        for alert in site.get("alerts", []):
            findings.append(_finding_from_alert(alert, host, port))
    return findings


def _xtext(el, tag: str) -> str:
    child = el.find(tag)
    return (child.text or "").strip() if child is not None else ""


def parse_xml(path: str) -> List[Finding]:
    root = ET.parse(path).getroot()
    findings: List[Finding] = []
    for site in root.findall("site"):
        host = site.get("host") or site.get("name", "")
        port = site.get("port")
        for item in site.findall("alerts/alertitem"):
            instances = []
            for inst in item.findall("instances/instance"):
                instances.append({
                    "uri": _xtext(inst, "uri"),
                    "method": _xtext(inst, "method"),
                    "param": _xtext(inst, "param"),
                    "evidence": _xtext(inst, "evidence"),
                })
            alert = {
                "alert": _xtext(item, "alert") or _xtext(item, "name"),
                "riskcode": _xtext(item, "riskcode"),
                "desc": _xtext(item, "desc"),
                "solution": _xtext(item, "solution"),
                "reference": _xtext(item, "reference"),
                "cweid": _xtext(item, "cweid"),
                "instances": instances,
            }
            findings.append(_finding_from_alert(alert, host, port))
    return findings


def parse(path: str) -> List[Finding]:
    if path.lower().endswith(".xml"):
        return parse_xml(path)
    return parse_json(path)
