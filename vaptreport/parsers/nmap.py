"""Parser for Nmap XML output (``nmap -oX out.xml``).

Open ports are reported as Informational service-inventory findings, while any
results produced by NSE ``vuln`` scripts are promoted to real findings with a
best-effort severity inferred from the script output.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import List

from ..models import Finding, Severity, Target

# NSE scripts whose output should be treated as a vulnerability finding.
_VULN_SCRIPTS = {
    "vulners",
    "vuln",
    "http-vuln",
    "ssl-poodle",
    "ssl-heartbleed",
    "smb-vuln",
}


def _looks_vulnerable(script_id: str, output: str) -> bool:
    if any(script_id.startswith(s) for s in _VULN_SCRIPTS):
        return True
    return "VULNERABLE" in output.upper()


def parse(path: str) -> List[Finding]:
    tree = ET.parse(path)
    root = tree.getroot()
    findings: List[Finding] = []
    open_targets: List[Target] = []

    for host in root.findall("host"):
        addr_el = host.find("address")
        host_ip = addr_el.get("addr") if addr_el is not None else "unknown"

        hostname_el = host.find("hostnames/hostname")
        host_label = hostname_el.get("name") if hostname_el is not None else host_ip

        for port in host.findall("ports/port"):
            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            portid = int(port.get("portid"))
            svc_el = port.find("service")
            service = None
            if svc_el is not None:
                name = svc_el.get("name", "")
                product = svc_el.get("product", "")
                version = svc_el.get("version", "")
                service = " ".join(x for x in (name, product, version) if x).strip()

            target = Target(host=host_label, port=portid, service=service or None)
            open_targets.append(target)

            for script in port.findall("script"):
                sid = script.get("id", "")
                output = script.get("output", "").strip()
                if not _looks_vulnerable(sid, output):
                    continue
                cves = [
                    line.strip()
                    for line in output.splitlines()
                    if line.strip().upper().startswith("CVE-")
                ]
                findings.append(
                    Finding(
                        title=f"{sid} on {host_label}:{portid}",
                        severity=Severity.MEDIUM,
                        description=output,
                        targets=[target],
                        cve=cves,
                        remediation=(
                            "Review the flagged service, apply vendor patches, and "
                            "disable or upgrade vulnerable components."
                        ),
                        evidence=output,
                        source="nmap",
                    )
                )

    if open_targets:
        findings.append(
            Finding(
                title="Open Network Services (Attack Surface Inventory)",
                severity=Severity.INFO,
                description=(
                    f"{len(open_targets)} open service(s) were discovered during the "
                    "port scan. Confirm each is required and properly hardened."
                ),
                targets=open_targets,
                remediation=(
                    "Close or firewall any service not required for business "
                    "operations and restrict access to trusted networks."
                ),
                source="nmap",
            )
        )

    return findings
