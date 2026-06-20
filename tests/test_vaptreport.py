"""Unit tests for vapt-report-generator."""

from pathlib import Path

import pytest

from vaptreport import scoring
from vaptreport.models import Finding, Report, Severity, Target
from vaptreport.parsers import detect_and_parse

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


# ── CVSS scoring ───────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "vector,expected",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),   # EternalBlue
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N", 8.2),
    ],
)
def test_base_score(vector, expected):
    assert scoring.base_score(vector) == expected


def test_severity_from_score():
    assert scoring.severity_from_score(9.8) == "Critical"
    assert scoring.severity_from_score(7.0) == "High"
    assert scoring.severity_from_score(4.0) == "Medium"
    assert scoring.severity_from_score(0.1) == "Low"
    assert scoring.severity_from_score(0.0) == "Informational"


def test_invalid_vector_raises():
    with pytest.raises(ValueError):
        scoring.base_score("CVSS:3.1/AV:N/AC:L")  # missing metrics


# ── Models ─────────────────────────────────────────────────────────────────────
def test_finding_derives_score_from_vector():
    f = Finding(title="x", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert f.cvss_score == 9.8
    assert f.severity == Severity.CRITICAL


def test_report_sort_and_ids():
    report = Report(findings=[
        Finding(title="low", severity=Severity.LOW),
        Finding(title="crit", severity=Severity.CRITICAL),
        Finding(title="med", severity=Severity.MEDIUM),
    ])
    report.finalize()
    assert [f.title for f in report.findings] == ["crit", "med", "low"]
    assert report.findings[0].finding_id == "VR-001"
    assert report.risk_rating() == "Critical"


def test_severity_coerce():
    assert Severity.coerce("HIGH") == Severity.HIGH
    assert Severity.coerce("moderate") == Severity.MEDIUM
    assert Severity.coerce(None) == Severity.INFO


def test_target_label():
    assert Target("h", 443, "https").label() == "h:443 (https)"
    assert Target("h").label() == "h"


# ── Parsers ────────────────────────────────────────────────────────────────────
def test_parse_findings_json():
    findings = detect_and_parse(str(EXAMPLES / "sample_findings.json"))
    assert len(findings) == 5
    sqli = next(f for f in findings if "SQL Injection" in f.title)
    assert sqli.severity == Severity.CRITICAL
    assert sqli.cvss_score == 9.8


def test_no_acme_in_examples():
    text = (EXAMPLES / "sample_findings.json").read_text().lower()
    assert "acme" not in text


def test_parse_nmap():
    findings = detect_and_parse(str(EXAMPLES / "sample_nmap.xml"))
    # POODLE vuln script + open-service inventory
    assert any("ssl-poodle" in f.title for f in findings)
    assert any("Open Network Services" in f.title for f in findings)


# Synthetic Acunetix Developer Report text (mimics the real PDF layout,
# including the typographic ligatures Acunetix uses: "Classiﬁcation",
# "Aﬀected"). Lets us test the parser without shipping a real client PDF.
_ACUNETIX_TEXT = """Developer Report
Acunetix Security Audit
Scan of test.example.com
Host test.example.com
Start url https://test.example.com/
2
Alerts summary
Conﬁguration ﬁle disclosure
Classiﬁcation
CVSS3
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:NBase Score: 5.8Attack Vector: Network
CWE CWE-538
Aﬀected items Variation
/WEB-INF/web.xml 1
HTTP Strict Transport Security (HSTS) Policy Not Enabled
Classiﬁcation
CWE CWE-16
Aﬀected items Variation
Web Server 1
3
Alerts details
Conﬁguration ﬁle disclosure
Severity High
Reported by module /Scripts/test.script
Description
A backup conﬁguration ﬁle was found.
Impact
Discloses sensitive information.
Recommendation
Remove this ﬁle from the web server.
References
OWASP (https://owasp.org/test)
Aﬀected items
/WEB-INF/web.xml
Details
Pattern found: <web-app>OWIT</web-app>
Request headers
GET /WEB-INF/web.xml HTTP/1.1
4
HTTP Strict Transport Security (HSTS) Policy Not Enabled
Severity Medium
Reported by module /httpdata/HSTS.js
Description
The Strict-Transport-Security header is missing.
Impact
MitM attacks possible.
Recommendation
Implement HSTS.
References
hstspreload (https://hstspreload.org/)
Aﬀected items
Web Server
Details
URLs where HSTS is not enabled: https://test.example.com/a/
Request headers
GET /a/ HTTP/1.1
5
Scanned items (coverage report)
https://test.example.com/
"""


def test_parse_acunetix_text():
    from vaptreport.parsers import acunetix_pdf

    findings = acunetix_pdf.parse_text(_ACUNETIX_TEXT)
    assert len(findings) == 2

    cfg = findings[0]
    assert cfg.title == "Configuration file disclosure"   # ligature normalised
    assert cfg.severity == Severity.HIGH
    assert cfg.cvss_score == 5.8                            # parsed from summary
    assert cfg.cwe == "CWE-538"
    assert "backup configuration file" in cfg.description
    assert "Remove this file" in cfg.remediation
    assert cfg.references == ["https://owasp.org/test"]
    assert "Pattern found" in cfg.evidence
    assert cfg.targets[0].host == "test.example.com"
    assert cfg.source == "acunetix"

    hsts = findings[1]
    assert hsts.severity == Severity.MEDIUM
    assert hsts.cwe == "CWE-16"
    assert hsts.cvss_score is None                          # no CVSS in summary


def test_parse_nessus_merges_hosts():
    findings = detect_and_parse(str(EXAMPLES / "sample_nessus.nessus"))
    eternalblue = next(f for f in findings if "EternalBlue" in f.title)
    # Same plugin on two hosts -> one finding, two targets.
    assert len(eternalblue.targets) == 2
    assert eternalblue.severity == Severity.CRITICAL


# ── Reporters ──────────────────────────────────────────────────────────────────
def test_render_html(tmp_path):
    from vaptreport import reporters

    findings = detect_and_parse(str(EXAMPLES / "sample_findings.json"))
    report = Report(findings=findings).finalize()
    out = reporters.render(report, "html", str(tmp_path / "r.html"))
    html = Path(out).read_text()
    assert "SQL Injection" in html
    assert "VR-001" in html


def test_html_escapes_xss_payload(tmp_path):
    """An XSS PoC in an evidence field must be escaped, not executable."""
    from vaptreport import reporters

    findings = detect_and_parse(str(EXAMPLES / "sample_findings.json"))
    report = Report(findings=findings).finalize()
    html = Path(reporters.render(report, "html", str(tmp_path / "r.html"))).read_text()
    # The raw, executable payload must NOT appear...
    assert "<img src=x onerror=alert" not in html
    # ...but its escaped, inert form must.
    assert "&lt;img src=x onerror=alert" in html


def test_custom_template(tmp_path):
    from vaptreport import reporters

    findings = detect_and_parse(str(EXAMPLES / "sample_findings.json"))
    report = Report(findings=findings).finalize()
    out = reporters.render(
        report, "html", str(tmp_path / "r.html"),
        template=str(EXAMPLES / "custom_template.html.j2"),
    )
    html = Path(out).read_text()
    assert "SENTINEL SECURITY" in html  # branding from the custom template
    assert "VR-001" in html


def test_custom_template_not_supported_for_xlsx(tmp_path):
    from vaptreport import reporters

    report = Report(findings=detect_and_parse(str(EXAMPLES / "sample_findings.json")))
    with pytest.raises(ValueError):
        reporters.render(report, "xlsx", str(tmp_path / "r.xlsx"), template="x.j2")


def test_pdf_passed_as_template_gives_clear_error(tmp_path):
    from vaptreport import reporters

    # A user pointing --template at their company report PDF must get a helpful
    # message, not a raw UTF-8 decode crash.
    pdf = tmp_path / "company template.pdf"
    pdf.write_bytes(b"%PDF-1.7\n\xb5\xb5\xb5 binary stream \x00\x01")
    report = Report(findings=detect_and_parse(str(EXAMPLES / "sample_findings.json")))
    with pytest.raises(ValueError, match="PDF"):
        reporters.render(report, "html", str(tmp_path / "r.html"), template=str(pdf))


def test_binary_template_gives_clear_error(tmp_path):
    from vaptreport import reporters

    blob = tmp_path / "logo.png"
    blob.write_bytes(b"\x89PNG\r\n\x1a\n\xb5\xff\x00not text")
    report = Report(findings=detect_and_parse(str(EXAMPLES / "sample_findings.json")))
    with pytest.raises(ValueError, match="UTF-8 text"):
        reporters.render(report, "html", str(tmp_path / "r.html"), template=str(blob))


def test_render_pdf(tmp_path):
    pytest.importorskip("weasyprint")
    from vaptreport import reporters

    findings = detect_and_parse(str(EXAMPLES / "sample_findings.json"))
    report = Report(findings=findings).finalize()
    out = reporters.render(report, "pdf", str(tmp_path / "r.pdf"))
    data = Path(out).read_bytes()
    assert data[:4] == b"%PDF"  # valid PDF magic bytes


def test_render_xlsx(tmp_path):
    from vaptreport import reporters

    findings = detect_and_parse(str(EXAMPLES / "sample_findings.json"))
    report = Report(findings=findings).finalize()
    out = reporters.render(report, "xlsx", str(tmp_path / "r.xlsx"))
    assert Path(out).exists() and Path(out).stat().st_size > 0
