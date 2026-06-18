"""VAPT Report Generator.

Parse raw vulnerability scanner output (Nmap, Nessus) or a generic findings
file, normalise it into a common model with CVSS scoring, and render
professional HTML / PDF / Excel reports.
"""

from .models import Finding, Report, Severity, Target

__version__ = "1.0.0"
__all__ = ["Finding", "Report", "Severity", "Target", "__version__"]
