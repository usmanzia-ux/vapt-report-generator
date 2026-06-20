"""Command-line interface for vapt-report-generator."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List

from rich.console import Console
from rich.table import Table

from . import __version__, parsers, reporters
from .models import Finding, Report
from .parsers import findings as findings_parser

console = Console()

_FORMAT_EXT = {"html": ".html", "pdf": ".pdf", "docx": ".docx", "xlsx": ".xlsx"}


def _gather_findings(inputs: List[str]) -> List[Finding]:
    all_findings: List[Finding] = []
    for path in inputs:
        if not Path(path).exists():
            console.print(f"[red]✗[/red] input not found: {path}")
            sys.exit(2)
        try:
            parsed = parsers.detect_and_parse(path)
        except Exception as exc:  # noqa: BLE001 - surface a clean message
            console.print(f"[red]✗[/red] failed to parse {path}: {exc}")
            sys.exit(2)
        console.print(f"[green]✓[/green] {path}: parsed {len(parsed)} finding(s)")
        all_findings.extend(parsed)
    return all_findings


def _build_report(args, all_findings: List[Finding]) -> Report:
    report = Report(findings=all_findings)

    # Pull metadata from the first JSON/YAML input that carries a 'report' block.
    for path in args.input:
        if path.lower().endswith((".json", ".yaml", ".yml")):
            meta = findings_parser.parse_report_meta(path)
            for key in ("client", "title", "assessor", "assessment_date", "scope", "standard"):
                if key in meta:
                    setattr(report, key, meta[key])
            break

    # CLI flags override file metadata.
    if args.client:
        report.client = args.client
    if args.title:
        report.title = args.title
    if args.assessor:
        report.assessor = args.assessor

    return report.finalize(prefix=args.id_prefix)


def _print_summary(report: Report) -> None:
    counts = report.severity_counts()
    table = Table(title="Findings Summary", title_style="bold cyan")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    styles = {
        "Critical": "bold red",
        "High": "red",
        "Medium": "yellow",
        "Low": "green",
        "Informational": "dim",
    }
    for sev, style in styles.items():
        table.add_row(f"[{style}]{sev}[/{style}]", str(counts[sev]))
    table.add_row("[bold]Total[/bold]", f"[bold]{len(report.findings)}[/bold]")
    console.print(table)
    console.print(f"Overall risk rating: [bold]{report.risk_rating()}[/bold]")


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vaptreport",
        description="Turn Nmap / Nessus / findings files into professional VAPT reports.",
    )
    parser.add_argument("input", nargs="*",
                        help="One or more input files: .xml (Nmap/Nessus), .nessus, "
                             ".pdf (Acunetix report), .json/.yaml (findings). "
                             "Omit to launch the interactive wizard.")
    parser.add_argument("-i", "--interactive", action="store_true",
                        help="Launch the guided interactive wizard.")
    parser.add_argument("-f", "--format", default="pdf",
                        choices=["pdf", "html", "docx", "xlsx"],
                        help="Output format (default: pdf).")
    parser.add_argument("-o", "--output", help="Output file path.")
    parser.add_argument("-t", "--template",
                        help="Custom template for the report's look: .html.j2 "
                             "(pdf/html); .docx (docx — tagged templates are filled, "
                             "untagged ones are used as a branded shell with findings "
                             "appended); .pdf (reuses its cover page). Omit for the "
                             "generic theme.")
    parser.add_argument("--client", help="Override client name.")
    parser.add_argument("--title", help="Override report title.")
    parser.add_argument("--assessor", help="Override assessor name.")
    parser.add_argument("--id-prefix", default="VR", help="Finding ID prefix (default: VR).")
    parser.add_argument("-V", "--version", action="version",
                        version=f"vapt-report-generator {__version__}")
    args = parser.parse_args(argv)

    # No inputs (or -i) → launch the guided interactive wizard.
    if args.interactive or not args.input:
        from . import wizard

        return wizard.run()

    console.print(f"[bold cyan]VAPT Report Generator[/bold cyan] v{__version__}\n")

    all_findings = _gather_findings(args.input)
    if not all_findings:
        console.print("[yellow]![/yellow] No findings parsed — nothing to report.")
        return 1

    report = _build_report(args, all_findings)
    _print_summary(report)

    output = args.output or f"vapt_report{_FORMAT_EXT[args.format]}"
    if args.template:
        console.print(f"[cyan]ℹ[/cyan] using custom template: {args.template}")
    try:
        path = reporters.render(report, args.format, output, template=args.template)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]✗[/red] failed to render report: {exc}")
        return 2

    console.print(f"\n[green]✓ Report written:[/green] {path}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
