"""Interactive shell wizard for vapt-report-generator.

Run ``vaptreport`` with no input files (or ``vaptreport --interactive``) and this
guided, styled flow walks the user through building a report step by step:

    1. choose the scan/findings file(s)
    2. choose a template — the default theme or their own company template
       (.docx / .html.j2 fill every field; .pdf reuses its cover page)
    3. build the report, with live progress
    4. choose the output format (pdf / docx / html / xlsx)
    5. name the output file

It is a thin UI layer on top of the same library the CLI uses, so behaviour is
identical — only the input collection differs.
"""

from __future__ import annotations

import glob
from pathlib import Path
from typing import List, Optional

from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from . import __version__, parsers, reporters
from .models import Finding, Report
from .parsers import findings as findings_parser

console = Console()

_FORMAT_EXT = {"pdf": ".pdf", "docx": ".docx", "html": ".html", "xlsx": ".xlsx"}
_SUPPORTED_INPUT = (".xml", ".nessus", ".pdf", ".json", ".yaml", ".yml", ".jsonl")


def _banner() -> None:
    console.clear()
    title = Text("VAPT REPORT GENERATOR", style="bold cyan", justify="center")
    sub = Text(f"interactive report builder · v{__version__}", style="dim", justify="center")
    console.print(Panel(Align.center(Text("\n").join([title, sub])),
                        border_style="cyan", padding=(1, 4)))
    console.print()


def _step(n: int, total: int, label: str) -> None:
    console.print(f"[bold cyan]Step {n}/{total}[/bold cyan]  [bold]{label}[/bold]")


def _prompt_inputs() -> List[str]:
    """Ask for one or more scan files; accept globs and validate existence."""
    while True:
        raw = Prompt.ask(
            "  [green]Scan / findings file(s)[/green] "
            "[dim](space-separated; globs ok, e.g. scans/*.nessus)[/dim]"
        )
        tokens = raw.split()
        files: List[str] = []
        for tok in tokens:
            matches = glob.glob(tok)
            files.extend(matches if matches else [tok])

        missing = [f for f in files if not Path(f).exists()]
        bad_ext = [f for f in files if not f.lower().endswith(_SUPPORTED_INPUT)]
        if not files:
            console.print("  [red]Please enter at least one file.[/red]")
            continue
        if missing:
            console.print(f"  [red]Not found:[/red] {', '.join(missing)}")
            continue
        if bad_ext:
            console.print(f"  [yellow]Unsupported type:[/yellow] {', '.join(bad_ext)} "
                          f"[dim](need {', '.join(_SUPPORTED_INPUT)})[/dim]")
            continue
        for f in files:
            console.print(f"  [green]✓[/green] {f}")
        return files


def _prompt_template() -> Optional[str]:
    """Default theme, or the user's own company template from a path."""
    console.print("  Template:")
    console.print("    [cyan]1[/cyan]) Default professional theme")
    console.print("    [cyan]2[/cyan]) My own company template (.docx / .html.j2 / .pdf)")
    choice = Prompt.ask("  Choose", choices=["1", "2"], default="1")
    if choice == "1":
        console.print("  [green]✓[/green] using the default theme")
        return None
    while True:
        path = Prompt.ask("  [green]Path to your template[/green]").strip().strip('"').strip("'")
        if not Path(path).exists():
            console.print(f"  [red]Not found:[/red] {path}")
            if not Confirm.ask("  Try again?", default=True):
                console.print("  [yellow]Falling back to the default theme.[/yellow]")
                return None
            continue
        ext = Path(path).suffix.lower()
        if ext == ".pdf":
            console.print("  [yellow]ℹ A PDF template can't be field-filled[/yellow] — "
                          "its cover page will be reused and findings rendered in the "
                          "default style. For full field-filling use .docx or .html.j2.")
        elif ext == ".docx":
            console.print("  [green]✓[/green] Word template — every field will be filled")
        elif ext in (".j2", ".html"):
            console.print("  [green]✓[/green] HTML/Jinja2 template — every field will be filled")
        else:
            console.print(f"  [yellow]Unrecognised template type '{ext}'.[/yellow]")
            if not Confirm.ask("  Use it anyway?", default=False):
                continue
        return path


def _prompt_metadata() -> dict:
    console.print("  [dim]Report details (Enter to skip / keep default):[/dim]")
    meta = {}
    client = Prompt.ask("  Client name", default="").strip()
    title = Prompt.ask("  Report title", default="").strip()
    assessor = Prompt.ask("  Assessor", default="Usman Zia").strip()
    if client:
        meta["client"] = client
    if title:
        meta["title"] = title
    if assessor:
        meta["assessor"] = assessor
    return meta


def _template_ok_for_format(template: Optional[str], fmt: str) -> bool:
    """Guard incompatible template/format combos with a friendly message."""
    if not template:
        return True
    ext = Path(template).suffix.lower()
    if fmt == "docx" and ext != ".docx":
        console.print(f"  [yellow]Your {ext} template only applies to pdf/html output, "
                      "not docx. The default docx layout will be used.[/yellow]")
        return False
    if fmt in ("pdf", "html") and ext == ".docx":
        console.print(f"  [yellow]A .docx template only applies to docx output. "
                      f"The default {fmt} theme will be used.[/yellow]")
        return False
    if fmt in ("xlsx", "html") and ext == ".pdf":
        console.print("  [yellow]A PDF template's cover reuse only applies to pdf output. "
                      f"The default {fmt} theme will be used.[/yellow]")
        return False
    return True


def _prompt_output() -> tuple[str, str]:
    console.print("  Output format:")
    console.print("    [cyan]1[/cyan]) PDF   [cyan]2[/cyan]) Word (.docx)   "
                  "[cyan]3[/cyan]) HTML   [cyan]4[/cyan]) Excel (.xlsx)")
    fmt = {"1": "pdf", "2": "docx", "3": "html", "4": "xlsx"}[
        Prompt.ask("  Choose", choices=["1", "2", "3", "4"], default="1")
    ]
    default_name = f"vapt_report{_FORMAT_EXT[fmt]}"
    name = Prompt.ask("  [green]Output file name[/green]", default=default_name).strip()
    if not name.lower().endswith(_FORMAT_EXT[fmt]):
        name += _FORMAT_EXT[fmt]
    return fmt, name


def _summary_table(report: Report) -> Table:
    counts = report.severity_counts()
    table = Table(title="Findings Summary", title_style="bold cyan")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    styles = {"Critical": "bold red", "High": "red", "Medium": "yellow",
              "Low": "green", "Informational": "dim"}
    for sev, style in styles.items():
        table.add_row(f"[{style}]{sev}[/{style}]", str(counts[sev]))
    table.add_row("[bold]Total[/bold]", f"[bold]{len(report.findings)}[/bold]")
    return table


def run() -> int:
    """Drive the full interactive session. Returns a process exit code."""
    _banner()
    total = 5

    _step(1, total, "Select scan / findings input")
    inputs = _prompt_inputs()
    console.print()

    _step(2, total, "Choose a template")
    template = _prompt_template()
    console.print()

    _step(3, total, "Report details")
    meta = _prompt_metadata()
    console.print()

    _step(4, total, "Build the report")
    all_findings: List[Finding] = []
    with console.status("[cyan]Parsing inputs…[/cyan]", spinner="dots"):
        for path in inputs:
            parsed = parsers.detect_and_parse(path)
            all_findings.extend(parsed)
            console.print(f"  [green]✓[/green] {path}: parsed {len(parsed)} finding(s)")
    if not all_findings:
        console.print("  [yellow]No findings parsed — nothing to report.[/yellow]")
        return 1

    report = Report(findings=all_findings)
    for path in inputs:
        if path.lower().endswith((".json", ".yaml", ".yml")):
            for k, v in findings_parser.parse_report_meta(path).items():
                setattr(report, k, v)
            break
    for k, v in meta.items():
        setattr(report, k, v)
    report.finalize()
    console.print(_summary_table(report))
    console.print(f"  Overall risk rating: [bold]{report.risk_rating()}[/bold]")
    console.print()

    _step(5, total, "Output format & file name")
    fmt, output = _prompt_output()
    use_template = template if _template_ok_for_format(template, fmt) else None
    console.print()

    with console.status(f"[cyan]Rendering {fmt.upper()} report…[/cyan]", spinner="dots"):
        path = reporters.render(report, fmt, output, template=use_template)

    console.print(Panel(
        f"[green]✓ Report written:[/green] [bold]{path}[/bold]\n"
        f"[dim]{len(report.findings)} findings · risk {report.risk_rating()}[/dim]",
        border_style="green", title="Done"))

    if Confirm.ask("\n  Build another report?", default=False):
        return run()
    console.print("[dim]Goodbye.[/dim]")
    return 0
