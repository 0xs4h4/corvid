"""Rich terminal dashboard."""

from __future__ import annotations

from typing import Any, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..core.context import ScanContext
from ..core.finding import Severity

SEV_STYLES = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "green",
}


def render_dashboard(ctx: ScanContext, graph: Optional[Any] = None,
                    paths: Optional[list] = None) -> None:
    console = Console()
    dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in ctx.findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        dist[sev] = dist.get(sev, 0) + 1

    console.print(Panel.fit(
        f"[bold]adscan[/bold] — {ctx.domain or 'n/a'}\n"
        f"mode=[cyan]{ctx.mode}[/cyan] source=[cyan]{ctx.source}[/cyan]",
        title="Active Directory Attack-Surface Assessment",
    ))

    # Collection stats — makes empty-collection failures immediately visible.
    s = ctx.stats
    console.print(
        f"[dim]collected:[/dim] users=[cyan]{s.users}[/cyan] groups=[cyan]{s.groups}[/cyan] "
        f"computers=[cyan]{s.computers}[/cyan] gpos=[cyan]{s.gpos}[/cyan] "
        f"cas=[cyan]{s.cas}[/cyan] templates=[cyan]{s.templates}[/cyan] "
        f"trusts=[cyan]{s.trusts}[/cyan] ous=[cyan]{s.ous}[/cyan] "
        f"[dim]({'complete' if s.is_complete() else 'INCOMPLETE'})[/dim]"
    )
    for w in s.warnings + ctx.scan_warnings:
        console.print(f"[yellow][!] {w}[/yellow]")

    summary = Table(title="Severity Distribution")
    summary.add_column("Severity")
    summary.add_column("Count")
    for sev in ("critical", "high", "medium", "low", "info"):
        summary.add_row(f"[{SEV_STYLES[sev]}]{sev}[/{SEV_STYLES[sev]}]", str(dist[sev]))
    console.print(summary)

    if paths:
        console.print("\n[bold]Attack Paths to High-Value Targets[/bold]")
        for p in paths:
            chain = " → ".join(
                f"[cyan]{h['from']}[/cyan] [yellow]—{h['edge']}→[/yellow]"
                for h in p["hops"]
            ) + f" → [bold red]{p['target']}[/bold red]"
            console.print(f"  {chain}")

    table = Table(title="Findings")
    table.add_column("Sev", justify="center")
    table.add_column("Category")
    table.add_column("Title")
    table.add_column("Principal")
    for f in ctx.sorted_findings():
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        table.add_row(
            f"[{SEV_STYLES.get(sev, 'white')}]{sev}[/{SEV_STYLES.get(sev, 'white')}]",
            f.category.value if hasattr(f.category, "value") else str(f.category),
            f.title,
            f.affected_principal or "",
        )
    console.print(table)
