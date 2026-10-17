"""JSON report writer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from ..core.context import ScanContext


def build_report_dict(ctx: ScanContext, graph: Optional[Any] = None, paths: Optional[list] = None) -> dict[str, Any]:
    findings = [f.to_dict() for f in ctx.sorted_findings()]
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        if sev in counts:
            counts[sev] += 1
    return {
        "metadata": {
            "tool": "adscan",
            "domain": ctx.domain,
            "mode": ctx.mode,
            "source": ctx.source,
            "started_at": ctx.started_at,
            "findings_count": len(findings),
            "severity_distribution": counts,
        },
        "collection": {
            "users": ctx.stats.users,
            "groups": ctx.stats.groups,
            "computers": ctx.stats.computers,
            "gpos": ctx.stats.gpos,
            "cas": ctx.stats.cas,
            "templates": ctx.stats.templates,
            "trusts": ctx.stats.trusts,
            "ous": ctx.stats.ous,
            "complete": ctx.stats.is_complete(),
            "warnings": ctx.stats.warnings + ctx.scan_warnings,
        },
        "findings": findings,
        "attack_paths": paths or [],
        "graph": graph.to_dict() if graph else None,
    }


def write_json(ctx: ScanContext, out_dir: str | Path, graph: Optional[Any] = None,
               paths: Optional[list] = None) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "results.json"
    path.write_text(json.dumps(build_report_dict(ctx, graph, paths), indent=2), encoding="utf-8")
    return path
