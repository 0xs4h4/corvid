"""JSON report writer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from ..core.context import ScanContext


def _active_to_dict(active_result: Optional[Any]) -> Optional[dict[str, Any]]:
    if active_result is None:
        return None
    from ..collectors.active_collector import ActiveResult

    if not isinstance(active_result, ActiveResult):
        return None
    return {
        "admin_hosts": active_result.admin_hosts,
        "credentials": [
            {
                "account": c.account,
                "kind": c.kind,
                "value": c.value,
                "source_host": c.source_host,
                "rid": c.rid,
            }
            for c in active_result.credentials
        ],
        "reuse_hints": active_result.reuse_hints,
    }


def build_report_dict(ctx: ScanContext, graph: Optional[Any] = None, paths: Optional[list] = None,
                      active_result: Optional[Any] = None) -> dict[str, Any]:
    findings = [f.to_dict() for f in ctx.sorted_findings()]
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        if sev in counts:
            counts[sev] += 1
    report = {
        "metadata": {
            "tool": "corvid_ad",
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
    active = _active_to_dict(active_result)
    if active is not None:
        report["active"] = active
    return report


def write_json(ctx: ScanContext, out_dir: str | Path, graph: Optional[Any] = None,
               paths: Optional[list] = None, active_result: Optional[Any] = None) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "results.json"
    path.write_text(json.dumps(build_report_dict(ctx, graph, paths, active_result), indent=2), encoding="utf-8")
    return path
