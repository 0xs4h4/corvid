"""CSV findings writer."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Optional

from ..core.context import ScanContext

COLUMNS = [
    "id", "module", "category", "severity", "confidence", "status", "title",
    "affected_principal", "affected_object", "impact", "prerequisites",
    "manual_verification", "remediation", "references", "mitre_attack", "evidence",
]


def write_csv(ctx: ScanContext, out_dir: str | Path) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "findings.csv"
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for f in ctx.sorted_findings():
            d = f.to_dict()
            for k in ("prerequisites", "manual_verification", "remediation", "references", "mitre_attack"):
                d[k] = " | ".join(d.get(k) or [])
            d["evidence"] = "; ".join(f"{k}={v}" for k, v in (d.get("evidence") or {}).items())
            writer.writerow(d)
    return path
