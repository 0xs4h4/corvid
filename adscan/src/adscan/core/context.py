"""Scan context: holds collected AD data, findings, and scan metadata."""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import Any, Optional

from .finding import Finding
from .models import ADData


@dataclass
class CollectionStats:
    """Track what was collected and whether collection was complete."""

    users: int = 0
    groups: int = 0
    computers: int = 0
    gpos: int = 0
    cas: int = 0
    templates: int = 0
    trusts: int = 0
    ous: int = 0
    acls_collected: int = 0
    warnings: list[str] = field(default_factory=list)

    def is_complete(self) -> bool:
        return bool(self.users and self.groups and self.computers)


@dataclass
class ScanContext:
    data: ADData = field(default_factory=ADData)
    findings: list[Finding] = field(default_factory=list)
    stats: CollectionStats = field(default_factory=CollectionStats)
    domain: str = ""
    mode: str = "quick"
    started_at: str = field(default_factory=lambda: _dt.datetime.now(_dt.timezone.utc).isoformat())
    source: str = "live"  # live | offline
    scan_warnings: list[str] = field(default_factory=list)

    def add_finding(self, f: Finding) -> None:
        self.findings.append(f)

    def deduplicate(self) -> None:
        seen: set[str] = set()
        out: list[Finding] = []
        for f in self.findings:
            key = f.stable_key
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        self.findings = out

    def sorted_findings(self) -> list[Finding]:
        from .finding import confidence_rank, severity_rank

        return sorted(
            self.findings,
            key=lambda f: (severity_rank(f.severity), confidence_rank(f.confidence)),
            reverse=True,
        )
