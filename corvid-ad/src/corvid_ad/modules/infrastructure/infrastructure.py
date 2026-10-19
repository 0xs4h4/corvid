"""Infrastructure module: SCCM, WSUS, Exchange, ADFS, MSSQL and legacy protocol
exposure indicators derived from SPNs and computer attributes."""

from __future__ import annotations

from ...core.context import ScanContext
from ...core.finding import Category, Confidence, Finding, Severity
from ..base import Module, register

SERVICE_MARKERS = {
    "MSSQLSvc": ("MSSQL", "MSSQL instance (check xp_cmdshell / linked servers)"),
    "exchangeMDB": ("Exchange", "Microsoft Exchange (privilege escalation via roles / DCSync paths)"),
    "http": ("Web", "HTTP service (check web enrollment / app exposure)"),
    "MSSMS": ("SCCM", "SCCM site server (SCCM hierarchy abuse / client push)"),
    "adfs": ("ADFS", "AD FS service (ADFS configuration / delegation abuse)"),
    "wsus": ("WSUS", "WSUS server (update injection)"),
    "teradata": ("Teradata", "Database service"),
}


@register
class InfrastructureModule(Module):
    name = "infrastructure"
    description = "SCCM/WSUS/Exchange/ADFS/MSSQL exposure indicators from SPNs and host attributes."
    category = Category.INFRASTRUCTURE
    quick = False

    def run(self, ctx: ScanContext) -> list[Finding]:
        data = ctx.data
        seen: dict[str, str] = {}
        for dn, c in data.computers.items():
            for spn in c.servicePrincipalName:
                low = spn.lower()
                for marker, (label, impact) in SERVICE_MARKERS.items():
                    if marker.lower() in low and label not in seen:
                        seen[label] = c.name
                        self._finding(
                            f"{label} service detected on '{c.name}'",
                            Severity.INFO, Confidence.HIGH, ctx,
                            affected_object=dn,
                            evidence={"spn": spn, "dNSHostName": c.dNSHostName},
                            impact=impact,
                            remediation=[f"Review {label} configuration and permissions."],
                        )
        return ctx.findings
