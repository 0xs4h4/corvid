"""Domain privilege-escalation module: DCSync rights and privileged-group control."""

from __future__ import annotations

from ...core.context import ScanContext
from ...core.finding import Category, Confidence, Finding, Severity
from ...core.sid import parse_sid
from ..base import Module, register

# SIDs/RIDs that are already highly privileged (granting them rights is expected)
PRIV_RIDS = {498, 500, 512, 516, 518, 519, 544, 526, 527}


def _is_already_privileged(sid: str) -> bool:
    if sid in ("S-1-5-18", "S-1-5-32-544"):
        return True
    p = parse_sid(sid)
    if p and p[1] in PRIV_RIDS:
        return True
    return False


@register
class PrivilegeEscalationModule(Module):
    name = "privesc"
    description = "DCSync permission exposure and dangerous privileged-group control."
    category = Category.PRIVESC
    quick = True

    def run(self, ctx: ScanContext) -> list[Finding]:
        self._dcsync_rights(ctx)
        return ctx.findings

    def _dcsync_rights(self, ctx: ScanContext) -> None:
        data = ctx.data
        acl = data.domain.acl
        if not acl:
            return
        for ace in acl.dacl:
            if ace.type not in ("ALLOW", "OBJECT_ALLOW"):
                continue
            rights = " ".join(ace.rights)
            if "DCSync" in rights:
                trustee = data.principal_name(ace.sid)
                if _is_already_privileged(ace.sid):
                    # DCSync for DCs / Domain Admins is expected
                    continue
                self._finding(
                    f"DCSync rights granted to '{trustee}' on the domain root",
                    Severity.CRITICAL, Confidence.HIGH, ctx,
                    affected_principal=trustee,
                    affected_object=data.domain.default_naming_context or data.domain.name,
                    evidence={"rights": ace.rights, "trustee_sid": ace.sid, "inherited": ace.inherited},
                    permissions=[r for r in ace.rights],
                    impact="This principal can replicate domain secrets (all NTLM hashes, krbtgt) — direct domain compromise.",
                    prerequisites=["Control of the trustee account."],
                    manual_verification=["impacket-secretsdump -just-dc <domain>/<user>@<DC>",
                                         "BloodHound: 'Can Replicate' (GetChanges/GetChangesAll) edge."],
                    remediation=["Remove DS-Replication-Get-Changes / Get-Changes-All from non-DC principals.",
                                 "Grant replication only to a dedicated, tightly-scoped service account."],
                    mitre_attack=["T1003.006"],
                )
