"""GPO attack-surface module: writable GPOs, dangerous delegated control, link scope."""

from __future__ import annotations

from ...core.context import ScanContext
from ...core.finding import Category, Confidence, Finding, Severity
from ..base import Module, register


@register
class GpoModule(Module):
    name = "gpo"
    description = "GPO ACLs, writable GPOs, SYSVOL password (cpassword) reminder, GPO link scope."
    category = Category.GPO
    quick = False

    def run(self, ctx: ScanContext) -> list[Finding]:
        data = ctx.data
        self._writable_gpos(ctx)
        self._sysvol_reminder(ctx)
        self._gpo_links(ctx)
        return ctx.findings

    def _writable_gpos(self, ctx: ScanContext) -> None:
        data = ctx.data
        for dn, gpo in data.gpos.items():
            if not gpo.acl:
                continue
            for ace in gpo.acl.dacl:
                if ace.type not in ("ALLOW", "OBJECT_ALLOW"):
                    continue
                joined = " ".join(ace.rights)
                if any(frag in joined for frag in ("GenericAll", "GenericWrite", "WriteDacl", "WriteOwner")):
                    trustee = data.principal_name(ace.sid)
                    self._finding(
                        f"Writable GPO '{gpo.name}' by {trustee}",
                        Severity.HIGH, Confidence.HIGH, ctx,
                        affected_principal=trustee, affected_object=dn,
                        evidence={"rights": ace.rights, "gpcFileSysPath": gpo.gpcFileSysPath, "inherited": ace.inherited},
                        permissions=[r for r in ace.rights],
                        impact="A principal who can write a GPO can push policy (scheduled tasks, scripts, startup) to all linked machines and their users.",
                        prerequisites=["Control of the trustee principal."],
                        manual_verification=["BloodHound 'Shortest Path to Domain Admin' via GPO.",
                                             "Check GPO links to determine blast radius."],
                        remediation=["Scope GPO edit rights to the least privileged group.",
                                     "Review GPO links to privileged systems."],
                        mitre_attack=["T1484.001"],
                    )
                    break

    def _sysvol_reminder(self, ctx: ScanContext) -> None:
        data = ctx.data
        if data.gpos:
            self._finding(
                "SYSVOL Group Policy Preferences should be checked for cpassword",
                Severity.MEDIUM, Confidence.MEDIUM, ctx,
                affected_object="SYSVOL",
                evidence={"gpo_count": len(data.gpos)},
                impact="Legacy GPP files (Groups.xml, Services.xml, etc.) may contain AES-encrypted-but-recoverable passwords (cpassword).",
                prerequisites=["Read access to SYSVOL (\\<domain>\\SYSVOL)."],
                detection_limitations=["cpassword lives in SYSVOL filesystem, not LDAP; requires SMB access."],
                manual_verification=["grep -r cpassword \\\\<DC>\\SYSVOL",
                                     "impacket-Get-GPPPassword -dc-ip <DC> <domain>/<user>"],
                remediation=["Remove legacy GPP password files; use LAPS for local admin passwords."],
                mitre_attack=["T1552.006"],
            )

    def _gpo_links(self, ctx: ScanContext) -> None:
        data = ctx.data
        # Correlate GPO links on OUs with writable GPOs (informational)
        for dn, ou in data.ous.items():
            gplink = ou.attributes.get("gPLink", [])
            if gplink:
                self._finding(
                    f"GPO linked to OU '{ou.name}'",
                    Severity.INFO, Confidence.HIGH, ctx,
                    affected_object=dn,
                    evidence={"gPLink": gplink},
                    impact="GPO applies to objects in this OU; a writable GPO here is high-impact.",
                    remediation=["Review linked GPOs for writability."],
                )
