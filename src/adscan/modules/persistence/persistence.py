"""Persistence & defense-evasion exposure module (assessment only — no
persistence/ticket-forgery is ever implemented)."""

from __future__ import annotations

from ...core.context import ScanContext
from ...core.finding import Category, Confidence, Finding, Severity
from ..base import Module, register


@register
class PersistenceModule(Module):
    name = "persistence"
    description = "Golden/silver ticket prerequisites, AdminSDHolder, SIDHistory and security-logging indicators."
    category = Category.PERSISTENCE
    quick = False

    def run(self, ctx: ScanContext) -> list[Finding]:
        data = ctx.data
        self._krbtgt(ctx)
        self._sidhistory(ctx)
        self._adminsdholder(ctx)
        self._logging(ctx)
        return ctx.findings

    def _krbtgt(self, ctx: ScanContext) -> None:
        data = ctx.data
        for dn, u in data.users.items():
            name = (u.sAMAccountName or u.name or "").lower()
            if name == "krbtgt":
                self._finding(
                    "krbtgt account present — protect its hash (Golden Ticket key)",
                    Severity.INFO, Confidence.HIGH, ctx,
                    affected_principal=u.sAMAccountName, affected_object=dn,
                    evidence={"sAMAccountName": u.sAMAccountName},
                    impact="The krbtgt NTLM hash is the domain Kerberos master key; possession enables forged (golden) tickets.",
                    remediation=["Rotate krbtgt password twice per Microsoft guidance if compromise is suspected.",
                                 "Monitor for unusual TGT issuance."],
                    mitre_attack=["T1558.001"],
                )

    def _sidhistory(self, ctx: ScanContext) -> None:
        self._finding(
            "SIDHistory should be audited for cross-domain privilege persistence",
            Severity.LOW, Confidence.LOW, ctx,
            affected_object="users/groups",
            detection_limitations=["sidHistory attribute is not collected in this pass; requires targeted query."],
            manual_verification=["Query sidHistory on principals: (sidHistory=*) with an LDAP client."],
            remediation=["Clear unnecessary sidHistory values; enable SID filtering on external trusts."],
            mitre_attack=["T1134.005"],
        )

    def _adminsdholder(self, ctx: ScanContext) -> None:
        data = ctx.data
        # AdminSDHolder is a well-known object; flag that its ACL should be pristine.
        self._finding(
            "AdminSDHolder ACL should be reviewed (SDProp propagates it to protected accounts)",
            Severity.LOW, Confidence.MEDIUM, ctx,
            affected_object="CN=AdminSDHolder,CN=System",
            detection_limitations=["AdminSDHolder ACL requires a targeted query in this pass."],
            manual_verification=["Query the AdminSDHolder object's ACL for unexpected grants."],
            remediation=["Ensure only expected admins can modify AdminSDHolder."],
            mitre_attack=["T1098"],
        )

    def _logging(self, ctx: ScanContext) -> None:
        self._finding(
            "Verify security auditing (account logon, logon, kerberos, changes) is enabled",
            Severity.INFO, Confidence.LOW, ctx,
            affected_object="domain controllers",
            detection_limitations=["Audit policy is a Group Policy / local setting, not an LDAP attribute."],
            manual_verification=["auditpol /get /category:* on a DC; check GPO 'Advanced Audit Policy'."],
            remediation=["Enable advanced audit policies for Kerberos, logon and directory changes."],
            mitre_attack=["T1562.002"],
        )
