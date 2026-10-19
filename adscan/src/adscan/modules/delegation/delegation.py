"""Kerberos delegation module: unconstrained, constrained and resource-based
constrained delegation (RBCD) detection."""

from __future__ import annotations

from ...core.context import ScanContext
from ...core.finding import Category, Confidence, Finding, Severity
from ..base import Module, register

UF_TRUSTED_FOR_DELEGATION = 0x80000
UF_NOT_DELEGATED = 0x100000
UF_SERVER_TRUST_ACCOUNT = 0x2000  # domain controller


@register
class DelegationModule(Module):
    name = "delegation"
    description = "Unconstrained/constrained/RBCD delegation configuration."
    category = Category.DELEGATION
    quick = True

    def run(self, ctx: ScanContext) -> list[Finding]:
        data = ctx.data
        self._unconstrained(ctx)
        self._constrained(ctx)
        self._rbcd(ctx)
        return ctx.findings

    def _unconstrained(self, ctx: ScanContext) -> None:
        data = ctx.data
        for dn, c in data.computers.items():
            if c.userAccountControl & UF_SERVER_TRUST_ACCOUNT:
                continue  # domain controllers are always trusted for delegation
            if c.userAccountControl & UF_TRUSTED_FOR_DELEGATION:
                self._finding(
                    f"Unconstrained delegation on computer '{c.name}'",
                    Severity.HIGH, Confidence.HIGH, ctx,
                    affected_object=dn,
                    evidence={"dNSHostName": c.dNSHostName, "userAccountControl": hex(c.userAccountControl)},
                    impact="Any user authenticated to this host's services yields a forwardable TGT in memory; dumping it allows impersonation of that user.",
                    prerequisites=["Local admin on the delegating host (or coerced authentication + privilege escalation)."],
                    manual_verification=["Check for privileged accounts authenticating to this host.",
                                         "Use printer-bug/PetitPotam to coerce a DC to authenticate, then dump TGTs."],
                    remediation=["Move to constrained delegation or resource-based delegation.",
                                 "Flag affected accounts with 'Account is sensitive and cannot be delegated'."],
                    mitre_attack=["T1558.001"],
                )
        for dn, u in data.users.items():
            if u.userAccountControl & UF_TRUSTED_FOR_DELEGATION:
                self._finding(
                    f"Unconstrained delegation on user '{u.sAMAccountName or u.name}'",
                    Severity.HIGH, Confidence.HIGH, ctx,
                    affected_principal=u.sAMAccountName or u.name, affected_object=dn,
                    evidence={"userAccountControl": hex(u.userAccountControl)},
                    impact="A TGT for this user can be captured if it authenticates to a compromised host.",
                    remediation=["Remove unconstrained delegation from user accounts."],
                    mitre_attack=["T1558.001"],
                )

    def _constrained(self, ctx: ScanContext) -> None:
        data = ctx.data
        for dn, c in data.computers.items():
            if c.msds_AllowedToDelegateTo:
                self._finding(
                    f"Constrained delegation on computer '{c.name}'",
                    Severity.MEDIUM, Confidence.HIGH, ctx,
                    affected_object=dn,
                    evidence={"allowedToDelegateTo": c.msds_AllowedToDelegateTo},
                    impact="This host can impersonate users to the listed services (S4U2Self/S4U2Proxy).",
                    prerequisites=["Local admin on the host (if not protocol-transition) to obtain service tickets."],
                    remediation=["Limit the delegated services to the minimum necessary.",
                                 "Use resource-based constrained delegation where possible."],
                    mitre_attack=["T1558.001"],
                )
        for dn, u in data.users.items():
            if u.msds_AllowedToDelegateTo:
                self._finding(
                    f"Constrained delegation on user '{u.sAMAccountName or u.name}'",
                    Severity.MEDIUM, Confidence.HIGH, ctx,
                    affected_principal=u.sAMAccountName or u.name, affected_object=dn,
                    evidence={"allowedToDelegateTo": u.msds_AllowedToDelegateTo},
                    impact="This account can impersonate users to the listed services.",
                    remediation=["Review and restrict delegation targets."],
                    mitre_attack=["T1558.001"],
                )

    def _rbcd(self, ctx: ScanContext) -> None:
        data = ctx.data
        for dn, c in data.computers.items():
            if c.msds_AllowedToActOnBehalfOfOtherIdentity:
                self._finding(
                    f"Resource-based constrained delegation on computer '{c.name}'",
                    Severity.MEDIUM, Confidence.HIGH, ctx,
                    affected_object=dn,
                    evidence={"allowedToAct": c.msds_AllowedToActOnBehalfOfOtherIdentity},
                    impact="The principal listed in msDS-AllowedToActOnBehalfOfOtherIdentity can impersonate any user to this host (S4U2Self).",
                    prerequisites=["Control of the 'AllowedToAct' account."],
                    manual_verification=["impacket-findDelegation <domain>/<user>",
                                         "Check MachineAccountQuota if you can add a computer and abuse RBCD."],
                    remediation=["Remove unnecessary msDS-AllowedToActOnBehalfOfOtherIdentity entries."],
                    mitre_attack=["T1558.001"],
                )
