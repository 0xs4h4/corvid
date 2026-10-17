"""Domain reconnaissance module: FSMO roles, trusts, DCs, accounts, policies."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ...core.context import ScanContext
from ...core.finding import Category, Confidence, Finding, Severity
from ...core.sid import WELL_KNOWN_RIDS
from ..base import Module, register

# UAC flags
UF_ACCOUNTDISABLE = 0x0002
UF_PASSWD_NOTREQD = 0x0020
UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x0080
UF_DONT_EXPIRE_PASSWD = 0x10000
UF_TRUSTED_FOR_DELEGATION = 0x80000
UF_NOT_DELEGATED = 0x100000
UF_DONT_REQUIRE_PREAUTH = 0x400000

# Privileged / interesting group RIDs (by well-known RID within domain)
PRIV_GROUP_RIDS = {
    512: "Domain Admins",
    518: "Schema Admins",
    519: "Enterprise Admins",
    516: "Domain Controllers",
    498: "Enterprise Read-Only Domain Controllers",
    548: "Account Operators",
    549: "Server Operators",
    550: "Print Operators",
    551: "Backup Operators",
    552: "Replicator",
    544: "Administrators",
    1101: "DnsAdmins",
}


@register
class DomainReconModule(Module):
    name = "domain_recon"
    description = "Domain/forest discovery, DCs, FSMO roles, trusts, privileged accounts, stale accounts, obsolete OS."
    category = Category.RECON
    quick = True

    def run(self, ctx: ScanContext) -> list[Finding]:
        data = ctx.data
        self._privileged_groups(ctx)
        self._spns(ctx)
        self._stale_accounts(ctx)
        self._obsolete_os(ctx)
        self._trusts(ctx)
        return ctx.findings

    def _privileged_groups(self, ctx: ScanContext) -> None:
        data = ctx.data
        for dn, g in data.groups.items():
            sid = g.objectSid or ""
            rid = None
            if sid:
                parts = sid.split("-")
                if parts and parts[-1].isdigit():
                    rid = int(parts[-1])
            if rid in PRIV_GROUP_RIDS:
                members = [data.principal_name(m) for m in g.member]
                self._finding(
                    f"Privileged group '{PRIV_GROUP_RIDS[rid]}' members",
                    Severity.INFO, Confidence.HIGH, ctx,
                    affected_object=dn,
                    evidence={"group": g.name, "rid": rid, "members": members},
                    impact="Members of this group hold elevated rights in the domain.",
                    remediation=["Audit membership of privileged groups regularly.",
                                 "Remove non-essential accounts from privileged groups."],
                    mitre_attack=["T1078"],
                )
            if g.adminCount and rid not in PRIV_GROUP_RIDS:
                self._finding(
                    f"adminCount=1 group '{g.name}' (unexpectedly protected)",
                    Severity.LOW, Confidence.HIGH, ctx,
                    affected_object=dn,
                    evidence={"group": g.name, "adminCount": g.adminCount},
                    impact="Group is marked as protected (SDProp); unexpected protected groups may indicate a delegated admin or persistence.",
                    remediation=["Review unexpected protected groups."],
                    mitre_attack=["T1078"],
                )

    def _spns(self, ctx: ScanContext) -> None:
        data = ctx.data
        for dn, u in data.users.items():
            if u.servicePrincipalName:
                self._finding(
                    f"User '{u.sAMAccountName or u.name}' has SPN(s) (Kerberoastable)",
                    Severity.MEDIUM, Confidence.HIGH, ctx,
                    affected_principal=u.sAMAccountName or u.name,
                    affected_object=dn,
                    evidence={"spns": u.servicePrincipalName},
                    impact="A service ticket for the SPN can be requested and brute-forced offline if the account password is weak.",
                    prerequisites=["Domain user access to request a TGS."],
                    manual_verification=["impacket-GetUserSPNs -request -dc-ip <DC> <domain>/<user>"],
                    remediation=["Use long random passwords for service accounts (or gMSA).",
                                 "Move services to group Managed Service Accounts."],
                    mitre_attack=["T1558.003"],
                )
        for dn, c in data.computers.items():
            if c.servicePrincipalName:
                # computer SPNs are normal (HOST/, etc.) — only flag user SPNs above
                pass

    def _stale_accounts(self, ctx: ScanContext) -> None:
        data = ctx.data
        now = datetime.now(timezone.utc)
        for dn, u in data.users.items():
            if u.lastLogonTimestamp:
                try:
                    # lastLogonTimestamp is FileTime (100ns since 1601)
                    ft = int(u.lastLogonTimestamp)
                    if ft > 0:
                        ts = datetime(1601, 1, 1, tzinfo=timezone.utc)
                        last = ts + timedelta(microseconds=ft / 10)
                        days = (now - last).days
                        if days > 180 and not (u.userAccountControl & UF_ACCOUNTDISABLE):
                            self._finding(
                                f"Stale enabled account '{u.sAMAccountName or u.name}' (last logon ~{days}d ago)",
                                Severity.LOW, Confidence.MEDIUM, ctx,
                                affected_principal=u.sAMAccountName or u.name, affected_object=dn,
                                evidence={"lastLogonDays": days},
                                impact="Stale accounts are attractive targets and increase the attack surface.",
                                remediation=["Disable or remove stale accounts."],
                            )
                except Exception:
                    continue

    def _obsolete_os(self, ctx: ScanContext) -> None:
        data = ctx.data
        obsolete = ["windows server 2003", "windows server 2008", "windows xp", "windows 7", "windows 8"]
        for dn, c in data.computers.items():
            os_name = (c.operatingSystem or "").lower()
            if any(o in os_name for o in obsolete):
                self._finding(
                    f"Obsolete operating system on '{c.name}' ({c.operatingSystem})",
                    Severity.MEDIUM, Confidence.HIGH, ctx,
                    affected_object=dn,
                    evidence={"os": c.operatingSystem},
                    impact="End-of-life OS is missing security patches and hardening.",
                    remediation=["Upgrade or decommission obsolete systems."],
                    mitre_attack=["T1210"],
                )

    def _trusts(self, ctx: ScanContext) -> None:
        data = ctx.data
        for dn, t in data.trusts.items():
            self._finding(
                f"Domain trust to '{t.trustPartner or t.name}'",
                Severity.INFO, Confidence.HIGH, ctx,
                affected_object=dn,
                evidence={"trustDirection": t.trustDirection, "trustType": t.trustType,
                          "trustAttributes": t.trustAttributes, "flatName": t.flatName},
                impact="Trust relationships expand the attack surface to other domains/forests.",
                remediation=["Review trust direction and SID filtering configuration."],
                mitre_attack=["T1482"],
            )
