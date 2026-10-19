"""Credential exposure module: AS-REP, reversible encryption, password flags,
LAPS, gMSA and sensitive attribute exposure — detection only, no dumping."""

from __future__ import annotations

from ...core.context import ScanContext
from ...core.finding import Category, Confidence, Finding, Severity
from ...core.sid import DANGEROUS_EXTENDED_RIGHTS
from ..base import Module, register

UF_ACCOUNTDISABLE = 0x0002
UF_PASSWD_NOTREQD = 0x0020
UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x0080
UF_DONT_EXPIRE_PASSWD = 0x10000
UF_DONT_REQUIRE_PREAUTH = 0x400000


@register
class CredentialExposureModule(Module):
    name = "credentials"
    description = "Kerberoast/AS-REP eligibility, reversible encryption, LAPS/gMSA exposure, sensitive attributes."
    category = Category.CREDENTIAL
    quick = True

    def run(self, ctx: ScanContext) -> list[Finding]:
        self._asrep(ctx)
        self._password_flags(ctx)
        self._description_exposure(ctx)
        return ctx.findings

    def _asrep(self, ctx: ScanContext) -> None:
        data = ctx.data
        for dn, u in data.users.items():
            if u.userAccountControl & UF_DONT_REQUIRE_PREAUTH:
                self._finding(
                    f"AS-REP roastable account '{u.sAMAccountName or u.name}' (no pre-auth required)",
                    Severity.MEDIUM, Confidence.HIGH, ctx,
                    affected_principal=u.sAMAccountName or u.name, affected_object=dn,
                    evidence={"userAccountControl": hex(u.userAccountControl)},
                    impact="A TGT encrypted with the account's password can be requested and brute-forced offline.",
                    prerequisites=["Domain user access to request an AS-REP for the account."],
                    manual_verification=["impacket-GetNPUsers -dc-ip <DC> <domain>/ -usersfile users.txt"],
                    remediation=["Enable 'Do not require Kerberos preauthentication' = OFF for these accounts.",
                                 "Rotate the account password."],
                    mitre_attack=["T1558.004"],
                )

    def _password_flags(self, ctx: ScanContext) -> None:
        data = ctx.data
        for dn, u in data.users.items():
            uac = u.userAccountControl
            name = u.sAMAccountName or u.name
            if uac & UF_ACCOUNTDISABLE:
                continue  # disabled accounts are not exploitable
            if uac & UF_PASSWD_NOTREQD:
                self._finding(
                    f"Account '{name}' has 'password not required' set",
                    Severity.MEDIUM, Confidence.HIGH, ctx,
                    affected_principal=name, affected_object=dn,
                    evidence={"userAccountControl": hex(uac)},
                    impact="Account may authenticate with an empty password.",
                    remediation=["Set a password and clear PASSWD_NOTREQD."],
                    mitre_attack=["T1078"],
                )
            if uac & UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED:
                self._finding(
                    f"Account '{name}' allows reversible encryption",
                    Severity.HIGH, Confidence.HIGH, ctx,
                    affected_principal=name, affected_object=dn,
                    evidence={"userAccountControl": hex(uac)},
                    impact="Password is stored reversibly-encrypted and can be recovered by a DC admin.",
                    remediation=["Disable reversible encryption (store passwords using reversible encryption = off)."],
                    mitre_attack=["T1110.002"],
                )
            if uac & UF_DONT_EXPIRE_PASSWD:
                self._finding(
                    f"Account '{name}' password never expires",
                    Severity.LOW, Confidence.HIGH, ctx,
                    affected_principal=name, affected_object=dn,
                    evidence={"userAccountControl": hex(uac)},
                    impact="Compromised credential remains valid indefinitely.",
                    remediation=["Enable password expiration for non-service accounts."],
                )

    def _description_exposure(self, ctx: ScanContext) -> None:
        data = ctx.data
        for dn, u in data.users.items():
            desc = (u.description or "").lower()
            for kw in ("password", "pass:", "pwd", "credential"):
                if kw in desc:
                    self._finding(
                        f"User '{u.sAMAccountName or u.name}' description contains '{kw}'",
                        Severity.MEDIUM, Confidence.MEDIUM, ctx,
                        affected_principal=u.sAMAccountName or u.name, affected_object=dn,
                        evidence={"description": u.description},
                        impact="Description field may expose a password or sensitive note.",
                        false_positive_considerations=["Word may be benign (e.g. 'password manager team')."],
                        manual_verification=["Review the full description value."],
                        remediation=["Remove credentials from description fields."],
                        mitre_attack=["T1552"],
                    )
                    break
