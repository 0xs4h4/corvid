"""Network & protocol security module.

Most of these controls (SMB signing, LDAP signing/channel binding, WinRM/RDP
exposure) are host-level and cannot be observed over LDAP alone. This module
reports the LDAP-observable context (functional level, OS) and emits clearly-
labelled manual-verification findings for the rest.
"""

from __future__ import annotations

from ...core.context import ScanContext
from ...core.finding import Category, Confidence, Finding, Severity
from ..base import Module, register


@register
class NetworkModule(Module):
    name = "network"
    description = "SMB/LDAP signing, NTLM relay prerequisites, WinRM/RDP exposure (host-level checks)."
    category = Category.NETWORK
    quick = True

    def run(self, ctx: ScanContext) -> list[Finding]:
        data = ctx.data
        fl = data.domain.functional_level or "unknown"
        self._finding(
            f"Domain functional level: {fl}",
            Severity.INFO, Confidence.HIGH, ctx,
            evidence={"functionalLevel": fl},
            impact="Functional level gates which Kerberos and protocol hardening features are available (e.g. AES-only, Protected Users).",
            remediation=["Raise functional level where supported to enable modern hardening."],
        )
        self._smb_signing(ctx)
        self._ldap_signing(ctx)
        self._relay_prereq(ctx)
        return ctx.findings

    def _smb_signing(self, ctx: ScanContext) -> None:
        self._finding(
            "Verify SMB signing configuration on domain hosts",
            Severity.MEDIUM, Confidence.LOW, ctx,
            affected_object="all hosts",
            detection_limitations=["SMB signing is negotiated per-host over SMB; not observable via LDAP."],
            manual_verification=["nxc smb <targets> --gen-relay-list <out>",
                                 "nxc smb <DC> -u <user> -p <pass> --local-auth (observe 'signing:true/false')"],
            remediation=["Require SMB signing on all hosts."],
            mitre_attack=["T1557"],
        )

    def _ldap_signing(self, ctx: ScanContext) -> None:
        self._finding(
            "Verify LDAP signing and channel binding",
            Severity.MEDIUM, Confidence.LOW, ctx,
            affected_object="domain controllers",
            detection_limitations=["LDAP signing/channel binding are DC security settings, not observable via LDAP query."],
            manual_verification=["Check DC registry: HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters (LDAPServerIntegrity)."],
            remediation=["Enable LDAP signing and channel binding (reject LDAP over plaintext)."],
            mitre_attack=["T1557"],
        )

    def _relay_prereq(self, ctx: ScanContext) -> None:
        self._finding(
            "NTLM relay prerequisites (SMB signing off + LLMNR/NBT-NS) require host-level assessment",
            Severity.MEDIUM, Confidence.LOW, ctx,
            affected_object="network",
            detection_limitations=["Relay conditions (SMB signing disabled, LLMNR/NBT-NS broadcast) are network behaviors."],
            manual_verification=["Run Responder to detect LLMNR/NBT-NS broadcast traffic.",
                                 "Combine with nxc --gen-relay-list to find non-signing SMB targets."],
            remediation=["Disable LLMNR and NBT-NS; require SMB signing and enable EPA."],
            mitre_attack=["T1557", "T1557.001"],
        )
