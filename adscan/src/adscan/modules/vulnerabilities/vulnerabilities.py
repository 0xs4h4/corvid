"""Historical vulnerability exposure module.

These are configuration-based indicators for known AD-related vulnerabilities.
They are heuristics — patch verification and manual testing are always
recommended, and findings are labelled accordingly.
"""

from __future__ import annotations

from ...core.context import ScanContext
from ...core.finding import Category, Confidence, Finding, Severity
from ..base import Module, register


@register
class VulnerabilityModule(Module):
    name = "vulnerabilities"
    description = "Zerologon/PrintNightmare/sAMAccountName spoofing/PetitPotam exposure indicators."
    category = Category.VULNERABILITY
    quick = False

    def run(self, ctx: ScanContext) -> list[Finding]:
        data = ctx.data
        self._zerologon(ctx)
        self._printnightmare(ctx)
        self._samaccountname(ctx)
        self._petitpotam(ctx)
        return ctx.findings

    def _zerologon(self, ctx: ScanContext) -> None:
        data = ctx.data
        for dn, c in data.computers.items():
            if not (c.userAccountControl & 0x2000):  # domain controller
                continue
            os_name = (c.operatingSystem or "").lower()
            # Zerologon affects Server 2008 R2 - Server 2019 (pre Aug-2020 patch)
            vulnerable_os = any(s in os_name for s in ("2008", "2012", "2016", "2019"))
            self._finding(
                f"Potential Zerologon (CVE-2020-1472) exposure on DC '{c.name}' ({c.operatingSystem})",
                Severity.HIGH if vulnerable_os else Severity.LOW,
                Confidence.LOW if vulnerable_os else Confidence.LOW,
                ctx,
                affected_object=dn,
                evidence={"os": c.operatingSystem, "dNSHostName": c.dNSHostName},
                impact="If unpatched, Zerologon resets the DC machine account password, enabling full domain compromise.",
                prerequisites=["Unpatched DC (must verify patch level — NOT determinable via LDAP)."],
                false_positive_considerations=["OS version alone does not confirm the vulnerability; patch level is decisive."],
                detection_limitations=["Patch status is not observable via LDAP."],
                manual_verification=["python3 zerologon_tester.py <dc-name> <dc-ip>",
                                     "Check KB4571710 / KB4565349 presence."],
                remediation=["Apply the August 2020 security updates (or later)."],
                references=["https://www.secura.com/blog/zero-logon"],
                mitre_attack=["T1210"],
            )

    def _printnightmare(self, ctx: ScanContext) -> None:
        data = ctx.data
        if data.computers:
            self._finding(
                "Verify Print Spooler (PrintNightmare CVE-2021-34527) on domain hosts",
                Severity.MEDIUM, Confidence.LOW, ctx,
                affected_object="all hosts",
                detection_limitations=["Print Spooler state is a host service, not an LDAP attribute."],
                manual_verification=["Check Print Spooler service status on each host.",
                                     "Test with impacket-rpcdump MS-RPRN (CVE-2021-1675) only in authorized engagements."],
                remediation=["Disable the Print Spooler service where not required."],
                references=["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527"],
                mitre_attack=["T1210"],
            )

    def _samaccountname(self, ctx: ScanContext) -> None:
        data = ctx.data
        pp = data.domain.password_policy
        if "machineAccountQuota" not in pp:
            return  # domain not collected — do not fabricate a default
        quota = pp.get("machineAccountQuota", 0)
        if quota and quota > 0:
            self._finding(
                f"MachineAccountQuota = {quota} (sAMAccountName spoofing / RBCD prerequisite)",
                Severity.INFO, Confidence.HIGH, ctx,
                affected_object=data.domain.default_naming_context or data.domain.name,
                evidence={"machineAccountQuota": quota},
                impact="Authenticated users can add computer accounts (up to the quota), enabling RBCD abuse and sAMAccountName spoofing (CVE-2021-42278/42287).",
                prerequisites=["A vulnerable DC (patch-dependent) for the spoofing variant."],
                remediation=["Set ms-DS-MachineAccountQuota to 0 if computer creation is not needed."],
                references=["https://posts.specterops.io/cve-2021-42287-42278-samaccountname-spoofing"],
                mitre_attack=["T1134", "T1558"],
            )

    def _petitpotam(self, ctx: ScanContext) -> None:
        self._finding(
            "Verify PetitPotam (MS-EFSR) / PrinterBug coercion on domain hosts",
            Severity.MEDIUM, Confidence.LOW, ctx,
            affected_object="domain controllers",
            detection_limitations=["Coercion requires an RPC/MS-EFSR probe; not observable via LDAP."],
            manual_verification=["impacket-ntlmrelayx with PetitPotam coercion (authorized only)."],
            remediation=["Disable MS-EFSR if not needed; enable EPA and SMB signing."],
            references=["https://github.com/topotam/PetitPotam"],
            mitre_attack=["T1557"],
        )
