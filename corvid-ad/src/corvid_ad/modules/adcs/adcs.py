"""AD CS module: detect ESC1-ESC8 misconfigurations detectable via LDAP.

References Certipy / SpecterOps ESC research. Only LDAP-observable ESC
conditions are reported; web-enrollment (ESC8) requires an HTTP endpoint check
which is flagged for manual verification.
"""

from __future__ import annotations

from ...core.context import ScanContext
from ...core.finding import Category, Confidence, Finding, Severity
from ...core.sid import parse_sid
from ..base import Module, register

CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x1
CT_FLAG_PEND_ALL_REQUESTS = 0x2
CT_FLAG_AUTO_ENROLLMENT = 0x20

EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
EKU_SMART_CARD = "1.3.6.1.4.1.311.20.2.2"
EKU_ANY_PURPOSE = "2.5.29.37.0"
EKU_CERT_REQ_AGENT = "1.3.6.1.4.1.311.20.2.1"

BROAD_SIDS = {"S-1-1-0": "Everyone", "S-1-5-11": "Authenticated Users"}
BROAD_RIDS = {513: "Domain Users", 515: "Domain Computers", 545: "BUILTIN\\Users"}


def _is_broad(sid: str) -> bool:
    if sid in BROAD_SIDS:
        return True
    p = parse_sid(sid)
    if p and p[1] in BROAD_RIDS:
        return True
    return False


def _enrollable_by_low_priv(template, data) -> bool:
    """True if a broad/low-privilege principal holds Enroll/AutoEnroll on the template."""
    if not template.acl:
        return False
    for ace in template.acl.dacl:
        if ace.type not in ("ALLOW", "OBJECT_ALLOW"):
            continue
        rights = " ".join(ace.rights)
        if ("Enroll" in rights or "AutoEnroll" in rights) and _is_broad(ace.sid):
            return True
    return False


@register
class AdcsModule(Module):
    name = "adcs"
    description = "AD CS ESC1-ESC8 misconfiguration detection (LDAP-observable)."
    category = Category.ADCS
    quick = False

    def run(self, ctx: ScanContext) -> list[Finding]:
        data = ctx.data
        if not data.templates and not data.cas:
            self._finding(
                "No AD CS detected (no CAs or certificate templates found)",
                Severity.INFO, Confidence.LOW, ctx,
                evidence={"cas": len(data.cas), "templates": len(data.templates)},
                impact="No certificate service attack surface via LDAP.",
                detection_limitations=["Enumeration permission might hide PKI objects; verify with certipy find."],
            )
            return ctx.findings

        for dn, tpl in data.templates.items():
            self._esc1(dn, tpl, ctx)
            self._esc2(dn, tpl, ctx)
            self._esc3_ra(dn, tpl, ctx)
            self._esc4(dn, tpl, ctx)

        for dn, ca in data.cas.items():
            self._esc5(dn, ca, ctx)
            self._esc7(dn, ca, ctx)

        self._esc6(ctx)
        self._esc8(ctx)
        return ctx.findings

    def _esc1(self, dn, tpl, ctx: ScanContext) -> None:
        data = ctx.data
        name = tpl.name or dn
        flag = tpl.msPKI_Certificate_Name_Flag
        enroll = tpl.msPKI_Enrollment_Flag
        eku = [e.lower() for e in tpl.pKIExtendedKeyUsage]
        if (flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) and EKU_CLIENT_AUTH in eku \
                and not (enroll & CT_FLAG_PEND_ALL_REQUESTS) and _enrollable_by_low_priv(tpl, data):
            self._finding(
                f"ESC1 — vulnerable template '{name}' (enrollee supplies subject + client auth EKU)",
                Severity.CRITICAL, Confidence.HIGH, ctx,
                affected_object=dn,
                evidence={"nameFlag": hex(flag), "enrollFlag": hex(enroll), "eku": tpl.pKIExtendedKeyUsage},
                impact="Any enrollee can request a client-auth certificate as an arbitrary user (SAN), enabling domain escalation.",
                prerequisites=["Low-privilege enrollment on the template."],
                manual_verification=["certipy-ad find -u <user> -p <pass> -dc-ip <DC> -vulnerable",
                                     "certipy-ad req -template <name> -upn <target> -ca <CA>"],
                remediation=["Remove ENROLLEE_SUPPLIES_SUBJECT or require manager approval; restrict enrollment.",
                             "Remove client authentication EKU or add strong subject requirements."],
                references=["https://posts.specterops.io/certified-pre-owned-d95910965cd2"],
                mitre_attack=["T1649"],
            )

    def _esc2(self, dn, tpl, ctx: ScanContext) -> None:
        data = ctx.data
        name = tpl.name or dn
        flag = tpl.msPKI_Certificate_Name_Flag
        eku = [e.lower() for e in tpl.pKIExtendedKeyUsage]
        if (flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) and (EKU_ANY_PURPOSE in eku or not eku) \
                and _enrollable_by_low_priv(tpl, data):
            self._finding(
                f"ESC2 — template '{name}' allows Any Purpose / no EKU with enrollee-supplied subject",
                Severity.CRITICAL, Confidence.HIGH, ctx,
                affected_object=dn,
                evidence={"nameFlag": hex(flag), "eku": tpl.pKIExtendedKeyUsage},
                impact="A certificate usable for any purpose (including client auth) can be requested as an arbitrary user.",
                manual_verification=["certipy-ad find -vulnerable"],
                remediation=["Remove Any Purpose EKU; restrict enrollment."],
                references=["https://posts.specterops.io/certified-pre-owned-d95910965cd2"],
                mitre_attack=["T1649"],
            )

    def _esc3_ra(self, dn, tpl, ctx: ScanContext) -> None:
        data = ctx.data
        name = tpl.name or dn
        eku = [e.lower() for e in tpl.pKIExtendedKeyUsage]
        # Enrollment agent template: has Certificate Request Agent EKU
        if EKU_CERT_REQ_AGENT in eku and _enrollable_by_low_priv(tpl, data):
            self._finding(
                f"ESC3 — enrollment agent template '{name}' is enrollable by low-priv",
                Severity.HIGH, Confidence.MEDIUM, ctx,
                affected_object=dn,
                evidence={"eku": tpl.pKIExtendedKeyUsage},
                impact="A low-priv user can obtain an enrollment-agent certificate and sign certificate requests for other templates.",
                prerequisites=["A target template that requires RA signatures (msPKI-RA-Signature > 0)."],
                manual_verification=["certipy-ad find -vulnerable"],
                remediation=["Restrict enrollment-agent template enrollment."],
                references=["https://posts.specterops.io/certified-pre-owned-d95910965cd2"],
                mitre_attack=["T1649"],
            )

    def _esc4(self, dn, tpl, ctx: ScanContext) -> None:
        data = ctx.data
        name = tpl.name or dn
        if not tpl.acl:
            return
        for ace in tpl.acl.dacl:
            if ace.type not in ("ALLOW", "OBJECT_ALLOW"):
                continue
            joined = " ".join(ace.rights)
            if any(f in joined for f in ("GenericAll", "GenericWrite", "WriteDacl", "WriteOwner")):
                trustee = data.principal_name(ace.sid)
                self._finding(
                    f"ESC4 — template '{name}' ACL is writable by {trustee}",
                    Severity.HIGH, Confidence.HIGH, ctx,
                    affected_principal=trustee, affected_object=dn,
                    evidence={"rights": ace.rights, "inherited": ace.inherited},
                    permissions=[r for r in ace.rights],
                    impact="A principal who can write the template can make it vulnerable (add EKUs, allow SAN).",
                    manual_verification=["certipy-ad find -vulnerable"],
                    remediation=["Remove write access to certificate templates from non-admin principals."],
                    references=["https://posts.specterops.io/certified-pre-owned-d95910965cd2"],
                    mitre_attack=["T1649"],
                )
                break

    def _esc5(self, dn, ca, ctx: ScanContext) -> None:
        data = ctx.data
        name = ca.name or dn
        if not ca.acl:
            return
        for ace in ca.acl.dacl:
            if ace.type not in ("ALLOW", "OBJECT_ALLOW"):
                continue
            joined = " ".join(ace.rights)
            if any(f in joined for f in ("GenericAll", "WriteDacl", "WriteOwner")):
                trustee = data.principal_name(ace.sid)
                self._finding(
                    f"ESC5 — CA '{name}' has dangerous ACL for {trustee}",
                    Severity.HIGH, Confidence.HIGH, ctx,
                    affected_principal=trustee, affected_object=dn,
                    evidence={"rights": ace.rights, "dNSHostName": ca.dNSHostName},
                    permissions=[r for r in ace.rights],
                    impact="Control of the CA object allows takeover of the CA (SAN spoofing, cert issuance).",
                    remediation=["Remove dangerous ACLs on the CA object."],
                    references=["https://posts.specterops.io/certified-pre-owned-d95910965cd2"],
                    mitre_attack=["T1649"],
                )
                break

    def _esc6(self, ctx: ScanContext) -> None:
        # EDITF_ATTRIBUTESUBJECTALTNAME2 is stored in the CA's registry, not LDAP.
        self._finding(
            "ESC6 — verify CA EDITF_ATTRIBUTESUBJECTALTNAME2 flag (registry, not LDAP)",
            Severity.MEDIUM, Confidence.LOW, ctx,
            affected_object="CA registry",
            detection_limitations=["CA flags live in the CA's registry; LDAP cannot observe them directly."],
            manual_verification=["certipy-ad find -vulnerable",
                                 "Check HKLM\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\<CA>\\EditFlags."],
            remediation=["Disable EDITF_ATTRIBUTESUBJECTALTNAME2 if unnecessary."],
            references=["https://posts.specterops.io/certified-pre-owned-d95910965cd2"],
            mitre_attack=["T1649"],
        )

    def _esc7(self, dn, ca, ctx: ScanContext) -> None:
        data = ctx.data
        name = ca.name or dn
        if not ca.acl:
            return
        # ESC7: ManageCA / ManageCertificates rights (extended rights on CA)
        for ace in ca.acl.dacl:
            if ace.type not in ("ALLOW", "OBJECT_ALLOW"):
                continue
            joined = " ".join(ace.rights)
            if "ManageCA" in joined or "ManageCertificates" in joined:
                trustee = data.principal_name(ace.sid)
                self._finding(
                    f"ESC7 — CA '{name}' grants Manage CA/Certificates to {trustee}",
                    Severity.HIGH, Confidence.HIGH, ctx,
                    affected_principal=trustee, affected_object=dn,
                    evidence={"rights": ace.rights},
                    permissions=[r for r in ace.rights],
                    impact="A principal with ManageCA/ManageCertificates can approve pending requests or configure the CA.",
                    remediation=["Remove ManageCA/ManageCertificates from non-admins."],
                    references=["https://posts.specterops.io/certified-pre-owned-d95910965cd2"],
                    mitre_attack=["T1649"],
                )
                break

    def _esc8(self, ctx: ScanContext) -> None:
        data = ctx.data
        if data.cas:
            self._finding(
                "ESC8 — check web enrollment (HTTP) endpoint for NTLM relay",
                Severity.MEDIUM, Confidence.LOW, ctx,
                affected_object="http://<CA>/certsrv/",
                detection_limitations=["Web enrollment endpoint requires an HTTP check; not observable via LDAP."],
                manual_verification=["curl -I http://<CA>/certsrv/certfnsh.asp",
                                     "Check for EPA (Extended Protection for Authentication)."],
                remediation=["Enable EPA on the web enrollment endpoint; disable NTLM."],
                references=["https://posts.specterops.io/certified-pre-owned-d95910965cd2"],
                mitre_attack=["T1649", "T1557"],
            )
