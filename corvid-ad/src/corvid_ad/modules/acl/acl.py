"""ACL abuse module: detect dangerous ACEs on users, groups, computers, GPOs and OUs.

Resolves trustee SIDs to principal names and classifies trustees (broad vs
privileged) so that severity reflects who holds the dangerous right.
"""

from __future__ import annotations

from ...core.context import ScanContext
from ...core.finding import Category, Confidence, Finding, Severity
from ...core.models import ADObject
from ...core.sid import parse_sid
from ..base import Module, register

# SIDs that represent very broad principals
BROAD_SIDS = {
    "S-1-1-0": "Everyone",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-7": "ANONYMOUS LOGON",
}
BROAD_RIDS = {513: "Domain Users", 515: "Domain Computers", 545: "BUILTIN\\Users"}

# Dangerous right fragments -> (label, default severity, impact hint)
DANGEROUS = [
    ("GenericAll", "GenericAll", Severity.HIGH, "full control of the object"),
    ("WriteDacl", "WriteDacl", Severity.HIGH, "modify the object's ACL"),
    ("WriteOwner", "WriteOwner", Severity.HIGH, "take ownership of the object"),
    ("GenericWrite", "GenericWrite", Severity.HIGH, "write properties (targeted Kerberoast, shadow credentials, logon script)"),
    ("DCSync", "DCSync", Severity.CRITICAL, "replicate domain secrets (DCSync)"),
    ("ForceChangePassword", "ForceChangePassword", Severity.HIGH, "reset the account password"),
    ("Self (validated write)", "Self-Membership", Severity.HIGH, "add themselves to the group"),
]


def _trustee_class(sid: str, data) -> tuple[str, bool]:
    """Return (label, is_broad)."""
    if sid in BROAD_SIDS:
        return BROAD_SIDS[sid], True
    p = parse_sid(sid)
    if p:
        _, rid = p
        if rid in BROAD_RIDS:
            return BROAD_RIDS[rid], True
    return data.principal_name(sid), False


@register
class AclAbuseModule(Module):
    name = "acl"
    description = "Dangerous ACL permissions (GenericAll/Write/WriteDacl/WriteOwner/DCSync/ForceChangePassword) on domain objects."
    category = Category.ACL
    quick = True

    def run(self, ctx: ScanContext) -> list[Finding]:
        data = ctx.data
        buckets: list[tuple[str, dict[str, ADObject]]] = [
            ("user", data.users),
            ("group", data.groups),
            ("computer", data.computers),
            ("gpo", data.gpos),
            ("ou", data.ous),
        ]
        for obj_type, objects in buckets:
            for dn, obj in objects.items():
                self._check_object(obj_type, obj, ctx)
        return ctx.findings

    def _check_object(self, obj_type: str, obj: ADObject, ctx: ScanContext) -> None:
        if not obj.acl:
            return
        data = ctx.data
        for ace in obj.acl.dacl:
            if ace.type not in ("ALLOW", "OBJECT_ALLOW"):
                continue
            for frag, label, sev, impact_hint in DANGEROUS:
                if frag in " ".join(ace.rights) or any(frag in r for r in ace.rights):
                    trustee, broad = _trustee_class(ace.sid, data)
                    severity = sev
                    if broad and sev == Severity.HIGH:
                        severity = Severity.CRITICAL
                    self._finding(
                        f"{label} on {obj_type} '{obj.name}' for {trustee}",
                        severity, Confidence.HIGH, ctx,
                        affected_principal=trustee,
                        affected_object=obj.distinguished_name,
                        evidence={
                            "object_type": obj_type,
                            "right": label,
                            "rights": ace.rights,
                            "trustee_sid": ace.sid,
                            "inherited": ace.inherited,
                            "broad": broad,
                        },
                        permissions=[r for r in ace.rights],
                        impact=f"Principal '{trustee}' can {impact_hint}.",
                        prerequisites=[
                            "Control of (or impersonation of) the trustee principal.",
                            "For inherited ACEs, verify the inheritance source and whether it can be blocked.",
                        ],
                        false_positive_considerations=[
                            "Inherited ACE may originate from a broader OU/container; verify effective access.",
                            "Deny ACEs may override; check for deny entries.",
                        ],
                        manual_verification=[
                            "BloodHound: 'Shortest Paths to X' for the trustee.",
                            "Verify effective permissions with the intended tooling (e.g. adacl / BloodHound path).",
                        ],
                        remediation=["Remove or scope down the dangerous ACE.",
                                     "Prefer least-privilege grants to specific principals over broad groups."],
                        mitre_attack=["T1484", "T1222"],
                    )
                    break
