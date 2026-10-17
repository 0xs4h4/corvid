"""ACL parsing: SDDL string -> ACL/ACE objects with resolved right names.

We prefer requesting ``nTSecurityDescriptor`` in SDDL form (the same approach
BloodHound/Certipy use) because it is compact, human-readable and avoids the
complexity of decoding the binary security descriptor.
"""

from __future__ import annotations

import re
from typing import Optional

from ..core.models import ACE, ACL
from ..core.sid import DANGEROUS_EXTENDED_RIGHTS, EXTENDED_RIGHTS

# SDDL right abbreviation -> friendly name
RIGHT_NAMES: dict[str, str] = {
    "GA": "GenericAll",
    "GR": "GenericRead",
    "GW": "GenericWrite",
    "GX": "GenericExecute",
    "RC": "ReadControl",
    "SD": "Delete",
    "WD": "WriteDacl",
    "WO": "WriteOwner",
    "CC": "CreateChild",
    "DC": "DeleteChild",
    "LC": "ListChildren",
    "SW": "Self (validated write)",
    "RP": "ReadProperty",
    "WP": "WriteProperty",
    "DT": "DeleteTree",
    "LO": "ListObject",
    "CR": "ControlAccess (extended right)",
}

# Rights that are directly dangerous for attack-path analysis.
DANGEROUS_GENERIC_RIGHTS = {"GA", "WD", "WO", "WP", "SW"}

# ACE type letters in SDDL
ACE_TYPE_NAMES: dict[str, str] = {
    "A": "ALLOW",
    "D": "DENY",
    "OA": "OBJECT_ALLOW",
    "OD": "OBJECT_DENY",
    "AU": "AUDIT",
    "AL": "ALARM",
}

# SDDL flag hex -> meaning (subset we care about)
ACE_FLAGS = {
    "CI": "CONTAINER_INHERIT",
    "OI": "OBJECT_INHERIT",
    "IO": "INHERIT_ONLY",
    "ID": "INHERITED",
    "NP": "NO_PROPAGATE_INHERIT",
}


def _split_rights(right_str: str) -> list[str]:
    """Split an SDDL rights string into its abbreviations."""
    rights: list[str] = []
    i = 0
    n = len(right_str)
    # Rights are two-letter codes; the string is a concatenation of them.
    while i < n:
        if i + 1 < n:
            rights.append(right_str[i : i + 2])
            i += 2
        else:
            rights.append(right_str[i])
            i += 1
    return rights


def resolve_right_name(code: str, object_type_guid: str = "") -> str:
    """Map an SDDL right code (+ optional extended-right GUID) to a friendly name."""
    if code == "CR" and object_type_guid:
        guid = object_type_guid.lower()
        if guid in DANGEROUS_EXTENDED_RIGHTS:
            return DANGEROUS_EXTENDED_RIGHTS[guid]
        if guid in EXTENDED_RIGHTS:
            return EXTENDED_RIGHTS[guid]
    return RIGHT_NAMES.get(code, code)


def is_dangerous_right(code: str) -> bool:
    return code in DANGEROUS_GENERIC_RIGHTS or code == "CR"


def parse_sddl(sddl: str) -> Optional[ACL]:
    """Parse an SDDL string into an :class:`ACL`.

    Example: ``O:S-1-5-21-...-512G:...D:(A;;GA;;;S-1-5-21-...-512)``
    """
    if not sddl:
        return None
    return _parse_sddl_tokens(sddl)


def _parse_sddl_tokens(sddl: str) -> Optional[ACL]:
    acl = ACL()
    # Section markers are a single letter + colon ("O:", "G:", "D:", "S:").
    # SIDs contain "S-" but never "S:", so the regex matches only real markers.
    sections = [(m.group(1), m.start(), m.end())
                for m in re.finditer(r"([OGDS]):", sddl)]
    for i, (letter, _start, end) in enumerate(sections):
        next_start = sections[i + 1][1] if i + 1 < len(sections) else len(sddl)
        content = sddl[end:next_start]
        if letter == "O":
            acl.owner_sid = content.strip()
        elif letter == "G":
            acl.group_sid = content.strip()
        elif letter == "D":
            _parse_ace_list_content(content, acl)
        # "S" is the SACL — ignored for this assessment.
    return acl


def _parse_ace_list_content(content: str, acl: ACL) -> None:
    """Parse ``(type;flags;rights;object;inherit;sid)`` ACEs from the DACL body."""
    for m in re.finditer(r"\((.*?)\)", content):
        ace = _parse_ace(m.group(1))
        if ace:
            acl.dacl.append(ace)


def _parse_ace(body: str) -> Optional[ACE]:
    fields = body.split(";")
    if len(fields) < 6:
        return None
    ace_type = fields[0].strip()
    flags_str = fields[1].strip()
    rights_str = fields[2].strip()
    object_type = fields[3].strip() if len(fields) > 3 else ""
    # fields[4] = inherited object type (ignored)
    trustee = fields[5].strip() if len(fields) > 5 else ""

    if ace_type not in ACE_TYPE_NAMES:
        return None

    codes = _split_rights(rights_str)
    resolved: list[str] = []
    for c in codes:
        resolved.append(resolve_right_name(c, object_type))

    flags = 0
    inherited = False
    for f in flags_str:
        if f in ACE_FLAGS:
            if f == "ID":
                inherited = True
        # numeric flags not common in SDDL text; ignore

    return ACE(
        sid=trustee,
        type=ACE_TYPE_NAMES.get(ace_type, ace_type),
        access_mask=0,
        flags=flags,
        inherited=inherited,
        rights=resolved,
        object_type=object_type,
    )


def acl_has_dangerous_right(acl: ACL, trustee_sid: Optional[str] = None) -> list[ACE]:
    """Return ACEs that grant dangerous rights (optionally for a specific trustee)."""
    out = []
    for ace in acl.dacl:
        if ace.type != "ALLOW" and ace.type != "OBJECT_ALLOW":
            continue
        if trustee_sid and ace.sid != trustee_sid:
            continue
        if any("GenericAll" in r or "WriteDacl" in r or "WriteOwner" in r or "DCSync" in r or "ForceChangePassword" in r for r in ace.rights):
            out.append(ace)
    return out


def sd_has_entries(sd: bytes) -> bool:
    """Return True if a raw security descriptor has a DACL with >=1 ACE.

    Used to tell a *set* ``msDS-AllowedToActOnBehalfOfOtherIdentity`` (RBCD)
    apart from the empty/absent security descriptor that AD returns for
    unconfigured objects (which otherwise stringifies as a false positive).
    """
    if not sd or len(sd) < 20:
        return False
    dacl_off = int.from_bytes(sd[16:20], "little")
    if dacl_off == 0 or dacl_off + 6 > len(sd):
        return False
    # ACL header: AclRevision(1) Sbz1(1) AclSize(2) AceCount(2)
    ace_count = int.from_bytes(sd[dacl_off + 4 : dacl_off + 6], "little")
    return ace_count > 0
