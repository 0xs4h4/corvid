"""SID handling: parsing, well-known SID/RID resolution, principal naming."""

from __future__ import annotations

from typing import Optional

# Well-known RIDs that indicate high-value principals within a domain.
WELL_KNOWN_RIDS: dict[int, str] = {
    498: "Enterprise Read-Only Domain Controllers",
    500: "Administrator",
    502: "krbtgt",
    512: "Domain Admins",
    513: "Domain Users",
    514: "Domain Guests",
    515: "Domain Computers",
    516: "Domain Controllers",
    517: "Cert Publishers",
    518: "Schema Admins",
    519: "Enterprise Admins",
    520: "Group Policy Creator Owners",
    521: "Read-Only Domain Controllers",
    525: "Protected Users",
    526: "Key Admins",
    527: "Enterprise Key Admins",
    553: "RAS and IAS Servers",
    571: "Allowed RODC Password Replication Group",
    572: "Denied RODC Password Replication Group",
    1101: "DnsAdmins",
    1102: "DnsUpdateProxy",
}

# Well-known SIDs not tied to a domain RID.
WELL_KNOWN_SIDS: dict[str, str] = {
    "S-1-0-0": "Null SID",
    "S-1-1-0": "Everyone",
    "S-1-2-0": "LOCAL",
    "S-1-3-0": "CREATOR OWNER",
    "S-1-3-1": "CREATOR GROUP",
    "S-1-5-7": "ANONYMOUS LOGON",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "Principal Self",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-15": "This Organization",
    "S-1-5-18": "SYSTEM",
    "S-1-5-19": "LOCAL SERVICE",
    "S-1-5-20": "NETWORK SERVICE",
    "S-1-5-21-*": "(domain SID)",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-546": "BUILTIN\\Guests",
    "S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
    "S-1-5-32-556": "BUILTIN\\Network Configuration Operators",
    "S-1-5-32-562": "BUILTIN\\Distributed COM Users",
    "S-1-5-32-573": "BUILTIN\\Event Log Readers",
    "S-1-5-32-580": "BUILTIN\\Remote Management Users",
    "S-1-5-32-582": "BUILTIN\\Storage Replica Administrators",
}

# Privileged / high-value RIDs worth flagging on their own.
PRIVILEGED_RIDS: set[int] = {498, 500, 502, 512, 516, 518, 519, 526, 527, 544}

# Extended-right GUIDs that gate powerful operations.
EXTENDED_RIGHTS: dict[str, str] = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
    "00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password",
    "45ec5156-db7e-47bb-b53f-dbeb2d03c40f": "Self-Membership",
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "User-Change-Password",
    "0e10c968-78fb-11d2-90d4-00c04f79dc55": "Enroll",
    "a05b8cc2-17bc-4802-a710-e7c15ab866a2": "AutoEnroll",
}

# Extended-right GUIDs that directly enable domain compromise.
DANGEROUS_EXTENDED_RIGHTS: dict[str, str] = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DCSync (GetChanges)",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DCSync (GetChangesAll)",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DCSync (GetChangesFiltered)",
    "00299570-246d-11d0-a768-00aa006e0529": "ForceChangePassword",
}


def parse_sid(sid: str) -> Optional[tuple[str, int]]:
    """Return (prefix, rid) — the last numeric component is the RID."""
    if not sid or not sid.startswith("S-"):
        return None
    parts = sid.split("-")
    if len(parts) < 2 or not parts[-1].isdigit():
        return None
    rid = int(parts[-1])
    prefix = "-".join(parts[:-1])
    return prefix, rid


def rid_name(sid: str) -> Optional[str]:
    """Best-effort human name for a SID from well-known tables."""
    if sid in WELL_KNOWN_SIDS:
        return WELL_KNOWN_SIDS[sid]
    parsed = parse_sid(sid)
    if parsed:
        _, rid = parsed
        if rid in WELL_KNOWN_RIDS:
            return WELL_KNOWN_RIDS[rid]
    return None


def is_privileged_sid(sid: str) -> bool:
    """True if the SID is a well-known privileged group/account."""
    if sid in WELL_KNOWN_SIDS and sid.startswith("S-1-5-32-544"):
        return True
    parsed = parse_sid(sid)
    if parsed:
        _, rid = parsed
        if rid in PRIVILEGED_RIDS:
            return True
    return False


def sid_to_sddl(sid_bytes: bytes) -> str:
    """Convert a raw binary SID (SID structure) to SDDL string form."""
    if not sid_bytes:
        return ""
    try:
        revision = sid_bytes[0]
        count = sid_bytes[1]
        authority = int.from_bytes(sid_bytes[2:8], "big")
        subs = []
        for i in range(count):
            off = 8 + i * 4
            subs.append(int.from_bytes(sid_bytes[off : off + 4], "little"))
        body = "-".join(str(s) for s in subs)
        return f"S-{revision}-{authority}{'-' + body if body else ''}"
    except Exception:
        return ""
