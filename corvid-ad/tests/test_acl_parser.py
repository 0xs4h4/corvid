"""ACL / SDDL parsing tests."""

from corvid_ad.utils.acl_parser import (
    parse_sddl,
    resolve_right_name,
    is_dangerous_right,
    acl_has_dangerous_right,
    sd_has_entries,
)

DCSYNC_GUID = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"


def test_parse_owner_group():
    acl = parse_sddl("O:S-1-5-21-1-2-3-512G:S-1-5-21-1-2-3-513D:(A;;GA;;;S-1-5-21-1-2-3-513)")
    assert acl.owner_sid == "S-1-5-21-1-2-3-512"
    assert acl.group_sid == "S-1-5-21-1-2-3-513"
    assert len(acl.dacl) == 1


def test_parse_generic_all():
    acl = parse_sddl("O:AAG:D:(A;;GA;;;S-1-5-21-1-2-3-513)")
    ace = acl.dacl[0]
    assert "GenericAll" in ace.rights
    assert ace.sid == "S-1-5-21-1-2-3-513"


def test_parse_extended_right_dcsync():
    acl = parse_sddl(f"O:AAG:D:(OA;;CR;{DCSYNC_GUID};;S-1-5-21-1-2-3-1601)")
    ace = acl.dacl[0]
    assert "DCSync" in " ".join(ace.rights)


def test_multiple_rights():
    acl = parse_sddl("O:AAG:D:(A;;RPLCRC;;;S-1-5-21-1-2-3-513)")
    ace = acl.dacl[0]
    assert "ReadProperty" in ace.rights
    assert "ListChildren" in ace.rights


def test_deny_ace_ignored_in_dangerous():
    acl = parse_sddl("O:AAG:D:(D;;GA;;;S-1-5-21-1-2-3-513)(A;;GA;;;S-1-5-21-1-2-3-514)")
    dang = acl_has_dangerous_right(acl)
    # only ALLOW ace counted
    assert len(dang) == 1
    assert dang[0].sid == "S-1-5-21-1-2-3-514"


def test_resolve_right_name():
    assert resolve_right_name("GA") == "GenericAll"
    assert resolve_right_name("CR", DCSYNC_GUID) == "DCSync (GetChanges)"


def test_is_dangerous():
    assert is_dangerous_right("GA")
    assert is_dangerous_right("WD")
    assert not is_dangerous_right("RC")


def test_sd_has_entries_empty():
    assert sd_has_entries(b"") is False
    assert sd_has_entries(b"\x01\x02") is False


def test_sd_has_entries_no_dacl():
    sd = bytearray(20)
    sd[16:20] = (0).to_bytes(4, "little")  # DACL offset = 0 (no DACL)
    assert sd_has_entries(bytes(sd)) is False


def test_sd_has_entries_with_ace():
    sd = bytearray(26)
    sd[16:20] = (20).to_bytes(4, "little")  # DACL offset = 20
    sd[20] = 2                              # AclRevision
    sd[21] = 0                              # Sbz1
    sd[22:24] = (8).to_bytes(2, "little")   # AclSize
    sd[24:26] = (1).to_bytes(2, "little")   # AceCount = 1
    assert sd_has_entries(bytes(sd)) is True
