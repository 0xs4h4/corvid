"""SID parsing and resolution tests."""

from corvid_ad.core.sid import (
    WELL_KNOWN_RIDS,
    is_privileged_sid,
    parse_sid,
    rid_name,
    sid_to_sddl,
)


def test_parse_domain_sid():
    assert parse_sid("S-1-5-21-1-2-3-512") == ("S-1-5-21-1-2-3", 512)


def test_parse_well_known_not_domain():
    # S-1-5-32-544 is a well-known SID with RID 544; parse_sid returns it as domain-shaped
    assert parse_sid("S-1-5-32-544") == ("S-1-5-32", 544)


def test_rid_name():
    assert rid_name("S-1-5-21-1-2-3-512") == "Domain Admins"
    assert rid_name("S-1-5-32-544") == "BUILTIN\\Administrators"
    assert rid_name("S-1-5-21-1-2-3-1101") == "DnsAdmins"


def test_is_privileged():
    assert is_privileged_sid("S-1-5-21-1-2-3-512") is True
    assert is_privileged_sid("S-1-5-21-1-2-3-513") is False


def test_sid_to_sddl():
    # S-1-5-21-... binary encoding
    # revision=1, count=5, authority=5 (big-endian 6 bytes), subs (little-endian 4 bytes each)
    b = b"\x01\x05\x00\x00\x00\x00\x00\x05" + b"\x15\x00\x00\x00" * 5
    assert sid_to_sddl(b).startswith("S-1-5-21")
