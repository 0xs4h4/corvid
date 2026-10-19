"""LDAP collector tests (control shape, error handling)."""

from unittest import mock

from adscan.collectors.ldap_collector import LDAPCollector
from adscan.core.config import ScanOptions


def _collector():
    opts = ScanOptions(domain="corp.local", dc_ip="10.0.0.1", username="u", password="p")
    cfg = {"ldap": {}, "scan": {}}
    return LDAPCollector(opts, cfg)


def test_sddl_control_not_nested():
    """The security descriptor control must be passed as a flat list, not
    [[control]] — ldap3 raises 'control must be a sequence of 3 elements'
    when it receives a nested list."""
    coll = _collector()
    conn = mock.Mock()
    conn.search = mock.Mock()
    conn.response = []  # no results -> single page, no cookie
    conn.result = {"controls": {}}
    coll._conn = conn

    coll._search("DC=corp,DC=local", "(objectClass=user)", ["sAMAccountName"], sddl=True)

    kwargs = conn.search.call_args.kwargs
    controls = kwargs["controls"]
    assert controls is not None
    assert isinstance(controls, list)
    # the bug was a nested list: [[control]]
    assert not isinstance(controls[0], list)


def test_no_controls_when_not_sddl():
    coll = _collector()
    conn = mock.Mock()
    conn.search = mock.Mock()
    conn.response = []
    conn.result = {"controls": {}}
    coll._conn = conn

    coll._search("DC=corp,DC=local", "(objectClass=user)", ["sAMAccountName"], sddl=False)

    assert conn.search.call_args.kwargs["controls"] is None


def test_rbcd_none_returns_empty():
    coll = _collector()
    assert coll._rbcd({}) == ""
    assert coll._rbcd({"msDS-AllowedToActOnBehalfOfOtherIdentity": None}) == ""


def test_rbcd_empty_sd_list_returns_empty():
    """ldap3 returns the attribute as [bytes]; an empty SD must not trip RBCD."""
    coll = _collector()
    sd = bytearray(20)
    sd[16:20] = (0).to_bytes(4, "little")  # no DACL
    e = {"msDS-AllowedToActOnBehalfOfOtherIdentity": [bytes(sd)]}
    assert coll._rbcd(e) == ""


def test_rbcd_real_sd_list_returns_hex():
    coll = _collector()
    sd = bytearray(26)
    sd[16:20] = (20).to_bytes(4, "little")  # DACL offset
    sd[20] = 2
    sd[22:24] = (8).to_bytes(2, "little")   # AclSize
    sd[24:26] = (1).to_bytes(2, "little")   # AceCount = 1
    e = {"msDS-AllowedToActOnBehalfOfOtherIdentity": [bytes(sd)]}
    assert coll._rbcd(e) == bytes(sd).hex()
