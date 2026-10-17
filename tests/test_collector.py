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
