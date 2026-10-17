"""Active (layer 2) collector + attack-path integration tests."""

from mock_domain import build_mock_context
from adscan.collectors.active_collector import (
    ActiveResult,
    Credential,
    _parse_lsa_secret,
    _parse_sam_line,
    _split_hashes,
)
from adscan.graph.engine import build_graph


def test_split_hashes():
    assert _split_hashes(None) == ("", "")
    assert _split_hashes("aad3b435b51404eeaad3b435b51404ee:36d55e1c7f5c9fc78f30e40de3b96708") == (
        "aad3b435b51404eeaad3b435b51404ee", "36d55e1c7f5c9fc78f30e40de3b96708")
    assert _split_hashes("36d55e1c7f5c9fc78f30e40de3b96708") == ("", "36d55e1c7f5c9fc78f30e40de3b96708")


def test_parse_sam_line():
    cred = _parse_sam_line(
        "Admin:1003:aad3b435b51404eeaad3b435b51404ee:36d55e1c7f5c9fc78f30e40de3b96708:::"
    )
    assert cred is not None
    assert cred.account == "Admin"
    assert cred.kind == "nthash"
    assert cred.value == "36d55e1c7f5c9fc78f30e40de3b96708"
    assert cred.rid == "1003"


def test_parse_sam_line_empty_hash_skipped():
    # Guest/DefaultAccount empty hash -> not a credential
    assert _parse_sam_line(
        "Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"
    ) is None


def test_parse_lsa_secret_password():
    cred = _parse_lsa_secret("cloudbase-init:C0yCGbydyJ1mgJeCTfcC")
    assert cred is not None
    assert cred.kind == "password"
    assert cred.value == "C0yCGbydyJ1mgJeCTfcC"


def test_parse_lsa_secret_hash_skipped():
    assert _parse_lsa_secret(
        "SECURA\\SECURE$:aad3b435b51404eeaad3b435b51404ee:f53ea4a26568c4ffebc092896dff170a:::"
    ) is None


def test_add_active_admin_to_edges():
    ctx = build_mock_context()
    g = build_graph(ctx)
    result = ActiveResult(
        admin_hosts=["192.168.1.50"],
        credentials=[],
    )
    g.add_active(result, "svc_dcsync")

    kinds = {d.get("kind") for _, _, d in g.g.edges(data=True)}
    assert "AdminTo" in kinds


def test_add_active_credential_reuse_path():
    """Dumping local 'Administrator' creds must reach Domain Admins via reuse."""
    ctx = build_mock_context()
    g = build_graph(ctx)
    result = ActiveResult(
        admin_hosts=["192.168.1.50"],
        credentials=[Credential("Administrator", "nthash", "deadbeef", "192.168.1.50")],
    )
    g.add_active(result, "svc_dcsync")

    # reuse hint must be recorded
    assert len(result.reuse_hints) == 1
    assert result.reuse_hints[0]["domain_account"] == "Administrator"

    # a path from svc_dcsync must now traverse AdminTo + CredentialReuse
    paths = g.find_paths(start="svc_dcsync")
    edges = {h["edge"] for p in paths for h in p["hops"]}
    assert "AdminTo" in edges
    assert "CredentialReuse" in edges


def test_add_active_no_match_no_reuse():
    """A dumped local account that has no domain counterpart -> no reuse edge."""
    ctx = build_mock_context()
    g = build_graph(ctx)
    result = ActiveResult(
        admin_hosts=["192.168.1.50"],
        credentials=[Credential("not_a_domain_user", "nthash", "deadbeef", "192.168.1.50")],
    )
    g.add_active(result, "svc_dcsync")
    assert result.reuse_hints == []
