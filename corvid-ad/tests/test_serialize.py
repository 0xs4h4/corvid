"""Serialization round-trip tests."""

from mock_domain import build_mock_domain
from corvid_ad.utils.serialize import data_from_dict, data_to_dict, load_snapshot, save_snapshot


def test_roundtrip(tmp_path):
    data = build_mock_domain()
    d = data_to_dict(data)
    restored = data_from_dict(d)
    assert len(restored.users) == len(data.users)
    assert len(restored.groups) == len(data.groups)
    assert len(restored.computers) == len(data.computers)
    assert len(restored.templates) == len(data.templates)
    assert restored.domain.name == "corp.local"


def test_acl_preserved():
    data = build_mock_domain()
    restored = data_from_dict(data_to_dict(data))
    # find victim_admin ACL
    victim = [u for u in restored.users.values() if u.sAMAccountName == "victim_admin"][0]
    assert victim.acl is not None
    assert any("GenericAll" in " ".join(ace.rights) for ace in victim.acl.dacl)


def test_save_load_file(tmp_path):
    data = build_mock_domain()
    p = tmp_path / "snap.json"
    save_snapshot(data, p)
    assert p.exists()
    restored = load_snapshot(p)
    assert restored.domain.domain_sid == data.domain.domain_sid
