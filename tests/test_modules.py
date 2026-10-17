"""Module detection tests against the mock domain."""

import pytest

from mock_domain import build_mock_context
from adscan.core.scanner import run_modules


def _findings(module_names, ctx=None):
    ctx = ctx or build_mock_context()
    ctx.findings = []
    run_modules(ctx, module_names)
    return ctx.findings


def _titles(findings):
    return [f.title for f in findings]


def test_kerberoast_detection():
    fs = _findings(["domain_recon"])
    assert any("SPN" in t and "svc_sql" in t for t in _titles(fs))


def test_kerberoast_excludes_krbtgt():
    """krbtgt carries a kadmin/changepw SPN but must not be reported as kerberoastable."""
    fs = _findings(["domain_recon"])
    assert not any("krbtgt" in t and "SPN" in t for t in _titles(fs))


def test_asrep_detection():
    fs = _findings(["credentials"])
    assert any("AS-REP" in t and "asrep_user" in t for t in _titles(fs))


def test_reversible_encryption():
    fs = _findings(["credentials"])
    assert any("reversible" in t and "reversible_user" in t for t in _titles(fs))


def test_acl_generic_all():
    fs = _findings(["acl"])
    assert any("GenericAll" in t and "victim_admin" in t for t in _titles(fs))


def test_dcsync_detection():
    fs = _findings(["privesc"])
    assert any("DCSync" in t and "svc_dcsync" in t for t in _titles(fs))


def test_unconstrained_delegation():
    fs = _findings(["delegation"])
    assert any("Unconstrained" in t and "WS01" in t for t in _titles(fs))


def test_constrained_delegation():
    fs = _findings(["delegation"])
    assert any("Constrained" in t and "SQL01" in t for t in _titles(fs))


def test_rbcd():
    fs = _findings(["delegation"])
    assert any("Resource-based" in t and "FILE01" in t for t in _titles(fs))


def test_adcs_esc1():
    fs = _findings(["adcs"])
    assert any("ESC1" in t for t in _titles(fs))


def test_privileged_group_membership():
    fs = _findings(["domain_recon"])
    assert any("Domain Admins" in t for t in _titles(fs))


def test_machine_account_quota():
    fs = _findings(["vulnerabilities"])
    assert any("MachineAccountQuota" in t for t in _titles(fs))


def test_finding_schema_complete():
    fs = _findings(["acl"])
    for f in fs:
        d = f.to_dict()
        for key in ("id", "category", "severity", "confidence", "title", "evidence", "status"):
            assert key in d
        assert f.severity.value in ("critical", "high", "medium", "low", "info")
        assert f.confidence.value in ("high", "medium", "low")
