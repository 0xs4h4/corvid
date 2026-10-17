"""CLI and error-handling tests."""

import io
import json
import sys
from unittest import mock

import pytest

from mock_domain import build_mock_context
from adscan import cli
from adscan.core.scanner import run_modules
from adscan.graph.engine import build_graph
from adscan.reporting import json_report
from adscan.utils.serialize import save_snapshot


def test_checks_list(capsys):
    rc = cli.main(["checks", "--list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "domain_recon" in out


def test_doctor(capsys):
    rc = cli.main(["doctor"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "ldap3" in out


def test_analyze_offline(tmp_path, capsys):
    ctx = build_mock_context()
    save_snapshot(ctx.data, tmp_path / "snapshot.json")
    rc = cli.main(["analyze", "--input", str(tmp_path), "--mode", "full", "--output", str(tmp_path / "out")])
    assert rc == 0
    assert (tmp_path / "out" / "report.html").exists()


def test_report_from_json(tmp_path, capsys):
    ctx = build_mock_context()
    run_modules(ctx, ["acl"])
    g = build_graph(ctx)
    p = json_report.write_json(ctx, tmp_path, g, [])
    rc = cli.main(["report", "--input", str(p), "--format", "html", "--output", str(tmp_path / "rep")])
    assert rc == 0
    assert (tmp_path / "rep" / "report.html").exists()


def test_scan_collection_failure_aborts(tmp_path, capsys):
    """A live-scan collection failure should abort (not run modules on empty data)."""
    args = mock.Mock(
        domain="corp.local", dc_ip="10.0.0.1", username="u", password="p",
        hashes=None, mode="quick", modules=[], output=str(tmp_path),
        use_ssl=False, no_password=False, config=None, no_dashboard=True,
    )
    with mock.patch("adscan.collectors.ldap_collector.LDAPCollector") as MockColl:
        inst = MockColl.return_value
        inst.collect.side_effect = ConnectionError("mock DNS failure")
        rc = cli.cmd_scan(args)
    assert rc == 1  # aborts on collection failure
    captured = capsys.readouterr()
    assert "Collection failed" in captured.err
    # no reports should be written for an aborted scan
    assert not (tmp_path / "results.json").exists()


def test_password_not_in_output(tmp_path, capsys):
    """Passwords must never appear in logs or stdout."""
    ctx = build_mock_context()
    save_snapshot(ctx.data, tmp_path / "snapshot.json")
    cli.main(["analyze", "--input", str(tmp_path), "--mode", "quick", "--output", str(tmp_path / "o")])
    out = capsys.readouterr()
    assert "secretpass" not in out.out
