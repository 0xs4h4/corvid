"""Reporting tests."""

import json

from mock_domain import build_mock_context
from adscan.core.scanner import run_modules
from adscan.graph.engine import build_graph
from adscan.reporting import csv_report, html_report, json_report


def _prepared(tmp_path):
    ctx = build_mock_context()
    run_modules(ctx, ["acl", "domain_recon", "adcs", "privesc", "delegation", "credentials"])
    ctx.deduplicate()
    g = build_graph(ctx)
    paths = g.find_paths()
    return ctx, g, paths


def test_json_report(tmp_path):
    ctx, g, paths = _prepared(tmp_path)
    p = json_report.write_json(ctx, tmp_path, g, paths)
    assert p.exists()
    data = json.loads(p.read_text())
    assert data["metadata"]["findings_count"] == len(ctx.findings)
    assert "findings" in data and "attack_paths" in data


def test_csv_report(tmp_path):
    ctx, g, paths = _prepared(tmp_path)
    p = csv_report.write_csv(ctx, tmp_path)
    assert p.exists()
    lines = p.read_text().strip().splitlines()
    assert lines[0].startswith("id,")
    assert len(lines) == len(ctx.findings) + 1


def test_html_report(tmp_path):
    ctx, g, paths = _prepared(tmp_path)
    p = html_report.write_html(ctx, tmp_path, g, paths)
    assert p.exists()
    content = p.read_text()
    assert "adscan" in content
    assert "Findings" in content
