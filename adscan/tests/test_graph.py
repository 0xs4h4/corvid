"""Graph / attack-path correlation tests."""

from mock_domain import build_mock_context
from adscan.graph.engine import build_graph


def test_build_graph_nodes():
    ctx = build_mock_context()
    g = build_graph(ctx)
    assert len(g.g.nodes) > 0
    # high-value targets should include Domain Admins and krbtgt
    assert any("Domain Admins" in v for v in g.high_value.values())


def test_high_value_detected():
    ctx = build_mock_context()
    g = build_graph(ctx)
    assert len(g.high_value) >= 2  # Domain Admins + krbtgt at minimum


def test_dcsync_edge_present():
    ctx = build_mock_context()
    g = build_graph(ctx)
    kinds = [d.get("kind") for _, _, d in g.g.edges(data=True)]
    assert any("DCSync" in (k or "") for k in kinds)


def test_acl_edge_present():
    ctx = build_mock_context()
    g = build_graph(ctx)
    kinds = [d.get("kind") for _, _, d in g.g.edges(data=True)]
    assert any("GenericAll" in (k or "") for k in kinds)


def test_to_dict_shape():
    ctx = build_mock_context()
    g = build_graph(ctx)
    d = g.to_dict()
    assert "nodes" in d and "edges" in d
    assert all("id" in n and "label" in n for n in d["nodes"])


def test_find_paths_from_start_dcsync():
    """svc_dcsync holds DCSync -> a one-hop path to the domain must be found."""
    ctx = build_mock_context()
    g = build_graph(ctx)
    paths = g.find_paths(start="svc_dcsync")
    assert paths, "expected at least one path from svc_dcsync"
    assert any("DCSync" in h["edge"] for p in paths for h in p["hops"])


def test_path_hops_annotated():
    """Every hop must carry a MITRE technique and an exploitation hint."""
    ctx = build_mock_context()
    g = build_graph(ctx)
    paths = g.find_paths(start="svc_dcsync")
    for p in paths:
        for h in p["hops"]:
            assert "technique" in h and "hint" in h
            assert "edge" in h and "from" in h and "to" in h


def test_find_paths_unknown_start():
    ctx = build_mock_context()
    g = build_graph(ctx)
    assert g.find_paths(start="does_not_exist") == []
