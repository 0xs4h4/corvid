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
