"""Attack-path graph engine.

Correlates ``Principal -> Group -> Permission -> Object -> High-Value Target``
using NetworkX and extracts candidate escalation paths. Connectivity is a
hypothesis, not proof of exploitation — paths are labelled accordingly.
"""

from __future__ import annotations

from typing import Any, Optional

import networkx as nx

from ..core.context import ScanContext
from ..core.models import ADData
from ..core.sid import parse_sid

# RIDs of high-value groups/accounts
HV_GROUP_RIDS = {512: "Domain Admins", 519: "Enterprise Admins", 518: "Schema Admins", 544: "Administrators"}
HV_USER_RIDS = {500: "Administrator", 502: "krbtgt"}

DANGEROUS_FRAGS = ("GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "DCSync", "ForceChangePassword", "Self (validated write)")


def _rid(sid: str) -> Optional[int]:
    p = parse_sid(sid)
    return p[1] if p else None


class AttackPathGraph:
    def __init__(self, ctx: ScanContext):
        self.ctx = ctx
        self.data: ADData = ctx.data
        self.g = nx.DiGraph()
        self.high_value: dict[str, str] = {}  # node_id -> label

    def _node(self, node_id: str, label: str, kind: str) -> None:
        if node_id not in self.g:
            self.g.add_node(node_id, label=label, kind=kind)

    def _resolve_trustee(self, sid: str) -> str:
        """Map a trustee SID to an existing node id (DN) or a SID-node."""
        if sid in self.data.sid_map:
            return self.data.sid_map[sid]
        return sid

    def build(self) -> "AttackPathGraph":
        data = self.data
        # --- nodes ---
        for dn, u in data.users.items():
            name = u.sAMAccountName or u.name
            self._node(dn, name, "user")
            rid = _rid(u.objectSid or "")
            if rid in HV_USER_RIDS:
                self.high_value[dn] = HV_USER_RIDS[rid]
        for dn, g in data.groups.items():
            self._node(dn, g.name, "group")
            rid = _rid(g.objectSid or "")
            if rid in HV_GROUP_RIDS:
                self.high_value[dn] = HV_GROUP_RIDS[rid]
        for dn, c in data.computers.items():
            self._node(dn, c.name, "computer")
        for dn, gpo in data.gpos.items():
            self._node(dn, gpo.name, "gpo")
        for dn, ou in data.ous.items():
            self._node(dn, ou.name, "ou")
        if data.domain.name:
            self._node("DOMAIN", data.domain.name, "domain")

        # --- membership edges ---
        for dn, g in data.groups.items():
            for member_dn in g.member:
                if member_dn in self.g:
                    self.g.add_edge(member_dn, dn, kind="MemberOf")

        # --- ACL edges (dangerous rights) ---
        buckets = [
            ("user", data.users), ("group", data.groups), ("computer", data.computers),
            ("gpo", data.gpos), ("ou", data.ous),
        ]
        for _kind, objects in buckets:
            for dn, obj in objects.items():
                self._acl_edges(obj, dn)

        # --- domain ACL (DCSync) ---
        if data.domain.acl:
            for ace in data.domain.acl.dacl:
                if ace.type in ("ALLOW", "OBJECT_ALLOW") and "DCSync" in " ".join(ace.rights):
                    src = self._resolve_trustee(ace.sid)
                    self._node(src, data.principal_name(ace.sid), "principal")
                    self.g.add_edge(src, "DOMAIN", kind="DCSync")
                    self.high_value["DOMAIN"] = "Domain (DCSync)"

        # --- delegation edges ---
        for dn, c in data.computers.items():
            if c.msds_AllowedToDelegateTo:
                self._node(dn, c.name, "computer")
                for svc in c.msds_AllowedToDelegateTo:
                    # service names are SPN-like; record as edge label only
                    self.g.add_edge(dn, dn, kind="ConstrainedDelegation", services=c.msds_AllowedToDelegateTo)
            if c.msds_AllowedToActOnBehalfOfOtherIdentity:
                self.g.add_edge(dn, dn, kind="RBCD", allowed=c.msds_AllowedToActOnBehalfOfOtherIdentity)
            if c.userAccountControl & 0x80000:
                self.g.add_edge(dn, dn, kind="UnconstrainedDelegation")

        # --- SPN (kerberoastable) edges to domain ---
        for dn, u in data.users.items():
            if u.servicePrincipalName:
                self.g.add_edge(dn, "DOMAIN", kind="Kerberoastable", spns=u.servicePrincipalName)
        return self

    def _acl_edges(self, obj, dn: str) -> None:
        if not obj.acl:
            return
        for ace in obj.acl.dacl:
            if ace.type not in ("ALLOW", "OBJECT_ALLOW"):
                continue
            rights = " ".join(ace.rights)
            matched = [f for f in DANGEROUS_FRAGS if f in rights]
            if matched:
                src = self._resolve_trustee(ace.sid)
                label = self.data.principal_name(ace.sid)
                self._node(src, label, "principal")
                self.g.add_edge(src, dn, kind="+".join(matched), rights=ace.rights)

    def find_paths(self, limit: int = 20) -> list[dict[str, Any]]:
        """Find candidate escalation paths from entry nodes to high-value targets."""
        paths: list[dict[str, Any]] = []
        for target, tlabel in self.high_value.items():
            for src in self._entry_nodes():
                if src == target:
                    continue
                try:
                    for path in nx.all_simple_paths(self.g, src, target, cutoff=6):
                        paths.append(self._describe_path(path, target, tlabel))
                        if len(paths) >= limit:
                            return paths
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue
        return paths

    def _entry_nodes(self) -> list[str]:
        """Nodes that represent ordinary users / broad principals (start points)."""
        entries = []
        for nid, nd in self.g.nodes(data=True):
            if nd.get("kind") == "user":
                entries.append(nid)
        return entries

    def _describe_path(self, path: list[str], target: str, tlabel: str) -> dict[str, Any]:
        hops = []
        for i in range(len(path) - 1):
            a, b = path[i], path[i + 1]
            ed = self.g.edges[a, b]
            hops.append({
                "from": self.g.nodes[a].get("label", a),
                "to": self.g.nodes[b].get("label", b),
                "edge": ed.get("kind", ""),
            })
        return {"target": tlabel, "target_id": target, "hops": hops, "length": len(hops)}

    def to_dict(self) -> dict[str, Any]:
        nodes = [{"id": n, "label": d.get("label", n), "kind": d.get("kind", "")}
                 for n, d in self.g.nodes(data=True)]
        edges = [{"from": a, "to": b, "kind": d.get("kind", "")}
                 for a, b, d in self.g.edges(data=True)]
        return {"nodes": nodes, "edges": edges}


def build_graph(ctx: ScanContext) -> AttackPathGraph:
    return AttackPathGraph(ctx).build()
