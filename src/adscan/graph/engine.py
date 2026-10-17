"""Attack-path graph engine (BloodHound-style).

Builds a directed graph of *compromise* edges — ``from`` = a principal you
control, ``to`` = what that lets you compromise — and finds shortest escalation
paths from a starting principal (or all low-privileged users) to high-value
targets (Domain Admins, Enterprise Admins, Schema Admins, Domain Controllers,
Administrators, krbtgt, DCSync).

Every edge carries a MITRE technique and a one-line exploitation hint. Paths
are **hypotheses**: connectivity is a candidate, not proof of exploitability.
"""

from __future__ import annotations

from typing import Any, Optional

import networkx as nx

from ..core.context import ScanContext
from ..core.models import ADData
from ..core.sid import parse_sid

# RIDs of high-value groups / accounts
HV_GROUP_RIDS = {
    512: "Domain Admins",
    516: "Domain Controllers",
    518: "Schema Admins",
    519: "Enterprise Admins",
    544: "Administrators",
}
HV_USER_RIDS = {500: "Administrator", 502: "krbtgt"}

# Edge kind -> (MITRE technique, one-line exploitation hint)
EDGE_INFO: dict[str, tuple[str, str]] = {
    "MemberOf": ("T1078", "membership grants the group's privileges"),
    "GenericAll": ("T1484", "full control: reset password / add-to-group / write DACL"),
    "GenericWrite": ("T1098", "write attributes (e.g. add SPN -> Kerberoast)"),
    "WriteDacl": ("T1484", "modify DACL -> grant self full control"),
    "WriteOwner": ("T1484", "take ownership -> then WriteDacl"),
    "ForceChangePassword": ("T1098", "reset the target's password and log in"),
    "DCSync": ("T1003.006", "replicate secrets — dump all hashes incl. krbtgt"),
    "AddSelf": ("T1098", "add self to the group"),
    "Owns": ("T1484", "owner can WriteDacl on the object"),
    "Kerberoastable": ("T1558.003", "request TGS and crack the password offline"),
    "ASREPRoastable": ("T1558.004", "request AS-REP and crack the password offline"),
    "ConstrainedDelegation": ("T1558.001", "control this host -> impersonate any user to target"),
    "RBCD": ("T1558.001", "control the allowed-to-act account -> impersonate on this host"),
    "UnconstrainedDelegation": ("T1558.001", "control this host -> capture TGTs (incl. DC)"),
    "GPOControl": ("T1484", "control the GPO -> push policy to linked computers"),
}

# Resolved right fragment -> edge kind (order matters: first match wins per ACE)
RIGHT_TO_EDGE: list[tuple[str, str]] = [
    ("GenericAll", "GenericAll"),
    ("GenericWrite", "GenericWrite"),
    ("WriteDacl", "WriteDacl"),
    ("WriteOwner", "WriteOwner"),
    ("DCSync", "DCSync"),
    ("ForceChangePassword", "ForceChangePassword"),
    ("Self-Membership", "AddSelf"),
]

# Which right fragments are dangerous at all (fast pre-filter)
DANGEROUS_FRAGS = tuple(k for k, _ in RIGHT_TO_EDGE)


def _rid(sid: str) -> Optional[int]:
    p = parse_sid(sid)
    return p[1] if p else None


class AttackPathGraph:
    def __init__(self, ctx: ScanContext):
        self.ctx = ctx
        self.data: ADData = ctx.data
        self.g = nx.DiGraph()
        self.high_value: dict[str, str] = {}  # node_id -> label
        self._name_index: dict[str, str] = {}  # lowercased name -> node id
        self._host_index: dict[str, str] = {}  # lowercased dNSHostName -> computer node id

    # -- node helpers --------------------------------------------------------
    def _node(self, node_id: str, label: str, kind: str) -> None:
        if node_id not in self.g:
            self.g.add_node(node_id, label=label, kind=kind)
            self._name_index[label.lower()] = node_id

    def _resolve_trustee(self, sid: str) -> str:
        """Map a trustee SID to an existing node id (DN), else a SID-node."""
        return self.data.sid_map.get(sid, sid)

    def _resolve_start(self, start: str) -> Optional[str]:
        """Resolve a user-supplied start (name / sAMAccountName / DN / SID) to a node id."""
        key = start.lower()
        if key in self._name_index:
            return self._name_index[key]
        # try exact DN match
        for nid, d in self.g.nodes(data=True):
            if nid.lower() == start.lower() or d.get("label", "").lower() == key:
                return nid
        # try SID
        if start in self.data.sid_map:
            return self.data.sid_map[start]
        return None

    # -- build ---------------------------------------------------------------
    def build(self) -> "AttackPathGraph":
        data = self.data
        # nodes
        for dn, u in data.users.items():
            self._node(dn, u.sAMAccountName or u.name, "user")
            if _rid(u.objectSid or "") in HV_USER_RIDS:
                self.high_value[dn] = HV_USER_RIDS[_rid(u.objectSid or "")]
        for dn, g in data.groups.items():
            self._node(dn, g.name, "group")
            if _rid(g.objectSid or "") in HV_GROUP_RIDS:
                self.high_value[dn] = HV_GROUP_RIDS[_rid(g.objectSid or "")]
        for dn, c in data.computers.items():
            self._node(dn, c.name, "computer")
            if c.dNSHostName:
                self._host_index[c.dNSHostName.lower()] = dn
        for dn, gpo in data.gpos.items():
            self._node(dn, gpo.name, "gpo")
        for dn, ou in data.ous.items():
            self._node(dn, ou.name, "ou")
        if data.domain.name:
            self._node("DOMAIN", data.domain.name, "domain")

        # mark DC computers high-value (control of a DC == domain admin)
        for dn, c in data.computers.items():
            if c.userAccountControl & 0x2000:  # UF_SERVER_TRUST_ACCOUNT
                self.high_value[dn] = "Domain Controller"
                self._dc = dn

        # membership edges (member -> group)
        for dn, g in data.groups.items():
            for member_dn in g.member:
                if member_dn in self.g:
                    self.g.add_edge(member_dn, dn, kind="MemberOf")

        # ACL edges on every object class
        buckets = [
            ("user", data.users), ("group", data.groups), ("computer", data.computers),
            ("gpo", data.gpos), ("ou", data.ous),
        ]
        for _kind, objects in buckets:
            for dn, obj in objects.items():
                self._acl_edges(obj, dn)

        # domain ACL (DCSync and other dangerous rights on the domain root)
        if data.domain.acl:
            for ace in data.domain.acl.dacl:
                self._ace_edge(ace, "DOMAIN")
                if ace.type in ("ALLOW", "OBJECT_ALLOW") and "DCSync" in " ".join(ace.rights):
                    self.high_value["DOMAIN"] = "Domain (DCSync)"

        # delegation edges
        self._delegation_edges()

        # roastable edges (user -> credentials crackable -> user's privileges)
        for dn, u in data.users.items():
            if u.servicePrincipalName and _rid(u.objectSid or "") != 502:
                self.g.add_edge(dn, dn, kind="Kerberoastable", spns=u.servicePrincipalName)
            if u.userAccountControl & 0x400000:  # UF_DONT_REQUIRE_PREAUTH
                self.g.add_edge(dn, dn, kind="ASREPRoastable")

        return self

    def _acl_edges(self, obj, dn: str) -> None:
        if not obj.acl:
            return
        # owner -> object (Owns => WriteDacl), skipping built-in privileged owners
        owner = (obj.acl.owner_sid or "").strip()
        if owner.startswith("S-") and _rid(owner) not in (500, 512, 516, 518, 519, 544, 498):
            src = self._resolve_trustee(owner)
            self._node(src, self.data.principal_name(owner), "principal")
            self.g.add_edge(src, dn, kind="Owns")
        for ace in obj.acl.dacl:
            self._ace_edge(ace, dn)

    def _ace_edge(self, ace, target: str) -> None:
        if ace.type not in ("ALLOW", "OBJECT_ALLOW"):
            return
        rights = " ".join(ace.rights)
        if not any(f in rights for f in DANGEROUS_FRAGS):
            return
        src = self._resolve_trustee(ace.sid)
        self._node(src, self.data.principal_name(ace.sid), "principal")
        for frag, edge in RIGHT_TO_EDGE:
            if frag in rights:
                self.g.add_edge(src, target, kind=edge, rights=ace.rights)
                break  # one edge per ACE (highest-value right)

    def _delegation_edges(self) -> None:
        for dn, c in self.data.computers.items():
            # unconstrained delegation: control this host -> capture TGTs
            if c.userAccountControl & 0x80000 and not (c.userAccountControl & 0x2000):
                self.g.add_edge(dn, dn, kind="UnconstrainedDelegation")
            # constrained delegation: control this host -> impersonate to target
            for spn in c.msds_AllowedToDelegateTo or []:
                target = self._spn_to_host(spn)
                if target:
                    self.g.add_edge(dn, target, kind="ConstrainedDelegation", spn=spn)
            # RBCD: control allowed-to-act account -> impersonate on this host
            if c.msds_AllowedToActOnBehalfOfOtherIdentity:
                self.g.add_edge(dn, dn, kind="RBCD")

    def _spn_to_host(self, spn: str) -> Optional[str]:
        """Map 'service/host.domain' to a computer node id via dNSHostName."""
        if "/" not in spn:
            return None
        host = spn.split("/", 1)[1].split(":")[0].lower()
        return self._host_index.get(host)

    # -- pathfinding ---------------------------------------------------------
    def find_paths(self, start: Optional[str] = None, limit: int = 50, max_hops: int = 5) -> list[dict[str, Any]]:
        """Find escalation paths to high-value targets.

        ``start`` may be a sAMAccountName, DN or SID. When omitted, every
        low-privileged user is treated as a possible starting point.
        """
        if start:
            s = self._resolve_start(start)
            if s is None:
                return []
            starts = [s]
        else:
            starts = self._entry_nodes()

        paths: list[dict[str, Any]] = []
        for target_id, tlabel in self.high_value.items():
            for s in starts:
                if s == target_id:
                    continue
                try:
                    for path in nx.all_simple_paths(self.g, s, target_id, cutoff=max_hops):
                        paths.append(self._describe_path(path, target_id, tlabel))
                        if len(paths) >= limit:
                            return self._rank(paths)
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue
        return self._rank(paths)

    def _entry_nodes(self) -> list[str]:
        """Low-privileged users (exclude built-in admin / krbtgt) as start points."""
        entries = []
        for nid, nd in self.g.nodes(data=True):
            if nd.get("kind") != "user":
                continue
            sid = ""
            for dn, u in self.data.users.items():
                if dn == nid:
                    sid = u.objectSid or ""
                    break
            rid = _rid(sid)
            if rid in (500, 502):
                continue
            entries.append(nid)
        return entries

    def _rank(self, paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return sorted(paths, key=lambda p: (p["length"], -p["technique_count"]))

    def _describe_path(self, path: list[str], target: str, tlabel: str) -> dict[str, Any]:
        hops = []
        techniques: set[str] = set()
        for i in range(len(path) - 1):
            a, b = path[i], path[i + 1]
            ed = self.g.edges[a, b]
            kind = ed.get("kind", "")
            mitre, hint = EDGE_INFO.get(kind, ("", ""))
            techniques.add(kind)
            hops.append({
                "from": self.g.nodes[a].get("label", a),
                "to": self.g.nodes[b].get("label", b),
                "edge": kind,
                "technique": mitre,
                "hint": hint,
            })
        return {
            "target": tlabel,
            "target_id": target,
            "hops": hops,
            "length": len(hops),
            "technique_count": len(techniques),
        }

    def to_dict(self) -> dict[str, Any]:
        nodes = [{"id": n, "label": d.get("label", n), "kind": d.get("kind", "")}
                 for n, d in self.g.nodes(data=True)]
        edges = [{"from": a, "to": b, "kind": d.get("kind", "")}
                 for a, b, d in self.g.edges(data=True)]
        return {"nodes": nodes, "edges": edges}


def build_graph(ctx: ScanContext) -> AttackPathGraph:
    return AttackPathGraph(ctx).build()
