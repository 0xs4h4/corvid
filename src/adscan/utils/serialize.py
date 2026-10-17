"""Serialization of :class:`ADData` to/from JSON for offline analysis."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from ..core.models import (
    ACE,
    ACL,
    ADCA,
    ADComputer,
    ADData,
    ADGPO,
    ADGroup,
    ADObject,
    ADTemplate,
    ADTrust,
    ADUser,
    DomainInfo,
)


def data_to_dict(data: ADData) -> dict[str, Any]:
    return asdict(data)


def _ace(d: dict) -> ACE:
    return ACE(
        sid=d.get("sid", ""), type=d.get("type", "ALLOW"),
        access_mask=d.get("access_mask", 0), flags=d.get("flags", 0),
        inherited=d.get("inherited", False), rights=d.get("rights", []),
        object_type=d.get("object_type"),
    )


def _acl(d: dict | None) -> ACL | None:
    if not d:
        return None
    return ACL(
        owner_sid=d.get("owner_sid", ""), group_sid=d.get("group_sid", ""),
        dacl=[_ace(a) for a in d.get("dacl", [])],
    )


def _obj(d: dict, cls) -> Any:
    kwargs = dict(d)
    kwargs.pop("acl", None)
    kwargs.pop("attributes", None)
    acl = _acl(d.get("acl"))
    attrs = d.get("attributes", {}) or {}
    return cls(acl=acl, attributes=attrs, **kwargs)


def data_from_dict(d: dict) -> ADData:
    dom_dict = dict(d.get("domain", {}))
    dom_dict["acl"] = _acl(dom_dict.get("acl"))
    dom = DomainInfo(**dom_dict)
    data = ADData(domain=dom, sid_map=d.get("sid_map", {}), name_map=d.get("name_map", {}))

    for dn, u in d.get("users", {}).items():
        data.users[dn] = _obj(u, ADUser)
    for dn, g in d.get("groups", {}).items():
        data.groups[dn] = _obj(g, ADGroup)
    for dn, c in d.get("computers", {}).items():
        data.computers[dn] = _obj(c, ADComputer)
    for dn, g in d.get("gpos", {}).items():
        data.gpos[dn] = _obj(g, ADGPO)
    for dn, c in d.get("cas", {}).items():
        data.cas[dn] = _obj(c, ADCA)
    for dn, t in d.get("templates", {}).items():
        data.templates[dn] = _obj(t, ADTemplate)
    for dn, t in d.get("trusts", {}).items():
        data.trusts[dn] = _obj(t, ADTrust)
    for dn, o in d.get("ous", {}).items():
        data.ous[dn] = _obj(o, ADObject)
    return data


def save_snapshot(data: ADData, path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data_to_dict(data), indent=2), encoding="utf-8")


def load_snapshot(path: str | Path) -> ADData:
    raw = Path(path).read_text(encoding="utf-8")
    return data_from_dict(json.loads(raw))
