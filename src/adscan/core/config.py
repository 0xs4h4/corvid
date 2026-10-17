"""Configuration loading (YAML + defaults) and scan options."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

DEFAULT_CONFIG = {
    "ldap": {
        "port": 389,
        "use_ssl": False,
        "connect_timeout": 10,
        "receive_timeout": 30,
        "page_size": 1000,
        "auth": "NTLM",  # NTLM | SIMPLE | ANONYMOUS | KERBEROS
    },
    "scan": {
        "mode": "quick",
        "concurrency": 4,
        "rate_limit": 0.05,  # seconds between queries
        "retries": 3,
        "backoff": 2.0,
    },
    "output": {
        "dir": "reports",
        "formats": ["json", "csv", "html"],
    },
    "logging": {
        "level": "INFO",
        "file": None,
    },
}


@dataclass
class ScanOptions:
    domain: str = ""
    dc_ip: Optional[str] = None
    username: str = ""
    password: str = ""
    hashes: Optional[str] = None  # LMHASH:NTHASH for pass-the-hash
    mode: str = "quick"
    modules: list[str] = field(default_factory=list)
    output_dir: str = "reports"
    dns_server: Optional[str] = None
    use_ssl: bool = False
    no_password: bool = False


def deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path: Optional[str] = None) -> dict[str, Any]:
    cfg = deep_merge(DEFAULT_CONFIG, {})
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        cfg = deep_merge(cfg, data)
    return cfg


def default_config_path() -> Path:
    return Path(__file__).resolve().parents[3] / "config" / "default.yaml"
