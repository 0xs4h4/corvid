"""Structured logging setup."""

from __future__ import annotations

import logging
import sys
from typing import Optional

_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
_configured = False


def setup_logging(level: str = "INFO", logfile: Optional[str] = None) -> None:
    global _configured
    if _configured:
        return
    root = logging.getLogger("adscan")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.propagate = False
    if not root.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(_FORMAT))
        root.addHandler(handler)
        if logfile:
            fh = logging.FileHandler(logfile, encoding="utf-8")
            fh.setFormatter(logging.Formatter(_FORMAT))
            root.addHandler(fh)
    _configured = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"adscan.{name}")
