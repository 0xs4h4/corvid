"""Scan orchestration: run modules over collected data and produce findings."""

from __future__ import annotations

from .context import ScanContext
from .logger import get_logger
from .models import ADData

log = get_logger("scanner")


def run_modules(ctx: ScanContext, module_names: list[str]) -> None:
    """Run the selected modules against ctx.data, appending findings to ctx."""
    from ..modules.base import all_modules

    registry = all_modules()
    for name in module_names:
        cls = registry.get(name)
        if cls is None:
            log.warning("unknown module: %s (skipped)", name)
            continue
        log.info("running module %s", name)
        try:
            cls().run(ctx)
        except Exception as exc:  # noqa: BLE001
            log.error("module %s failed: %s", name, exc)


def resolve_modules(mode: str, selected: list[str]) -> list[str]:
    """Resolve the list of module names for a mode (quick/full) or explicit selection."""
    from ..modules.base import all_modules

    registry = all_modules()
    if selected:
        return [n for n in selected if n in registry]
    if mode == "quick":
        return [n for n, cls in registry.items() if cls.quick]
    return list(registry.keys())


def update_stats(ctx: ScanContext, data: ADData) -> None:
    ctx.stats.users = len(data.users)
    ctx.stats.groups = len(data.groups)
    ctx.stats.computers = len(data.computers)
    ctx.stats.gpos = len(data.gpos)
    ctx.stats.cas = len(data.cas)
    ctx.stats.templates = len(data.templates)
    ctx.stats.trusts = len(data.trusts)
    ctx.stats.ous = len(data.ous)
