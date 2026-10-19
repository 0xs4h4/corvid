"""Module base class and registry.

Every detection module is a subclass of :class:`Module` that implements
:meth:`run` and returns a list of :class:`Finding`. Modules never mutate AD
objects; they only read :class:`ADData` from the scan context.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..core.finding import Category, Confidence, Finding, Severity

if TYPE_CHECKING:
    from ..core.context import ScanContext


class Module:
    name: str = "base"
    description: str = ""
    category: Category = Category.RECON
    #: modules that run in "quick" mode (low-impact / high-signal)
    quick: bool = True

    def run(self, ctx: "ScanContext") -> list[Finding]:
        raise NotImplementedError

    def _finding(
        self,
        title: str,
        severity: Severity,
        confidence: Confidence,
        ctx: "ScanContext",
        **kwargs,
    ) -> Finding:
        f = Finding(
            title=title,
            module=self.name,
            category=self.category,
            severity=severity,
            confidence=confidence,
            **kwargs,
        )
        ctx.add_finding(f)
        return f


_REGISTRY: dict[str, type[Module]] = {}


def register(cls: type[Module]) -> type[Module]:
    _REGISTRY[cls.name] = cls
    return cls


def get_module(name: str) -> type[Module]:
    return _REGISTRY[name]


def all_modules() -> dict[str, type[Module]]:
    return dict(_REGISTRY)
