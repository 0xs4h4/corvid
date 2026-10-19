"""Finding model — the single evidence-driven result object every module emits.

Every finding carries the full set of fields required for a defensible,
reproducible assessment result: technical evidence, confidence scoring,
exploitability prerequisites, manual-verification guidance, remediation and
references. Confidence is derived from evidence, never guessed.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ValidationStatus(str, Enum):
    DETECTED = "detected"                       # observed configuration, not yet judged exploitable
    POTENTIALLY_EXPLOITABLE = "potentially_exploitable"
    MANUALLY_VERIFIED = "manually_verified"
    INCONCLUSIVE = "inconclusive"
    NOT_TESTED = "not_tested"


class Category(str, Enum):
    RECON = "domain_reconnaissance"
    CREDENTIAL = "credential_exposure"
    ACL = "acl_abuse"
    GPO = "gpo_attack_surface"
    KERBEROS = "kerberos"
    DELEGATION = "delegation"
    ADCS = "ad_certificate_services"
    PRIVESC = "privilege_escalation"
    NETWORK = "network_protocol"
    INFRASTRUCTURE = "infrastructure"
    VULNERABILITY = "vulnerability"
    PERSISTENCE = "persistence_defense_evasion"


@dataclass
class Finding:
    title: str
    module: str
    category: Category
    severity: Severity
    confidence: Confidence
    status: ValidationStatus = ValidationStatus.DETECTED

    affected_principal: Optional[str] = None
    affected_object: Optional[str] = None
    evidence: dict[str, Any] = field(default_factory=dict)
    permissions: list[str] = field(default_factory=list)
    impact: str = ""
    prerequisites: list[str] = field(default_factory=list)
    false_positive_considerations: list[str] = field(default_factory=list)
    detection_limitations: list[str] = field(default_factory=list)
    manual_verification: list[str] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    mitre_attack: list[str] = field(default_factory=list)

    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value if isinstance(self.category, Category) else self.category
        d["severity"] = self.severity.value if isinstance(self.severity, Severity) else self.severity
        d["confidence"] = self.confidence.value if isinstance(self.confidence, Confidence) else self.confidence
        d["status"] = self.status.value if isinstance(self.status, ValidationStatus) else self.status
        return d

    @property
    def stable_key(self) -> str:
        """Deterministic key for deduplication across re-scans."""
        raw = f"{self.module}:{self.title}:{self.affected_principal}:{self.affected_object}"
        return hashlib.sha1(raw.encode("utf-8", "ignore")).hexdigest()


def severity_rank(sev: Severity) -> int:
    order = {
        Severity.CRITICAL: 5,
        Severity.HIGH: 4,
        Severity.MEDIUM: 3,
        Severity.LOW: 2,
        Severity.INFO: 1,
    }
    return order.get(sev, 0)


def confidence_rank(conf: Confidence) -> int:
    order = {Confidence.HIGH: 3, Confidence.MEDIUM: 2, Confidence.LOW: 1}
    return order.get(conf, 0)
