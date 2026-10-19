"""In-memory AD object models built by the collectors and consumed by modules.

Models are deliberately thin dataclasses; the LDAP collector populates them
from live queries and the offline loader rehydrates them from JSON snapshots.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class ACE:
    """A single access-control entry from an nTSecurityDescriptor."""

    sid: str
    type: str  # ALLOW / DENY
    access_mask: int
    flags: int = 0  # INHERITED_ACE, OBJECT_INHERIT, etc.
    inherited: bool = False
    # Right names are resolved later against the object class / schema.
    rights: list[str] = field(default_factory=list)
    object_type: Optional[str] = None  # e.g. extended-right GUID name


@dataclass
class ACL:
    owner_sid: str = ""
    group_sid: str = ""
    dacl: list[ACE] = field(default_factory=list)


@dataclass
class ADObject:
    distinguished_name: str
    name: str
    object_class: str
    sAMAccountName: Optional[str] = None
    objectSid: Optional[str] = None
    description: Optional[str] = None
    attributes: dict[str, Any] = field(default_factory=dict)
    acl: Optional[ACL] = None


@dataclass
class ADUser(ADObject):
    memberOf: list[str] = field(default_factory=list)
    servicePrincipalName: list[str] = field(default_factory=list)
    userAccountControl: int = 0
    lastLogonTimestamp: Optional[str] = None
    pwdLastSet: Optional[str] = None
    adminCount: int = 0
    primaryGroupID: int = 513
    msds_AllowedToDelegateTo: list[str] = field(default_factory=list)


@dataclass
class ADGroup(ADObject):
    member: list[str] = field(default_factory=list)  # DNs of direct members
    adminCount: int = 0
    groupType: int = 0


@dataclass
class ADComputer(ADObject):
    servicePrincipalName: list[str] = field(default_factory=list)
    operatingSystem: Optional[str] = None
    userAccountControl: int = 0
    msds_AllowedToActOnBehalfOfOtherIdentity: Optional[str] = None
    msds_AllowedToDelegateTo: list[str] = field(default_factory=list)
    dNSHostName: Optional[str] = None


@dataclass
class ADGPO(ADObject):
    gpcFileSysPath: Optional[str] = None
    gPLink: list[str] = field(default_factory=list)  # GPO link strings on OUs


@dataclass
class ADCA(ADObject):
    """Enterprise / standalone certificate authority."""

    dNSHostName: Optional[str] = None
    cACertificateDN: Optional[str] = None
    enrollPerm: list[str] = field(default_factory=list)  # resolved enrollment principals


@dataclass
class ADTemplate(ADObject):
    """Certificate template (pKICertificateTemplate)."""

    msPKI_Certificate_Name_Flag: int = 0
    msPKI_Enrollment_Flag: int = 0
    pKIExtendedKeyUsage: list[str] = field(default_factory=list)
    msPKI_RA_Signature: int = 0
    nTSecurityDescriptor: Optional[ACL] = None


@dataclass
class ADTrust(ADObject):
    trustDirection: int = 0
    trustType: int = 0
    trustAttributes: int = 0
    flatName: Optional[str] = None
    trustPartner: Optional[str] = None


@dataclass
class DomainInfo:
    name: str = ""
    dns_root: str = ""
    domain_sid: str = ""
    functional_level: Optional[str] = None
    forest: Optional[str] = None
    domain_controllers: list[str] = field(default_factory=list)
    fsmo_roles: dict[str, str] = field(default_factory=dict)
    password_policy: dict[str, Any] = field(default_factory=dict)
    default_naming_context: str = ""
    configuration_context: str = ""
    schema_context: str = ""
    acl: Optional[ACL] = None


@dataclass
class ADData:
    """Aggregate snapshot of everything collected from a domain."""

    domain: DomainInfo = field(default_factory=DomainInfo)
    users: dict[str, ADUser] = field(default_factory=dict)          # DN -> user
    groups: dict[str, ADGroup] = field(default_factory=dict)        # DN -> group
    computers: dict[str, ADComputer] = field(default_factory=dict)  # DN -> computer
    gpos: dict[str, ADGPO] = field(default_factory=dict)            # DN -> gpo
    cas: dict[str, ADCA] = field(default_factory=dict)              # DN -> CA
    templates: dict[str, ADTemplate] = field(default_factory=dict)  # DN -> template
    trusts: dict[str, ADTrust] = field(default_factory=dict)        # DN -> trust
    ous: dict[str, ADObject] = field(default_factory=dict)          # DN -> OU
    # SID -> DN reverse map for principal resolution
    sid_map: dict[str, str] = field(default_factory=dict)
    # dn -> name convenience map
    name_map: dict[str, str] = field(default_factory=dict)

    def principal_name(self, sid_or_dn: str) -> str:
        """Resolve a SID or DN to a friendly principal name if known."""
        if sid_or_dn in self.sid_map:
            dn = self.sid_map[sid_or_dn]
            return self.name_map.get(dn, dn)
        if sid_or_dn in self.name_map:
            return self.name_map[sid_or_dn]
        return sid_or_dn

    def register_principal(self, dn: str, sid: str, name: str) -> None:
        self.name_map[dn] = name
        if sid:
            self.sid_map[sid] = dn
