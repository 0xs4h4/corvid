"""Mock Active Directory fixtures for testing.

Builds an in-memory :class:`ADData` with a known set of misconfigurations so
module logic can be tested deterministically without a live domain.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from corvid_ad.core.context import ScanContext
from corvid_ad.core.models import (
    ADCA,
    ADComputer,
    ADData,
    ADGroup,
    ADTemplate,
    ADUser,
    DomainInfo,
)
from corvid_ad.utils.acl_parser import parse_sddl

DOMAIN_SID = "S-1-5-21-1000000000-2000000000-3000000000"
BASE = "DC=corp,DC=local"

# UAC flags
UF_ENCRYPTED = 0x0080
UF_DONT_REQUIRE_PREAUTH = 0x400000
UF_TRUSTED_FOR_DELEGATION = 0x80000


def _sid(rid: int) -> str:
    return f"{DOMAIN_SID}-{rid}"


def _dn(name: str, container: str = "CN=Users") -> str:
    return f"CN={name},{container},{BASE}"


def _sddl(aces: str, owner_rid: int = 512) -> str:
    return f"O:{_sid(owner_rid)}G:{_sid(513)}D:{aces}"


# DCSync GetChanges GUID and GetChanges-All GUID
DCSYNC_GUID = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
ENROLL_GUID = "0e10c968-78fb-11d2-90d4-00c04f79dc55"


def build_mock_domain() -> ADData:
    data = ADData()
    data.domain = DomainInfo(
        name="corp.local", dns_root="corp.local", domain_sid=DOMAIN_SID,
        functional_level="2016", default_naming_context=BASE,
        configuration_context="CN=Configuration," + BASE,
        schema_context="CN=Schema,CN=Configuration," + BASE,
        domain_controllers=["dc01.corp.local"],
        password_policy={"machineAccountQuota": 10, "lockoutThreshold": 0,
                         "minPwdLength": 7, "pwdProperties": 0},
    )

    # --- Domain root ACL: DCSync granted to a low-priv user (svc_dcsync) ---
    dcsync_ace = f"(OA;;CR;{DCSYNC_GUID};;{_sid(1601)})"
    data.domain.acl = parse_sddl(_sddl(dcsync_ace))

    def add_user(rid, name, uac=0, spns=None, desc=None, last_logon=None):
        dn = _dn(name)
        u = ADUser(
            distinguished_name=dn, name=name, object_class="user",
            sAMAccountName=name, objectSid=_sid(rid), description=desc,
            memberOf=[], servicePrincipalName=spns or [],
            userAccountControl=uac, lastLogonTimestamp=last_logon,
            adminCount=0, acl=None,
        )
        data.users[dn] = u
        data.register_principal(dn, u.objectSid, name)
        return dn, u

    def add_group(rid, name, members=None):
        dn = _dn(name)
        g = ADGroup(
            distinguished_name=dn, name=name, object_class="group",
            sAMAccountName=name, objectSid=_sid(rid), member=members or [],
            groupType=0x80000002, acl=None,
        )
        data.groups[dn] = g
        data.register_principal(dn, g.objectSid, name)
        return dn, g

    def add_computer(name, uac=0, delegate_to=None, rbcd=None):
        dn = _dn(name, "CN=Computers")
        c = ADComputer(
            distinguished_name=dn, name=name, object_class="computer",
            sAMAccountName=name + "$", objectSid=_sid(2000 + len(data.computers)),
            servicePrincipalName=[f"HOST/{name}.corp.local"],
            operatingSystem="Windows Server 2019", userAccountControl=uac,
            msds_AllowedToDelegateTo=delegate_to or [],
            msds_AllowedToActOnBehalfOfOtherIdentity=rbcd or "",
            dNSHostName=f"{name}.corp.local", acl=None,
        )
        data.computers[dn] = c
        data.register_principal(dn, c.objectSid, name + "$")
        return dn, c

    # Administrator (RID 500), krbtgt (502)
    add_user(500, "Administrator")
    add_user(502, "krbtgt", spns=["kadmin/changepw"])
    # Domain Admins (512), Domain Users (513), DnsAdmins (1101)
    da_dn, _ = add_group(512, "Domain Admins", members=[_dn("Administrator")])
    du_dn, du = add_group(513, "Domain Users")
    add_group(1101, "DnsAdmins")

    # svc_dcsync user (RID 1601) — holds DCSync
    add_user(1601, "svc_dcsync")

    # Kerberoastable user (has SPN)
    add_user(1602, "svc_sql", spns=["MSSQLSvc/sql01.corp.local:1433"])

    # AS-REP roastable
    add_user(1603, "asrep_user", uac=UF_DONT_REQUIRE_PREAUTH)

    # Reversible encryption
    add_user(1604, "reversible_user", uac=UF_ENCRYPTED)

    # Victim admin with GenericAll granted to Domain Users
    victim_dn, _ = add_user(1605, "victim_admin")
    victim_acl = parse_sddl(_sddl(f"(A;;GA;;;{_sid(513)})"))
    data.users[victim_dn].acl = victim_acl

    # Computer with unconstrained delegation
    add_computer("WS01", uac=UF_TRUSTED_FOR_DELEGATION)
    # Computer with constrained delegation
    add_computer("SQL01", delegate_to=["cifs/dc01.corp.local"])
    # Computer with RBCD
    add_computer("FILE01", rbcd=_sid(1602))

    # --- AD CS: ESC1 template ---
    esc1_dn = f"CN=ESC1-Template,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{BASE}"
    esc1_acl = parse_sddl(_sddl(f"(OA;;CR;{ENROLL_GUID};;{_sid(513)})"))
    data.templates[esc1_dn] = ADTemplate(
        distinguished_name=esc1_dn, name="ESC1-Template", object_class="pKICertificateTemplate",
        msPKI_Certificate_Name_Flag=0x1,  # ENROLLEE_SUPPLIES_SUBJECT
        msPKI_Enrollment_Flag=0x0,
        pKIExtendedKeyUsage=["1.3.6.1.5.5.7.3.2"],  # Client Auth
        msPKI_RA_Signature=0, acl=esc1_acl,
    )
    # CA
    ca_dn = f"CN=corp-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,{BASE}"
    data.cas[ca_dn] = ADCA(
        distinguished_name=ca_dn, name="corp-CA", object_class="pKIEnrollmentService",
        dNSHostName="ca.corp.local", acl=None,
    )

    return data


def build_mock_context() -> ScanContext:
    ctx = ScanContext(domain="corp.local", mode="full", source="fixture")
    ctx.data = build_mock_domain()
    from corvid_ad.core.scanner import update_stats

    update_stats(ctx, ctx.data)
    return ctx
