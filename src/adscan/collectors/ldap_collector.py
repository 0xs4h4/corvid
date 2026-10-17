"""LDAP collector: performs read-only domain collection into :class:`ADData`.

Uses ldap3 with paged results and (optionally) the Microsoft security
descriptor control to retrieve ``nTSecurityDescriptor`` in SDDL form for
ACL analysis. Read-only by design — no writes are ever issued.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Optional

from ldap3 import ALL, BASE, Connection, Server, SUBTREE, NTLM, SIMPLE
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.core.exceptions import LDAPException, LDAPBindError, LDAPSocketOpenError

from ..core.context import CollectionStats, ScanContext
from ..core.logger import get_logger
from ..core.models import (
    ADCA,
    ADComputer,
    ADData,
    ADGPO,
    ADGroup,
    ADObject,
    ADTemplate,
    ADTrust,
    ADUser,
    ACL,
    DomainInfo,
)
from ..core.sid import sid_to_sddl
from ..utils.acl_parser import parse_sddl, sd_has_entries

log = get_logger("collector")

# SDDL control flags: OWNER | GROUP | DACL (no SACL, which needs admin)
SDDL_FLAGS = 0x7

# Domain/forest functional level numeric -> friendly name
FUNCTIONAL_LEVELS = {
    "0": "Windows 2000",
    "1": "Windows Server 2003 interim",
    "2": "Windows Server 2003",
    "3": "Windows Server 2008",
    "4": "Windows Server 2008 R2",
    "5": "Windows Server 2012",
    "6": "Windows Server 2012 R2",
    "7": "Windows Server 2016",
}

USER_ATTRS = [
    "sAMAccountName", "name", "description", "objectSid", "memberOf",
    "servicePrincipalName", "userAccountControl", "lastLogonTimestamp",
    "pwdLastSet", "adminCount", "primaryGroupID", "msDS-AllowedToDelegateTo",
]
GROUP_ATTRS = ["sAMAccountName", "name", "description", "objectSid", "member", "adminCount", "groupType"]
COMPUTER_ATTRS = [
    "sAMAccountName", "name", "dNSHostName", "operatingSystem", "objectSid",
    "servicePrincipalName", "userAccountControl",
    "msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-AllowedToDelegateTo",
]
GPO_ATTRS = ["name", "displayName", "gPCFileSysPath", "objectSid"]
CA_ATTRS = ["name", "dNSHostName", "cACertificateDN", "objectSid"]
TEMPLATE_ATTRS = [
    "name", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
    "pKIExtendedKeyUsage", "msPKI-RA-Signature", "objectSid",
]
TRUST_ATTRS = ["name", "trustDirection", "trustType", "trustAttributes", "flatName", "trustPartner"]
OU_ATTRS = ["name", "gPLink", "objectSid", "description"]


class LDAPCollector:
    def __init__(self, options, config: dict[str, Any]):
        self.options = options
        self.cfg = config
        self.ldap_cfg = config.get("ldap", {})
        self.scan_cfg = config.get("scan", {})
        self._conn: Optional[Connection] = None

    # -- connection ---------------------------------------------------------
    def _server(self) -> Server:
        use_ssl = self.options.use_ssl or self.ldap_cfg.get("use_ssl", False)
        port = 636 if use_ssl else self.ldap_cfg.get("port", 389)
        host = self.options.dc_ip or self.options.domain
        return Server(
            host,
            port=port,
            use_ssl=use_ssl,
            get_info=ALL,
            connect_timeout=self.ldap_cfg.get("connect_timeout", 10),
        )

    def connect(self) -> Connection:
        server = self._server()
        auth = (self.ldap_cfg.get("auth", "NTLM") or "NTLM").upper()
        user = self.options.username
        if self.options.domain and "\\" not in user and "@" not in user:
            # build UPN or NETBIOS\user
            user = f"{self.options.domain.split('.')[0].upper()}\\{user}"
        if auth == "SIMPLE":
            conn = Connection(server, user=user, password=self.options.password,
                              authentication=SIMPLE, auto_bind=True,
                              receive_timeout=self.ldap_cfg.get("receive_timeout", 30))
        elif auth == "ANONYMOUS":
            conn = Connection(server, auto_bind=True,
                              receive_timeout=self.ldap_cfg.get("receive_timeout", 30))
        else:
            conn = Connection(server, user=user, password=self.options.password,
                              authentication=NTLM, auto_bind=True,
                              receive_timeout=self.ldap_cfg.get("receive_timeout", 30))
        self._conn = conn
        return conn

    def _retry(self, fn: Callable[[], Any]) -> Any:
        retries = int(self.scan_cfg.get("retries", 3))
        backoff = float(self.scan_cfg.get("backoff", 2.0))
        last = None
        for attempt in range(retries):
            try:
                return fn()
            except (LDAPException, OSError) as exc:
                last = exc
                log.warning("LDAP op failed (attempt %d/%d): %s", attempt + 1, retries, exc)
                if attempt < retries - 1:
                    time.sleep(backoff * (attempt + 1))
        raise last  # type: ignore[misc]

    # -- paged search -------------------------------------------------------
    def _search(self, base: str, filt: str, attrs: list[str], sddl: bool = False) -> list[dict]:
        # security_descriptor_control() already returns a list of controls —
        # do NOT wrap it in another list.
        controls = security_descriptor_control(sdflags=SDDL_FLAGS) if sddl else None
        entries: list[dict] = []
        cookie = None
        page_size = int(self.ldap_cfg.get("page_size", 1000))
        while True:
            self._retry(lambda: self._conn.search(
                search_base=base, search_filter=filt, search_scope=SUBTREE,
                attributes=attrs + (["nTSecurityDescriptor"] if sddl else []),
                paged_size=page_size, paged_cookie=cookie, controls=controls,
            ))
            for e in self._conn.response:
                if e.get("type") == "searchResEntry":
                    attrs = dict(e.get("attributes") or {})
                    # distinguishedName is the entry DN, not a returned attribute.
                    attrs.setdefault("distinguishedName", e.get("dn", ""))
                    entries.append(attrs)
            cookie = self._conn.result.get("controls", {}).get("1.2.840.113556.1.4.319", {}).get("value", {}).get("cookie")
            if not cookie:
                break
            self._sleep()
        return entries

    def _sleep(self) -> None:
        rate = float(self.scan_cfg.get("rate_limit", 0.05))
        if rate:
            time.sleep(rate)

    # -- extraction helpers -------------------------------------------------
    def _dn(self, e: dict) -> str:
        return str(e.get("distinguishedName", "") or "")

    def _sid(self, e: dict) -> str:
        raw = e.get("objectSid")
        if isinstance(raw, bytes):
            return sid_to_sddl(raw)
        return str(raw or "")

    def _acl(self, e: dict) -> Optional[ACL]:
        sddl = e.get("nTSecurityDescriptor")
        if isinstance(sddl, bytes):
            decoded = None
            for enc in ("utf-16-le", "utf-8", "latin-1"):
                try:
                    s = sddl.decode(enc)
                    if "O:" in s or "D:" in s:
                        decoded = s
                        break
                except Exception:
                    continue
            sddl = decoded
        if not sddl:
            return None
        return parse_sddl(str(sddl))

    def _int(self, e: dict, key: str) -> int:
        v = e.get(key)
        try:
            return int(v)
        except (TypeError, ValueError):
            return 0

    def _strlist(self, e: dict, key: str) -> list[str]:
        v = e.get(key)
        if v is None:
            return []
        if isinstance(v, (list, tuple)):
            return [str(x) for x in v]
        return [str(v)]

    def _str(self, e: dict, key: str) -> str:
        v = e.get(key)
        if isinstance(v, (list, tuple)) and v:
            v = v[0]
        return str(v) if v is not None else ""

    def _rbcd(self, e: dict) -> str:
        """Extract msDS-AllowedToActOnBehalfOfOtherIdentity, but return '' when
        the security descriptor is empty/absent (avoids a false-positive RBCD)."""
        v = e.get("msDS-AllowedToActOnBehalfOfOtherIdentity")
        if v is None:
            return ""
        if isinstance(v, bytes):
            return v.hex() if sd_has_entries(v) else ""
        return str(v)

    # -- collection ---------------------------------------------------------
    def collect(self, ctx: ScanContext) -> ADData:
        data = ctx.data
        conn = self.connect()
        self._conn = conn
        base = conn.server.info.other.get("defaultNamingContext", [""])[0]
        cfg_base = conn.server.info.other.get("configurationNamingContext", [""])[0]
        if not base:
            raise RuntimeError("could not determine defaultNamingContext from Root DSE")

        data.domain.default_naming_context = base
        data.domain.configuration_context = cfg_base
        data.domain.dns_root = self._root_dns(conn)
        data.domain.forest = conn.server.info.other.get("rootDomainNamingContext", [""])[0]
        data.domain.functional_level = self._func_level(conn)

        self._collect_domain(base, data)
        self._collect_objects(base, data)
        self._collect_gpos(base, data)
        self._collect_trusts(base, data)
        self._collect_adcs(cfg_base, data)
        self._collect_templates(cfg_base, data)
        self._collect_ous(base, data)
        return data

    def _root_dns(self, conn: Connection) -> str:
        info = conn.server.info
        if hasattr(info, "other") and "dnsHostName" in info.other:
            return str(info.other["dnsHostName"][0])
        return self.options.domain

    def _func_level(self, conn: Connection) -> Optional[str]:
        info = conn.server.info
        if hasattr(info, "other") and "domainFunctionality" in info.other:
            raw = str(info.other["domainFunctionality"][0])
            return FUNCTIONAL_LEVELS.get(raw, raw)
        return None

    def _collect_domain(self, base: str, data: ADData) -> None:
        entries = self._search(base, "(objectClass=domain)", [
            "objectSid", "name", "distinguishedName", "lockoutThreshold",
            "lockoutDuration", "minPwdLength", "maxPwdAge", "minPwdAge",
            "pwdHistoryLength", "pwdProperties", "msDS-Behavior-Version",
            "msDS-PerUserTrustQuota", "fSMORoleOwner", "dnsRoot",
            "ms-DS-MachineAccountQuota",
        ], sddl=True)
        for e in entries:
            d = data.domain
            d.name = self._str(e, "name")
            d.domain_sid = self._sid(e)
            d.password_policy = {
                "lockoutThreshold": self._int(e, "lockoutThreshold"),
                "lockoutDuration": self._int(e, "lockoutDuration"),
                "minPwdLength": self._int(e, "minPwdLength"),
                "maxPwdAge": self._int(e, "maxPwdAge"),
                "minPwdAge": self._int(e, "minPwdAge"),
                "pwdHistoryLength": self._int(e, "pwdHistoryLength"),
                "pwdProperties": self._int(e, "pwdProperties"),
                "machineAccountQuota": self._int(e, "ms-DS-MachineAccountQuota"),
            }
            data.domain.dns_root = self._str(e, "dnsRoot") or data.domain.dns_root
            data.domain.acl = self._acl(e)

    def _collect_objects(self, base: str, data: ADData) -> None:
        # Users
        for e in self._search(base, "(&(objectClass=user)(objectCategory=person))", USER_ATTRS, sddl=True):
            dn = self._dn(e)
            if not dn:
                continue
            u = ADUser(
                distinguished_name=dn, name=self._str(e, "name"), object_class="user",
                sAMAccountName=self._str(e, "sAMAccountName"), objectSid=self._sid(e),
                description=self._str(e, "description"),
                memberOf=self._strlist(e, "memberOf"),
                servicePrincipalName=self._strlist(e, "servicePrincipalName"),
                userAccountControl=self._int(e, "userAccountControl"),
                lastLogonTimestamp=self._str(e, "lastLogonTimestamp"),
                pwdLastSet=self._str(e, "pwdLastSet"),
                adminCount=self._int(e, "adminCount"),
                msds_AllowedToDelegateTo=self._strlist(e, "msDS-AllowedToDelegateTo"),
                acl=self._acl(e),
            )
            data.users[dn] = u
            data.register_principal(dn, u.objectSid or "", u.sAMAccountName or u.name)
        # Groups
        for e in self._search(base, "(objectClass=group)", GROUP_ATTRS, sddl=True):
            dn = self._dn(e)
            if not dn:
                continue
            g = ADGroup(
                distinguished_name=dn, name=self._str(e, "name"), object_class="group",
                sAMAccountName=self._str(e, "sAMAccountName"), objectSid=self._sid(e),
                member=self._strlist(e, "member"), adminCount=self._int(e, "adminCount"),
                groupType=self._int(e, "groupType"), acl=self._acl(e),
            )
            data.groups[dn] = g
            data.register_principal(dn, g.objectSid or "", g.sAMAccountName or g.name)
        # Computers
        for e in self._search(base, "(objectClass=computer)", COMPUTER_ATTRS, sddl=True):
            dn = self._dn(e)
            if not dn:
                continue
            c = ADComputer(
                distinguished_name=dn, name=self._str(e, "name"), object_class="computer",
                sAMAccountName=self._str(e, "sAMAccountName"), objectSid=self._sid(e),
                servicePrincipalName=self._strlist(e, "servicePrincipalName"),
                operatingSystem=self._str(e, "operatingSystem"),
                userAccountControl=self._int(e, "userAccountControl"),
                msds_AllowedToActOnBehalfOfOtherIdentity=self._rbcd(e),
                msds_AllowedToDelegateTo=self._strlist(e, "msDS-AllowedToDelegateTo"),
                dNSHostName=self._str(e, "dNSHostName"), acl=self._acl(e),
            )
            data.computers[dn] = c
            data.register_principal(dn, c.objectSid or "", c.sAMAccountName or c.name)
        # Domain controllers (populate domain info)
        dc_dns = []
        for dn, c in data.computers.items():
            if c.userAccountControl & 0x2000:  # SERVER_TRUST_ACCOUNT / DC flag (0x2000 = workstation, DC has 0x2000 too? use 8192)
                dc_dns.append(c.dNSHostName or c.name)
        # 0x2000 = SERVER_TRUST_ACCOUNT; DCs have UF_SERVER_TRUST_ACCOUNT (0x2000)
        data.domain.domain_controllers = [c.dNSHostName or c.name for c in data.computers.values()
                                          if c.userAccountControl & 0x2000]

    def _collect_gpos(self, base: str, data: ADData) -> None:
        for e in self._search(base, "(objectClass=groupPolicyContainer)", GPO_ATTRS, sddl=True):
            dn = self._dn(e)
            if not dn:
                continue
            gpo = ADGPO(
                distinguished_name=dn, name=self._str(e, "name"), object_class="groupPolicyContainer",
                gpcFileSysPath=self._str(e, "gPCFileSysPath"),
                gPLink=self._strlist(e, "gPLink"), acl=self._acl(e),
            )
            data.gpos[dn] = gpo

    def _collect_trusts(self, base: str, data: ADData) -> None:
        for e in self._search(base, "(objectClass=trustedDomain)", TRUST_ATTRS):
            dn = self._dn(e)
            if not dn:
                continue
            t = ADTrust(
                distinguished_name=dn, name=self._str(e, "name"), object_class="trustedDomain",
                trustDirection=self._int(e, "trustDirection"),
                trustType=self._int(e, "trustType"),
                trustAttributes=self._int(e, "trustAttributes"),
                flatName=self._str(e, "flatName"), trustPartner=self._str(e, "trustPartner"),
            )
            data.trusts[dn] = t

    def _collect_adcs(self, cfg_base: str, data: ADData) -> None:
        filt = "(objectClass=pKIEnrollmentService)"
        for e in self._search(cfg_base, filt, CA_ATTRS, sddl=True):
            dn = self._dn(e)
            if not dn:
                continue
            ca = ADCA(
                distinguished_name=dn, name=self._str(e, "name"), object_class="pKIEnrollmentService",
                dNSHostName=self._str(e, "dNSHostName"),
                cACertificateDN=self._str(e, "cACertificateDN"), acl=self._acl(e),
            )
            data.cas[dn] = ca

    def _collect_templates(self, cfg_base: str, data: ADData) -> None:
        filt = "(objectClass=pKICertificateTemplate)"
        for e in self._search(cfg_base, filt, TEMPLATE_ATTRS, sddl=True):
            dn = self._dn(e)
            if not dn:
                continue
            t = ADTemplate(
                distinguished_name=dn, name=self._str(e, "name"), object_class="pKICertificateTemplate",
                msPKI_Certificate_Name_Flag=self._int(e, "msPKI-Certificate-Name-Flag"),
                msPKI_Enrollment_Flag=self._int(e, "msPKI-Enrollment-Flag"),
                pKIExtendedKeyUsage=self._strlist(e, "pKIExtendedKeyUsage"),
                msPKI_RA_Signature=self._int(e, "msPKI-RA-Signature"),
                acl=self._acl(e),
            )
            data.templates[dn] = t

    def _collect_ous(self, base: str, data: ADData) -> None:
        for e in self._search(base, "(objectClass=organizationalUnit)", OU_ATTRS, sddl=True):
            dn = self._dn(e)
            if not dn:
                continue
            ou = ADObject(
                distinguished_name=dn, name=self._str(e, "name"), object_class="organizationalUnit",
                description=self._str(e, "description"),
                attributes={"gPLink": self._strlist(e, "gPLink")}, acl=self._acl(e),
            )
            data.ous[dn] = ou
