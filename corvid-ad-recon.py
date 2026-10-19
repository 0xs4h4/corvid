#!/usr/bin/env python3
"""Read-only Active Directory attack-surface scanner (Phase 2 MVP).

Collects directory metadata over LDAPS and reports evidence-backed conditions.
It never requests Kerberos hashes, cracks passwords, changes AD, or exploits.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import getpass
import html
import json
import os
import re
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

VERSION = "0.2.0"
MODULES = ("domain", "users", "groups", "computers", "policies", "delegation", "trusts", "ous")
QUICK_MODULES = ("domain", "users", "groups", "computers", "policies", "delegation")
PRIVILEGED_GROUPS = {"domain admins", "enterprise admins", "schema admins", "administrators",
                     "account operators", "backup operators", "server operators",
                     "print operators", "dnsadmins", "group policy creator owners"}
UAC_DISABLED = 0x0002
UAC_PASSWD_NOT_REQUIRED = 0x0020
UAC_TRUSTED_FOR_DELEGATION = 0x80000
UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
UAC_DONT_REQUIRE_PREAUTH = 0x400000
EPOCH_AD = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)


def domain_to_dn(domain: str) -> str:
    labels = domain.rstrip(".").split(".")
    if not labels or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
                         for part in labels):
        raise ValueError("domain must be a DNS name such as corp.example")
    return ",".join(f"DC={part}" for part in labels)


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple, set)) else [value]


def ad_datetime(value: Any) -> dt.datetime | None:
    if value in (None, "", 0, "0"):
        return None
    if isinstance(value, dt.datetime):
        return value.replace(tzinfo=value.tzinfo or dt.timezone.utc).astimezone(dt.timezone.utc)
    try:
        raw = int(value)
        return EPOCH_AD + dt.timedelta(microseconds=raw / 10) if raw > 0 else None
    except (ValueError, TypeError, OverflowError):
        return None


def finding(fid: str, title: str, severity: str, affected: str, principal: str,
            evidence: str, explanation: str, prerequisites: str, confidence: str,
            impact: str, status: str, manual: str, remediation: str,
            references: list[str] | None = None) -> dict[str, Any]:
    references = references or [
        "https://learn.microsoft.com/en-us/windows/win32/adschema/active-directory-schema",
        "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory",
        "https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties"
    ]
    return {"finding_id": fid, "title": title, "severity": severity,
            "affected_object": affected or "(not supplied)",
            "relevant_principal": principal or "(not identified)", "evidence": evidence,
            "technical_explanation": explanation, "exploitability_prerequisites": prerequisites,
            "confidence_level": confidence, "potential_impact": impact,
            "validation_status": status, "recommended_manual_verification": manual,
            "remediation_guidance": remediation, "references": references or []}


def analyze_snapshot(snapshot: dict[str, Any], modules: tuple[str, ...] | list[str] = MODULES,
                     stale_days: int = 90, threads: int = 1) -> list[dict[str, Any]]:
    """Analyze collected records without network access."""
    users, groups = snapshot.get("users", []), snapshot.get("groups", [])
    group_by_dn = {str(g.get("distinguishedName", "")).casefold(): g for g in groups}

    def users_check() -> list[dict[str, Any]]:
        out, now = [], dt.datetime.now(dt.timezone.utc)
        for user in users:
            name = user.get("sAMAccountName", "(unknown user)")
            dn = user.get("distinguishedName", name)
            uac = int(user.get("userAccountControl") or 0)
            disabled = bool(uac & UAC_DISABLED)
            memberships = []
            for member_dn in as_list(user.get("memberOf")):
                found_group = group_by_dn.get(str(member_dn).casefold(), {})
                group_name = found_group.get("sAMAccountName")
                if not group_name:
                    match = re.match(r"CN=([^,]+)", str(member_dn), re.IGNORECASE)
                    group_name = match.group(1) if match else ""
                memberships.append(group_name)
            privileged = bool(int(user.get("adminCount") or 0)) or any(
                str(x).casefold() in PRIVILEGED_GROUPS for x in memberships)
            spns = as_list(user.get("servicePrincipalName"))
            if spns and not disabled:
                out.append(finding(
                    "KERB-SPN-ELIGIBILITY", "Enabled account has service principal names", "INFO", dn,
                    name, "SPNs: " + ", ".join(map(str, spns)),
                    "An enabled user has SPNs and may be eligible for a Kerberos service-ticket assessment. This scan did not request ticket material and says nothing about password strength.",
                    "Account remains enabled; service and owner context must be reviewed.", "High",
                    "A weak service-account secret could increase credential risk.", "DETECTED",
                    "Confirm the SPN owner, service dependency, and whether the identity is managed.",
                    "Prefer gMSA or another managed identity; use a unique, strong secret and least privilege."))
            if uac & UAC_DONT_REQUIRE_PREAUTH and not disabled:
                out.append(finding(
                    "KERB-ASREP-ELIGIBILITY", "Kerberos pre-authentication is not required", "MEDIUM", dn,
                    name, "userAccountControl includes DONT_REQUIRE_PREAUTH (0x400000).",
                    "This configuration may permit an unauthenticated AS-REP eligibility check. No AS-REP response or hash was requested.",
                    "Account must be enabled and the KDC must honor the setting.", "High",
                    "Could expose offline password-guessing material if separately requested; this scanner does not request it.",
                    "POTENTIALLY EXPLOITABLE", "Confirm the flag and business requirement with the account owner.",
                    "Enable Kerberos pre-authentication unless a documented exception requires otherwise."))
            if uac & UAC_PASSWD_NOT_REQUIRED and not disabled:
                out.append(finding(
                    "ACCOUNT-PASSWORD-NOT-REQUIRED", "Account has PASSWD_NOTREQD set", "MEDIUM", dn, name,
                    "userAccountControl includes PASSWD_NOTREQD (0x20).",
                    "This is a risky account attribute; it does not prove that the account currently has an empty password.",
                    "Verify effective policy and approved authentication behavior.", "High",
                    "May indicate weak account configuration.", "DETECTED",
                    "Check the enabled state and reset history using approved procedures.",
                    "Remove the flag where unnecessary and enforce the organization's password policy."))
            last_logon = ad_datetime(user.get("lastLogonTimestamp"))
            if privileged and not disabled and last_logon:
                age = (now - last_logon).days
                if age >= stale_days:
                    out.append(finding(
                        "PRIV-STALE-ACCOUNT", "Privileged account has an old logon timestamp", "MEDIUM", dn,
                        name, f"LastLogonTimestamp={last_logon.isoformat()} ({age} days ago); adminCount={user.get('adminCount') or 0}; groups={', '.join(map(str, memberships)) or '(not returned)' }.",
                        "This replicated timestamp is approximate and does not prove the account is unused.",
                        "Confirm current ownership, service dependencies, and a more authoritative logon record.",
                        "Medium", "Dormant privileged credentials may remain a high-value exposure.", "DETECTED",
                        "Validate activity with the account owner and DC security logs before disabling.",
                        "Remove unnecessary privileged access after owner and dependency review."))
            elif privileged and not disabled:
                out.append(finding(
                    "PRIV-STALE-UNKNOWN", "Privileged account activity could not be aged", "INFO", dn, name,
                    "No usable lastLogonTimestamp was returned.",
                    "A missing timestamp is inconclusive; it does not show that the account is stale.",
                    "Check DC event data or other approved inventory sources.", "Low",
                    "Activity state is unknown for a privileged account.", "INCONCLUSIVE",
                    "Verify activity with the account owner and authoritative logon sources.",
                    "Review privileged account ownership and access periodically."))
        return out

    def policy_check() -> list[dict[str, Any]]:
        policy, out = snapshot.get("policy") or {}, []
        try:
            minimum = int(policy.get("minPwdLength"))
        except (TypeError, ValueError):
            minimum = None
        if minimum is not None and minimum < 8:
            out.append(finding(
                "POLICY-MIN-PASSWORD-LENGTH", "Domain minimum password length is below 8", "MEDIUM",
                snapshot.get("domain_dn", "domain root"), "Domain password policy", f"minPwdLength={minimum}",
                "The default domain policy permits shorter passwords than this conservative review threshold. It does not prove any password is weak.",
                "Fine-grained password policies may override the domain default.", "High",
                "Shorter permitted passwords can increase guessing exposure.", "POTENTIALLY EXPLOITABLE",
                "Review fine-grained policies and the approved password standard.",
                "Set a stronger minimum consistent with current organizational guidance."))
        try:
            lockout = int(policy.get("lockoutThreshold"))
        except (TypeError, ValueError):
            lockout = None
        if lockout == 0:
            out.append(finding(
                "POLICY-NO-LOCKOUT-THRESHOLD", "Domain policy has no lockout threshold", "LOW",
                snapshot.get("domain_dn", "domain root"), "Domain password policy", "lockoutThreshold=0",
                "The domain default does not define a lockout after failed attempts; other controls may apply.",
                "Check fine-grained policies and identity-provider controls.", "High",
                "Repeated guessing may be less constrained if other throttling is absent.", "DETECTED",
                "Review effective policy and authentication throttling controls.",
                "Set a threshold and duration aligned with security and availability requirements."))
        return out

    def delegation_check() -> list[dict[str, Any]]:
        out = []
        for obj in snapshot.get("computers", []) + users:
            name, dn = obj.get("sAMAccountName", "(unknown object)"), obj.get("distinguishedName", "")
            uac = int(obj.get("userAccountControl") or 0)
            if uac & UAC_TRUSTED_FOR_DELEGATION:
                out.append(finding(
                    "DELEGATION-UNCONSTRAINED", "Unconstrained delegation is configured", "HIGH", dn, name,
                    "userAccountControl includes TRUSTED_FOR_DELEGATION (0x80000).",
                    "The object is marked for unconstrained Kerberos delegation. This flag does not prove a usable path to a privileged target.",
                    "Assess host role, service identity, and privileged-principal exposure.", "High",
                    "Compromise of the service or host could broaden credential exposure.",
                    "POTENTIALLY EXPLOITABLE", "Confirm the service requirement and privileged-account exposure.",
                    "Remove unconstrained delegation where possible and restrict privileged account delegation."))
            targets = as_list(obj.get("msDS-AllowedToDelegateTo"))
            if targets or uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION:
                out.append(finding(
                    "DELEGATION-CONSTRAINED", "Constrained delegation is configured", "INFO", dn, name,
                    f"AllowedToDelegateTo={', '.join(map(str, targets)) or '(not returned)'}; protocol-transition={bool(uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION)}.",
                    "Constrained delegation limits targets, but impact depends on configured services and principal rights.",
                    "Review each SPN, service owner, protocol transition, and target privilege.", "High",
                    "Mis-scoped delegation may extend access beyond the intended service boundary.", "DETECTED",
                    "Compare configured SPNs with the documented application design.",
                    "Remove unnecessary targets and protocol transition; protect privileged accounts."))
            if obj.get("msDS-AllowedToActOnBehalfOfOtherIdentity"):
                out.append(finding(
                    "DELEGATION-RBCD-DESCRIPTOR", "Resource-based delegation descriptor is present", "INFO", dn, name,
                    "msDS-AllowedToActOnBehalfOfOtherIdentity is present; this MVP does not parse its security descriptor.",
                    "Presence alone does not identify permitted trustees or establish abuse rights.",
                    "Parse the descriptor and resolve trustees against target privilege and ownership.", "Low",
                    "A configured principal may be allowed to delegate to this resource.", "INCONCLUSIVE",
                    "Manually inspect the descriptor and confirm trustee rights.",
                    "Remove unexpected trustees and restrict write access to the attribute."))
        return out

    analyzers = {"users": users_check, "policies": policy_check, "delegation": delegation_check}
    selected = [name for name in modules if name in analyzers]
    if threads > 1 and len(selected) > 1:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            result_sets = list(executor.map(lambda name: analyzers[name](), selected))
    else:
        result_sets = [analyzers[name]() for name in selected]
    return [item for subset in result_sets for item in subset]


class LdapCollector:
    """LDAPS collector. Search attribute lists intentionally omit credential material."""
    SEARCHES = {
        "users": ("(&(objectCategory=person)(objectClass=user))",
                   ["sAMAccountName", "distinguishedName", "displayName", "userAccountControl", "adminCount",
                   "memberOf", "servicePrincipalName", "lastLogonTimestamp", "pwdLastSet", "description",
                   "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity"]),
        "groups": ("(objectCategory=group)", ["sAMAccountName", "distinguishedName", "groupType", "member", "adminCount"]),
        "computers": ("(objectCategory=computer)", ["sAMAccountName", "distinguishedName", "dNSHostName",
                      "operatingSystem", "operatingSystemVersion", "userAccountControl",
                      "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity"]),
        "trusts": ("(objectClass=trustedDomain)", ["trustPartner", "trustDirection", "trustType", "trustAttributes", "distinguishedName"]),
        "ous": ("(objectCategory=organizationalUnit)", ["name", "distinguishedName", "gPLink"]),
        "dcs": ("(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
                ["sAMAccountName", "distinguishedName", "dNSHostName", "operatingSystem", "operatingSystemVersion"]),
    }

    def __init__(self, host: str, port: int, username: str, password: str,
                 timeout: int, insecure_tls: bool, plain_anonymous: bool = False):
        try:
            import ldap3
        except ImportError as exc:
            raise RuntimeError("ldap3 is required; install with: python3 -m pip install -r requirements-adscanner.txt") from exc
        tls = ldap3.Tls(validate=ssl.CERT_NONE if insecure_tls else ssl.CERT_REQUIRED)
        self.ldap3 = ldap3
        self.plain_anonymous = plain_anonymous
        self.server = ldap3.Server(host, port=port, use_ssl=not plain_anonymous, tls=tls,
                                   get_info=ldap3.NONE, connect_timeout=timeout)
        self.username, self.password, self.timeout = username, password, timeout
        self.connection = None

    def connect(self, domain: str) -> None:
        if self.plain_anonymous and (self.username or self.password):
            raise ValueError("plaintext LDAP mode is anonymous only; credentials are not allowed")
        user = self.username
        if user and "\\" not in user and "@" not in user:
            user = f"{domain}\\{user}"
        self.connection = self.ldap3.Connection(
            self.server, user=user or None, password=self.password or None,
            authentication=self.ldap3.SIMPLE if user else self.ldap3.ANONYMOUS,
            auto_bind=True, receive_timeout=self.timeout, auto_referrals=False,
            read_only=True, raise_exceptions=True)

    def search(self, base: str, search_filter: str, attributes: list[str], page_size: int = 500) -> list[dict[str, Any]]:
        result = []
        for entry in self.connection.extend.standard.paged_search(
                search_base=base, search_filter=search_filter, search_scope=self.ldap3.SUBTREE,
                attributes=attributes, paged_size=page_size, generator=True):
            if entry.get("type") == "searchResEntry":
                attrs = dict(entry.get("attributes", {}))
                attrs["distinguishedName"] = entry.get("dn", "")
                result.append(attrs)
        return result

    def root_dse(self) -> dict[str, Any]:
        self.connection.search("", "(objectClass=*)", search_scope=self.ldap3.BASE,
                               attributes=["defaultNamingContext", "configurationNamingContext",
                                           "rootDomainNamingContext", "dnsHostName", "supportedCapabilities"])
        if not self.connection.entries:
            raise RuntimeError("RootDSE query returned no entry")
        return dict(self.connection.entries[0].entry_attributes_as_dict)

    def close(self) -> None:
        if self.connection:
            self.connection.unbind()


def clean_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    clean = []
    for row in rows:
        item = {}
        for key, value in row.items():
            if key.casefold() == "msds-allowedtoactonbehalfofotheridentity":
                item[key] = ["<binary security descriptor present>"] if value else []
            elif isinstance(value, (bytes, bytearray, memoryview)):
                item[key] = "<binary data omitted>" if value else ""
            else:
                vals = as_list(value)
                item[key] = vals if len(vals) != 1 else vals[0]
        clean.append(item)
    return clean


def collect_snapshot(args: argparse.Namespace, password: str, modules: tuple[str, ...]) -> tuple[dict[str, Any], dict[str, str]]:
    base_dn = domain_to_dn(args.domain)
    collector = LdapCollector(args.dc_host or args.dc_ip, args.ldap_port, args.username or "",
                              password, args.timeout, args.insecure_tls,
                              getattr(args, "plain_anonymous", False))
    snapshot: dict[str, Any] = {"domain": args.domain, "domain_dn": base_dn,
                                "collected_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                                "root_dse": {}, "policy": {}, "users": [], "groups": [],
                                "computers": [], "dcs": [], "trusts": [], "ous": []}
    coverage = {name: "NOT TESTED" for name in MODULES}
    try:
        collector.connect(args.domain)
        snapshot["root_dse"] = clean_rows([collector.root_dse()])[0]
        observed_dn = snapshot["root_dse"].get("defaultNamingContext")
        if observed_dn and str(observed_dn).casefold() != base_dn.casefold():
            raise RuntimeError(f"DC RootDSE domain {observed_dn!r} does not match requested domain {base_dn!r}")
        if "domain" in modules:
            coverage["domain"] = "COMPLETED"
        if "policies" in modules or "domain" in modules:
            try:
                rows = collector.search(base_dn, "(objectCategory=domain)",
                                        ["minPwdLength", "pwdProperties", "lockoutThreshold", "lockoutDuration",
                                         "lockOutObservationWindow", "ms-DS-MachineAccountQuota", "msDS-Behavior-Version"])
                snapshot["policy"] = clean_rows(rows)[0] if rows else {}
                if "policies" in modules:
                    coverage["policies"] = "COMPLETED" if rows else "INCONCLUSIVE"
                if "domain" in modules and not rows:
                    coverage["domain"] = "INCONCLUSIVE"
            except Exception as exc:
                if "policies" in modules:
                    coverage["policies"] = f"FAILED: {type(exc).__name__}: {exc}"
                if "domain" in modules:
                    coverage["domain"] = f"FAILED: {type(exc).__name__}: {exc}"
        query_modules = [name for name in modules if name in collector.SEARCHES]
        if "delegation" in modules:
            for dependency in ("users", "computers"):
                if dependency not in query_modules:
                    query_modules.append(dependency)
        for name in query_modules:
            search = collector.SEARCHES[name]
            search_filter, attrs = search
            base = f"CN=System,{base_dn}" if name == "trusts" else base_dn
            try:
                snapshot[name] = clean_rows(collector.search(base, search_filter, attrs))
                coverage[name] = "COMPLETED"
                if name == "computers":
                    dc_filter, dc_attrs = collector.SEARCHES["dcs"]
                    snapshot["dcs"] = clean_rows(collector.search(base_dn, dc_filter, dc_attrs))
            except Exception as exc:
                coverage[name] = f"FAILED: {type(exc).__name__}: {exc}"
                if args.verbose:
                    print(f"[!] {name} query failed: {exc}", file=sys.stderr)
        if "delegation" in modules:
            dependency_status = [coverage[name] for name in ("users", "computers")]
            if all(status == "COMPLETED" for status in dependency_status):
                coverage["delegation"] = "COMPLETED"
            elif any(status.startswith("FAILED") for status in dependency_status):
                coverage["delegation"] = "FAILED: user/computer attributes unavailable"
            else:
                coverage["delegation"] = "INCONCLUSIVE"
    finally:
        collector.close()
    return snapshot, coverage


def inventory_findings(snapshot: dict[str, Any], modules: tuple[str, ...]) -> list[dict[str, Any]]:
    out = []
    if "domain" in modules:
        root, policy = snapshot.get("root_dse", {}), snapshot.get("policy", {})
        out.append(finding(
            "DOMAIN-INVENTORY", "Domain and forest naming contexts collected", "INFO",
            snapshot.get("domain_dn", ""), "Directory", 
            f"defaultNamingContext={root.get('defaultNamingContext', '(not returned)')}; rootDomainNamingContext={root.get('rootDomainNamingContext', '(not returned)')}; configurationNamingContext={root.get('configurationNamingContext', '(not returned)')}; domainBehaviorVersion={policy.get('msDS-Behavior-Version', '(not returned)')}.",
            "RootDSE and domain attributes identify directory naming contexts and behavior level. Missing fields may reflect server support or access limitations.",
            "Review against the authoritative directory inventory.", "High", "Establishes the directory scope and baseline.",
            "DETECTED", "Confirm domain and forest naming contexts with the directory owner.",
            "Maintain documented forest and domain functional levels."))
        dcs = snapshot.get("dcs", [])
        if dcs:
            out.append(finding(
                "DOMAIN-CONTROLLERS", "Domain controller inventory collected", "INFO",
                snapshot.get("domain_dn", ""), "Directory",
                "; ".join(f"{x.get('dNSHostName', x.get('sAMAccountName', 'unknown'))} ({x.get('operatingSystem', 'OS not returned')} {x.get('operatingSystemVersion', '')})".strip() for x in dcs),
                "DC candidates were selected using the SERVER_TRUST_ACCOUNT userAccountControl bit. Confirm against the authoritative inventory.",
                "Verify the DC role and patch state separately.", "High", "Identifies DC assets for follow-up review.",
                "DETECTED", "Compare with AD Sites and Services and the approved asset inventory.",
                "Maintain supported, patched domain controllers."))
    return out


def report_payload(args: argparse.Namespace, snapshot: dict[str, Any], coverage: dict[str, str], findings: list[dict[str, Any]]) -> dict[str, Any]:
    return {"product": "AD Attack Surface Scanner", "version": VERSION,
            "scan": {"domain": args.domain, "dc": args.dc_host or args.dc_ip, "mode": args.mode,
                     "modules": list(args.selected_modules), "started_at": snapshot.get("collected_at"),
                     "transport": "LDAP anonymous without TLS" if getattr(args, "plain_anonymous", False) else "LDAPS",
                     "read_only": True, "credential_hash_requests": False},
            "coverage": coverage,
            "summary": {"finding_count": len(findings), "by_severity": {
                s: sum(1 for item in findings if item["severity"] == s)
                for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}},
            "findings": findings, "inventory": snapshot,
            "limitations": [
                "Phase 2 MVP covers LDAP domain, user, group, computer, policy, and basic delegation enumeration.",
                "ACL security-descriptor parsing, GPO effect/scope analysis, AD CS, network posture, trust security, and attack-path correlation are not implemented yet.",
                "No finding means only that this collection did not report a condition; incomplete modules are listed in coverage and do not prove absence.",
                "DETECTED and POTENTIALLY EXPLOITABLE are configuration assessments, not proof of exploitation. MANUALLY VERIFIED is never assigned automatically."]}


def write_reports(output: Path, payload: dict[str, Any]) -> None:
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(output, 0o700)
    (output / "report.json").write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")
    findings = payload["findings"]
    fields = list(findings[0]) if findings else list(finding("", "", "", "", "", "", "", "", "", "", "", "", "", []))
    with (output / "findings.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for item in findings:
            writer.writerow({**item, "references": "; ".join(item["references"])})
    rows = []
    for item in findings:
        details = "".join(
            f"<p><b>{html.escape(key.replace('_', ' ').title())}:</b> "
            f"{html.escape('; '.join(map(str, value)) if isinstance(value, list) else str(value))}</p>"
            for key, value in item.items() if key not in {"finding_id", "title", "severity"})
        cells = [item["finding_id"], item["title"], item["severity"],
                 f"<details><summary>{html.escape(item['validation_status'])} · details</summary>{details}</details>"]
        rows.append("<tr>" + "".join(f"<td>{x}</td>" if index == 3 else
                                       f"<td>{html.escape(str(x))}</td>"
                                       for index, x in enumerate(cells)) + "</tr>")
    page = ("<!doctype html><meta charset='utf-8'><title>AD Scanner Report</title>"
            "<style>body{font:15px system-ui;margin:2rem;background:#0b1220;color:#e7edf5}"
            "table{border-collapse:collapse;width:100%}th,td{padding:.7rem;border:1px solid #304154;text-align:left;vertical-align:top}"
            "th{background:#17283a}td{max-width:40rem;overflow-wrap:anywhere}</style>"
            f"<h1>AD Attack Surface Scanner · {html.escape(str(payload['scan']['domain']))}</h1>"
            f"<p>{payload['summary']['finding_count']} findings · {html.escape(str(payload['scan']['mode']))} mode · read-only</p>"
            "<h2>Collection coverage</h2><ul>" + "".join(
                f"<li><b>{html.escape(k)}</b>: {html.escape(v)}</li>" for k, v in payload["coverage"].items()) + "</ul>"
            "<h2>Findings</h2><table><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Evidence, context, validation and remediation</th></tr></thead><tbody>"
            + "".join(rows) + "</tbody></table><h2>Limitations</h2><ul>"
            + "".join(f"<li>{html.escape(x)}</li>" for x in payload["limitations"]) + "</ul>")
    (output / "report.html").write_text(page, encoding="utf-8")
    for path in output.iterdir():
        if path.is_file():
            os.chmod(path, 0o600)


def print_summary(payload: dict[str, Any]) -> None:
    print(f"\nAD Attack Surface Scanner {VERSION} · {payload['scan']['domain']}")
    print(f"Mode: {payload['scan']['mode']} | DC: {payload['scan']['dc']} | "
          f"Transport: {payload['scan'].get('transport', 'LDAPS')} | Read-only")
    print("-" * 86)
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count = payload["summary"]["by_severity"][severity]
        if count:
            print(f"{severity:<9} {count}")
    print("\nCollection coverage")
    for module, status in payload["coverage"].items():
        print(f"  {module:<13} {status}")
    print("\nFindings")
    for item in payload["findings"]:
        print(f"  [{item['severity']:<8}] {item['finding_id']:<28} {item['title']} ({item['validation_status']})")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=f"adscanner {VERSION}")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Run a read-only Active Directory collection")
    scan.add_argument("--domain", required=True, help="AD DNS domain, e.g. corp.example")
    scan.add_argument("--dc-ip", required=True, help="Domain controller IP or resolvable hostname")
    scan.add_argument("--dc-host", help="DC certificate/DNS hostname when connecting by IP")
    scan.add_argument("--username", "--user", dest="username", help="Username; password is prompted securely")
    scan.add_argument("--mode", choices=("quick", "full", "focused"), default="quick")
    scan.add_argument("--modules", help=f"Comma-separated focused modules: {', '.join(MODULES)}")
    scan.add_argument("--output", type=Path, default=Path("./reports/adscanner"))
    scan.add_argument("--ldap-port", type=int, help="LDAP port (default: 389 for --plain-anonymous, otherwise 636)")
    scan.add_argument("--plain-anonymous", action="store_true",
                      help="Use unencrypted LDAP with anonymous bind only; no username/password accepted")
    scan.add_argument("--timeout", type=int, default=8)
    scan.add_argument("--threads", type=int, default=1, help="Analysis workers; LDAP collection remains sequential")
    scan.add_argument("--stale-days", type=int, default=90)
    scan.add_argument("--insecure-tls", action="store_true", help="Disable TLS validation for isolated labs only")
    scan.add_argument("--verbose", action="store_true")
    scan.add_argument("--dry-run", action="store_true", help="Validate options and list checks without connecting")
    scan.add_argument("--yes", action="store_true", help="Confirm DC is explicitly in authorized scope")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.ldap_port = args.ldap_port or (389 if args.plain_anonymous else 636)
    if not 1 <= args.ldap_port <= 65535 or not 1 <= args.timeout <= 300:
        parser.error("--ldap-port must be 1–65535 and --timeout 1–300 seconds")
    if args.plain_anonymous and args.username:
        parser.error("--plain-anonymous cannot be combined with --username; credentials require TLS")
    if not 1 <= args.threads <= 16 or args.stale_days < 1:
        parser.error("--threads must be 1–16 and --stale-days must be at least 1")
    try:
        base_dn = domain_to_dn(args.domain)
    except ValueError as exc:
        parser.error(str(exc))
    if args.mode == "focused" and not args.modules:
        parser.error("focused mode requires --modules")
    if args.modules and args.mode != "focused":
        parser.error("use --modules with --mode focused")
    selected = tuple(item.strip().lower() for item in args.modules.split(",")) if args.modules else (
        QUICK_MODULES if args.mode == "quick" else MODULES)
    unknown = set(selected) - set(MODULES)
    if not selected or unknown:
        parser.error(f"unknown or empty module list: {', '.join(sorted(unknown)) or '(empty)'}")
    args.selected_modules = selected
    transport = "anonymous LDAP · UNENCRYPTED" if args.plain_anonymous else "LDAPS"
    print(f"AD Attack Surface Scanner {VERSION} · read-only {transport}")
    print(f"Domain: {args.domain} ({base_dn}) | DC: {args.dc_host or args.dc_ip} | Mode: {args.mode}")
    print(f"Modules: {', '.join(selected)} | Output: {args.output}")
    if args.insecure_tls:
        print("WARNING: TLS certificate validation is disabled.", file=sys.stderr)
    if args.plain_anonymous:
        print("WARNING: LDAP traffic and directory results are not encrypted; anonymous bind only.", file=sys.stderr)
    if args.dry_run:
        print("Dry run complete; no network connection was made.")
        return 0
    if not args.yes:
        try:
            answer = input("Confirm this DC is in your authorized scope? [y/N]: ").strip().lower()
        except EOFError:
            answer = ""
        if answer not in ("y", "yes"):
            print("Cancelled; no network requests were made.")
            return 0
    password = getpass.getpass("Password (hidden): ") if args.username else ""
    try:
        snapshot, coverage = collect_snapshot(args, password, selected)
    except Exception as exc:
        print(f"Collection failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        print("Do not infer a clean result from a failed collection.", file=sys.stderr)
        return 2
    findings = inventory_findings(snapshot, selected)
    findings.extend(analyze_snapshot(snapshot, selected, args.stale_days, args.threads))
    payload = report_payload(args, snapshot, coverage, findings)
    try:
        write_reports(args.output, payload)
    except OSError as exc:
        print(f"Could not write report: {exc}", file=sys.stderr)
        return 2
    print_summary(payload)
    print(f"\nReports saved: {args.output.resolve()} (report.html, report.json, findings.csv)")
    return 1 if any(value.startswith("FAILED") for value in coverage.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
