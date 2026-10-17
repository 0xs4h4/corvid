# Changelog

All notable changes to adscan are documented here.

## [1.0.0] — 2026-10-18

First stable release. Live-validated against a real Active Directory lab (SECURA).

### Features

- **11 detection modules** across discovery, credentials, ACL, GPO, delegation,
  AD CS (ESC1–8), privilege escalation, network, infrastructure, vulnerability
  and persistence surfaces.
- **Live LDAP collection** (NTLM/SIMPLE auth, paged results, security-descriptor
  control 0x7) with graceful abort-on-failure (no findings produced on empty data).
- **Graph engine** (NetworkX) correlating principal → group → permission →
  object → high-value-target attack paths.
- **4 report formats**: JSON, CSV, interactive HTML, and a Rich terminal dashboard.
- **CLI** subcommands: `scan` (quick/full), `analyze` (offline from snapshot),
  `report`, `checks`, `doctor`.
- **Evidence-driven findings**: every finding carries severity, confidence,
  category, MITRE mapping, evidence, `manual_verify` flag and false-positive notes.
- **Read-only** by design — no secret dumping, ticket roasting, or auto-exploit.

### False-positive hardening (from live SECURA validation)

- `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD) now parsed as a security
  descriptor; empty/absent SD no longer reported (fixes "RBCD on every computer").
- Domain controllers excluded from unconstrained-delegation reporting.
- Disabled accounts (Guest/DefaultAccount) excluded from credential-flag findings.
- `krbtgt` excluded from Kerberoast reporting.
- `adminCount=1` only reported for unexpectedly-protected groups.
- Zerologon heuristic downgraded to HIGH/LOW-confidence (OS version is not proof).
- Empty-list LDAP attributes serialize as `""` rather than `"[]"`.

### Tests

- 50 tests passing (`pytest -q`).
