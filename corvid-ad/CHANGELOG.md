# Changelog

All notable changes to corvid-ad are documented here.

## [1.3.0] - 2026-10-19

- Scan output now goes to `corvid-ad-output/corvid-ad-YYYYMMDD-N/` (was
  `reports/`), matching the `corvid-sweep` layout. `-o` still overrides the
  parent directory.
- `analyze` and `report` keep writing straight into `-o`.

## [1.2.1] — 2026-10-18

Active-layer bugfixes (impacket 0.13 compatibility + safer hive dumps).

- **DPAPI keys filtered from LSA printable secrets**: `dpapi_machinekey` /
  `dpapi_userkey` are hex key material, not credentials — skipped in parsing.
- **`LSASecrets.dump()` → `dumpSecrets()`**: impacket's `LSASecrets` exposes
  `dumpSecrets()` (not `dump()`, unlike `SAMHashes`); each dump is wrapped in
  try/finally so the hive `RemoteFile` is always closed.
- **Registry export via `remoteOps.saveSAM()` / `saveSECURITY()`**: hives are not
  at `ADMIN$\SAM` — `RemoteOperations` exports them over WinReg RPC (fixes
  `STATUS_OBJECT_NAME_NOT_FOUND`).
- **`SMBConnection.login()` args**: impacket 0.13 takes `lmhash`/`nthash`, not a
  combined `hashes` kwarg — split `LM:NTH` in `_connect()`.

62 tests pass.

## [1.2.0] — 2026-10-18

Active layer (local attack surface) — the missing half of the attack graph.

- **`--active` / `--hosts`**: opt-in layer that, given credentials, checks which
  hosts they are local admin on and dumps SAM hashes + printable LSA secrets
  (service/account passwords) via impacket.
- **Two new graph edges**: `AdminTo` (principal → host) and `CredentialReuse`
  (host → domain account) when a dumped local account name matches a domain
  account — turns the full local→domain path into a single `find_paths` chain.
- **Password-reuse hints** surfaced in the dashboard, JSON report and graph.
- New optional extra: `pip install corvid-ad[active]` (pulls in `impacket`).
- New collector: `collectors/active_collector.py` (SMB admin check via `C$`,
  SAM/LSA dump via `RemoteOperations` + `SAMHashes` + `LSASecrets`).

## [1.1.0] — 2026-10-18

BloodHound-style attack-path engine.

- **Comprehensive attack graph** with compromise edges: `MemberOf`, `GenericAll`,
  `GenericWrite`, `WriteDacl`, `WriteOwner`, `ForceChangePassword`, `DCSync`,
  `AddSelf`, `Owns`, `Kerberoastable`, `ASREPRoastable`,
  `ConstrainedDelegation`, `RBCD`, `UnconstrainedDelegation`.
- **Pathfinding** (`find_paths`) with a `--start` flag (sAMAccountName/DN/SID),
  ranked by hop count then technique diversity; MITRE technique + exploitation
  hint on every hop.
- Expanded high-value targets (Domain Controllers group + DC computers + krbtgt).
- New doc: `docs/attack-paths.md`.

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
