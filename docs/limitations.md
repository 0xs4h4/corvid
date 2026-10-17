# Known Limitations

This document is an honest accounting of what adscan does **not** cover and
what can go wrong, so results are interpreted correctly.

## Not a full replacement for BloodHound / Certipy / NetExec

- adscan does **not** collect session data, local admin relationships, or
  SPN/session edges the way SharpHound does. Its graph is built from LDAP-only
  data (ACLs, memberships, delegation, SPNs) and therefore shows fewer,
  narrower paths than BloodHound.
- adscan does **not** request TGTs/TGSs (Kerberoast/AS-REP), dump hashes, or
  crack passwords. It only reports *eligibility*.
- adscan does **not** probe SMB/RPC/MS-EFSR/web endpoints. Host-level controls
  (SMB signing, LDAP signing, Print Spooler, web enrollment) are reported as
  manual-verification items.

## Data-completeness caveats

- **Permission errors**: if the scan account lacks read access to certain
  objects/attributes, they are silently missing. *Failed enumeration is never
  proof of absence.* The scan records collection warnings where possible, but
  LDAP rarely errors — it just omits.
- **Inherited ACEs**: dangerous rights may be inherited from a parent OU/container
  not explicitly collected. Severity may be overstated if a deny ACE or
  inheritance block neutralizes the right.
- **SDDL-only ACL analysis**: ACLs are parsed from SDDL (`nTSecurityDescriptor`).
  The security-descriptor control is required; if the DC does not return SDDL,
  ACL-based modules produce no findings (not zero findings).
- **SACL is ignored**: audit-only (SACL) entries are not analyzed.

## Vulnerability indicators are heuristics

- ZeroLogon / PrintNightmare / sAMAccountName / PetitPotam findings are based
  on **configuration indicators** (OS version, MachineAccountQuota), not patch
  verification. They are marked LOW/MEDIUM confidence and labelled
  "patch-dependent — verify manually". Do not treat them as confirmed
  vulnerabilities.

## Scoring honesty

- **Confidence** reflects how directly the observed configuration implies a
  risk, not proof of exploitability. A HIGH-confidence finding means the
  configuration is clearly present; exploitation still depends on factors
  adscan does not observe (weak passwords, reachable services, patch state).
- **Graph connectivity is not exploitation.** An attack path means a
  permission chain exists, not that it is traversable. Manual verification is
  always listed per finding.

## Live vs. mock-tested

- The LDAP collector (`ldap3`) is implemented but has **not** been validated
  against a live domain controller in this environment. Offline analysis,
  module logic, graph correlation, and reporting are covered by the automated
  test suite against a mock AD dataset (`fixtures/mock_domain.py`).
- If you run `adscan scan` against a real domain and the collector behaves
  unexpectedly, check: LDAP bind method (NTLM vs SIMPLE vs Kerberos), the
  security-descriptor control support, and account read permissions.

## Performance

- Paged LDAP queries with configurable rate limiting keep load low, but a
  full scan of a large domain (100k+ objects) can be slow. Use `--mode quick`
  for a first pass and `--modules` to target specific areas.
