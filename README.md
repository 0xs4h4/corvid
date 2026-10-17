# adscan

A **read-only** Active Directory attack-surface and exploitability scanner.

adscan performs authenticated LDAP reconnaissance and detects exploitable
misconfigurations, dangerous permissions, privilege-escalation paths, lateral
movement prerequisites and domain-compromise risks. It is designed for
**explicitly authorized** assessments (internal pentests, OSCP-style labs,
purple-team exercises).

> **Read-only by default.** adscan never modifies AD objects, never dumps
> secrets, never requests roasting tickets, never cracks passwords, and never
> forges tickets or implements persistence.

## Features

- **11 detection modules** across domain recon, credential exposure, ACL
  abuse, GPO, Kerberos/delegation, AD CS (ESC1–ESC8), privilege escalation,
  network, infrastructure, vulnerabilities and persistence.
- **Attack-path graph engine** (NetworkX, BloodHound-style): builds a directed
  graph of *compromise* edges and finds shortest escalation paths to Domain
  Admin from any starting principal. Edge types: `MemberOf`, `GenericAll`,
  `GenericWrite`, `WriteDacl`, `WriteOwner`, `ForceChangePassword`, `DCSync`,
  `AddSelf`, `Owns`, `Kerberoastable`, `ASREPRoastable`,
  `ConstrainedDelegation`, `RBCD`, `UnconstrainedDelegation` — each annotated
  with a MITRE technique and exploitation hint.
- **Finding validation model** with severity + confidence scoring, evidence,
  prerequisites, manual verification, remediation, references and MITRE ATT&CK.
- **Reporting**: interactive HTML, JSON, CSV, Rich terminal dashboard, graph
  visualization data, and a snapshot for offline analysis.
- **Modes**: `quick` (high-signal), `full` (all modules), `focused` (selected
  modules), `offline` (analyze prior snapshots).
- **Safe credential handling** (never logged or printed; pass-the-hash supported).

## Installation

```bash
# On Kali Linux / Debian
sudo apt-get install -y python3-venv python3-dev libkrb5-dev libsasl2-dev libldap2-dev
python3 -m venv .venv
source .venv/bin/activate
pip install .
```

Or with `uv`:

```bash
uv venv .venv
uv pip install --python .venv/bin/python .
```

Docker:

```bash
docker build -t adscan .
docker run --rm adscan --help
```

## Usage

```bash
# Quick low-impact scan
adscan scan --domain corp.local --dc-ip 10.0.0.2 --username audit.user --mode quick -o reports/

# Full assessment
adscan scan --domain corp.local --dc-ip 10.0.0.2 --username audit.user --mode full -o reports/

# Focused modules
adscan scan --domain corp.local --username audit.user --modules acl,gpo,delegation,adcs

# Offline analysis of a prior snapshot
adscan analyze --input reports/ --mode full

# Regenerate a report from results.json
adscan report --input reports/results.json --format html

# List available checks
adscan checks --list

# Environment/dependency check
adscan doctor
```

### Find attack paths to Domain Admin

The graph engine finds escalation paths from a starting principal (or every
low-privileged user by default) to high-value targets.

```bash
# All low-privileged users as possible starts (default)
adscan scan --domain corp.local --dc-ip 10.0.0.2 --username audit.user --mode full

# Start from a specific compromised principal
adscan scan --domain corp.local --dc-ip 10.0.0.2 --username audit.user --start svc_sql

# Offline, from a prior snapshot
adscan analyze -i reports/snapshot.json --start Eric.Wallows
```

`--start` accepts a `sAMAccountName`, DN or SID. Example output:

```
Attack Paths to High-Value Targets
  svc_dcsync —DCSync (T1003.006) → Domain (DCSync)
  michael —GenericAll (T1484) → Domain Admins
```

See [docs/attack-paths.md](docs/attack-paths.md) for the full edge taxonomy and
caveats.

### Credentials

The password is requested interactively (getpass), or read from the
`ADSCAN_PASSWORD` environment variable, or passed with `--password` (not
recommended — it is visible in process listings). Passwords are never written
to logs or reports.

## Architecture

```
src/adscan/
├── cli.py               # argparse CLI (scan/analyze/report/checks/doctor)
├── core/                # finding model, data models, config, SID, scanner
├── collectors/          # ldap3 live collector (+ serialization)
├── modules/             # 11 detection modules (registered via decorator)
│   ├── discovery/  credentials/  acl/  gpo/  delegation/  adcs/
│   ├── privilege/  network/  infrastructure/  vulnerabilities/  persistence/
├── graph/               # NetworkX attack-path engine
├── reporting/           # JSON / CSV / HTML / Rich dashboard
└── utils/               # SDDL ACL parser, serialization
```

## Testing

```bash
pip install pytest
pytest -q
```

The test suite (53 tests) covers SDDL parsing, SID resolution, ACL analysis,
delegation flags, Kerberos eligibility, AD CS templates, graph correlation and
attack-path finding, report generation, serialization round-trips and error
handling (failed authentication, DNS failure, collection failure, insufficient
data).

## Authorization

Only run adscan against environments you are **explicitly authorized** to
assess. Unauthorized scanning of Active Directory is illegal and harmful.

## License

MIT. This project builds on concepts from public research (BloodHound,
Certipy, PingCastle, ADRecon, NetExec) but is an independent implementation.
