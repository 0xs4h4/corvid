# corvid-ad

A **read-only** Active Directory attack-surface and exploitability scanner.

corvid-ad performs authenticated LDAP reconnaissance and detects exploitable
misconfigurations, dangerous permissions, privilege-escalation paths, lateral
movement prerequisites and domain-compromise risks. It is designed for
**explicitly authorized** assessments (internal pentests, OSCP-style labs,
purple-team exercises).

> **Read-only by default.** corvid-ad never modifies AD objects, never dumps
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
- **Active layer (`--active`)**: opt-in local attack surface — checks which
  hosts your credentials are local admin on (`AdminTo`) and dumps SAM hashes +
  LSA service/account passwords (`impacket`), then folds `CredentialReuse`
  edges into the graph so the *local → domain* hop is part of the same path.
- **Finding validation model** with severity + confidence scoring, evidence,
  prerequisites, manual verification, remediation, references and MITRE ATT&CK.
- **Reporting**: interactive HTML, JSON, CSV, Rich terminal dashboard, graph
  visualization data, and a snapshot for offline analysis.
- **Modes**: `quick` (high-signal), `full` (all modules), `focused` (selected
  modules), `offline` (analyze prior snapshots).
- **Safe credential handling** (never logged or printed; pass-the-hash supported).

## Installation

The repo is public — no key or token needed.

**Recommended — `pipx`** (command on `PATH`, no venv activation):

```bash
# straight from git, no clone
pipx install "git+https://github.com/0xs4h4/corvid.git#subdirectory=corvid-ad"

# or from a clone, editable so source edits take effect immediately
git clone https://github.com/0xs4h4/corvid.git
pipx install --editable ./corvid/corvid-ad

corvid-ad doctor
```

To update a non-editable install after new commits: `pipx reinstall corvid-ad`.

**Dev venv** — needed for `pytest` and the `[active]` impacket extra:

```bash
# On Kali Linux / Debian
sudo apt-get install -y python3-venv python3-dev libkrb5-dev libsasl2-dev libldap2-dev
python3 -m venv .venv
source .venv/bin/activate
pip install .              # read-only layer
pip install .[active]      # + impacket for the --active layer
```

Or with `uv`:

```bash
uv venv .venv
uv pip install --python .venv/bin/python .
```

Docker:

```bash
docker build -t corvid-ad .
docker run --rm corvid-ad --help
```

## Usage

```bash
# Quick low-impact scan
corvid-ad scan --domain corp.local --dc-ip 10.0.0.2 --username audit.user --mode quick -o reports/

# Full assessment
corvid-ad scan --domain corp.local --dc-ip 10.0.0.2 --username audit.user --mode full -o reports/

# Focused modules
corvid-ad scan --domain corp.local --username audit.user --modules acl,gpo,delegation,adcs

# Offline analysis of a prior snapshot
corvid-ad analyze --input reports/ --mode full

# Regenerate a report from results.json
corvid-ad report --input reports/results.json --format html

# List available checks
corvid-ad checks --list

# Environment/dependency check
corvid-ad doctor
```

### Find attack paths to Domain Admin

The graph engine finds escalation paths from a starting principal (or every
low-privileged user by default) to high-value targets.

```bash
# All low-privileged users as possible starts (default)
corvid-ad scan --domain corp.local --dc-ip 10.0.0.2 --username audit.user --mode full

# Start from a specific compromised principal
corvid-ad scan --domain corp.local --dc-ip 10.0.0.2 --username audit.user --start svc_sql

# Offline, from a prior snapshot
corvid-ad analyze -i reports/snapshot.json --start Eric.Wallows
```

`--start` accepts a `sAMAccountName`, DN or SID. Example output:

```
Attack Paths to High-Value Targets
  svc_dcsync —DCSync (T1003.006) → Domain (DCSync)
  michael —GenericAll (T1484) → Domain Admins
```

See [docs/attack-paths.md](docs/attack-paths.md) for the full edge taxonomy and
caveats.

### Active layer — local admin + credentials

`--active` adds the *local* attack surface (the hop the read-only LDAP layer
can't see). Given credentials, it checks which hosts you're local admin on and
dumps SAM hashes + printable LSA secrets from those hosts, then folds
`AdminTo` and `CredentialReuse` edges into the graph.

```bash
# Requires impacket (pip install corvid-ad[active])
corvid-ad scan --domain corp.local --dc-ip 10.0.0.2 --username audit.user \
    --mode full --active --hosts 10.0.0.10,10.0.0.11 -o reports/
```

What it does per host:

1. `check_admin` — tries to connect to the `C$` admin share (SMB).
2. `dump_secrets` — on admin hosts, dumps the SAM hive (local NTLM hashes) and
   LSA secrets (service/account passwords) via impacket's `RemoteOperations`.
3. `CredentialReuse` — if a dumped local account name matches a domain account
   (e.g. local `Admin` ↔ domain `Admin`), it records a password-reuse hint and
   a graph edge, so the full path shows up in `find_paths`.

Example output:

```
Active Layer (local admin + credentials)
  AdminTo: 10.0.0.10
  [!] CredentialReuse local 'Admin' (nthash) → domain 'Admin' via 10.0.0.10
```

Attack path:

```
audit.user —AdminTo (T1078) → 10.0.0.10 —CredentialReuse (T1078) → Admin —MemberOf (T1078) → Administrators
```

> **Use only on hosts you are authorized to assess.** This layer performs
> authenticated SMB access and registry reads on the target hosts.

### Credentials

The password is requested interactively (getpass), or read from the
`CORVID_AD_PASSWORD` environment variable, or passed with `--password` (not
recommended — it is visible in process listings). Passwords are never written
to logs or reports.

## Architecture

```
src/corvid-ad/
├── cli.py               # argparse CLI (scan/analyze/report/checks/doctor)
├── core/                # finding model, data models, config, SID, scanner
├── collectors/          # ldap3 live collector (+ active layer: SAM/LSA dump)
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

The test suite (60 tests) covers SDDL parsing, SID resolution, ACL analysis,
delegation flags, Kerberos eligibility, AD CS templates, graph correlation and
attack-path finding, the active-layer credential parsing and AdminTo /
CredentialReuse graph edges, report generation, serialization round-trips and
error handling (failed authentication, DNS failure, collection failure,
insufficient data).

## Authorization

Only run corvid-ad against environments you are **explicitly authorized** to
assess. Unauthorized scanning of Active Directory is illegal and harmful.

## License

MIT. This project builds on concepts from public research (BloodHound,
Certipy, PingCastle, ADRecon, NetExec) but is an independent implementation.
