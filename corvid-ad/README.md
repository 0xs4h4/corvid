# corvid-ad

A read-only scanner for Active Directory.

You give it a domain and one normal user account. It reads whatever that
account is allowed to read, then tells you what is weak and how someone could
move up from there to Domain Admin.

Use it only on systems you are allowed to test: internal pentests, OSCP-style
labs, purple-team work.

> **It only reads.** It does not change AD objects, does not dump secrets,
> does not ask for roastable tickets, does not crack passwords, and does not
> forge tickets.

## What it checks

- **11 check groups** — domain info, stored credentials, ACL abuse, GPO,
  Kerberos delegation, AD CS (ESC1–ESC8), privilege escalation, network,
  infrastructure, vulnerabilities, persistence.
- **Attack paths** — builds a BloodHound-style graph, then shows the shortest
  path from your account to Domain Admin. Each edge names the weakness (for
  example `GenericAll`, `WriteDacl`, `DCSync`) and how it is normally abused.
- **Optional local layer (`--active`)** — checks which hosts your account is
  local admin on, dumps local SAM hashes and LSA secrets with impacket, then
  joins the local → domain hop into the same path.
- **Evidence for every finding** — severity, confidence, what proves it, how
  to verify it by hand, and how to fix it.
- **Reports** — HTML, JSON, CSV, a terminal dashboard, and a snapshot you can
  analyse offline later.

## Installation

Two ways. Pick one.

**Way 1 — you just want to use it**

```bash
pipx install "git+https://github.com/0xs4h4/corvid.git#subdirectory=corvid-ad"
corvid-ad doctor
```

**Way 2 — you want to change the code**

```bash
git clone https://github.com/0xs4h4/corvid.git
pipx install --editable ./corvid/corvid-ad
```

Updating: Way 1 → `pipx reinstall corvid-ad`. Way 2 → `git pull`.

**Need the dev extras?**

`pytest` and the `--active` impacket layer need a project venv:

```bash
sudo apt-get install -y python3-venv python3-dev libkrb5-dev libsasl2-dev libldap2-dev
python3 -m venv .venv
source .venv/bin/activate
pip install .[active]
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
