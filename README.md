# corvid

Personal offensive-security toolkit — the things I actually reach for in OSCP
labs and authorised internal assessments. Recon first, then the targeted work.

**corvid** (the crow family): smart, opportunistic, remembers faces, uses
tools. That is the job. Every tool lives here under the `corvid-` prefix so
the family stays recognisable.

## Tools

### `corvid-ad`
Read-only Active Directory attack-surface and exploitability scanner. LDAP(S)
collection, attack-path graph, JSON/CSV/HTML reporting. It never requests
Kerberos hashes, cracks passwords, modifies AD, or exploits anything.

```bash
pipx install --editable ./corvid-ad
corvid-ad doctor
corvid-ad scan --domain corp.example --dc-ip 10.0.0.10 --username <user> \
    --mode quick -o reports/
```

Modes: `quick`, `full`, or `--modules acl,gpo,...` for focused runs. Password
is prompted securely (or set `CORVID_AD_PASSWORD`).

### `corvid-sweep`
Two-pass TCP discovery across every host in a target list, then service
detection on the open ports, followed by a text report.

```bash
python3 corvid-sweep.py -i targets.txt -o runs/        # SYN scan, timing 4
python3 corvid-sweep.py -i targets.txt --connect       # TCP connect scan
python3 corvid-sweep.py -i targets.txt --resume runs/  # reuse finished scans
```

- Pass 1: discovery across every target — you see the whole attack surface
  before committing to one host.
- Pass 2: service/version detection only on ports that answered.

## History

`corvid-ad` grew out of a 566-line LDAPS MVP (`ad_recon.py`, v0.2.0). It was
removed once the packaged scanner reached feature parity — the code is still
in git history:

```bash
git log --oneline --all -- '*ad_recon*'
git show <commit>:corvid-ad-recon.py
```

## Conventions

- Python 3.11+.
- Lab/engagement tooling only — run it against systems you are authorised to
  test.
- Tests: `cd corvid-ad && .venv/bin/python -m pytest -q`.
