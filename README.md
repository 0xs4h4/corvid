# corvid

Personal offensive-security toolkit — the things I actually reach for in OSCP
labs and authorised internal assessments. Recon first, then the targeted work.

**corvid** (the crow family): smart, opportunistic, remembers faces, uses
tools. That is the job.

Every tool is its own directory, its own package, its own tests, and installs
as a `corvid-` prefixed command:

```
corvid/
├── corvid-ad/       # AD attack-surface + exploitability scanner
├── corvid-sweep/    # two-pass TCP discovery + service detection
└── README.md
```

## Install

```bash
pipx install --editable ./corvid-ad
pipx install --editable ./corvid-sweep
```

Editable installs mean source edits take effect immediately — `git pull` is
enough to stay current (only `pipx reinstall <tool>` when dependencies move).

## `corvid-ad`

Read-only Active Directory attack-surface scanner. LDAP(S) collection,
attack-path graph, JSON/CSV/HTML reporting. It never requests Kerberos hashes,
cracks passwords, modifies AD, or exploits anything.

```bash
corvid-ad doctor
corvid-ad checks --list
corvid-ad scan --domain corp.example --dc-ip 10.0.0.10 --username <user> \
    --mode quick -o reports/
```

Modes: `quick` (low-impact), `full` (all modules), or `--modules acl,gpo,adcs`
for focused runs. Password prompted securely or via `CORVID_AD_PASSWORD`.
`--active/--hosts` adds the impacket SAM/LSA layer (needs the `[active]` extra).

## `corvid-sweep`

Two-pass TCP discovery: pass 1 finds what is listening across every target,
pass 2 runs version detection only on ports that answered.

```bash
corvid-sweep -i targets.txt                  # SYN scan (root), timing 4
corvid-sweep -i targets.txt --connect        # TCP connect scan, no root
corvid-sweep -i targets.txt --resume runs/X  # reuse finished scans
```

Each run creates a timestamped folder with the nmap artefacts plus
`report.txt`.

## History

`corvid-ad` grew out of a 566-line LDAPS MVP (`ad_recon.py`, 8 modules,
v0.2.0). Removed once the packaged scanner reached parity; the code is still
in git history:

```bash
git log --oneline --all -- '*ad_recon*'
git show <commit>:corvid-ad-recon.py
```

## Conventions

- Python 3.11+; Kali is PEP 668, so install with `pipx`, never system `pip`.
- Lab/engagement tooling only — run it against systems you are authorised to
  test.
- Tests live with each tool: `cd corvid-ad && .venv/bin/python -m pytest -q`.
