# pentest-tools

Personal reconnaissance / assessment scripts used in OSCP labs and authorised
internal assessments. Private by default — nothing here is a public release.

## netsweep.py

Two-pass TCP discovery across every host in a target list, then service
detection on the open ports, followed by a text report.

```bash
python3 netsweep.py -i targets.txt -o runs/                   # SYN scan, timing 4
python3 netsweep.py -i targets.txt --connect                  # TCP connect scan
python3 netsweep.py -i targets.txt --resume runs/             # reuse finished scans
```

- Pass 1: discovery across all targets (gives the full attack-surface picture
  before committing to one host).
- Pass 2: service/version detection on discovered ports only.
- Output: per-target text report plus the nmap artefacts it parsed.

## ad_recon.py

Read-only Active Directory attack-surface scanner over LDAPS. Collects
directory metadata and reports evidence-backed conditions — it never requests
Kerberos hashes, cracks passwords, modifies AD, or exploits anything.

```bash
python3 ad_recon.py scan --domain corp.example --dc-ip 10.0.0.10 \
    --username <user> --mode quick -o reports/
```

Modes: `quick`, `full`, or `--modules acl,gpo,...` for focused runs. Password
is prompted securely (never passed on the command line).

An expanded fork of this scanner lives in
[adscan](https://github.com/0xs4h4/adscan).

## Notes

- Both scripts are lab/engagement tooling; only run them against systems you
  are authorised to test.
- Python 3.11+.
