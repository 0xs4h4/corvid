# corvid-sweep

Two-pass TCP discovery across a list of targets, then service detection on the
ports that answered, then a per-target text report.

The point of the two passes: see the whole attack surface before committing
time to one host. Pass 1 is cheap discovery across everything; pass 2 spends
`-sV` only where something is actually listening.

## Install

Public repo — no key or token needed.

```bash
# from a clone (editable, for when you're editing)
git clone https://github.com/0xs4h4/corvid.git
pipx install --editable ./corvid/corvid-sweep

# or straight from git, no clone
pipx install "git+https://github.com/0xs4h4/corvid.git#subdirectory=corvid-sweep"

corvid-sweep --help
```

Or run it from a checkout without installing:

```bash
python3 -m corvid_sweep.cli -i targets.txt
```

## Usage

```bash
corvid-sweep -i targets.txt                    # SYN scan (needs root), timing 4
corvid-sweep -i targets.txt --connect          # TCP connect scan, no root
corvid-sweep -i targets.txt --resume runs/X    # reuse finished scans in a run dir
corvid-sweep -i targets.txt -o runs/           # write results under runs/
```

- `-i, --targets` — file with one host/IP/CIDR per line (default `targets.txt`).
- `-o, --output` — parent directory for run folders (default `./output`).
- `--timing 3|4` — nmap timing template (default 4).
- `--connect` — use `-sT` instead of `-sS` when you are not root.
- `--resume` — point at an existing run directory; completed scans are reused.

Each run creates a timestamped folder containing the nmap artefacts and a
plain-text report.

## Requirements

`nmap` on `PATH`. Python 3.11+.
