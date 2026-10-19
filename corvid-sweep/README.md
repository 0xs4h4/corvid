# corvid-sweep

A port scanner for a list of hosts.

It works in two passes. Pass one: which ports are open. Pass two: what service
and version runs on those ports. At the end you get one text report.

Why two passes? You see the whole picture first. Then you spend the slow
version scan only on ports that answered.

## Install

Two ways. Pick one.

**Way 1 — you just want to use it**

```bash
pipx install "git+https://github.com/0xs4h4/corvid.git#subdirectory=corvid-sweep"
corvid-sweep --help
```

**Way 2 — you want to change the code**

```bash
git clone https://github.com/0xs4h4/corvid.git
pipx install --editable ./corvid/corvid-sweep
```

Updating: Way 1 → `pipx reinstall corvid-sweep`. Way 2 → `git pull`.

No pipx? `sudo apt install pipx && pipx ensurepath`

Or run it from a checkout without installing:

```bash
python3 -m corvid_sweep.cli -i targets.txt
```

## Usage

```bash
corvid-sweep -i targets.txt                    # SYN scan (needs root), timing 4
corvid-sweep -i targets.txt --connect          # TCP connect scan, no root
corvid-sweep -i targets.txt --resume corvid-sweep-output/corvid-sweep-20261019-1
corvid-sweep -i targets.txt -o scans/          # write runs under scans/
```

- `-i, --targets` — file with one host/IP/CIDR per line (default `targets.txt`).
- `-o, --output` — parent directory for run folders (default
  `./corvid-sweep-output`).
- `--timing 3|4` — nmap timing template (default 4).
- `--connect` — use `-sT` instead of `-sS` when you are not root.
- `--resume` — point at an existing run directory; completed scans are reused.

Each run creates a timestamped folder containing the nmap artefacts and a
plain-text report:

```
corvid-sweep-output/
└── corvid-sweep-20261019-1/
    ├── report.txt
    ├── all-ipv4-tcp.xml
    └── all-ipv4-services.xml
```

Run it with `sudo` and the output is handed back to you (`chown` to
`SUDO_UID`), so you do not end up with root-owned reports you cannot delete.

Need a SYN scan but `sudo` cannot find the command? `sudo` throws away your
`PATH`. Use `sudo $(which corvid-sweep) -i targets.txt`, or symlink it once:
`sudo ln -sf ~/.local/bin/corvid-sweep /usr/bin/corvid-sweep`.

## Requirements

`nmap` on `PATH`. Python 3.11+.
