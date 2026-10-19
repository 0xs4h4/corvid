# corvid

My offensive-security toolkit. I use it in OSCP labs and on authorised
assessments.

`corvid` means the crow family. Crows are smart. They watch, they remember,
and they use tools. That is the job.

Two tools. Each one lives in its own folder:

```
corvid/
├── corvid-ad/      # looks at Active Directory (read only)
└── corvid-sweep/   # finds open ports on many hosts
```

## Install

Two ways. Pick one.

**Way 1 — you just want to use it**

Copy these two lines. Nothing to download by hand:

```bash
pipx install "git+https://github.com/0xs4h4/corvid.git#subdirectory=corvid-ad"
pipx install "git+https://github.com/0xs4h4/corvid.git#subdirectory=corvid-sweep"
```

Done. Now type `corvid-ad` or `corvid-sweep` anywhere in your terminal.

**Way 2 — you want to change the code**

Clone first. Then install it so your edits take effect right away:

```bash
git clone https://github.com/0xs4h4/corvid.git
cd corvid
pipx install --editable ./corvid-ad
pipx install --editable ./corvid-sweep
```

**Updating later**

- Way 1: run `pipx reinstall corvid-ad`
- Way 2: run `git pull` — that's it

**No pipx?**

```bash
sudo apt install pipx && pipx ensurepath
```

**Check it works**

```bash
corvid-ad --version
corvid-sweep --version
```

## corvid-ad

This tool looks at Active Directory.

You give it a domain and one normal account. It reads whatever that account is
allowed to read. Then it tells you what is weak, and how someone could move
up from that account to Domain Admin.

What it reports:

- who can take over which user or computer
- weak password settings on the domain
- risky Kerberos delegation settings
- accounts that never expire or store passwords weakly
- attack paths, drawn as a graph
- the same findings as JSON, CSV and HTML

What it does **not** do:

- it does not guess or crack passwords
- it does not change anything in AD
- it does not run exploits

So it is safe to point at a live domain. It only reads.

```bash
corvid-ad doctor                                   # check dependencies first
corvid-ad checks --list                            # list the checks
corvid-ad scan --domain corp.example --dc-ip 10.0.0.10 \
    --username jdoe --mode quick -o reports/
```

Modes: `quick` is the light one. `full` runs everything. `--modules acl,gpo`
runs only the checks you name. The password is asked for at the prompt, or you
can set `CORVID_AD_PASSWORD`.

## corvid-sweep

This tool looks at the network.

It takes a list of hosts and scans them in two passes. Pass one: which ports
are open. Pass two: what service and version runs on those ports.

Why two passes? You see the whole picture first. Then you spend the slow
version scan only on ports that answered.

```bash
corvid-sweep -i targets.txt                  # SYN scan, needs root
corvid-sweep -i targets.txt --connect        # connect scan, no root needed
corvid-sweep -i targets.txt --resume runs/X  # reuse scans already done
```

Each run makes a new folder with the nmap files and one `report.txt` you can
read at the end.

## History

`corvid-ad` started life as a 566-line script (`ad_recon.py`, 8 checks,
v0.2.0). I removed it once the packaged version did everything it did. The old
code is still in git history:

```bash
git log --oneline --all -- '*ad_recon*'
```

## Notes

- Python 3.11 or newer. On Kali, install with `pipx`, not system `pip`.
- Use it only on systems you are allowed to test.
- Each tool has its own tests: `cd corvid-ad && .venv/bin/python -m pytest -q`.
