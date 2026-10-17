# Usage Guide

## Workflows

### 1. Quick triage (low impact)

```bash
adscan scan --domain corp.local --username audit.user --mode quick -o reports/
```

Runs the high-signal modules: domain recon, credential exposure, ACL abuse,
delegation, privilege escalation (DCSync), network indicators.

### 2. Full assessment

```bash
adscan scan --domain corp.local --dc-ip 10.0.0.2 --username audit.user --mode full -o reports/
```

Adds GPO, AD CS (ESC1–ESC8), infrastructure, vulnerability and persistence
modules.

### 3. Focused module run

```bash
adscan scan --domain corp.local --username audit.user --modules acl,gpo,adcs -o reports/
```

### 4. Offline analysis (no domain contact)

```bash
adscan analyze --input reports/snapshot.json --mode full -o reports/
```

Useful for re-running modules with different logic, or analyzing data
collected elsewhere.

### 5. Report regeneration

```bash
adscan report --input reports/results.json --format html -o reports/
adscan report --input reports/results.json --format csv -o reports/
```

## Authentication

| Method | Flag / env |
|---|---|
| Interactive prompt | (default — getpass) |
| Environment | `export ADSCAN_PASSWORD=...` |
| Flag | `--password ...` |
| Pass-the-hash | `--hashes LMHASH:NTHASH` |
| Anonymous | `--no-password` (and no username) |

Use NTLM by default; set `ldap.auth: SIMPLE` in config for simple bind, or use
`--use-ssl` for LDAPS (port 636).

## Interpreting results

1. **Severity** = potential impact of the finding.
2. **Confidence** = how directly the observed configuration implies the risk
   (not proof of exploitability).
3. **`manual_verification`** = exact commands/steps to confirm the finding.
4. **Attack paths** = candidate permission chains; verify each hop before
   claiming a path is exploitable.
5. **`detection_limitations`** = why the finding may be incomplete.

## Config

Copy `config/default.yaml` and pass `--config myconfig.yaml` to tune LDAP
timeouts, paging, rate limiting, retries/backoff and logging.

## Writing a new module

Subclass `adscan.modules.base.Module`, set `name`, `category`, `quick`, and
implement `run(ctx) -> list[Finding]`. Decorate with `@register`. Import it in
`src/adscan/modules/__init__.py`.
