# Attack-Path Engine

corvid-ad builds a BloodHound-style attack graph and finds escalation paths from a
starting principal to high-value targets.

## Usage

```bash
# all low-privileged users as possible starts (default)
corvid-ad scan --domain secura.yzx --dc-ip 192.168.216.97 --username Eric.Wallows --mode full

# start from a specific compromised principal
corvid-ad scan --domain secura.yzx --dc-ip 192.168.216.97 --username Eric.Wallows --start michael

# offline, from a prior snapshot
corvid-ad analyze -i reports/snapshot.json --start Eric.Wallows
```

`--start` accepts a `sAMAccountName`, DN or SID.

## Edge types

Each edge means "if you control the *from* node, you can compromise the *to* node":

| Edge | Meaning | MITRE |
|---|---|---|
| `MemberOf` | membership grants the group's privileges | T1078 |
| `GenericAll` | full control: reset password / add-to-group / write DACL | T1484 |
| `GenericWrite` | write attributes (add SPN → Kerberoast) | T1098 |
| `WriteDacl` | modify DACL → grant self full control | T1484 |
| `WriteOwner` | take ownership → then WriteDacl | T1484 |
| `ForceChangePassword` | reset the target's password and log in | T1098 |
| `DCSync` | replicate secrets — dump all hashes incl. krbtgt | T1003.006 |
| `AddSelf` | add self to the group (Self-Membership) | T1098 |
| `Owns` | owner can WriteDacl on the object | T1484 |
| `Kerberoastable` | request TGS and crack offline | T1558.003 |
| `ASREPRoastable` | request AS-REP and crack offline | T1558.004 |
| `ConstrainedDelegation` | control host → impersonate to target | T1558.001 |
| `RBCD` | control allowed-to-act account → impersonate on host | T1558.001 |
| `UnconstrainedDelegation` | control host → capture TGTs (incl. DC) | T1558.001 |

## High-value targets

- Domain Admins, Enterprise Admins, Schema Admins
- Domain Controllers group + domain-controller computers
- Administrators (RID 544)
- `krbtgt` (golden ticket) and `Administrator`
- Any principal holding `DCSync` on the domain

## Important caveats

- **Paths are hypotheses**, not proof. Connectivity implies a candidate
  escalation; actual exploitability depends on password strength, patch level,
  and pre-existing control of intermediate nodes.
- **Read-only scope**: corvid-ad only sees what LDAP exposes. It does **not** model
  `AdminTo` (local admin on a machine), `HasSession` (interactive sessions) or
  `CanRDP/CanPSRemote` — those require per-host collection (SharpHound-style),
  which is out of scope for a read-only LDAP scanner.
- `RBCD` / `UnconstrainedDelegation` are recorded as node flags; the precise
  allowed-to-act SID is not parsed from the security descriptor yet.
