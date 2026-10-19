# Detection Coverage Matrix

Maps Active Directory attack techniques to the corvid-ad modules/checks that
detect their *prerequisites* or *configurations*. corvid-ad detects
**configuration exposure** — it does not exploit, dump secrets, or forge
tickets.

Legend:
- ✅ Implemented (detected from LDAP-observable data)
- 🟡 Partial (indicator only; requires host-level / manual verification)
- ⬜ Not applicable (out of read-only LDAP scope)

| Attack technique | Module | Detection | Status |
|---|---|---|---|
| **Kerberoasting** | `domain_recon` | User accounts with `servicePrincipalName` | ✅ |
| **AS-REP Roasting** | `credentials` | `DONT_REQUIRE_PREAUTH` (UAC 0x400000) | ✅ |
| **Password spraying (prereq)** | `domain_recon` | Password policy (lockout threshold), `PASSWD_NOTREQD` | 🟡 |
| **Reversible encryption** | `credentials` | `ENCRYPTED_TEXT_PASSWORD_ALLOWED` (UAC 0x80) | ✅ |
| **Password never expires** | `credentials` | `DONT_EXPIRE_PASSWD` (UAC 0x10000) | ✅ |
| **GPP cpassword** | `gpo` | GPO presence + SYSVOL manual check | 🟡 |
| **LAPS exposure** | `credentials` | (`ms-Mcs-AdmPwd` read rights — requires targeted query) | 🟡 |
| **gMSA exposure** | `credentials` | (`msDS-ManagedPassword` read rights — targeted query) | 🟡 |
| **GenericAll / GenericWrite** | `acl` | DACL scan of users/groups/computers/GPOs/OUs | ✅ |
| **WriteDacl / WriteOwner** | `acl` | DACL scan | ✅ |
| **ForceChangePassword** | `acl` | `User-Force-Change-Password` extended right | ✅ |
| **AddMember (self)** | `acl` | `Self-Membership` validated-write right | ✅ |
| **DCSync** | `privesc` | `GetChanges`/`GetChangesAll` on domain root | ✅ |
| **AdminSDHolder** | `persistence` | manual check + reminder | 🟡 |
| **Unconstrained delegation** | `delegation` | `TRUSTED_FOR_DELEGATION` (UAC 0x80000) | ✅ |
| **Constrained delegation** | `delegation` | `msDS-AllowedToDelegateTo` | ✅ |
| **RBCD** | `delegation` | `msDS-AllowedToActOnBehalfOfOtherIdentity` | ✅ |
| **MachineAccountQuota** | `vulnerabilities` | `ms-DS-MachineAccountQuota` | ✅ |
| **AD CS ESC1** | `adcs` | ENROLLEE_SUPPLIES_SUBJECT + Client Auth EKU + enrollable | ✅ |
| **AD CS ESC2** | `adcs` | Any Purpose / no EKU + enrollee-supplied subject | ✅ |
| **AD CS ESC3** | `adcs` | Enrollment-agent template enrollable | ✅ |
| **AD CS ESC4** | `adcs` | Writable template ACL | ✅ |
| **AD CS ESC5** | `adcs` | Dangerous CA ACL | ✅ |
| **AD CS ESC6** | `adcs` | CA registry flag (manual) | 🟡 |
| **AD CS ESC7** | `adcs` | ManageCA / ManageCertificates | ✅ |
| **AD CS ESC8** | `adcs` | Web enrollment (manual HTTP check) | 🟡 |
| **NTLM relay** | `network` | SMB signing / LLMNR prerequisites (manual) | 🟡 |
| **Golden Ticket (prereq)** | `persistence` | krbtgt account presence | ✅ |
| **Silver Ticket (prereq)** | `domain_recon` | Service accounts with SPNs | ✅ |
| **SIDHistory abuse** | `persistence` | manual / targeted query | 🟡 |
| **GPO abuse** | `gpo` | Writable GPO ACLs | ✅ |
| **ZeroLogon (CVE-2020-1472)** | `vulnerabilities` | DC OS version indicator | 🟡 |
| **PrintNightmare (CVE-2021-34527)** | `vulnerabilities` | host service check (manual) | 🟡 |
| **sAMAccountName spoofing** | `vulnerabilities` | MachineAccountQuota | 🟡 |
| **PetitPotam / PrinterBug** | `vulnerabilities` | RPC/MS-EFSR probe (manual) | 🟡 |
| **MSSQL / linked servers** | `infrastructure` | `MSSQLSvc` SPN detection | ✅ |
| **Exchange / SCCM / WSUS / ADFS** | `infrastructure` | SPN/host indicators | 🟡 |
| **Obsolete OS** | `domain_recon` | `operatingSystem` attribute | ✅ |
| **Stale accounts** | `domain_recon` | `lastLogonTimestamp` | ✅ |
| **Domain trusts** | `domain_recon` | `trustedDomain` objects | ✅ |
| **Privileged group members** | `domain_recon` | RID 512/518/519/544/1101 membership | ✅ |
| **DNSAdmins** | `domain_recon` | RID 1101 group membership | ✅ |
