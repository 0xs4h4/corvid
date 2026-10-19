"""corvid_ad command-line interface."""

from __future__ import annotations

import argparse
import datetime as dt
import getpass
import json
import os
import re
import sys
from pathlib import Path

from . import __version__
from .core.config import ScanOptions, load_config
from .core.context import ScanContext
from .core.logger import get_logger, setup_logging
from .core.scanner import resolve_modules, run_modules, update_stats
from .graph.engine import build_graph
from .reporting import csv_report, html_report, json_report, rich_dashboard
from .utils.serialize import load_snapshot, save_snapshot

log = get_logger("cli")


def _password_from(args: argparse.Namespace) -> str:
    if args.password:
        return args.password
    if args.hashes:
        return ""
    env = os.environ.get("CORVID_AD_PASSWORD")
    if env:
        return env
    if args.no_password:
        return ""
    if sys.stdin.isatty():
        return getpass.getpass("Password: ")
    return ""


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="corvid-ad",
        description="Read-only Active Directory attack-surface & exploitability scanner.",
    )
    p.add_argument("--version", action="version", version=f"corvid-ad {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    # --- scan ---
    sp = sub.add_parser("scan", help="Perform a live LDAP scan of a domain.")
    sp.add_argument("--domain", help="Target domain (FQDN or NETBIOS).")
    sp.add_argument("--dc-ip", help="Domain controller IP (overrides DNS).")
    sp.add_argument("--username", help="Authenticated username (user, DOMAIN\\user, or user@domain).")
    sp.add_argument("--password", help="Password (prefer CORVID_AD_PASSWORD or interactive prompt).")
    sp.add_argument("--hashes", help="LMHASH:NTHASH for pass-the-hash (not stored/logged).")
    sp.add_argument("--mode", choices=["quick", "full", "focused"], default="quick")
    sp.add_argument("--modules", help="Comma-separated module names (with --mode focused).")
    sp.add_argument("--output", "-o", default="corvid-ad-output", help="Output directory.")
    sp.add_argument("--use-ssl", action="store_true", help="Use LDAPS (port 636).")
    sp.add_argument("--no-password", action="store_true", help="No password (anonymous / env-provided).")
    sp.add_argument("--config", help="Path to YAML config file.")
    sp.add_argument("--no-dashboard", action="store_true", help="Skip the Rich terminal dashboard.")
    sp.add_argument("--start", help="Principal to start attack-path search from (sAMAccountName/DN/SID).")
    sp.add_argument("--active", action="store_true", help="Active layer: check local-admin + dump SAM/LSA on --hosts.")
    sp.add_argument("--hosts", help="Comma-separated target hosts (IPs/hostnames) for --active.")
    sp.set_defaults(func=cmd_scan)

    # --- analyze ---
    ap = sub.add_parser("analyze", help="Analyze previously collected data (offline).")
    ap.add_argument("--input", "-i", required=True, help="Directory or snapshot JSON from a prior scan.")
    ap.add_argument("--mode", choices=["quick", "full"], default="full")
    ap.add_argument("--modules", help="Comma-separated module names (optional).")
    ap.add_argument("--output", "-o", default="corvid-ad-output", help="Output directory.")
    ap.add_argument("--start", help="Principal to start attack-path search from (sAMAccountName/DN/SID).")
    ap.set_defaults(func=cmd_analyze)

    # --- report ---
    rp = sub.add_parser("report", help="Generate reports from a results.json file.")
    rp.add_argument("--input", "-i", required=True, help="Path to results.json.")
    rp.add_argument("--format", choices=["html", "json", "csv"], default="html")
    rp.add_argument("--output", "-o", default="corvid-ad-output", help="Output directory.")
    rp.set_defaults(func=cmd_report)

    # --- checks ---
    cp = sub.add_parser("checks", help="List detection modules/checks.")
    cp.add_argument("--list", action="store_true", help="List all modules.")
    cp.set_defaults(func=cmd_checks)

    # --- doctor ---
    dp = sub.add_parser("doctor", help="Check the environment and dependencies.")
    dp.set_defaults(func=cmd_doctor)

    return p


def _selected_modules(args: argparse.Namespace) -> list[str]:
    if args.modules:
        return [m.strip() for m in args.modules.split(",") if m.strip()]
    return []


def _graph_principal(username: str) -> str:
    """Normalize 'DOMAIN\\user' / 'user@domain' to the bare sAMAccountName."""
    u = username.replace("\\", "/").split("/")[-1]
    return u.split("@")[0]


def _run_active(args: argparse.Namespace, opts, password: str, graph):
    """Run the active layer (admin check + SAM/LSA dump) and fold it into the graph."""
    if not args.hosts:
        print("[-] --active requires --hosts (comma-separated IPs/hostnames).", file=sys.stderr)
        return None
    from .collectors.active_collector import ActiveCollector

    hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
    collector = ActiveCollector(
        username=opts.username, password=password, domain=opts.domain, hashes=opts.hashes
    )
    print(f"\n[*] Active layer: checking admin access on {len(hosts)} host(s)...")
    result = collector.run(hosts)
    graph.add_active(result, _graph_principal(opts.username))
    return result


def _create_run_dir(base: Path, prefix: str = "corvid-ad") -> Path:
    """Create <prefix>-YYYYMMDD-N under base, incrementing past existing runs."""
    base.mkdir(parents=True, exist_ok=True)
    date = dt.datetime.now().strftime("%Y%m%d")
    pattern = re.compile(rf"^{prefix}-{date}-(\d+)$")
    highest = 0
    for entry in base.iterdir():
        match = pattern.fullmatch(entry.name)
        if match:
            highest = max(highest, int(match.group(1)))
    iteration = highest + 1
    while True:
        folder = base / f"{prefix}-{date}-{iteration}"
        try:
            folder.mkdir()
            return folder
        except FileExistsError:
            iteration += 1


def cmd_scan(args: argparse.Namespace) -> int:
    setup_logging()
    # Ensure all modules are registered before resolving.
    from . import modules as _modules  # noqa: F401

    cfg = load_config(args.config)
    password = _password_from(args)
    opts = ScanOptions(
        domain=args.domain or "",
        dc_ip=args.dc_ip,
        username=args.username or "",
        password=password,
        hashes=args.hashes,
        mode=args.mode,
        modules=_selected_modules(args),
        output_dir=args.output,
        use_ssl=args.use_ssl,
        no_password=args.no_password,
    )

    ctx = ScanContext(domain=opts.domain, mode=opts.mode, source="live")

    from .collectors.ldap_collector import LDAPCollector

    try:
        collector = LDAPCollector(opts, cfg)
        data = collector.collect(ctx)
    except Exception as exc:  # noqa: BLE001
        log.error("collection failed: %s", exc)
        print(f"\n[-] Collection failed: {exc}", file=sys.stderr)
        print("[!] Nothing was collected — aborting (no findings were produced on empty data).", file=sys.stderr)
        print("[!] Check: --dc-ip (DNS may not resolve the domain), reachability, and credentials.", file=sys.stderr)
        return 1
    update_stats(ctx, data)

    modules = resolve_modules(opts.mode, opts.modules)
    run_modules(ctx, modules)
    ctx.deduplicate()

    graph = build_graph(ctx)

    active_result = None
    if args.active:
        active_result = _run_active(args, opts, password, graph)
        if active_result is None:
            return 1
        paths = graph.find_paths(start=_graph_principal(opts.username))
    else:
        paths = graph.find_paths(start=getattr(args, "start", None))

    out = _create_run_dir(Path(opts.output_dir))
    json_report.write_json(ctx, out, graph, paths, active_result)
    csv_report.write_csv(ctx, out)
    html_report.write_html(ctx, out, graph, paths)
    save_snapshot(data, out / "snapshot.json")
    if not args.no_dashboard:
        rich_dashboard.render_dashboard(ctx, graph, paths, active_result)

    print(f"\n[+] Scan complete. {len(ctx.findings)} findings. Reports written to {out.resolve()}")
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    setup_logging()
    from . import modules as _modules  # noqa: F401

    inp = Path(args.input)
    if inp.is_dir():
        snapshot = inp / "snapshot.json"
    else:
        snapshot = inp
    if not snapshot.exists():
        print(f"[-] snapshot not found: {snapshot}", file=sys.stderr)
        return 1

    data = load_snapshot(snapshot)
    ctx = ScanContext(domain=data.domain.name, mode=args.mode, source="offline")
    ctx.data = data
    update_stats(ctx, data)

    modules = resolve_modules(args.mode, _selected_modules(args))
    run_modules(ctx, modules)
    ctx.deduplicate()

    graph = build_graph(ctx)
    paths = graph.find_paths(start=getattr(args, "start", None))

    out = Path(args.output)
    json_report.write_json(ctx, out, graph, paths)
    csv_report.write_csv(ctx, out)
    html_report.write_html(ctx, out, graph, paths)
    rich_dashboard.render_dashboard(ctx, graph, paths)

    print(f"\n[+] Offline analysis complete. {len(ctx.findings)} findings. Reports in {out.resolve()}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    inp = Path(args.input)
    if not inp.exists():
        print(f"[-] results.json not found: {inp}", file=sys.stderr)
        return 1
    report = json.loads(inp.read_text(encoding="utf-8"))
    ctx = ScanContext(domain=report.get("metadata", {}).get("domain", ""), source="report")
    # rehydrate findings minimally for re-render
    from .core.finding import Confidence, Finding, Severity, ValidationStatus, Category

    for f in report.get("findings", []):
        try:
            ctx.findings.append(Finding(
                title=f.get("title", ""), module=f.get("module", ""),
                category=Category(f.get("category", "domain_reconnaissance")),
                severity=Severity(f.get("severity", "info")),
                confidence=Confidence(f.get("confidence", "low")),
                status=ValidationStatus(f.get("status", "detected")),
                affected_principal=f.get("affected_principal"),
                affected_object=f.get("affected_object"),
                evidence=f.get("evidence", {}), impact=f.get("impact", ""),
                prerequisites=f.get("prerequisites", []),
                remediation=f.get("remediation", []),
                references=f.get("references", []),
                mitre_attack=f.get("mitre_attack", []),
            ))
        except (ValueError, KeyError):
            continue

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    if args.format == "html":
        html_report.write_html(ctx, out, None, report.get("attack_paths", []))
    elif args.format == "json":
        (out / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    elif args.format == "csv":
        csv_report.write_csv(ctx, out)
    print(f"[+] Report written to {out.resolve()}")
    return 0


def cmd_checks(args: argparse.Namespace) -> int:
    from .modules.base import all_modules

    registry = all_modules()
    print(f"{'module':<16} {'quick':<6} {'description'}")
    print("-" * 80)
    for name, cls in sorted(registry.items()):
        print(f"{name:<16} {'yes' if cls.quick else 'no':<6} {cls.description}")
    print(f"\n{len(registry)} modules registered.")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    print("corvid-ad environment check")
    print("-" * 40)
    print(f"Python: {sys.version.split()[0]}")
    deps = ["ldap3", "networkx", "rich", "jinja2", "yaml"]
    for d in deps:
        try:
            __import__(d)
            print(f"  [ok] {d}")
        except ImportError:
            print(f"  [MISSING] {d}")
    print("Platform:", sys.platform)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
