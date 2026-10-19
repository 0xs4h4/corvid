#!/usr/bin/env python3
"""Two-pass TCP discovery for all targets, then service detection; text report."""
import argparse
import copy
import datetime as dt
import ipaddress
import os
import re
import time
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

from . import __version__

TARGET_COLORS = (39, 213, 220, 118, 75, 203, 177, 81)


def color_enabled():
    return sys.stdout.isatty() and 'NO_COLOR' not in os.environ


def target_color_map(records):
    return {record['target']: TARGET_COLORS[index % len(TARGET_COLORS)]
            for index, record in enumerate(records)}


def color_text(value, color, enabled=True):
    if not enabled or color is None:
        return value
    return f'\033[38;5;{color}m{value}\033[0m'


def parse_scan(path):
    root = ET.parse(path).getroot()
    finished = root.find('runstats/finished')
    if finished is None or finished.get('exit') != 'success':
        raise ValueError('Nmap XML does not indicate successful completion')
    hosts = root.findall('host')
    ports = []
    for host in hosts:
        for port in host.findall('ports/port'):
            state = port.find('state')
            if state is None:
                continue
            service = port.find('service')
            ports.append({
                'port': int(port.get('portid')), 'protocol': port.get('protocol'),
                'state': state.get('state'), 'reason': state.get('reason', ''),
                'service': dict(service.attrib) if service is not None else {},
                'cpe': [c.text or '' for c in service.findall('cpe')] if service is not None else [],
                'scripts': [ET.tostring(s, encoding='unicode') for s in port.findall('script')],
            })
    return root, ports


def run_scan(command, base):
    # No shell: targets and paths remain literal arguments.
    with Path(str(base) + '.console.txt').open('w') as output:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, errors='replace')
        try:
            for line in process.stdout:
                output.write(line)
            code = process.wait()
        except BaseException:
            print('\n  Scan interrupted; output retained.', flush=True)
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            raise
    if code:
        raise RuntimeError(f'Nmap exited with status {code}; see {base.name}.console.txt')
    root, ports = parse_scan(Path(str(base) + '.xml'))
    return {'command': shlex.join(command), 'base': base.name, 'root': root, 'ports': ports}


def cached_scan(base, target):
    root, ports = parse_scan(Path(str(base) + '.xml'))
    addresses = {a.get('addr') for a in root.findall('host/address')}
    if target not in addresses:
        raise ValueError(f'Cached XML does not contain expected target {target}')
    return {'command': root.get('args', '(original command unavailable)'),
            'base': base.name, 'root': root, 'ports': ports}


def run_group_scan(nmap, targets, ports, scan_flags, output_base, console_path, colors):
    """Run one Nmap process across a same-family target group; keep per-host results."""
    target_file = Path(str(output_base) + '.targets.txt')
    target_file.write_text('\n'.join(targets) + '\n')
    command = [nmap, *scan_flags]
    if ipaddress.ip_address(targets[0]).version == 6:
        command.append('-6')
    command += ports + ['-oA', str(output_base), '-iL', str(target_file)]
    with console_path.open('w') as output:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, errors='replace')
        try:
            for line in process.stdout:
                output.write(line)
                output.flush()
            code = process.wait()
        except BaseException:
            print('\n  Scan interrupted; output retained.', flush=True)
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            raise
    if code:
        raise RuntimeError(f'Nmap exited with status {code}; see {console_path.name}')

    root = ET.parse(Path(str(output_base) + '.xml')).getroot()
    finished = root.find('runstats/finished')
    if finished is None or finished.get('exit') != 'success':
        raise ValueError('Nmap XML does not indicate successful completion')
    scaninfo = root.findall('scaninfo')
    by_target = {}
    for host in root.findall('host'):
        addresses = {node.get('addr') for node in host.findall('address')}
        target = next((candidate for candidate in targets if candidate in addresses), None)
        if target is None:
            continue
        host_root = ET.Element('nmaprun', root.attrib)
        host_root.extend(copy.deepcopy(node) for node in scaninfo)
        host_root.append(copy.deepcopy(host))
        runstats = root.find('runstats')
        if runstats is not None:
            host_root.append(copy.deepcopy(runstats))
        ports_found = []
        for port in host.findall('ports/port'):
            state = port.find('state')
            if state is None:
                continue
            service = port.find('service')
            ports_found.append({
                'port': int(port.get('portid')), 'protocol': port.get('protocol'),
                'state': state.get('state'), 'reason': state.get('reason', ''),
                'service': dict(service.attrib) if service is not None else {},
                'cpe': [c.text or '' for c in service.findall('cpe')] if service is not None else [],
                'scripts': [ET.tostring(s, encoding='unicode') for s in port.findall('script')],
            })
        by_target[target] = {
            'command': shlex.join(command), 'base': output_base.name,
            'root': host_root, 'ports': ports_found,
        }
    return by_target, scaninfo


def render_completion_status(records):
    lines = [f'{"TARGET":<18} {"TCP FULL PORTS":<22} SERVICE / VERSION']
    lines.append('-' * 78)
    for record in records:
        tcp = record.get('tcp_status', 'Queued')
        service = record.get('service_status', 'Waiting')
        lines.append(f'{record["target"]:<18} {tcp:<22} {service}')
    return '\n'.join(lines)


def render_terminal_summary(records, colored=False):
    lines = ['', '=== RECON SUMMARY · TCP ===',
             f'{"TARGET":<18} {"PORT":<12} {"STATE":<12} SERVICE / VERSION',
             '-' * 96]
    colors = target_color_map(records) if colored else {}
    for index, record in enumerate(records):
        if index:
            lines.append('-' * 96)
        target_cell = f'{record["target"]:<18}'
        target_cell = color_text(target_cell, colors.get(record['target']), colored)
        found = []
        for label, scan in record.get('scans', []):
            if label == 'Service detection':
                found.extend(p for p in scan['ports']
                             if p['protocol'] == 'tcp' and p['state'] == 'open')
        if not found:
            detail = record.get('error') or ('No open TCP ports reported'
                                             if not record.get('open_ports')
                                             else 'Service detection unavailable')
            lines.append(f'{target_cell} {"—":<12} {"—":<12} {detail}')
            continue
        for port in sorted(found, key=lambda p: p['port']):
            service = port['service']
            label = ' '.join(service.get(k, '') for k in
                             ('name', 'product', 'version', 'extrainfo')).strip()
            lines.append(f'{target_cell} {"TCP/" + str(port["port"]):<12} '
                         f'{port["state"]:<12} {label or "unknown"}')
    return '\n'.join(lines) + '\n'


def print_completion_status(records, colors=None):
    print('\nCompletion Status :', flush=True)
    if not color_enabled() or not colors:
        print(render_completion_status(records), flush=True)
        return
    print(f'{"TARGET":<18} {"TCP FULL PORTS":<22} SERVICE / VERSION')
    print('-' * 78)
    for record in records:
        target = color_text(f'{record["target"]:<18}', colors.get(record['target']))
        print(f'{target} {record.get("tcp_status", "Queued"):<22} '
              f'{record.get("service_status", "Waiting")}')


def print_terminal_summary(records):
    print(render_terminal_summary(records, colored=color_enabled()), end='', flush=True)


def write_text_report(path, records, started, duration):
    targets = ', '.join(record['target'] for record in records)
    content = [
        f'Starting to scan {len(records)} Targets : {targets}',
        '',
        'Completion Status :',
        render_completion_status(records),
        f'Started: {started}',
        render_terminal_summary(records),
        f'Report save to : {path.resolve()}',
        f'Total Scan : {duration}',
    ]
    path.write_text('\n'.join(content), encoding='utf-8')


def create_run_folder(output, date=None):
    """Create recon-YYYYMMDD-N, incrementing safely if a run already exists."""
    output.mkdir(parents=True, exist_ok=True)
    date = date or dt.datetime.now().strftime('%Y%m%d')
    pattern = re.compile(rf'^recon-{re.escape(date)}-(\d+)$')
    highest = 0
    for entry in output.iterdir():
        match = pattern.fullmatch(entry.name)
        if match:
            highest = max(highest, int(match.group(1)))
    iteration = highest + 1
    while True:
        folder = output / f'recon-{date}-{iteration}'
        try:
            folder.mkdir()
            return folder
        except FileExistsError:
            iteration += 1


def run_grouped_scans(records, folder, nmap, timing, connect, started):
    """Use one adaptive Nmap process per address family and phase."""
    grouped = {}
    for record in records:
        version = ipaddress.ip_address(record['target']).version
        grouped.setdefault(version, []).append(record)
    failed = False
    interrupted = False
    scan_type = '-sT' if connect else '-sS'
    colors = target_color_map(records)

    for version, group in grouped.items():
        targets = [record['target'] for record in group]
        family_name = 'ipv4' if version == 4 else 'ipv6'
        for record in group:
            record['status'] = 'TCP discovery running'
            record['tcp_status'] = 'Running'
            record['service_status'] = 'Waiting'
        output_base = folder / f'all-{family_name}-tcp'
        try:
            scans, scaninfo = run_group_scan(
                nmap, targets, ['-p-'],
                [scan_type, '-Pn', '-n', '-T' + timing, '-v', '--reason', '--stats-every', '2s'],
                output_base, folder / f'{output_base.name}.console.txt', colors)
            coverage = next((s for s in scaninfo if s.get('protocol') == 'tcp'), None)
            if coverage is None or coverage.get('numservices') != '65535':
                raise ValueError('Nmap XML does not confirm full TCP coverage (1–65535)')
            for record in group:
                scan = scans.get(record['target'])
                if scan is None:
                    record['status'] = 'Failed — target missing from Nmap XML'
                    record['error'] = 'Nmap output did not include this target'
                    record['tcp_status'] = 'Failed'
                    record['service_status'] = 'Not run'
                    failed = True
                    continue
                record['scans'].append(('Full TCP discovery', scan))
                record['open_ports'] = sorted({p['port'] for p in scan['ports']
                                               if p['protocol'] == 'tcp' and p['state'] == 'open'})
                record['status'] = ('Ports ready — awaiting service detection'
                                    if record['open_ports'] else
                                    'Complete — no open TCP ports reported')
                record['tcp_status'] = 'Complete'
                record['service_status'] = ('Queued' if record['open_ports']
                                            else 'Not needed (no open TCP ports)')
        except KeyboardInterrupt:
            interrupted = failed = True
            for record in group:
                if record['status'] == 'TCP discovery running':
                    record['status'] = 'Interrupted'
                    record['tcp_status'] = 'Interrupted'
                    record['service_status'] = 'Not run'
            break
        except (OSError, RuntimeError, ValueError, ET.ParseError) as exc:
            failed = True
            for record in group:
                record['status'] = 'Failed — review retained output'
                record['error'] = str(exc)
                record['tcp_status'] = 'Failed'
                record['service_status'] = 'Not run'

    if not interrupted:
        for version, group in grouped.items():
            eligible = [record for record in group if record.get('open_ports') and not record.get('error')]
            if not eligible:
                continue
            targets = [record['target'] for record in eligible]
            port_union = sorted({port for record in eligible for port in record['open_ports']})
            family_name = 'ipv4' if version == 4 else 'ipv6'
            for record in eligible:
                record['status'] = 'Service detection running'
                record['service_status'] = 'Running'
            output_base = folder / f'all-{family_name}-services'
            try:
                scans, _ = run_group_scan(
                    nmap, targets, ['-sC', '-sV', '-p', ','.join(map(str, port_union))],
                    [scan_type, '-Pn', '-n', '-T' + timing, '-v', '--reason', '--stats-every', '2s'],
                    output_base, folder / f'{output_base.name}.console.txt', colors)
                for record in eligible:
                    scan = scans.get(record['target'])
                    if scan is None:
                        raise ValueError(f'Nmap service output omitted {record["target"]}')
                    scanned = {p['port'] for p in scan['ports'] if p['protocol'] == 'tcp'}
                    if not set(record['open_ports']).issubset(scanned):
                        raise ValueError(f'Service output for {record["target"]} omitted a discovered open port')
                    record['scans'].append(('Service detection', scan))
                    record['status'] = 'Complete'
                    record['service_status'] = 'Complete'
            except KeyboardInterrupt:
                interrupted = failed = True
                for record in eligible:
                    if record['status'] == 'Service detection running':
                        record['status'] = 'Interrupted'
                        record['service_status'] = 'Interrupted'
                break
            except (OSError, RuntimeError, ValueError, ET.ParseError) as exc:
                failed = True
                for record in eligible:
                    record['status'] = 'Failed — review retained output'
                    record['error'] = str(exc)
                    record['service_status'] = 'Failed'
    return failed, interrupted


def run_resumed_scans(records, folder, started, nmap, args):
    """Retain the existing per-host resume format for previously created runs."""
    failed = interrupted = False
    for stage in ('discovery', 'services'):
        for record in records:
            if stage == 'services' and (record.get('error') or not record.get('open_ports')):
                continue
            ip = record['target']
            common = [nmap, '-sT' if args.connect else '-sS', '-Pn', '-n',
                      '-T' + args.timing, '-v', '--reason', '--stats-every', '2s']
            if ipaddress.ip_address(ip).version == 6:
                common.append('-6')
            try:
                if stage == 'discovery':
                    record['status'] = 'TCP discovery running'
                    base = folder / (ip.replace(':', '_') + '-tcp')
                    if Path(str(base) + '.xml').exists():
                        scan = cached_scan(base, ip)
                        coverage = scan['root'].find("scaninfo[@protocol='tcp']")
                        if coverage is None or coverage.get('numservices') != '65535':
                            raise ValueError('Cached TCP scan does not confirm full 65535-port coverage')
                    else:
                        scan = run_scan(common + ['-p-', '-oA', str(base), ip], base)
                    record['scans'].append(('Full TCP discovery', scan))
                    record['open_ports'] = sorted({p['port'] for p in scan['ports']
                                                   if p['protocol'] == 'tcp' and p['state'] == 'open'})
                    record['status'] = 'Ports ready — awaiting service detection' if record['open_ports'] else 'Complete — no open TCP ports reported'
                    record['tcp_status'] = 'Complete'
                    record['service_status'] = ('Queued' if record['open_ports']
                                                else 'Not needed (no open TCP ports)')
                else:
                    ports = record['open_ports']
                    record['status'] = 'Service detection running'
                    base = folder / (ip.replace(':', '_') + '-services')
                    if Path(str(base) + '.xml').exists():
                        scan = cached_scan(base, ip)
                        scanned = {p['port'] for p in scan['ports'] if p['protocol'] == 'tcp'}
                        if not set(ports).issubset(scanned):
                            raise ValueError('Cached service scan does not include all discovered open ports')
                    else:
                        scan = run_scan(common + ['-sC', '-sV', '-p', ','.join(map(str, ports)),
                                                   '-oA', str(base), ip], base)
                    record['scans'].append(('Service detection', scan))
                    record['status'] = 'Complete'
                    record['service_status'] = 'Complete'
            except KeyboardInterrupt:
                record['status'] = 'Interrupted'
                record['tcp_status' if stage == 'discovery' else 'service_status'] = 'Interrupted'
                failed = interrupted = True
            except (OSError, RuntimeError, ValueError, ET.ParseError) as exc:
                record['status'] = 'Failed — review retained output'
                record['error'] = str(exc)
                record['tcp_status' if stage == 'discovery' else 'service_status'] = 'Failed'
                failed = True
            if interrupted:
                break
        if interrupted:
            break
    return failed, interrupted


def main():
    run_started = time.monotonic()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', action='version',
                        version=f'corvid-sweep {__version__}')
    parser.add_argument('-i', '--targets', type=Path, default=Path('targets.txt'))
    parser.add_argument('-o', '--output', type=Path,
                        default=Path('output'))
    parser.add_argument('--timing', choices=['3', '4'], default='4')
    parser.add_argument('--connect', action='store_true', help='TCP connect scan instead of privileged SYN scan')
    parser.add_argument('--resume', type=Path, help='Reuse completed scans in an existing run directory')
    args = parser.parse_args()
    nmap = shutil.which('nmap')
    if not nmap:
        parser.error('nmap is not installed or not on PATH')
    if not args.connect and os.geteuid() != 0:
        parser.error('SYN scans require sudo; alternatively use --connect')
    try:
        targets = []
        for line in args.targets.read_text().splitlines():
            value = line.split('#', 1)[0].strip()
            if value:
                ip = str(ipaddress.ip_address(value))
                if ip not in targets:
                    targets.append(ip)
        if not targets:
            raise ValueError('target list is empty')
    except (OSError, ValueError) as exc:
        parser.error(f'Invalid target list: {exc}. Use one explicit IP per line (no CIDRs or hostnames).')
    started = dt.datetime.now().astimezone().isoformat(timespec='seconds')
    if args.resume:
        folder = args.resume
        if not folder.is_dir():
            parser.error('--resume must point to an existing run directory')
        previous = folder / 'report.txt'
        if previous.exists():
            shutil.copy2(previous, folder / ('report-before-resume-' + dt.datetime.now().strftime('%Y%m%d-%H%M%S-%f') + '.txt'))
    else:
        folder = create_run_folder(args.output)
    records = [{'target': ip, 'status': 'Pending', 'tcp_status': 'Queued',
                'service_status': 'Waiting', 'scans': []} for ip in targets]
    colors = target_color_map(records)
    target_labels = ', '.join(color_text(ip, colors[ip], color_enabled()) for ip in targets)
    print(f'Starting to scan {len(records)} Targets : {target_labels}', flush=True)
    print('Completion Status :', flush=True)
    if args.resume:
        failed, interrupted = run_resumed_scans(records, folder, started, nmap, args)
    else:
        failed, interrupted = run_grouped_scans(records, folder, nmap, args.timing,
                                                args.connect, started)
    print_completion_status(records, colors)
    print_terminal_summary(records)
    elapsed = int(time.monotonic() - run_started)
    minutes, seconds = divmod(elapsed, 60)
    duration = f'{minutes} min {seconds} sec'
    report_path = folder / 'report.txt'
    write_text_report(report_path, records, started, duration)
    print(f'Report save to : {report_path.resolve()}')
    print(f'Total Scan : {duration}')
    return 130 if interrupted else (1 if failed else 0)


if __name__ == '__main__':
    sys.exit(main())
