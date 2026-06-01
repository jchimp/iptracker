"""
nmap-based port scanner. Parses XML output into structured dicts.
"""
import os
import shutil
import subprocess
import xml.etree.ElementTree as ET


def find_nmap() -> str | None:
    if shutil.which('nmap'):
        return 'nmap'
    windows_path = r'C:\Program Files (x86)\Nmap\nmap.exe'
    if os.path.exists(windows_path):
        return windows_path
    windows_path2 = r'C:\Program Files\Nmap\nmap.exe'
    if os.path.exists(windows_path2):
        return windows_path2
    return None


PROFILES = {
    'quick': {
        'label': 'Quick (host discovery only)',
        'args': ['-n', '-T4', '-sn'],
    },
    'standard': {
        'label': 'Standard (top 100 ports + services)',
        'args': ['-n', '-T4', '--top-ports', '100', '-sV'],
    },
    'full': {
        'label': 'Full (top 1000 ports + services + OS detect*)',
        'args': ['-n', '-T4', '--top-ports', '1000', '-sV', '-O', '--osscan-guess'],
    },
}


def scan_network(cidr: str, profile: str = 'standard', timeout: int = 300) -> list[dict]:
    """
    Run nmap against cidr with the selected profile.

    Returns list of host dicts:
      {
        'ip': str,
        'hostname': str,
        'state': 'up'|'down',
        'ports': [{'port': int, 'protocol': str, 'state': str,
                   'service': str, 'product': str, 'version': str}]
      }

    Raises RuntimeError if nmap is not found or exits non-zero.
    """
    nmap = find_nmap()
    if not nmap:
        raise RuntimeError(
            'nmap not found. Install it or add it to PATH.'
        )

    profile_cfg = PROFILES.get(profile, PROFILES['standard'])
    cmd = [nmap] + profile_cfg['args'] + ['-oX', '-', cidr]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f'nmap timed out after {timeout}s')

    if result.returncode != 0:
        raise RuntimeError(f'nmap exited {result.returncode}: {result.stderr[:500]}')

    return _parse_xml(result.stdout)


def _parse_xml(xml_data: str) -> list[dict]:
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as exc:
        raise RuntimeError(f'Failed to parse nmap XML: {exc}') from exc

    hosts = []
    for host_el in root.findall('host'):
        status_el = host_el.find('status')
        state = status_el.get('state', 'down') if status_el is not None else 'down'

        ip = None
        mac_address = ''
        mac_vendor = ''
        for addr_el in host_el.findall('address'):
            atype = addr_el.get('addrtype', '')
            if atype == 'ipv4':
                ip = addr_el.get('addr')
            elif atype == 'mac':
                mac_address = addr_el.get('addr', '').upper().replace('-', ':')
                mac_vendor = addr_el.get('vendor', '')
        if not ip:
            continue

        hostname = ''
        hostnames_el = host_el.find('hostnames')
        if hostnames_el is not None:
            for hn_el in hostnames_el.findall('hostname'):
                hostname = hn_el.get('name', '')
                break

        # OS detection (only present with -O flag and sufficient privileges)
        os_name = ''
        os_el = host_el.find('os')
        if os_el is not None:
            best = None
            for match_el in os_el.findall('osmatch'):
                acc = int(match_el.get('accuracy', 0))
                if best is None or acc > best[0]:
                    best = (acc, match_el.get('name', ''))
            if best:
                os_name = best[1]

        ports = []
        if state == 'up':
            ports_el = host_el.find('ports')
            if ports_el is not None:
                for port_el in ports_el.findall('port'):
                    state_el = port_el.find('state')
                    if state_el is None or state_el.get('state') != 'open':
                        continue
                    svc = port_el.find('service')
                    ports.append({
                        'port': int(port_el.get('portid', 0)),
                        'protocol': port_el.get('protocol', 'tcp'),
                        'state': 'open',
                        'service': svc.get('name', '') if svc is not None else '',
                        'product': svc.get('product', '') if svc is not None else '',
                        'version': svc.get('version', '') if svc is not None else '',
                    })

        hosts.append({
            'ip': ip,
            'hostname': hostname,
            'state': state,
            'ports': ports,
            'mac_address': mac_address,
            'mac_vendor': mac_vendor,
            'os_name': os_name,
        })

    return hosts
