"""
Ping scanner: multi-threaded ICMP ping sweep with reverse DNS and ARP-based MAC lookup.
"""
import ipaddress
import platform
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

IS_WINDOWS = platform.system().lower() == 'windows'
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0


def get_mac_address(ip: str) -> str:
    """
    Query the local ARP cache for the MAC of a host.
    Only works for hosts on the same local subnet; returns '' otherwise.
    Call after ping_host() so the ARP entry is populated.
    """
    try:
        if IS_WINDOWS:
            result = subprocess.run(
                ['arp', '-a', ip], capture_output=True, text=True,
                timeout=3, creationflags=CREATE_NO_WINDOW,
            )
        else:
            result = subprocess.run(
                ['arp', '-n', ip], capture_output=True, text=True, timeout=3,
            )
        m = re.search(r'([\da-fA-F]{2}[:\-]){5}[\da-fA-F]{2}', result.stdout)
        if m:
            return m.group(0).replace('-', ':').upper()
    except Exception:
        pass
    return ''


def ping_host(ip: str, timeout: int = 1) -> dict:
    """
    Ping a single host. Returns:
      {'ip', 'is_up', 'response_ms', 'hostname', 'mac_address'}
    mac_address is '' for hosts not on the same local subnet.
    """
    if IS_WINDOWS:
        cmd = ['ping', '-n', '1', '-w', str(timeout * 1000), ip]
    else:
        cmd = ['ping', '-c', '1', '-W', str(timeout), ip]

    t0 = time.monotonic()
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout + 2,
            creationflags=CREATE_NO_WINDOW,
        )
        elapsed_ms = (time.monotonic() - t0) * 1000
        is_up = result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        is_up = False
        elapsed_ms = None

    hostname = ''
    mac = ''
    if is_up:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass
        mac = get_mac_address(ip)

    return {
        'ip': ip,
        'is_up': is_up,
        'response_ms': round(elapsed_ms, 2) if (is_up and elapsed_ms is not None) else None,
        'hostname': hostname,
        'mac_address': mac,
    }


def scan_network(cidr: str, workers: int = 64, timeout: int = 1) -> list:
    """
    Scan all hosts in a CIDR range. Returns list of ping_host() dicts.
    """
    network = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(ip) for ip in network.hosts()]
    if not hosts:
        return []

    results = []
    with ThreadPoolExecutor(max_workers=min(workers, len(hosts))) as executor:
        futures = {executor.submit(ping_host, ip, timeout): ip for ip in hosts}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                results.append(future.result())
            except Exception:
                results.append({'ip': ip, 'is_up': False,
                                 'response_ms': None, 'hostname': ''})

    results.sort(key=lambda r: ipaddress.ip_address(r['ip']))
    return results
