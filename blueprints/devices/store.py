import os
import json
import uuid
import time
import ipaddress
import contextlib
from datetime import datetime, timezone
import threading

DATA_DIR = os.environ.get("DATA_DIR", "./data")
DEVICES_FILE = os.path.join(DATA_DIR, "devices.json")
NETWORKS_FILE = os.path.join(DATA_DIR, "networks.json")

DEFAULT_TYPES = ["Switch", "Router", "AP", "Server", "Client", "Host"]

_devices_lock = threading.Lock()


# ── helpers ─────────────────────────────────────────────────────
def _utcnow_iso():
    return datetime.now(timezone.utc).isoformat()



# ── file lock (simple threading) ──────────────────────────────────
@contextlib.contextmanager
def devices_file_lock(timeout=30):
    acquired = _devices_lock.acquire(timeout=timeout)
    if not acquired:
        raise TimeoutError("Timed out waiting for devices lock")
    try:
        yield
    finally:
        _devices_lock.release()

"""
# ── file lock (cross-platform) ──────────────────────────────────
@contextlib.contextmanager
def devices_file_lock(timeout=30):
    """ """Serialize all read-modify-write on devices.json.""" """
    os.makedirs(os.path.dirname(DEVICES_FILE) or ".", exist_ok=True)
    start = time.time()
    fh = None

    while True:
        try:
            fh = open(LOCK_FILE, "w")
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except Exception:
            if fh:
                try:
                    fh.close()
                except Exception:
                    pass
                fh = None
            if time.time() - start > timeout:
                raise TimeoutError("Timed out waiting for devices.json lock")
            time.sleep(0.05)

    try:
        yield
    finally:
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass
        finally:
            try:
                fh.close()
            except Exception:
                pass
"""

# ── networks (read-only from this module) ───────────────────────
def load_networks():
    if not os.path.exists(NETWORKS_FILE):
        return {"networks": []}
    try:
        with open(NETWORKS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"networks": []}


def assign_network_id(ip):
    if not ip:
        return None
    try:
        ip_obj = ipaddress.ip_address(ip)
    except Exception:
        return None
    for n in load_networks().get("networks", []):
        try:
            if ip_obj in ipaddress.ip_network(n.get("cidr", ""), strict=False):
                return n["id"]
        except Exception:
            continue
    return None


# ── devices file I/O ────────────────────────────────────────────
def load_devices():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(DEVICES_FILE):
        return {"devices": [], "types": list(DEFAULT_TYPES)}
    try:
        with open(DEVICES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {"devices": [], "types": list(DEFAULT_TYPES)}
    data.setdefault("devices", [])
    data.setdefault("types", list(DEFAULT_TYPES))
    return data

def save_devices(data):
    data.setdefault("devices", [])
    data.setdefault("types", list(DEFAULT_TYPES))
    os.makedirs(os.path.dirname(DEVICES_FILE) or ".", exist_ok=True)

    if os.name == "nt":
        # Windows: write directly (os.replace fails if any handle is open)
        with open(DEVICES_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    else:
        # Linux/Mac: atomic write via tmp + rename
        tmp = DEVICES_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, DEVICES_FILE)


def _find_idx(devices, network_id, ip):
    for i, d in enumerate(devices):
        if d.get("network_id") == network_id and d.get("ip") == ip:
            return i
    return -1


# ── in-memory device ensure (NO file I/O) ──────────────────────
def _ensure_device(devices, network_id, ip, hostname=""):
    """Find or create a device in the given list. NO file read/write.

    Returns (dev, is_new).
    """
    idx = _find_idx(devices, network_id, ip)

    if idx >= 0:
        dev = devices[idx]
        # ✅ NEVER reset — only ensure keys exist
        dev.setdefault("ping", {})
        dev.setdefault("discovery", {})
        dev.setdefault("notes", "")
        dev.setdefault("detailed_notes", "")
        dev.setdefault("favorite", False)
        dev.setdefault("type", "")
        dev.setdefault("url", "")
        # hostname enrichment only if we learned something new
        if hostname and not dev.get("hostname"):
            dev["hostname"] = hostname
        if hostname and dev.get("name") in ("", dev.get("ip")):
            dev["name"] = hostname
        return dev, False
    else:
        dev = {
            "id": uuid.uuid4().hex[:10],
            "network_id": network_id,
            "ip": ip,
            "hostname": hostname or "",
            "name": hostname or ip,
            "url": "",
            "type": "",
            "notes": "",
            "detailed_notes": "",
            "favorite": False,
            "created_at": _utcnow_iso(),
            "ping": {},
            "discovery": {},
        }
        devices.append(dev)
        return dev, True


# ── public: upsert device (for resolve endpoint, manual use) ───
def upsert_device(network_id, ip, hostname=""):
    """Find or create device. ONE load-save cycle."""
    with devices_file_lock():
        data = load_devices()
        dev, _ = _ensure_device(data["devices"], network_id, ip, hostname)
        dev["updated_at"] = _utcnow_iso()
        save_devices(data)
        return dev


# ── public: ping enrichment ────────────────────────────────────
def upsert_ping_observation(network_id, ip, hostname, ping_rec):
    """Merge ping results into device.ping. ONE load-save cycle."""
    with devices_file_lock():
        data = load_devices()
        dev, _ = _ensure_device(data["devices"], network_id, ip, hostname)

        pb = dev["ping"]  # guaranteed to exist by _ensure_device

        # Always set scan time
        pb["last_scan_at"] = ping_rec.get("last_scan_at") or _utcnow_iso()

        # Status
        pb["last_up"] = bool(ping_rec.get("last_scan_up"))

        # Reserved + notes from ping record
        pb["reserved"] = bool(ping_rec.get("reserved", False))
        pb["notes"] = ping_rec.get("notes") or ""

        # First seen (set once, never overwrite)
        if ping_rec.get("first_seen") and not pb.get("first_seen"):
            pb["first_seen"] = ping_rec["first_seen"]

        # Last seen (update every time host is up)
        if ping_rec.get("last_seen"):
            pb["last_seen"] = ping_rec["last_seen"]

        # Hostname enrichment
        if hostname and not dev.get("hostname"):
            dev["hostname"] = hostname
        if hostname and dev.get("name") in ("", dev.get("ip")):
            dev["name"] = hostname

        dev["updated_at"] = _utcnow_iso()
        save_devices(data)
        return dev


# ── public: discovery enrichment ────────────────────────────────
def upsert_discovery_observation(network_id, host, completed_at=""):
    """Merge discovery results into device.discovery. ONE load-save cycle."""
    ip = host.get("ip")
    if not ip:
        return {}
    hostname = host.get("hostname") or ""

    with devices_file_lock():
        data = load_devices()
        dev, _ = _ensure_device(data["devices"], network_id, ip, hostname)

        db = dev["discovery"]  # guaranteed to exist by _ensure_device

        db["last_scan"] = completed_at or _utcnow_iso()
        db["state"] = host.get("state")
        db["open_ports"] = host.get("open_ports", 0)
        db["services"] = host.get("services", []) or []
        db["ports"] = host.get("ports", []) or []

        # Hostname enrichment
        if hostname and not dev.get("hostname"):
            dev["hostname"] = hostname
        if hostname and dev.get("name") in ("", dev.get("ip")):
            dev["name"] = hostname

        dev["updated_at"] = _utcnow_iso()
        save_devices(data)
        return dev
