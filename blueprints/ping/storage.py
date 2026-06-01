import json
import os
import tempfile
from threading import Lock
from datetime import datetime, timezone

_lock = Lock()


def utcnow_iso():
    """Return current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def ensure_dirs(data_dir: str):
    """Create the data directory and results sub-directory."""
    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(os.path.join(data_dir, "results"), exist_ok=True)


def atomic_write_json(path: str, data: dict):
    """Write JSON atomically (temp-file then rename)."""
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    with _lock:
        fd, tmp_path = tempfile.mkstemp(prefix=".tmp_", dir=d)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, sort_keys=True)
            os.replace(tmp_path, path)
        finally:
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except OSError:
                pass


def read_json(path: str, default: dict):
    """Read a JSON file or return *default* if it doesn't exist."""
    with _lock:
        if not os.path.exists(path):
            return default
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)


def networks_path(data_dir: str) -> str:
    return os.path.join(data_dir, "networks.json")


def results_path(data_dir: str, network_id: str) -> str:
    return os.path.join(data_dir, "results", f"{network_id}.json")
