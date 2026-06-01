# iptracker

A self-hosted network inventory and monitoring tool. Track hosts across subnets with ICMP ping sweeps, nmap port discovery, hardware fingerprinting via OUI lookup, and a persistent device inventory — all from a browser UI.

---

## Features

| Area | What it does |
|---|---|
| **Ping** | Multi-threaded ICMP sweep of any CIDR range; sparkline history per host; online-only filter; inline notes |
| **Discovery** | nmap port scans (quick / standard / full profiles); tracks open port changes between runs; OS detection |
| **Devices** | Auto-created inventory record for every host that responds; name, type, URL, notes, favorites |
| **Networks** | CIDR-based grouping with optional VLAN tag; per-network ping and discovery dashboards |
| **Hardware info** | MAC address from ARP cache (ping) or nmap XML (discovery); OUI vendor lookup via bundled database |
| **Tools** | OUI Lookup and CIDR Calculator utilities |
| **Export** | CSV export from Ping and Discovery dashboards; timestamps in configured timezone |
| **Auth** | Username/password login via Flask-Login; CLI user management |
| **Themes** | Dark / light mode toggle, persisted per browser |

---

## Requirements

| Dependency | Notes |
|---|---|
| Python 3.12+ | Earlier 3.x may work but is untested |
| nmap | Required for Discovery scans; optional for Ping-only use |
| ping / ICMP | Standard OS `ping` binary; container needs `NET_RAW` capability |

Python packages are in `requirements.txt` — Flask 3, Flask-SQLAlchemy, Flask-Login, Gunicorn, mac-vendor-lookup.

---

## Quick Start — Docker (recommended)

```bash
# 1. Copy and edit the env file
cp .env.example .env
#    Set SECRET_KEY and IPTRACKER_PORT as needed

# 2. Start
docker compose up -d

# 3. Create your first user
docker exec -it iptracker flask --app app.py create-user admin

# 4. Open the UI
#    http://localhost:8080  (or whatever IPTRACKER_PORT is set to)
```

The SQLite database is stored in `./data/iptracker.db` on the host (bind-mounted volume).

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | `change-me-to-a-random-string` | Flask session signing key — **change this in production** |
| `IPTRACKER_PORT` | `8080` | Host port the UI is exposed on |
| `DATABASE_URL` | `sqlite:////app/data/iptracker.db` | SQLAlchemy connection string |
| `TZ` | `America/Denver` | Timezone for all displayed timestamps |
| `PING_TIMEOUT` | `1` | Seconds per ICMP ping attempt |
| `MAX_WORKERS` | `64` | Concurrent ping threads |

Generate a strong secret key:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

---

## Quick Start — Local Development

```bash
# 1. Create and activate a virtual environment
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Create the database
py -m flask --app app.py create-db

# 4. Create a user
py -m flask --app app.py create-user admin

# 5. Run the dev server
python app.py
#    Open: http://localhost:8005
```

---

## CLI Reference

All commands run via `flask --app app.py <command>` (or `py -m flask --app app.py <command>` on Windows).

| Command | Description |
|---|---|
| `create-db` | Create all database tables (safe to re-run; does not drop existing data) |
| `create-user <username>` | Create a new login account (prompts for password) |
| `list-users` | List all accounts and their status |
| `set-password <username>` | Reset a user's password |

---

## nmap Setup

Discovery scans require nmap to be installed and accessible.

**Linux / Docker:** nmap is included in the Docker image (`apt-get install nmap`). The container runs as root so all profiles work without extra setup.

**Windows (local dev):**
1. Download and install from https://nmap.org/download.html
2. The app checks `C:\Program Files (x86)\Nmap\nmap.exe` and `C:\Program Files\Nmap\nmap.exe` automatically, so no PATH change is needed.

**OS detection (Full profile):** The Full scan profile uses `nmap -O --osscan-guess`, which requires elevated privileges — root on Linux, Administrator on Windows. OS detection is optional; the scan will complete and return port data either way.

### Scan profiles

| Profile | nmap flags | Use when |
|---|---|---|
| Quick | `-sn -T4` | Just want to know which hosts are alive; no ports |
| Standard | `--top-ports 100 -sV -T4` | Normal everyday scan |
| Full | `--top-ports 1000 -sV -O --osscan-guess -T4` | Deep audit; requires admin/root for OS detect |

---

## MAC Address & Vendor Lookup

**Ping scans** query the local ARP cache after each successful ping. This only returns a MAC address for hosts on the **same local subnet** as the machine running iptracker. Hosts across a router will not have a MAC.

**Discovery scans** get MAC addresses directly from nmap's XML output. This also uses ARP internally so the same subnet limitation applies, but nmap populates the ARP cache during the scan.

**OUI lookup** is handled by the `mac-vendor-lookup` package, which bundles the full IEEE OUI database locally. No network call is made after installation.

---

## Schema Changes

The database schema is managed with SQLAlchemy's `db.create_all()` — there are no migration files. When a model change adds or removes columns, drop the database and recreate it:

```bash
# Back up first if you have data to keep
copy data\iptracker.db data\iptracker.db.bak

# Windows
del data\iptracker.db

# Recreate
py -m flask --app app.py create-db
py -m flask --app app.py create-user admin
```

---

## Project Structure

```
iptracker/
├── app.py                    # App factory, CLI commands, template filters
├── extensions.py             # db and login_manager singletons
├── models.py                 # SQLAlchemy models (Network, Host, Device, ScanRun, ...)
├── oui.py                    # Lazy singleton wrapper for mac-vendor-lookup
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .env.example
│
├── blueprints/
│   ├── auth/                 # Login / logout
│   ├── overview/             # Dashboard summary
│   ├── networks/             # Network CRUD and detail view
│   ├── ping/                 # ICMP sweep, history, CSV export
│   ├── discovery/            # nmap scans, port diff, CSV export
│   ├── devices/              # Device inventory
│   └── tools/                # OUI lookup, CIDR calculator
│
├── templates/
│   ├── base.html             # Navbar, theme toggle, makeResizable, makeTableSortable
│   ├── overview/
│   ├── networks/
│   ├── ping/
│   ├── discovery/
│   ├── devices/
│   ├── tools/
│   └── auth/
│
├── static/
│   └── style.css
│
└── data/
    └── iptracker.db          # SQLite database (git-ignored)
```

---

## Data Model

```
Network  ──< Host  ──< PingResult
                   ──< PortScan
                   ──  Device (1:1, optional)

ScanRun  ──< PingResult
         ──< PortScan
```

- **Network** — a CIDR range (e.g. `192.168.1.0/24`), optional VLAN ID
- **Host** — one row per IP per network; stores MAC, vendor, OS name, hostname, notes
- **Device** — optional inventory record linked 1:1 to a Host; stores name, type, URL, notes, favorite flag
- **ScanRun** — a log of each ping or discovery scan; status, timing, counts
- **PingResult** — append-only per-host ping outcome; powers sparklines and last-seen tracking
- **PortScan** — one row per open port per host per discovery scan; enables new/closed port diff

---

## Timezone

All timestamps are stored in UTC. The `fmt_dt` template filter converts to the configured `TZ` timezone for display. Change `TZ` in `.env` (or `docker-compose.yml`) to match your location — no data change needed.

---

## Tips

- **Large subnets:** Networks larger than `/20` (4,094+ hosts) will generate very large amounts of scan data and slow scans considerably. The UI warns you when adding a network that exceeds this threshold.
- **Ping accuracy:** The concurrent ping sweep uses the OS `ping` binary. On Windows, ICMP responses may be filtered by the host firewall even if the host is online — check with a manual ping if you see unexpected down results.
- **Port diff:** The Discovery page highlights ports that are **new** (green) or **closed** (red) since the previous scan of that host. This makes it easy to spot unexpected service changes.
- **Reserved IPs:** Mark any IP as Reserved (lock icon on the Ping page) to exclude it from the Up/Down count — useful for gateway addresses, printers, etc. that you do not actively monitor.
