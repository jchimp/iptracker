import threading
from collections import defaultdict
from datetime import datetime, timedelta

from flask import (Blueprint, render_template, request,
                   redirect, url_for, flash, jsonify, Response)
from flask_login import login_required
from sqlalchemy import func

from extensions import db
from models import Network, Host, Device, PingResult, ScanRun
from zoneinfo import ZoneInfo
from .scanner import scan_network, ping_host
from oui import vendor_for_mac

_DENVER = ZoneInfo('America/Denver')


def _fmt_denver(dt):
    """Format a naive-UTC datetime as a Denver-local string."""
    if not dt:
        return '—'
    from datetime import timezone
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(_DENVER).strftime('%Y-%m-%d %H:%M')

ping_bp = Blueprint('ping', __name__, template_folder='../../templates')

PING_TIMEOUT = 1
MAX_WORKERS = 64
HISTORY_DAYS = 90


@ping_bp.route('/')
@login_required
def index():
    net = Network.query.order_by(Network.name).first()
    if not net:
        return redirect(url_for('networks.list_networks'))
    return redirect(url_for('ping.dashboard', network_id=net.id))


@ping_bp.route('/networks/<int:network_id>')
@login_required
def dashboard(network_id):
    net = Network.query.get_or_404(network_id)
    networks = Network.query.order_by(Network.name).all()

    online_only = request.args.get('online') == '1'

    hosts = sorted(net.hosts.all(), key=lambda h: _ip_sort_key(h.ip))

    latest_ping = _latest_ping_map(network_id)

    if online_only:
        hosts = [h for h in hosts if latest_ping.get(h.id) and latest_ping[h.id].is_up]

    sparklines = _compute_sparklines(network_id)
    first_seen, last_seen = _first_last_seen(network_id)

    online_count = sum(1 for h in net.hosts.all()
                       if latest_ping.get(h.id) and latest_ping[h.id].is_up)
    total_count = net.hosts.count()

    last_run = (ScanRun.query
                .filter_by(network_id=network_id, type='ping')
                .order_by(ScanRun.started_at.desc())
                .first())
    running_run = (ScanRun.query
                   .filter_by(network_id=network_id, type='ping', status='running')
                   .first())

    return render_template('ping/dashboard.html',
                           network=net,
                           networks=networks,
                           hosts=hosts,
                           latest_ping=latest_ping,
                           sparklines=sparklines,
                           first_seen=first_seen,
                           last_seen=last_seen,
                           online_count=online_count,
                           total_count=total_count,
                           online_only=online_only,
                           last_run=last_run,
                           running_run=running_run)


@ping_bp.route('/networks/<int:network_id>/scan', methods=['POST'])
@login_required
def start_scan(network_id):
    net = Network.query.get_or_404(network_id)

    running = ScanRun.query.filter_by(
        network_id=network_id, type='ping', status='running').first()
    if running:
        return jsonify(ok=False, error='Scan already running',
                       scan_run_id=running.id), 409

    scan_run = ScanRun(network_id=network_id, type='ping', status='running')
    db.session.add(scan_run)
    db.session.commit()

    from flask import current_app
    app = current_app._get_current_object()
    t = threading.Thread(target=_run_ping_scan,
                         args=(app, scan_run.id, network_id, net.cidr),
                         daemon=True)
    t.start()

    return jsonify(ok=True, scan_run_id=scan_run.id)


@ping_bp.route('/networks/<int:network_id>/scan/<int:run_id>/status')
@login_required
def scan_status(network_id, run_id):
    run = ScanRun.query.get_or_404(run_id)
    return jsonify(
        status=run.status,
        host_count=run.host_count,
        up_count=run.up_count,
        error_msg=run.error_msg,
        finished_at=run.finished_at.isoformat() if run.finished_at else None,
    )


@ping_bp.route('/networks/<int:network_id>/host-note', methods=['POST'])
@login_required
def host_note(network_id):
    body = request.get_json(silent=True) or {}
    host = Host.query.get(body.get('host_id'))
    if not host or host.network_id != network_id:
        return jsonify(ok=False, error='not found'), 404
    host.notes = body.get('note', '')
    db.session.commit()
    return jsonify(ok=True)


@ping_bp.route('/networks/<int:network_id>/host-reserved', methods=['POST'])
@login_required
def host_reserved(network_id):
    body = request.get_json(silent=True) or {}
    host = Host.query.get(body.get('host_id'))
    if not host or host.network_id != network_id:
        return jsonify(ok=False, error='not found'), 404
    host.is_reserved = bool(body.get('reserved', False))
    db.session.commit()
    return jsonify(ok=True, reserved=host.is_reserved)


@ping_bp.route('/networks/<int:network_id>/host/<int:host_id>/ping-single', methods=['POST'])
@login_required
def host_ping_single(network_id, host_id):
    host = Host.query.get_or_404(host_id)
    result = ping_host(host.ip)
    now = datetime.utcnow()
    run = ScanRun(network_id=network_id, type='ping', status='complete',
                  started_at=now, finished_at=now,
                  host_count=1, up_count=1 if result['is_up'] else 0)
    db.session.add(run)
    db.session.flush()
    pr = PingResult(host_id=host.id, scan_run_id=run.id, scanned_at=now,
                    is_up=result['is_up'], response_ms=result['response_ms'])
    db.session.add(pr)
    if result['hostname'] and not host.hostname:
        host.hostname = result['hostname']
    mac = result.get('mac_address', '')
    if mac and not host.mac_address:
        host.mac_address = mac
        host.mac_vendor = vendor_for_mac(mac)
    db.session.commit()
    # Fetch the latest up-ping for last_seen after commit
    last_up = (PingResult.query
               .filter_by(host_id=host.id, is_up=True)
               .order_by(PingResult.scanned_at.desc())
               .first())
    return jsonify(
        ok=True,
        is_up=result['is_up'],
        response_ms=result['response_ms'],
        scanned_at_fmt=_fmt_denver(now),
        last_seen_fmt=_fmt_denver(last_up.scanned_at) if last_up else '—',
    )


@ping_bp.route('/networks/<int:network_id>/export.csv')
@login_required
def export_csv(network_id):
    net = Network.query.get_or_404(network_id)
    hosts = sorted(net.hosts.all(), key=lambda h: _ip_sort_key(h.ip))
    latest_ping = _latest_ping_map(network_id)
    first_seen, last_seen = _first_last_seen(network_id)

    def _c(v):
        return (str(v) if v is not None else '').replace(',', '').replace('\n', ' ')

    def generate():
        yield 'ip,hostname,is_up,response_ms,first_seen,last_seen,reserved,notes\n'
        for h in hosts:
            pr = latest_ping.get(h.id)
            yield ','.join([
                _c(h.ip), _c(h.hostname),
                _c(pr.is_up if pr else ''),
                _c(pr.response_ms if pr else ''),
                _fmt_denver(first_seen.get(h.id)),
                _fmt_denver(last_seen.get(h.id)),
                _c(h.is_reserved),
                _c(h.notes),
            ]) + '\n'

    return Response(generate(), mimetype='text/csv',
                    headers={'Content-Disposition':
                             f'attachment; filename=ping_{net.name}.csv'})


# ── background scan ──────────────────────────────────────────────

def _run_ping_scan(app, scan_run_id, network_id, cidr):
    with app.app_context():
        run = ScanRun.query.get(scan_run_id)
        try:
            results = scan_network(cidr, workers=MAX_WORKERS, timeout=PING_TIMEOUT)

            now = datetime.utcnow()
            up_count = 0

            for r in results:
                ip = r['ip']
                is_up = r['is_up']
                hostname = r.get('hostname', '')

                mac = r.get('mac_address', '')

                # Upsert Host — created for ALL IPs (up or down)
                host = Host.query.filter_by(network_id=network_id, ip=ip).first()
                if not host:
                    host = Host(network_id=network_id, ip=ip, hostname=hostname)
                    db.session.add(host)
                    db.session.flush()
                else:
                    if is_up and hostname and not host.hostname:
                        host.hostname = hostname
                if mac and not host.mac_address:
                    host.mac_address = mac
                    host.mac_vendor = vendor_for_mac(mac)

                # Append ping result for every host
                pr = PingResult(
                    host_id=host.id,
                    scan_run_id=scan_run_id,
                    scanned_at=now,
                    is_up=is_up,
                    response_ms=r.get('response_ms'),
                )
                db.session.add(pr)

                if is_up:
                    up_count += 1
                    # Auto-promote to Device on first successful ping
                    if not host.device:
                        dev = Device(
                            host_id=host.id,
                            network_id=network_id,
                            name=hostname or ip,
                        )
                        db.session.add(dev)

            # Prune ping history older than 90 days
            cutoff = now - timedelta(days=HISTORY_DAYS)
            host_id_subq = (
                db.session.query(Host.id)
                .filter(Host.network_id == network_id)
                .scalar_subquery()
            )
            (db.session.query(PingResult)
             .filter(PingResult.host_id.in_(host_id_subq),
                     PingResult.scanned_at < cutoff)
             .delete(synchronize_session='fetch'))

            run.status = 'complete'
            run.host_count = len(results)
            run.up_count = up_count
            run.finished_at = datetime.utcnow()
            db.session.commit()

        except Exception as exc:
            db.session.rollback()
            run = ScanRun.query.get(scan_run_id)
            if run:
                run.status = 'error'
                run.error_msg = str(exc)[:500]
                run.finished_at = datetime.utcnow()
                db.session.commit()


# ── helpers ──────────────────────────────────────────────────────

def _ip_sort_key(ip_str):
    import ipaddress
    try:
        return ipaddress.ip_address(ip_str)
    except Exception:
        return ipaddress.ip_address('255.255.255.255')


def _latest_ping_map(network_id):
    """dict of host_id -> latest PingResult for a network."""
    subq = (db.session.query(
        PingResult.host_id,
        func.max(PingResult.scanned_at).label('latest')
    ).join(Host, Host.id == PingResult.host_id)
     .filter(Host.network_id == network_id)
     .group_by(PingResult.host_id).subquery())

    rows = (db.session.query(PingResult)
            .join(subq, (PingResult.host_id == subq.c.host_id) &
                        (PingResult.scanned_at == subq.c.latest))
            .all())
    return {r.host_id: r for r in rows}


def _compute_sparklines(network_id):
    """
    dict of host_id -> list of 24 values (float 0-1 or None).
    Index 0 = 23 hours ago, index 23 = current hour.
    """
    now = datetime.utcnow()
    cutoff = now - timedelta(hours=24)

    rows = (db.session.query(
        PingResult.host_id,
        PingResult.scanned_at,
        PingResult.is_up
    ).join(Host, Host.id == PingResult.host_id)
     .filter(Host.network_id == network_id, PingResult.scanned_at >= cutoff)
     .all())

    buckets = defaultdict(lambda: [[] for _ in range(24)])
    for host_id, scanned_at, is_up in rows:
        age_hours = int((now - scanned_at).total_seconds() / 3600)
        slot = 23 - min(age_hours, 23)
        buckets[host_id][slot].append(is_up)

    return {
        hid: [(sum(s) / len(s) if s else None) for s in slots]
        for hid, slots in buckets.items()
    }


def _first_last_seen(network_id):
    """(first_seen_map, last_seen_map) — host_id -> datetime for is_up=True pings."""
    rows_first = (db.session.query(
        PingResult.host_id,
        func.min(PingResult.scanned_at).label('first_seen')
    ).join(Host, Host.id == PingResult.host_id)
     .filter(Host.network_id == network_id, PingResult.is_up == True)
     .group_by(PingResult.host_id).all())

    rows_last = (db.session.query(
        PingResult.host_id,
        func.max(PingResult.scanned_at).label('last_seen')
    ).join(Host, Host.id == PingResult.host_id)
     .filter(Host.network_id == network_id, PingResult.is_up == True)
     .group_by(PingResult.host_id).all())

    return (
        {r.host_id: r.first_seen for r in rows_first},
        {r.host_id: r.last_seen for r in rows_last},
    )
