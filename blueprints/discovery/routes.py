import threading
import ipaddress
from datetime import datetime

from flask import (Blueprint, render_template, request,
                   redirect, url_for, flash, jsonify, Response)
from flask_login import login_required

from extensions import db
from models import Network, Host, Device, ScanRun, PortScan
from .scanner import scan_network, find_nmap, PROFILES
from oui import vendor_for_mac

discovery_bp = Blueprint('discovery', __name__, template_folder='../../templates')


@discovery_bp.route('/')
@login_required
def index():
    net = Network.query.order_by(Network.name).first()
    if not net:
        return redirect(url_for('networks.list_networks'))
    return redirect(url_for('discovery.dashboard', network_id=net.id))


@discovery_bp.route('/networks/<int:network_id>')
@login_required
def dashboard(network_id):
    net = Network.query.get_or_404(network_id)
    networks = Network.query.order_by(Network.name).all()

    nmap_path = find_nmap()

    latest_run = (ScanRun.query
                  .filter_by(network_id=network_id, type='discovery', status='complete')
                  .order_by(ScanRun.finished_at.desc())
                  .first())
    prev_run = None
    if latest_run:
        prev_run = (ScanRun.query
                    .filter_by(network_id=network_id, type='discovery', status='complete')
                    .filter(ScanRun.id < latest_run.id)
                    .order_by(ScanRun.finished_at.desc())
                    .first())

    running_run = (ScanRun.query
                   .filter_by(network_id=network_id, type='discovery', status='running')
                   .first())

    host_rows = []
    if latest_run:
        # Hosts that had open ports in the latest run
        hosts_with_ports = (
            db.session.query(Host)
            .join(PortScan, PortScan.host_id == Host.id)
            .filter(PortScan.scan_run_id == latest_run.id,
                    Host.network_id == network_id)
            .distinct()
            .all()
        )
        hosts_with_ports.sort(key=lambda h: _ip_sort_key(h.ip))

        seen_ids = {h.id for h in hosts_with_ports}

        for host in hosts_with_ports:
            ports = (PortScan.query
                     .filter_by(host_id=host.id, scan_run_id=latest_run.id)
                     .order_by(PortScan.port)
                     .all())

            new_ports = set()
            closed_ports = set()
            if prev_run:
                prev_port_set = {(p.port, p.protocol) for p in
                                 PortScan.query.filter_by(host_id=host.id,
                                                          scan_run_id=prev_run.id).all()}
                curr_port_set = {(p.port, p.protocol) for p in ports}
                new_ports = curr_port_set - prev_port_set
                closed_ports = prev_port_set - curr_port_set

            host_rows.append({
                'host': host,
                'ports': ports,
                'new_ports': new_ports,
                'closed_ports': closed_ports,
            })

    return render_template('discovery/discovery_dashboard.html',
                           network=net,
                           networks=networks,
                           profiles=PROFILES,
                           nmap_path=nmap_path,
                           latest_run=latest_run,
                           prev_run=prev_run,
                           running_run=running_run,
                           host_rows=host_rows)


@discovery_bp.route('/networks/<int:network_id>/scan', methods=['POST'])
@login_required
def start_scan(network_id):
    net = Network.query.get_or_404(network_id)

    running = ScanRun.query.filter_by(
        network_id=network_id, type='discovery', status='running').first()
    if running:
        return jsonify(ok=False, error='Scan already running',
                       scan_run_id=running.id), 409

    profile = request.form.get('profile', 'standard')
    if profile not in PROFILES:
        profile = 'standard'

    scan_run = ScanRun(network_id=network_id, type='discovery', status='running')
    db.session.add(scan_run)
    db.session.commit()

    from flask import current_app
    app = current_app._get_current_object()
    t = threading.Thread(target=_run_discovery_scan,
                         args=(app, scan_run.id, network_id, net.cidr, profile),
                         daemon=True)
    t.start()

    return jsonify(ok=True, scan_run_id=scan_run.id)


@discovery_bp.route('/networks/<int:network_id>/host/<int:host_id>/scan-single', methods=['POST'])
@login_required
def host_scan_single(network_id, host_id):
    host = Host.query.get_or_404(host_id)

    nmap_path = find_nmap()
    if not nmap_path:
        return jsonify(ok=False, error='nmap not found'), 400

    data = request.get_json(silent=True) or {}
    profile = data.get('profile', 'quick')
    if profile not in PROFILES:
        profile = 'quick'

    run = ScanRun(network_id=network_id, type='discovery', status='running',
                  host_count=0, up_count=0)
    db.session.add(run)
    db.session.commit()

    from flask import current_app
    app = current_app._get_current_object()
    t = threading.Thread(
        target=_run_discovery_scan,
        args=(app, run.id, network_id, host.ip + '/32', profile),
        daemon=True
    )
    t.start()

    return jsonify(ok=True, scan_run_id=run.id)


@discovery_bp.route('/networks/<int:network_id>/scan/<int:run_id>/status')
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


@discovery_bp.route('/networks/<int:network_id>/export.csv')
@login_required
def export_csv(network_id):
    net = Network.query.get_or_404(network_id)
    latest_run = (ScanRun.query
                  .filter_by(network_id=network_id, type='discovery', status='complete')
                  .order_by(ScanRun.finished_at.desc())
                  .first())

    def _e(v):
        v = str(v or '').replace('"', '""')
        return f'"{v}"'

    # Materialise everything before streaming to avoid session-detach issues
    hosts = sorted(net.hosts.all(), key=lambda h: _ip_sort_key(h.ip))
    rows = ['ip,hostname,mac_address,mac_vendor,os_name,open_ports,services\n']
    for host in hosts:
        ports = (PortScan.query
                 .filter_by(host_id=host.id, scan_run_id=latest_run.id)
                 .all()) if latest_run else []
        services = '; '.join(
            f'{p.port}/{p.protocol} {p.service}'.strip() for p in ports)
        rows.append(','.join([
            _e(host.ip), _e(host.hostname),
            _e(host.mac_address), _e(host.mac_vendor), _e(host.os_name),
            _e(len(ports) if ports else ''), _e(services),
        ]) + '\n')

    return Response(''.join(rows), mimetype='text/csv',
                    headers={'Content-Disposition':
                             f'attachment; filename=discovery_{net.name}.csv'})


# ── background scan ──────────────────────────────────────────────

def _run_discovery_scan(app, scan_run_id, network_id, cidr, profile):
    with app.app_context():
        run = ScanRun.query.get(scan_run_id)
        try:
            scan_hosts = scan_network(cidr, profile=profile)

            now = datetime.utcnow()
            up_count = 0

            for h in scan_hosts:
                if h['state'] != 'up' or not h['ports']:
                    continue

                ip = h['ip']
                hostname = h.get('hostname', '')
                mac = h.get('mac_address', '')
                mac_vendor = h.get('mac_vendor', '') or (vendor_for_mac(mac) if mac else '')
                os_name = h.get('os_name', '')

                # Upsert Host
                host = Host.query.filter_by(network_id=network_id, ip=ip).first()
                if not host:
                    host = Host(network_id=network_id, ip=ip, hostname=hostname)
                    db.session.add(host)
                    db.session.flush()
                else:
                    if hostname and not host.hostname:
                        host.hostname = hostname
                if mac and not host.mac_address:
                    host.mac_address = mac
                    host.mac_vendor = mac_vendor
                if os_name and not host.os_name:
                    host.os_name = os_name

                # Auto-promote to Device if not already one
                if not host.device:
                    dev = Device(
                        host_id=host.id,
                        network_id=network_id,
                        name=hostname or ip,
                    )
                    db.session.add(dev)

                for p in h['ports']:
                    ps = PortScan(
                        host_id=host.id,
                        scan_run_id=scan_run_id,
                        scanned_at=now,
                        port=p['port'],
                        protocol=p.get('protocol', 'tcp'),
                        state=p.get('state', 'open'),
                        service=p.get('service', ''),
                        product=p.get('product', ''),
                        version=p.get('version', ''),
                    )
                    db.session.add(ps)

                up_count += 1

            run.status = 'complete'
            run.host_count = len(scan_hosts)
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


def _ip_sort_key(ip_str):
    try:
        return ipaddress.ip_address(ip_str)
    except Exception:
        return ipaddress.ip_address('255.255.255.255')
