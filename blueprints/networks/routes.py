import ipaddress
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required
from sqlalchemy import func
from extensions import db
from models import Network, Host, Device, ScanRun, PingResult, PortScan

networks_bp = Blueprint('networks', __name__, template_folder='../../templates')


@networks_bp.route('/')
@login_required
def list_networks():
    networks = Network.query.order_by(Network.name).all()
    stats = {}
    for net in networks:
        total_hosts = net.hosts.count()
        total_devices = net.devices.count()

        last_ping = (ScanRun.query
                     .filter_by(network_id=net.id, type='ping', status='complete')
                     .order_by(ScanRun.finished_at.desc()).first())
        last_disc = (ScanRun.query
                     .filter_by(network_id=net.id, type='discovery', status='complete')
                     .order_by(ScanRun.finished_at.desc()).first())

        up_count = _up_count(net.id)

        stats[net.id] = {
            'total_hosts': total_hosts,
            'total_devices': total_devices,
            'up': up_count,
            'last_ping': last_ping,
            'last_disc': last_disc,
        }

    return render_template('networks/list.html', networks=networks, stats=stats)


@networks_bp.route('/<int:network_id>')
@login_required
def network_detail(network_id):
    net = Network.query.get_or_404(network_id)

    hosts = sorted(net.hosts.all(), key=lambda h: _ip_sort_key(h.ip))
    latest_ping = _latest_ping_map(network_id)

    open_ports = (db.session.query(func.count(PortScan.id))
                  .join(Host, Host.id == PortScan.host_id)
                  .filter(Host.network_id == network_id)
                  .scalar()) or 0

    last_ping_run = (ScanRun.query
                     .filter_by(network_id=network_id, type='ping', status='complete')
                     .order_by(ScanRun.finished_at.desc()).first())
    last_disc_run = (ScanRun.query
                     .filter_by(network_id=network_id, type='discovery', status='complete')
                     .order_by(ScanRun.finished_at.desc()).first())

    up_count = sum(1 for h in hosts
                   if latest_ping.get(h.id) and latest_ping[h.id].is_up)

    return render_template('networks/detail.html',
                           network=net,
                           hosts=hosts,
                           latest_ping=latest_ping,
                           up_count=up_count,
                           open_ports=open_ports,
                           last_ping_run=last_ping_run,
                           last_disc_run=last_disc_run)


@networks_bp.route('/new', methods=['GET', 'POST'])
@login_required
def network_new():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        cidr = request.form.get('cidr', '').strip()
        notes = request.form.get('notes', '').strip()
        vlan = _parse_vlan(request.form.get('vlan', ''))

        error = _validate_network(name, cidr, exclude_id=None)
        if error:
            flash(error, 'danger')
            return render_template('networks/form.html', mode='new',
                                   network=None, form=request.form)

        net = Network(name=name, cidr=cidr, notes=notes, vlan=vlan)
        db.session.add(net)
        db.session.commit()
        flash(f'Network "{name}" added.', 'success')
        return redirect(url_for('networks.network_detail', network_id=net.id))

    return render_template('networks/form.html', mode='new', network=None, form={})


@networks_bp.route('/<int:network_id>/edit', methods=['GET', 'POST'])
@login_required
def network_edit(network_id):
    net = Network.query.get_or_404(network_id)

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        cidr = request.form.get('cidr', '').strip()
        notes = request.form.get('notes', '').strip()
        vlan = _parse_vlan(request.form.get('vlan', ''))

        error = _validate_network(name, cidr, exclude_id=network_id)
        if error:
            flash(error, 'danger')
            return render_template('networks/form.html', mode='edit',
                                   network=net, form=request.form)

        net.name = name
        net.cidr = cidr
        net.notes = notes
        net.vlan = vlan
        db.session.commit()
        flash('Network updated.', 'success')
        return redirect(url_for('networks.network_detail', network_id=network_id))

    return render_template('networks/form.html', mode='edit', network=net, form={})


@networks_bp.route('/<int:network_id>/delete', methods=['POST'])
@login_required
def network_delete(network_id):
    net = Network.query.get_or_404(network_id)
    name = net.name
    db.session.delete(net)
    db.session.commit()
    flash(f'Network "{name}" deleted.', 'success')
    return redirect(url_for('networks.list_networks'))


@networks_bp.route('/<int:network_id>/notes', methods=['POST'])
@login_required
def save_notes(network_id):
    net = Network.query.get_or_404(network_id)
    body = request.get_json(silent=True) or {}
    net.notes = body.get('notes', '')
    db.session.commit()
    return jsonify(ok=True)


# ── helpers ──────────────────────────────────────────────────────

def _parse_vlan(val):
    try:
        v = int(val)
        return v if 1 <= v <= 4094 else None
    except (ValueError, TypeError):
        return None


def _ip_sort_key(ip_str):
    try:
        return ipaddress.ip_address(ip_str)
    except Exception:
        return ipaddress.ip_address('255.255.255.255')


def _validate_network(name, cidr, exclude_id):
    if not name:
        return 'Network name is required.'
    if not cidr:
        return 'CIDR is required.'
    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return f'Invalid CIDR "{cidr}". Example: 192.168.1.0/24'
    existing = Network.query.filter_by(cidr=cidr).first()
    if existing and existing.id != exclude_id:
        return f'A network with CIDR "{cidr}" already exists.'
    return None


def _up_count(network_id):
    subq = (db.session.query(
        PingResult.host_id,
        func.max(PingResult.scanned_at).label('latest')
    ).join(Host, Host.id == PingResult.host_id)
     .filter(Host.network_id == network_id)
     .group_by(PingResult.host_id).subquery())

    return (db.session.query(func.count())
            .select_from(PingResult)
            .join(subq, (PingResult.host_id == subq.c.host_id) &
                        (PingResult.scanned_at == subq.c.latest))
            .filter(PingResult.is_up == True)
            .scalar()) or 0


def _latest_ping_map(network_id):
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
