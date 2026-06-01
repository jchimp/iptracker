import ipaddress
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, Response
from flask_login import login_required
from sqlalchemy import func
from extensions import db
from models import Network, Host, Device, PingResult, PortScan, ScanRun, DEVICE_TYPES

devices_bp = Blueprint('devices', __name__, template_folder='../../templates')


@devices_bp.route('/')
@login_required
def list_devices():
    networks = Network.query.order_by(Network.name).all()

    net_filter = request.args.get('network', 'all')
    type_filter = request.args.get('type', 'all')
    fav_filter = request.args.get('favorites', '')

    query = Device.query
    if net_filter not in ('all', ''):
        try:
            query = query.filter(Device.network_id == int(net_filter))
        except ValueError:
            pass
    if type_filter not in ('all', ''):
        query = query.filter(Device.type == type_filter)
    if fav_filter:
        query = query.filter(Device.is_favorite == True)

    devices = query.all()
    devices.sort(key=lambda d: (not d.is_favorite, (d.name or d.hostname or d.ip).lower()))

    latest_ping = _latest_ping_map_all()

    return render_template('devices/list.html',
                           devices=devices,
                           networks=networks,
                           device_types=DEVICE_TYPES,
                           latest_ping=latest_ping,
                           net_filter=net_filter,
                           type_filter=type_filter,
                           fav_filter=fav_filter)


@devices_bp.route('/new', methods=['GET', 'POST'])
@login_required
def device_new():
    networks = Network.query.order_by(Network.name).all()

    if request.method == 'POST':
        ip = request.form.get('ip', '').strip()
        network_id = request.form.get('network_id', '').strip()

        if not ip:
            flash('IP address is required.', 'danger')
            return render_template('devices/form.html', networks=networks,
                                   device_types=DEVICE_TYPES, form=request.form)
        if not network_id:
            flash('Network is required.', 'danger')
            return render_template('devices/form.html', networks=networks,
                                   device_types=DEVICE_TYPES, form=request.form)

        net_id = int(network_id)

        # Upsert Host for this IP
        host = Host.query.filter_by(network_id=net_id, ip=ip).first()
        if not host:
            host = Host(
                network_id=net_id,
                ip=ip,
                hostname=request.form.get('hostname', '').strip(),
            )
            db.session.add(host)
            db.session.flush()

        # Check no Device already linked to this host
        if host.device:
            flash(f'A device for {ip} already exists.', 'danger')
            return redirect(url_for('devices.device_detail', device_id=host.device.id))

        dev = Device(
            host_id=host.id,
            network_id=net_id,
            name=request.form.get('name', '').strip() or ip,
            url=request.form.get('url', '').strip(),
            type=request.form.get('type', 'Host'),
            notes=request.form.get('notes', '').strip(),
        )
        db.session.add(dev)
        db.session.commit()
        flash(f'Device {dev.display_name} added.', 'success')
        return redirect(url_for('devices.device_detail', device_id=dev.id))

    return render_template('devices/form.html', networks=networks,
                           device_types=DEVICE_TYPES, form={})


@devices_bp.route('/<int:device_id>', methods=['GET', 'POST'])
@login_required
def device_detail(device_id):
    dev = Device.query.get_or_404(device_id)
    networks = Network.query.order_by(Network.name).all()

    if request.method == 'POST':
        dev.name = request.form.get('name', '').strip() or dev.ip
        dev.url = request.form.get('url', '').strip()
        dev.type = request.form.get('type', dev.type)
        dev.notes = request.form.get('notes', '').strip()
        # hostname and notes live on Host
        if dev.host:
            new_hostname = request.form.get('hostname', '').strip()
            if new_hostname:
                dev.host.hostname = new_hostname
        db.session.commit()
        flash('Device updated.', 'success')
        return redirect(url_for('devices.device_detail', device_id=device_id))

    # Latest ping
    latest_ping = None
    if dev.host:
        latest_ping = (PingResult.query
                       .filter_by(host_id=dev.host_id)
                       .order_by(PingResult.scanned_at.desc())
                       .first())

    # Latest discovery ports
    latest_ports = []
    if dev.host:
        latest_disc_run = (ScanRun.query
                           .filter_by(network_id=dev.network_id, type='discovery', status='complete')
                           .order_by(ScanRun.finished_at.desc())
                           .first())
        if latest_disc_run:
            latest_ports = (PortScan.query
                            .filter_by(host_id=dev.host_id, scan_run_id=latest_disc_run.id)
                            .order_by(PortScan.port)
                            .all())

    # First/last seen from ping history
    first_seen = None
    last_seen = None
    if dev.host:
        first_seen = (PingResult.query
                      .filter_by(host_id=dev.host_id, is_up=True)
                      .order_by(PingResult.scanned_at.asc())
                      .first())
        last_seen = (PingResult.query
                     .filter_by(host_id=dev.host_id, is_up=True)
                     .order_by(PingResult.scanned_at.desc())
                     .first())

    return render_template('devices/detail.html',
                           device=dev,
                           networks=networks,
                           device_types=DEVICE_TYPES,
                           latest_ping=latest_ping,
                           latest_ports=latest_ports,
                           first_seen=first_seen,
                           last_seen=last_seen)


@devices_bp.route('/<int:device_id>/delete', methods=['POST'])
@login_required
def device_delete(device_id):
    dev = Device.query.get_or_404(device_id)
    name = dev.display_name
    # Unlink from host but keep host + ping history
    if dev.host:
        dev.host.device = None
    db.session.delete(dev)
    db.session.commit()
    flash(f'Device "{name}" removed from inventory. Ping history kept.', 'success')
    return redirect(url_for('devices.list_devices'))


@devices_bp.route('/favorite', methods=['POST'])
@login_required
def device_favorite():
    body = request.get_json(silent=True) or {}
    dev = Device.query.get(body.get('id'))
    if not dev:
        return jsonify(ok=False, error='not found'), 404
    dev.is_favorite = bool(body.get('favorite', False))
    db.session.commit()
    return jsonify(ok=True, favorite=dev.is_favorite)


@devices_bp.route('/export.csv')
@login_required
def export_csv():
    devices = Device.query.all()
    devices.sort(key=lambda d: (d.name or d.hostname or d.ip).lower())

    def _c(v):
        return (str(v or '')).replace(',', '').replace('\n', ' ')

    def generate():
        yield 'name,ip,hostname,url,type,network,favorite,reserved,notes\n'
        for d in devices:
            net_name = d.network.name if d.network else ''
            yield ','.join([
                _c(d.name), _c(d.ip), _c(d.hostname), _c(d.url),
                _c(d.type), _c(net_name),
                str(d.is_favorite), str(d.is_reserved), _c(d.notes)
            ]) + '\n'

    return Response(generate(), mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=devices.csv'})


# ── helpers ──────────────────────────────────────────────────────

def _latest_ping_map_all():
    """dict of host_id -> latest PingResult across all hosts."""
    subq = (db.session.query(
        PingResult.host_id,
        func.max(PingResult.scanned_at).label('latest')
    ).group_by(PingResult.host_id).subquery())

    rows = (db.session.query(PingResult)
            .join(subq, (PingResult.host_id == subq.c.host_id) &
                        (PingResult.scanned_at == subq.c.latest))
            .all())
    return {r.host_id: r for r in rows}
