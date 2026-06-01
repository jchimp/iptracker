from flask import Blueprint, render_template
from flask_login import login_required
from sqlalchemy import func
from extensions import db
from models import Network, Host, Device, ScanRun, PingResult

overview_bp = Blueprint('overview', __name__, template_folder='../../templates')


@overview_bp.route('/overview')
@login_required
def index():
    networks = Network.query.order_by(Network.name).all()

    network_stats = []
    for net in networks:
        total_hosts = net.hosts.count()
        total_devices = net.devices.count()
        up = _up_count(net.id)

        last_ping = (ScanRun.query
                     .filter_by(network_id=net.id, type='ping', status='complete')
                     .order_by(ScanRun.finished_at.desc()).first())
        last_disc = (ScanRun.query
                     .filter_by(network_id=net.id, type='discovery', status='complete')
                     .order_by(ScanRun.finished_at.desc()).first())

        network_stats.append({
            'network': net,
            'total_hosts': total_hosts,
            'total_devices': total_devices,
            'up': up,
            'last_ping': last_ping,
            'last_disc': last_disc,
        })

    total_devices = Device.query.count()
    total_up = sum(s['up'] for s in network_stats)

    favorites = (Device.query
                 .filter_by(is_favorite=True)
                 .all())
    favorites.sort(key=lambda d: (d.name or d.hostname or d.ip).lower())

    # Latest ping for each favorite (keyed by host_id)
    fav_status = {}
    for dev in favorites:
        if dev.host_id:
            pr = (PingResult.query
                  .filter_by(host_id=dev.host_id)
                  .order_by(PingResult.scanned_at.desc())
                  .first())
            fav_status[dev.id] = pr

    return render_template(
        'overview/index.html',
        networks=networks,
        network_stats=network_stats,
        total_devices=total_devices,
        total_up=total_up,
        favorites=favorites,
        fav_status=fav_status,
    )


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
