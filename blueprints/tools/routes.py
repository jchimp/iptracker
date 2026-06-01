import ipaddress
from itertools import islice

from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required

from oui import vendor_for_mac

tools_bp = Blueprint('tools', __name__, template_folder='../../templates')

MAX_HOST_DISPLAY = 512


@tools_bp.route('/')
@login_required
def index():
    return render_template('tools/index.html')


@tools_bp.route('/oui', methods=['POST'])
@login_required
def oui_lookup():
    data = request.get_json(silent=True, force=True) or {}
    mac = data.get('mac', '').strip()
    if not mac:
        return jsonify(ok=False, error='Enter a MAC address.')
    vendor = vendor_for_mac(mac)
    return jsonify(ok=True, mac=mac, vendor=vendor if vendor else None)


@tools_bp.route('/cidr', methods=['POST'])
@login_required
def cidr_calc():
    data = request.get_json(silent=True, force=True) or {}
    raw = data.get('cidr', '').strip()
    if not raw:
        return jsonify(ok=False, error='Enter an IP range.')

    # Accept "192.168.1.0 255.255.255.0" as well as CIDR notation
    if ' ' in raw and '/' not in raw:
        raw = raw.replace(' ', '/', 1)

    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError as exc:
        return jsonify(ok=False, error=str(exc))

    usable = list(islice(net.hosts(), MAX_HOST_DISPLAY + 1))
    total_usable = net.num_addresses - (2 if net.prefixlen < 31 else 0)
    truncated = len(usable) > MAX_HOST_DISPLAY
    host_list = [str(h) for h in usable[:MAX_HOST_DISPLAY]]

    # First / last usable host (handle /31 and /32 edge cases)
    all_hosts = list(net.hosts())
    first_host = str(all_hosts[0]) if all_hosts else str(net.network_address)
    last_host = str(all_hosts[-1]) if all_hosts else str(net.broadcast_address)

    return jsonify(
        ok=True,
        cidr=str(net),
        network=str(net.network_address),
        broadcast=str(net.broadcast_address),
        netmask=str(net.netmask),
        wildcard=str(net.hostmask),
        prefix_len=net.prefixlen,
        num_addresses=net.num_addresses,
        total_usable=total_usable,
        first_host=first_host,
        last_host=last_host,
        host_list=host_list,
        truncated=truncated,
    )
