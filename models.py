from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Network(db.Model):
    __tablename__ = 'networks'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    cidr = db.Column(db.String(50), nullable=False, unique=True)
    vlan = db.Column(db.Integer, nullable=True)
    notes = db.Column(db.Text, default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    hosts = db.relationship('Host', backref='network', lazy='dynamic',
                            cascade='all, delete-orphan')
    devices = db.relationship('Device', backref='network', lazy='dynamic',
                              cascade='all, delete-orphan')
    scan_runs = db.relationship('ScanRun', backref='network', lazy='dynamic',
                                cascade='all, delete-orphan')


class Host(db.Model):
    """
    One row per IP per network. Created for every IP that gets scanned
    (up or down) or manually added. Owns ping history and port scan data.
    This is what the Ping dashboard shows.
    """
    __tablename__ = 'hosts'
    __table_args__ = (
        db.UniqueConstraint('network_id', 'ip', name='uq_host_network_ip'),
    )

    id = db.Column(db.Integer, primary_key=True)
    network_id = db.Column(db.Integer, db.ForeignKey('networks.id'), nullable=False)
    ip = db.Column(db.String(45), nullable=False)
    hostname = db.Column(db.String(255), default='')
    is_reserved = db.Column(db.Boolean, default=False, nullable=False)
    notes = db.Column(db.Text, default='')
    mac_address = db.Column(db.String(17), default='')   # "AA:BB:CC:DD:EE:FF"
    mac_vendor = db.Column(db.String(200), default='')
    os_name = db.Column(db.String(200), default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    ping_results = db.relationship('PingResult', backref='host', lazy='dynamic',
                                   cascade='all, delete-orphan')
    port_scans = db.relationship('PortScan', backref='host', lazy='dynamic',
                                 cascade='all, delete-orphan')
    # one-to-one back to Device (nullable — not every host becomes a device)
    device = db.relationship('Device', backref='host', uselist=False)

    def __repr__(self):
        return f'<Host {self.ip}>'


DEVICE_TYPES = ['Router', 'Switch', 'AP', 'Server', 'Client', 'Host',
                'Printer', 'Camera', 'Firewall', 'Other']


class Device(db.Model):
    """
    Inventory record for a known host. Auto-created the first time a host
    responds to a ping. Enriched with name, type, URL, notes, favorite flag.
    This is what the Devices page shows.
    """
    __tablename__ = 'devices'

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'),
                        nullable=True, unique=True)
    network_id = db.Column(db.Integer, db.ForeignKey('networks.id'), nullable=False)
    name = db.Column(db.String(255), default='')
    url = db.Column(db.String(500), default='')
    type = db.Column(db.String(50), default='Host')
    notes = db.Column(db.Text, default='')   # inventory / detailed notes
    is_favorite = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Convenience properties — delegate to the linked Host so templates
    # can still write device.ip, device.hostname, device.is_reserved.
    @property
    def ip(self):
        return self.host.ip if self.host else ''

    @property
    def hostname(self):
        return self.host.hostname if self.host else ''

    @property
    def is_reserved(self):
        return self.host.is_reserved if self.host else False

    @property
    def display_name(self):
        return self.name or self.hostname or self.ip

    def __repr__(self):
        return f'<Device {self.ip}>'


class ScanRun(db.Model):
    __tablename__ = 'scan_runs'

    id = db.Column(db.Integer, primary_key=True)
    network_id = db.Column(db.Integer, db.ForeignKey('networks.id'), nullable=False)
    type = db.Column(db.String(20), nullable=False)       # 'ping' | 'discovery'
    status = db.Column(db.String(20), default='running')  # running | complete | error
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    finished_at = db.Column(db.DateTime)
    host_count = db.Column(db.Integer, default=0)
    up_count = db.Column(db.Integer, default=0)
    error_msg = db.Column(db.Text, default='')

    ping_results = db.relationship('PingResult', backref='scan_run', lazy='dynamic')
    port_scans = db.relationship('PortScan', backref='scan_run', lazy='dynamic')


class PingResult(db.Model):
    """Append-only ping history. Linked to Host (not Device)."""
    __tablename__ = 'ping_results'

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False, index=True)
    scan_run_id = db.Column(db.Integer, db.ForeignKey('scan_runs.id'))
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    is_up = db.Column(db.Boolean, nullable=False)
    response_ms = db.Column(db.Float)


class PortScan(db.Model):
    """One row per open port per host per scan run. Linked to Host (not Device)."""
    __tablename__ = 'port_scans'

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False, index=True)
    scan_run_id = db.Column(db.Integer, db.ForeignKey('scan_runs.id'), nullable=False)
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    port = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), default='tcp')
    state = db.Column(db.String(20), default='open')
    service = db.Column(db.String(100), default='')
    product = db.Column(db.String(200), default='')
    version = db.Column(db.String(200), default='')
