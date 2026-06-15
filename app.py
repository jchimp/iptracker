import os
import click
from datetime import datetime
from zoneinfo import ZoneInfo
from flask import Flask, redirect, url_for
from extensions import db, login_manager
from models import User, ScanRun


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-insecure-change-me')

    db_path = os.path.join(os.path.dirname(__file__), 'data', 'iptracker.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
        'DATABASE_URL', f'sqlite:///{db_path}'
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    login_manager.init_app(app)

    from blueprints.auth.routes import auth_bp
    from blueprints.overview.routes import overview_bp
    from blueprints.networks.routes import networks_bp
    from blueprints.devices.routes import devices_bp
    from blueprints.ping.routes import ping_bp
    from blueprints.discovery.routes import discovery_bp
    from blueprints.tools.routes import tools_bp

    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(overview_bp)
    app.register_blueprint(networks_bp, url_prefix='/networks')
    app.register_blueprint(devices_bp, url_prefix='/devices')
    app.register_blueprint(ping_bp, url_prefix='/ping')
    app.register_blueprint(discovery_bp, url_prefix='/discovery')
    app.register_blueprint(tools_bp, url_prefix='/tools')

    @app.route('/')
    def index():
        return redirect(url_for('overview.index'))

    @app.template_filter('fmt_dt')
    def fmt_dt_filter(value):
        if not value:
            return '—'
        try:
            if isinstance(value, str):
                value = datetime.fromisoformat(value)
            if value.tzinfo is None:
                from datetime import timezone
                value = value.replace(tzinfo=timezone.utc)
            return value.astimezone(ZoneInfo('America/Denver')).strftime('%Y-%m-%d %H:%M')
        except Exception:
            return str(value)

    @app.template_filter('ago')
    def ago_filter(value):
        """Human-readable relative time ('2h ago', '3d ago')."""
        if not value:
            return '—'
        try:
            if isinstance(value, str):
                value = datetime.fromisoformat(value)
            from datetime import timezone
            now = datetime.now(timezone.utc)
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            delta = now - value
            s = int(delta.total_seconds())
            if s < 60:
                return f'{s}s ago'
            if s < 3600:
                return f'{s // 60}m ago'
            if s < 86400:
                return f'{s // 3600}h ago'
            return f'{s // 86400}d ago'
        except Exception:
            return '—'

    register_cli(app)
    return app


def register_cli(app):
    @app.cli.command('create-db')
    def create_db_cmd():
        """Create all database tables."""
        os.makedirs(os.path.join(os.path.dirname(__file__), 'data'), exist_ok=True)
        db.create_all()
        click.echo('Database tables created.')

    @app.cli.command('create-user')
    @click.argument('username')
    @click.option('--password', default=None, help='Password (will prompt if not provided)')
    def create_user_cmd(username, password):
        """Create a new user account."""
        if User.query.filter_by(username=username).first():
            click.echo(f'Error: user "{username}" already exists.', err=True)
            return

        if password is None:
            password = click.prompt('Password', hide_input=True, confirmation_prompt=True)

        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        click.echo(f'User "{username}" created.')

    @app.cli.command('list-users')
    def list_users_cmd():
        """List all users."""
        users = User.query.all()
        if not users:
            click.echo('No users.')
            return
        for u in users:
            status = 'active' if u.is_active else 'disabled'
            click.echo(f'  {u.id:3d}  {u.username:<30}  {status}  created {u.created_at}')

    @app.cli.command('set-password')
    @click.argument('username')
    @click.password_option()
    def set_password_cmd(username, password):
        """Reset a user's password."""
        user = User.query.filter_by(username=username).first()
        if not user:
            click.echo(f'Error: user "{username}" not found.', err=True)
            return
        user.set_password(password)
        db.session.commit()
        click.echo(f'Password updated for "{username}".')

    @app.cli.command('reset-scans')
    def reset_scans_cmd():
        """Clear all running scans (for stuck processes after crash/restart)."""
        running = ScanRun.query.filter_by(status='running').all()
        if not running:
            click.echo('No running scans.')
            return
        for scan in running:
            scan.status = 'error'
            scan.error_msg = 'Cleared by reset-scans command'
            scan.finished_at = datetime.utcnow()
        db.session.commit()
        click.echo(f'Cleared {len(running)} running scan(s).')


app = create_app()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8005)
