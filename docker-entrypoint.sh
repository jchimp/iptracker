#!/bin/bash
set -e

# Ensure admin password is set
if [ -z "$IPTRACKER_ADMIN_PASSWORD" ]; then
    echo "Error: IPTRACKER_ADMIN_PASSWORD not set in .env" >&2
    exit 1
fi

# Initialize database if it doesn't exist
if [ ! -f /app/data/iptracker.db ]; then
    echo "Creating database..."
    flask --app app.py create-db

    echo "Creating admin user..."
    flask --app app.py create-user admin --password "$IPTRACKER_ADMIN_PASSWORD"
fi

# Start gunicorn
exec gunicorn --bind 0.0.0.0:8000 --workers 2 --timeout 120 app:app
