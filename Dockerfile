FROM python:3.12-slim

# Install ping (iputils-ping) and dig (dnsutils) for network scanning
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       iputils-ping \
       nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/data

EXPOSE 8000

# Production WSGI server — timeout raised for large subnet scans
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--timeout", "120", "app:app"]
