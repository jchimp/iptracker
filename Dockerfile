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

RUN mkdir -p /app/data && chmod +x /app/docker-entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["/app/docker-entrypoint.sh"]
