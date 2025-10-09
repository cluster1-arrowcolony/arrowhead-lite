# Operations Guide

**Audience:** System administrators deploying and maintaining Arrowhead Lite

This guide covers installation, configuration, security, monitoring, and maintenance of Arrowhead Lite.

## Quick Start

### Install and Run (5 minutes)

```bash
# Clone and build
git clone https://github.com/cluster1-arrowcolony/arrowhead-lite.git
cd arrowhead-lite
make build

# Run in development mode
./bin/arrowhead-lite --disable-tls

# Check health (in another terminal)
curl http://localhost:8080/health
```

For production deployment, continue reading.

## Installation

### Binary Installation

**Option 1: Build from Source** (Recommended)

```bash
# Install prerequisites
sudo apt update && sudo apt install -y git make golang

# Clone and build
git clone https://github.com/cluster1-arrowcolony/arrowhead-lite.git
cd arrowhead-lite
make build

# Install
sudo cp bin/arrowhead-lite /usr/local/bin/
sudo chmod +x /usr/local/bin/arrowhead-lite

# Verify
arrowhead-lite --version
```

**Option 2: Download Pre-built Binary** (When available)

```bash
# Pre-built releases will be available at:
# https://github.com/cluster1-arrowcolony/arrowhead-lite/releases

# Example (once releases are published):
# wget https://github.com/cluster1-arrowcolony/arrowhead-lite/releases/latest/download/arrowhead-lite-linux-amd64
# sudo mv arrowhead-lite-linux-amd64 /usr/local/bin/arrowhead-lite
# sudo chmod +x /usr/local/bin/arrowhead-lite
```

### Docker Installation

```bash
# Pull image
docker pull arrowhead-lite:latest

# Run
docker run -d \
  --name arrowhead-lite \
  -p 8443:8443 \
  -v $(pwd)/config.yaml:/config.yaml \
  -v $(pwd)/certs:/certs \
  arrowhead-lite:latest
```

### Kubernetes Installation

Kubernetes deployment is not currently documented. Use Docker or Docker Compose for containerized deployments.

## Configuration

### Minimal Production Config

```yaml
# /etc/arrowhead/config.yaml
server:
  port: 8443

tls:
  enabled: true
  cert: /etc/arrowhead/certs/server.crt
  key: /etc/arrowhead/certs/server.key
  ca_cert: /etc/arrowhead/certs/ca.crt
  client_auth: true
  min_version: "TLS1.3"

database:
  type: postgres
  host: localhost
  port: 5432
  name: arrowhead
  user: arrowhead
  password: ${DB_PASSWORD}  # From environment
  ssl_mode: require

logging:
  level: info
  format: json
  output: file
  file:
    path: /var/log/arrowhead/app.log
```

### Configuration Options

| Setting | Default | Description |
|---------|---------|-------------|
| `server.port` | 8080 | HTTP port (8443 for HTTPS) |
| `tls.enabled` | false | Enable TLS |
| `tls.client_auth` | true | Require client certificates |
| `database.type` | sqlite | Database (sqlite, postgres) |
| `database.max_open_connections` | 25 | Connection pool size |
| `logging.level` | info | Log level (debug, info, warn, error) |
| `monitoring.metrics_enabled` | true | Enable Prometheus metrics |

**Complete reference:** See [Configuration Reference](#configuration-reference) section below.

### Environment Variables

```bash
# Set secrets via environment
export ARROWHEAD_DATABASE_PASSWORD=secure_password
export ARROWHEAD_AUTH_JWT_SECRET=$(openssl rand -base64 32)

# Run
arrowhead-lite --config /etc/arrowhead/config.yaml
```

## Security Setup

**Visual Guide**: See the [Certificate Generation diagram](./diagrams/1-cert-generation-dev.md) for the complete PKI setup process.

### 1. Generate Certificates

```bash
# Use provided script
./scripts/generate-certs.sh

# Or manually
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 1024 -out ca.crt

openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -out server.crt -days 365
```

### 2. Set File Permissions

```bash
chmod 644 certs/*.crt
chmod 600 certs/*.key
chmod 640 /etc/arrowhead/config.yaml
chown arrowhead:arrowhead /etc/arrowhead/config.yaml
```

### 3. Configure Firewall

```bash
# Allow only necessary ports
ufw allow 8443/tcp comment 'Arrowhead HTTPS'
ufw allow 9090/tcp comment 'Metrics (internal only)'
ufw default deny incoming
ufw enable
```

### 4. Security Checklist

| Item | Status |
|------|--------|
| TLS 1.3 enabled | [ ] |
| Client cert authentication enabled | [ ] |
| Certificates not expired | [ ] |
| JWT secret set (32+ chars) | [ ] |
| Database password in environment | [ ] |
| Firewall configured | [ ] |
| Audit logging enabled | [ ] |
| Regular backups configured | [ ] |

## Deployment Methods

### SystemD Service

Create `/etc/systemd/system/arrowhead-lite.service`:

```ini
[Unit]
Description=Arrowhead Lite Service Mesh
After=network.target

[Service]
Type=simple
User=arrowhead
WorkingDirectory=/opt/arrowhead-lite
ExecStart=/usr/local/bin/arrowhead-lite --config /etc/arrowhead/config.yaml
Restart=always
RestartSec=5

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/arrowhead-lite /var/log/arrowhead-lite

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable arrowhead-lite
sudo systemctl start arrowhead-lite
sudo systemctl status arrowhead-lite
```

### Docker Compose

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: arrowhead
      POSTGRES_PASSWORD: ${DB_PASSWORD}
      POSTGRES_DB: arrowhead
    volumes:
      - postgres-data:/var/lib/postgresql/data

  arrowhead-lite:
    image: arrowhead-lite:latest
    depends_on:
      - postgres
    ports:
      - "8443:8443"
      - "9090:9090"
    environment:
      ARROWHEAD_DATABASE_TYPE: postgres
      ARROWHEAD_DATABASE_HOST: postgres
      ARROWHEAD_DATABASE_PASSWORD: ${DB_PASSWORD}
    volumes:
      - ./certs:/certs:ro
      - ./config.yaml:/config.yaml:ro
    restart: always

volumes:
  postgres-data:
```

Start:
```bash
export DB_PASSWORD=secure_password
docker-compose up -d
```

### Kubernetes

Kubernetes deployment manifests are not currently provided. Use Docker Compose for multi-container deployments.

### IoT Edge (Raspberry Pi)

```bash
#!/bin/bash
# Quick install for Raspberry Pi

# Install dependencies
sudo apt update && sudo apt install -y git make wget

# Install Go for ARM
wget https://go.dev/dl/go1.23.0.linux-arm64.tar.gz
sudo tar -C /usr/local -xzf go1.23.0.linux-arm64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Build
git clone https://github.com/cluster1-arrowcolony/arrowhead-lite.git
cd arrowhead-lite
GOARCH=arm64 make build

# Install
sudo mkdir -p /opt/arrowhead/{data,logs,config}
sudo cp bin/arrowhead-lite /opt/arrowhead/
sudo chown -R pi:pi /opt/arrowhead

# Create minimal config
cat > /opt/arrowhead/config/config.yaml << 'EOF'
server:
  port: 8080
database:
  type: sqlite
  path: /opt/arrowhead/data/arrowhead.db
  max_open_connections: 5
logging:
  level: info
  output: file
EOF

# Create systemd service (similar to above)
# Start service
sudo systemctl enable arrowhead-lite
sudo systemctl start arrowhead-lite
```

## Monitoring

### Health Check

```bash
curl http://localhost:8080/health
# {"status":"healthy"}
```

### Prometheus Metrics

Arrowhead Lite exposes Prometheus metrics on the main server port:

```bash
# Development mode (HTTP)
curl http://localhost:8080/metrics

# Production mode (HTTPS with certs)
curl --cert certs/sysop.pem --key certs/sysop.key --cacert certs/truststore.pem \
  https://localhost:8443/metrics
```

Key metrics:
- `arrowhead_requests_total` - Request count
- `arrowhead_request_duration_seconds` - Latency
- `arrowhead_registered_systems` - System count
- `arrowhead_db_connections` - Database connections

**Note**: Port 9090 in docker-compose is for the Prometheus server itself, not arrowhead-lite.

### Grafana Dashboard

Grafana is available at http://localhost:3000 (admin/admin) when using docker-compose:

1. Add Prometheus data source (URL: http://prometheus:9090)
2. Create custom dashboards for Arrowhead Lite metrics
3. Monitor key metrics

**Note**: Pre-built dashboard files are not yet available. You'll need to create custom dashboards.

### Log Monitoring

```bash
# View logs
sudo journalctl -u arrowhead-lite -f

# View recent errors
sudo journalctl -u arrowhead-lite -p err -n 50

# Search logs
sudo journalctl -u arrowhead-lite | grep "ERROR"
```

## Database Management

### SQLite (Development/Edge)

```bash
# Check database
sqlite3 /data/arrowhead.db "SELECT count(*) FROM systems;"

# Backup
sqlite3 /data/arrowhead.db ".backup /backup/arrowhead-$(date +%Y%m%d).db"

# Restore
cp /backup/arrowhead-20250109.db /data/arrowhead.db
```

### PostgreSQL (Production)

```bash
# Backup
pg_dump -h localhost -U arrowhead arrowhead | gzip > backup-$(date +%Y%m%d).sql.gz

# Restore
gunzip < backup-20250109.sql.gz | psql -h localhost -U arrowhead arrowhead

# Check connections
psql -U postgres -c "SELECT count(*) FROM pg_stat_activity WHERE datname='arrowhead';"
```

## Upgrading

### Upgrade Procedure

```bash
# 1. Backup
pg_dump arrowhead > backup-pre-upgrade.sql
cp -r /etc/arrowhead/certs /backup/certs-$(date +%Y%m%d)

# 2. Stop service
sudo systemctl stop arrowhead-lite

# 3. Backup current binary
sudo cp /usr/local/bin/arrowhead-lite /usr/local/bin/arrowhead-lite.backup

# 4. Install new version
sudo cp arrowhead-lite /usr/local/bin/
sudo chmod +x /usr/local/bin/arrowhead-lite

# 5. Run migrations (if needed)
arrowhead-lite migrate --config /etc/arrowhead/config.yaml

# 6. Start and verify
sudo systemctl start arrowhead-lite
curl http://localhost:8080/health
sudo journalctl -u arrowhead-lite -n 50
```

### Rollback

```bash
sudo systemctl stop arrowhead-lite
sudo cp /usr/local/bin/arrowhead-lite.backup /usr/local/bin/arrowhead-lite
sudo systemctl start arrowhead-lite
```

## Troubleshooting

| Problem | Diagnostic | Solution |
|---------|-----------|----------|
| Won't start | `lsof -i :8443` | Kill conflicting process or change port |
| Permission denied | `ls -la /opt/arrowhead-lite` | Fix ownership: `chown -R arrowhead:arrowhead /opt/arrowhead-lite` |
| Certificate error | `openssl verify -CAfile ca.crt server.crt` | Regenerate certificates |
| Database connection failed | `psql -h localhost -U arrowhead -c "SELECT 1"` | Check credentials and connectivity |
| High memory usage | `top -p $(pgrep arrowhead-lite)` | Reduce `max_open_connections` |
| Can't connect | `nc -zv localhost 8443` | Check firewall, service running |

### Common Issues

**Port already in use:**
```bash
sudo lsof -i :8443
sudo kill $(lsof -t -i:8443)
```

**Certificate expired:**
```bash
openssl x509 -in certs/server.crt -noout -dates
./scripts/generate-certs.sh  # Regenerate
systemctl restart arrowhead-lite
```

**Database locked (SQLite):**
```bash
fuser -k /data/arrowhead.db
systemctl restart arrowhead-lite
```

### Enable Debug Logging

```yaml
# config.yaml
logging:
  level: debug
  include_caller: true
```

Or via environment:
```bash
export ARROWHEAD_LOG_LEVEL=debug
systemctl restart arrowhead-lite
```

## Backup and Recovery

### Automated Backup Script

```bash
#!/bin/bash
# /usr/local/bin/arrowhead-backup.sh

BACKUP_DIR="/backup/arrowhead"
DATE=$(date +%Y%m%d-%H%M%S)

mkdir -p $BACKUP_DIR

# Backup database
pg_dump -U arrowhead arrowhead | gzip > $BACKUP_DIR/db-$DATE.sql.gz

# Backup config
cp /etc/arrowhead/config.yaml $BACKUP_DIR/config-$DATE.yaml

# Backup certificates
tar czf $BACKUP_DIR/certs-$DATE.tar.gz /etc/arrowhead/certs

# Keep only last 7 days
find $BACKUP_DIR -name "*.gz" -mtime +7 -delete
find $BACKUP_DIR -name "*.yaml" -mtime +7 -delete
find $BACKUP_DIR -name "*.tar.gz" -mtime +7 -delete

echo "✓ Backup complete: $DATE"
```

Schedule with cron:
```bash
# Daily backup at 2 AM
0 2 * * * /usr/local/bin/arrowhead-backup.sh
```

### Disaster Recovery

```bash
# 1. Install Arrowhead Lite
# 2. Restore database
gunzip < /backup/db-latest.sql.gz | psql -U arrowhead arrowhead

# 3. Restore certificates
tar xzf /backup/certs-latest.tar.gz -C /

# 4. Restore config
cp /backup/config-latest.yaml /etc/arrowhead/config.yaml

# 5. Start service
systemctl start arrowhead-lite
```

## Performance Tuning

### Performance Quick Reference

| Scenario | Key Settings |
|----------|-------------|
| High throughput (1000+ req/s) | Increase workers, connections, cache |
| Low latency (<10ms) | Optimize DB queries, enable caching |
| Limited resources (<512MB) | Reduce workers, limit connections |
| Many concurrent clients | Increase connection pool, timeouts |
| Large service registry (1000+ services) | Enable caching, optimize indexes |

### High Load Configuration

```yaml
database:
  max_open_connections: 100
  max_idle_connections: 25

advanced:
  worker_pool_size: 50
  event_buffer_size: 5000

registry:
  cache:
    enabled: true
    ttl: "10m"
    max_entries: 5000
```

### Low Resource Configuration

```yaml
database:
  max_open_connections: 5
  max_idle_connections: 2

advanced:
  worker_pool_size: 4
  event_buffer_size: 100

registry:
  cache:
    max_entries: 500
```

### System-Level Tuning

```bash
# Increase file descriptors
echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf

# Network tuning
cat >> /etc/sysctl.conf << EOF
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 8192
EOF
sysctl -p
```

## Configuration Reference

### Complete Configuration Options

```yaml
server:
  host: 0.0.0.0
  port: 8080
  read_timeout: 30s
  write_timeout: 30s

tls:
  enabled: false
  cert: certs/server.crt
  key: certs/server.key
  ca_cert: certs/ca.crt
  client_auth: true
  min_version: "TLS1.3"

database:
  type: sqlite  # sqlite | postgres
  path: data/arrowhead.db  # SQLite only
  host: localhost  # PostgreSQL only
  port: 5432
  name: arrowhead
  user: arrowhead
  password: ""  # Use env var
  max_open_connections: 25
  max_idle_connections: 5
  ssl_mode: disable  # disable | require

auth:
  jwt:
    secret: ""  # Use env var
    expiration: "24h"
  rate_limit:
    enabled: true
    requests: 100

registry:
  heartbeat_timeout: "60s"
  cache:
    enabled: true
    ttl: "5m"
    max_entries: 1000

logging:
  level: info  # debug | info | warn | error
  format: text  # text | json
  output: stdout  # stdout | file | both
  file:
    path: logs/app.log
    max_size: 100MB
    max_backups: 5

monitoring:
  metrics_enabled: true
  metrics_port: 9090
  health_enabled: true

advanced:
  worker_pool_size: 10
  event_buffer_size: 1000
```

## See Also

- [APPLICATION_DEVELOPMENT.md](./APPLICATION_DEVELOPMENT.md) - For application developers
- [API_REFERENCE.md](./API_REFERENCE.md) - Complete API documentation
- [ARCHITECTURE.md](./ARCHITECTURE.md) - System architecture

## Getting Help

- Check logs: `journalctl -u arrowhead-lite -n 100`
- Review metrics: `curl http://localhost:8080/metrics`
- Search issues: https://github.com/cluster1-arrowcolony/arrowhead-lite/issues
- Contact support for production deployments
