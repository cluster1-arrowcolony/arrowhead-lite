# Quick Reference

Fast reference for common commands, configurations, and troubleshooting.

## Common Commands

### Running Arrowhead Lite

```bash
# Development mode (HTTP, no auth)
./arrowhead-lite --disable-tls

# Production mode (HTTPS, mTLS)
./arrowhead-lite --config config.yaml

# With custom port
./arrowhead-lite --disable-tls --port 9090

# Verbose logging
./arrowhead-lite --disable-tls --verbose

# Show version
./arrowhead-lite --version

# Validate config
./arrowhead-lite validate --config config.yaml
```

### Build Commands

```bash
# Build binary
make build

# Run tests
make test

# Run tests with coverage
make test-coverage

# Run all checks (fmt, vet, lint, test)
make check

# Clean build artifacts
make clean

# Build for specific platform
GOOS=linux GOARCH=amd64 make build
```

### Docker Commands

```bash
# Build image
docker build -t arrowhead-lite:latest .

# Run container (dev mode)
docker run -d -p 8080:8080 \
  -e ARROWHEAD_TLS_ENABLED=false \
  arrowhead-lite:latest

# Run with docker-compose
cd docker && docker-compose up -d

# View logs
docker logs -f arrowhead-lite

# Stop and remove
docker-compose down
```

### SystemD Commands

```bash
# Start service
sudo systemctl start arrowhead-lite

# Stop service
sudo systemctl stop arrowhead-lite

# Restart service
sudo systemctl restart arrowhead-lite

# Check status
sudo systemctl status arrowhead-lite

# Enable on boot
sudo systemctl enable arrowhead-lite

# View logs
sudo journalctl -u arrowhead-lite -f

# View recent logs
sudo journalctl -u arrowhead-lite -n 100 --no-pager
```

## Client Libraries

### Python SDK

**Installation:**
```bash
pip install arrowhead-python-sdk
```

**Repository:** https://github.com/cluster1-arrowcolony/arrowhead-python-sdk

**Features:**
- Automatic service registration with heartbeat
- Service discovery with caching
- Built-in error handling and retry logic
- High-level abstractions for common patterns

**Quick Example:**
```python
from arrowhead import ArrowheadClient

client = ArrowheadClient(system_name="my-app", arrowhead_url="http://localhost:8080")
client.register_service("temperature", "/api/temperature")
services = client.discover("humidity")
```

### Go Client

**Installation:**
```bash
go get github.com/eislab-cps/arrowhead-client-go
```

**Repository:** https://github.com/eislab-cps/arrowhead-client-go

**Features:**
- Type-safe interfaces for Arrowhead services
- Automatic service lifecycle management
- Context-aware operations
- Native Go concurrency patterns

**Quick Example:**
```go
import "github.com/eislab-cps/arrowhead-client-go"

client := arrowhead.NewClient("my-app", "http://localhost:8080")
client.RegisterService("temperature", "/api/temperature")
services := client.Discover("humidity")
```

### Other Languages

For Java, JavaScript, Rust, and other languages, use the REST API directly. See [APPLICATION_DEVELOPMENT.md](./APPLICATION_DEVELOPMENT.md) for examples.

## Essential API Endpoints

### Health & Info

```bash
# Health check
curl http://localhost:8080/health

# Metrics (Prometheus format)
curl http://localhost:8080/metrics
```

### Service Registry

```bash
# Register system and service
curl -X POST http://localhost:8080/serviceregistry/register \
  -H "Content-Type: application/json" \
  -d @system.json

# Query services
curl -X POST http://localhost:8080/serviceregistry/query \
  -H "Content-Type: application/json" \
  -d '{"serviceDefinitionRequirement": "temperature"}'

# List all systems
curl http://localhost:8080/serviceregistry/systems

# Unregister system
curl -X DELETE http://localhost:8080/serviceregistry/unregister \
  -H "Content-Type: application/json" \
  -d '{"systemName": "sensor-1", "address": "192.168.1.100", "port": 8081}'
```

### Authorization

```bash
# Check authorization
curl -X POST http://localhost:8080/authorization/check \
  -H "Content-Type: application/json" \
  -d @auth-check.json

# Create authorization rule
curl -X POST http://localhost:8080/authorization/rules \
  -H "Content-Type: application/json" \
  -d @auth-rule.json

# List all rules
curl http://localhost:8080/authorization/rules

# Delete rule
curl -X DELETE http://localhost:8080/authorization/rules/1
```

### Orchestration

```bash
# Request orchestration
curl -X POST http://localhost:8080/orchestrator/orchestration \
  -H "Content-Type: application/json" \
  -d @orchestration-request.json
```

### With TLS (Production)

```bash
# Add certificate options to any curl command
curl --cert certs/sysop.crt \
     --key certs/sysop.key \
     --cacert certs/ca.crt \
     https://localhost:8443/health
```

## Configuration Snippets

### Minimal Development Config

```yaml
# config.dev.yaml
server:
  port: 8080

tls:
  enabled: false

database:
  type: sqlite
  path: data/arrowhead.db

logging:
  level: debug
```

### Minimal Production Config

```yaml
# config.prod.yaml
server:
  port: 8443

tls:
  enabled: true
  cert: /etc/arrowhead/certs/server.crt
  key: /etc/arrowhead/certs/server.key
  ca_cert: /etc/arrowhead/certs/ca.crt
  client_auth: true

database:
  type: postgres
  host: localhost
  port: 5432
  name: arrowhead
  user: arrowhead
  # Use environment variable for password
  # ARROWHEAD_DATABASE_PASSWORD=secret

logging:
  level: info
  format: json
  output: file
  file:
    path: /var/log/arrowhead/app.log
```

### Environment Variables

```bash
# Server
export ARROWHEAD_SERVER_PORT=8443
export ARROWHEAD_SERVER_HOST=0.0.0.0

# TLS
export ARROWHEAD_TLS_ENABLED=true
export ARROWHEAD_TLS_CERT=/path/to/server.crt
export ARROWHEAD_TLS_KEY=/path/to/server.key
export ARROWHEAD_TLS_CA_CERT=/path/to/ca.crt

# Database
export ARROWHEAD_DATABASE_TYPE=postgres
export ARROWHEAD_DATABASE_HOST=localhost
export ARROWHEAD_DATABASE_PASSWORD=secret

# Logging
export ARROWHEAD_LOGGING_LEVEL=info
export ARROWHEAD_LOGGING_FORMAT=json
```

## Default Ports and Paths

### Ports

| Service | Default Port | Protocol |
|---------|-------------|----------|
| HTTP (dev) | 8080 | HTTP |
| HTTPS (prod) | 8443 | HTTPS |
| Metrics | 9090 | HTTP |
| Profiling (debug) | 6060 | HTTP |
| PostgreSQL | 5432 | TCP |

### File Paths

| Component | Default Path |
|-----------|-------------|
| Binary | `./bin/arrowhead-lite` |
| Config | `./config.yaml` or `/etc/arrowhead/config.yaml` |
| Database (SQLite) | `./data/arrowhead.db` |
| Logs | `./logs/app.log` or `/var/log/arrowhead/app.log` |
| Certificates | `./certs/` or `/etc/arrowhead/certs/` |
| PID file | `/var/run/arrowhead-lite.pid` |

## Certificate Commands

### Generate Development Certificates

```bash
# Use built-in script
./scripts/generate-certs.sh

# Or manually with openssl
# Generate CA
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 1024 -out ca.crt

# Generate server cert
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365
```

### Verify Certificates

```bash
# Check certificate validity
openssl x509 -in certs/server.crt -text -noout

# Check certificate dates
openssl x509 -in certs/server.crt -noout -dates

# Verify certificate chain
openssl verify -CAfile certs/ca.crt certs/server.crt

# Test TLS connection
openssl s_client -connect localhost:8443 -CAfile certs/ca.crt
```

### Check Certificate Expiration

```bash
# Check expiration date
openssl x509 -enddate -noout -in certs/server.crt

# Check all certificates
for cert in certs/*.crt; do
  echo "$cert:"
  openssl x509 -enddate -noout -in "$cert"
done
```

## Database Commands

### SQLite

```bash
# Open database
sqlite3 data/arrowhead.db

# List tables
sqlite3 data/arrowhead.db ".tables"

# Check integrity
sqlite3 data/arrowhead.db "PRAGMA integrity_check;"

# Backup
sqlite3 data/arrowhead.db ".backup backup.db"

# Export to SQL
sqlite3 data/arrowhead.db ".dump" > backup.sql
```

### PostgreSQL

```bash
# Connect to database
psql -h localhost -U arrowhead -d arrowhead

# Test connection
psql -h localhost -U arrowhead -d arrowhead -c "SELECT 1;"

# Backup
pg_dump -h localhost -U arrowhead arrowhead > backup.sql

# Restore
psql -h localhost -U arrowhead -d arrowhead < backup.sql

# Check connections
psql -U postgres -c "SELECT count(*) FROM pg_stat_activity;"
```

## Troubleshooting Quick Fixes

### Service Won't Start

```bash
# Check port availability
sudo lsof -i :8443
sudo netstat -tlnp | grep 8443

# Check logs
journalctl -u arrowhead-lite -n 50

# Check permissions
ls -la /opt/arrowhead-lite/bin/arrowhead-lite
ls -la /etc/arrowhead/certs/

# Run in foreground to see errors
./arrowhead-lite --disable-tls --verbose
```

### Certificate Issues

```bash
# Regenerate certificates
./scripts/generate-certs.sh

# Fix certificate permissions
chmod 644 certs/*.crt
chmod 600 certs/*.key

# Verify certificate chain
openssl verify -CAfile certs/ca.crt certs/server.crt
```

### Database Issues

```bash
# SQLite locked
fuser -k data/arrowhead.db
rm -f data/arrowhead.db-wal data/arrowhead.db-shm

# PostgreSQL connection
psql -h localhost -U arrowhead -d arrowhead -c "SELECT 1;"

# Reset database (CAUTION: deletes all data)
rm -f data/arrowhead.db
./arrowhead-lite --disable-tls  # Will recreate
```

### Performance Issues

```bash
# Check resource usage
top -p $(pgrep arrowhead-lite)
ps aux | grep arrowhead-lite

# Check disk space
df -h

# Check database size
du -h data/arrowhead.db

# Check goroutines (if profiling enabled)
curl http://localhost:6060/debug/pprof/goroutine?debug=1
```

### Network Issues

```bash
# Test connectivity
nc -zv localhost 8443
telnet localhost 8443

# Check firewall
sudo iptables -L -n
sudo ufw status

# Check DNS
nslookup arrowhead.local
ping arrowhead.local
```

## Monitoring Quick Commands

### Check Service Health

```bash
# One-liner health check
curl -sf http://localhost:8080/health > /dev/null && echo "OK" || echo "FAIL"

# Get specific service status
curl -s http://localhost:8080/health | jq '.services'

# Check uptime
curl -s http://localhost:8080/health | jq '.uptime'
```

### View Metrics

```bash
# Total requests
curl -s http://localhost:8080/metrics | grep http_requests_total

# Response times
curl -s http://localhost:8080/metrics | grep http_request_duration

# Database connections
curl -s http://localhost:8080/metrics | grep db_connections

# Memory usage
curl -s http://localhost:8080/metrics | grep go_memstats
```

### Log Analysis

```bash
# Count errors in last hour
journalctl -u arrowhead-lite --since "1 hour ago" | grep -c ERROR

# Find authentication failures
journalctl -u arrowhead-lite | grep -i "auth.*failed"

# Monitor in real-time
journalctl -u arrowhead-lite -f | grep -E "(ERROR|WARN)"

# Extract error summary
journalctl -u arrowhead-lite --since today | \
  grep ERROR | cut -d' ' -f5- | sort | uniq -c | sort -rn
```

## JSON Request Templates

### System Registration

```json
{
  "system": {
    "systemName": "my-iot-device",
    "address": "192.168.1.100",
    "port": 8081,
    "authenticationInfo": ""
  },
  "services": [
    {
      "serviceDefinition": "temperature",
      "interfaces": ["HTTP-SECURE-JSON"],
      "serviceUri": "/api/temperature",
      "metadata": {
        "unit": "celsius"
      }
    }
  ]
}
```

### Service Query

```json
{
  "serviceDefinitionRequirement": "temperature",
  "interfaceRequirements": ["HTTP-SECURE-JSON"],
  "metadataRequirements": {
    "unit": "celsius"
  }
}
```

### Authorization Rule

```json
{
  "consumer": {
    "systemName": "consumer-system",
    "address": "192.168.1.101",
    "port": 8082
  },
  "providers": [
    {
      "systemName": "my-iot-device",
      "address": "192.168.1.100",
      "port": 8081
    }
  ],
  "services": [
    {
      "serviceDefinition": "temperature",
      "interfaces": ["HTTP-SECURE-JSON"]
    }
  ]
}
```

### Orchestration Request

```json
{
  "requesterSystem": {
    "systemName": "consumer-system",
    "address": "192.168.1.101",
    "port": 8082
  },
  "requestedService": {
    "serviceDefinitionRequirement": "temperature",
    "interfaceRequirements": ["HTTP-SECURE-JSON"]
  },
  "orchestrationFlags": {
    "overrideStore": false,
    "matchmaking": true
  }
}
```

## Performance Tuning Quick Settings

### High Load Configuration

```yaml
database:
  max_open_connections: 100
  max_idle_connections: 25

advanced:
  worker_pool_size: 50
  event_buffer_size: 5000

server:
  read_timeout: 60s
  write_timeout: 60s
```

### Low Resource Configuration

```yaml
database:
  max_open_connections: 10
  max_idle_connections: 2

advanced:
  worker_pool_size: 5
  event_buffer_size: 100

registry:
  cache:
    enabled: true
    max_entries: 500
```

## Security Quick Checklist

- [ ] TLS enabled with valid certificates
- [ ] Client certificate authentication enabled
- [ ] Strong JWT secret configured
- [ ] Firewall rules in place
- [ ] Database credentials in environment variables
- [ ] Rate limiting enabled
- [ ] Audit logging enabled
- [ ] Regular certificate rotation scheduled
- [ ] Backup strategy implemented
- [ ] Monitoring and alerts configured

## Common Error Messages

| Error | Quick Fix |
|-------|-----------|
| "port already in use" | `sudo lsof -i :8443` then kill process or use different port |
| "certificate expired" | Run `./scripts/generate-certs.sh` |
| "database locked" | `fuser -k data/arrowhead.db` |
| "connection refused" | Check if service is running: `systemctl status arrowhead-lite` |
| "permission denied" | Check file permissions: `chmod 755 arrowhead-lite` |
| "out of memory" | Set `GOMEMLIMIT=1GiB` or increase system resources |

## Useful One-Liners

```bash
# Watch service health
watch -n 5 'curl -s http://localhost:8080/health | jq ".status"'

# Count registered systems
curl -s http://localhost:8080/serviceregistry/systems | jq 'length'

# Find large log files
find /var/log/arrowhead -type f -size +100M

# Backup everything important
tar czf arrowhead-backup-$(date +%Y%m%d).tar.gz \
  data/ certs/ config.yaml

# Kill all arrowhead processes
pkill -9 arrowhead-lite

# Check memory usage
ps aux | grep arrowhead-lite | awk '{print $6/1024 " MB"}'

# Auto-restart on failure
while true; do ./arrowhead-lite || sleep 5; done
```

## Getting More Help

- Full documentation: [README.md](./README.md)
- Developer guide: [APPLICATION_DEVELOPMENT.md](./APPLICATION_DEVELOPMENT.md)
- Operations guide: [OPERATIONS_GUIDE.md](./OPERATIONS_GUIDE.md)
- GitHub Issues: https://github.com/cluster1-arrowcolony/arrowhead-lite/issues

## Print This Page

This quick reference is designed to be printer-friendly. Key information is organized in tables and lists for easy scanning.
