# Troubleshooting Guide

## Overview

This guide helps diagnose and resolve common issues with Arrowhead Lite. Each section includes symptoms, diagnostic steps, and solutions.

## Quick Diagnostics

### Health Check

```bash
# Check if service is running
curl -k https://localhost:8443/health

# Check service status
systemctl status arrowhead-lite

# Check recent logs
journalctl -u arrowhead-lite -n 100 --no-pager

# Test connectivity
nc -zv localhost 8443
```

### System Information

```bash
# Get version info
./arrowhead-lite --version

# Check system resources
free -h
df -h
top -n 1 | head -20

# Check open files/connections
lsof -p $(pgrep arrowhead-lite) | wc -l
netstat -antp | grep arrowhead
```

## Common Issues

## 1. Service Won't Start

### Symptoms
- Service fails to start
- Process exits immediately
- No log output

### Diagnostic Steps

```bash
# Check for port conflicts
sudo lsof -i :8443
sudo netstat -tlnp | grep 8443

# Check configuration syntax
./arrowhead-lite validate --config config.yaml

# Run in foreground with debug
./arrowhead-lite --disable-tls --verbose

# Check system limits
ulimit -a
```

### Solutions

#### Port Already in Use
```bash
# Find and kill process using port
sudo kill -9 $(sudo lsof -t -i:8443)

# Or change port in config
server:
  port: 8444
```

#### Permission Denied
```bash
# Fix file permissions
sudo chown -R arrowhead:arrowhead /opt/arrowhead-lite
sudo chmod 755 /opt/arrowhead-lite/bin/arrowhead-lite

# Fix certificate permissions
sudo chmod 644 certs/*.crt
sudo chmod 600 certs/*.key
```

#### Missing Dependencies
```bash
# Install required libraries (Linux)
sudo apt-get update
sudo apt-get install ca-certificates

# Check dynamic libraries
ldd ./bin/arrowhead-lite
```

## 2. TLS/Certificate Issues

### Symptoms
- TLS handshake failures
- Certificate verification errors
- "x509: certificate signed by unknown authority"

### Diagnostic Steps

```bash
# Verify certificate validity
openssl x509 -in certs/server.crt -text -noout

# Check certificate dates
openssl x509 -in certs/server.crt -noout -dates

# Verify certificate chain
openssl verify -CAfile certs/ca.crt certs/server.crt

# Test TLS connection
openssl s_client -connect localhost:8443 \
  -CAfile certs/ca.crt \
  -cert certs/client.crt \
  -key certs/client.key

# Check cipher suites
nmap --script ssl-enum-ciphers -p 8443 localhost
```

### Solutions

#### Expired Certificates
```bash
# Regenerate certificates
./scripts/generate-certs.sh

# Restart service
systemctl restart arrowhead-lite
```

#### Certificate Mismatch
```yaml
# Ensure config matches cert files
tls:
  cert: /absolute/path/to/server.crt
  key: /absolute/path/to/server.key
  ca_cert: /absolute/path/to/ca.crt
```

#### Client Certificate Issues
```bash
# Generate client certificate
openssl req -new -newkey rsa:2048 -nodes \
  -keyout client.key -out client.csr

openssl x509 -req -in client.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 365

# Test with curl
curl --cert client.crt --key client.key \
  --cacert ca.crt https://localhost:8443/health
```

## 3. Database Connection Problems

### Symptoms
- "database connection failed"
- "too many connections"
- Slow queries
- Data inconsistencies

### Diagnostic Steps

#### SQLite
```bash
# Check database file
ls -la data/arrowhead.db
file data/arrowhead.db

# Check integrity
sqlite3 data/arrowhead.db "PRAGMA integrity_check;"

# Check locks
lsof data/arrowhead.db

# View schema
sqlite3 data/arrowhead.db ".schema"
```

#### PostgreSQL
```bash
# Test connection
psql -h localhost -U arrowhead -d arrowhead -c "SELECT 1;"

# Check connections
psql -U postgres -c "SELECT count(*) FROM pg_stat_activity;"

# Check database size
psql -U postgres -c "SELECT pg_database_size('arrowhead');"

# View active queries
psql -U postgres -c "SELECT * FROM pg_stat_activity WHERE state != 'idle';"
```

### Solutions

#### SQLite Locked
```bash
# Find and kill processes holding locks
fuser -k data/arrowhead.db

# Or move database and restart
mv data/arrowhead.db data/arrowhead.db.backup
systemctl restart arrowhead-lite
```

#### PostgreSQL Connection Pool Exhausted
```yaml
# Increase connection pool
database:
  max_open_connections: 50
  max_idle_connections: 10
```

```sql
-- Increase PostgreSQL max connections
ALTER SYSTEM SET max_connections = 200;
SELECT pg_reload_conf();
```

#### Database Corruption
```bash
# SQLite recovery
sqlite3 data/arrowhead.db ".recover" > recovered.sql
sqlite3 data/arrowhead_new.db < recovered.sql

# PostgreSQL backup/restore
pg_dump arrowhead > backup.sql
dropdb arrowhead
createdb arrowhead
psql arrowhead < backup.sql
```

## 4. Authentication/Authorization Failures

### Symptoms
- 401 Unauthorized errors
- 403 Forbidden errors
- Token validation failures
- Certificate authentication issues

### Diagnostic Steps

```bash
# Test without auth (development)
curl http://localhost:8080/health

# Test with certificate
curl --cert client.crt --key client.key \
  --cacert ca.crt https://localhost:8443/health

# Check JWT token
TOKEN="your-jwt-token"
echo $TOKEN | cut -d. -f2 | base64 -d | jq

# View auth logs
grep -i "auth" /var/log/arrowhead/app.log | tail -20
```

### Solutions

#### Invalid JWT Secret
```bash
# Generate new secret
openssl rand -base64 32 > jwt-secret.txt

# Update configuration
export ARROWHEAD_AUTH_JWT_SECRET=$(cat jwt-secret.txt)

# Restart service
systemctl restart arrowhead-lite
```

#### Certificate Not Trusted
```bash
# Add CA to trust store
sudo cp certs/ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates

# Or specify CA in request
curl --cacert certs/ca.crt https://localhost:8443/api/...
```

#### Rate Limiting
```yaml
# Increase rate limits
auth:
  rate_limit:
    requests: 1000
    burst: 100
```

## 5. Performance Issues

### Symptoms
- Slow response times
- High CPU/memory usage
- Request timeouts
- Connection drops

### Diagnostic Steps

```bash
# Monitor resource usage
top -p $(pgrep arrowhead-lite)
iostat -x 1
vmstat 1

# Check goroutines
curl http://localhost:6060/debug/pprof/goroutine?debug=1

# Profile CPU usage
go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30

# Check database performance
# SQLite
sqlite3 data/arrowhead.db "EXPLAIN QUERY PLAN SELECT ..."

# PostgreSQL
psql -U arrowhead -c "EXPLAIN ANALYZE SELECT ..."
```

### Solutions

#### High Memory Usage
```bash
# Set memory limits
GOGC=50 GOMEMLIMIT=1GiB ./arrowhead-lite

# Or in systemd
[Service]
Environment="GOGC=50"
Environment="GOMEMLIMIT=1GiB"
```

#### Slow Database Queries
```sql
-- Add missing indexes
CREATE INDEX idx_systems_name ON systems(system_name);
CREATE INDEX idx_services_definition ON services(service_definition);

-- Analyze tables (PostgreSQL)
ANALYZE systems;
ANALYZE services;

-- Vacuum database
VACUUM ANALYZE;
```

#### Connection Pool Tuning
```yaml
database:
  max_open_connections: 100
  max_idle_connections: 20
  connection_max_lifetime: "5m"

advanced:
  worker_pool_size: 50
```

## 6. Service Discovery Issues

### Symptoms
- Services not found
- Stale service entries
- Heartbeat failures

### Diagnostic Steps

```bash
# List all registered services
curl -X GET https://localhost:8443/serviceregistry/systems

# Check specific service
curl -X POST https://localhost:8443/serviceregistry/query \
  -H "Content-Type: application/json" \
  -d '{"serviceDefinitionRequirement": "temperature"}'

# Check heartbeat status
grep -i "heartbeat" /var/log/arrowhead/app.log | tail -20
```

### Solutions

#### Stale Services
```yaml
# Adjust heartbeat settings
registry:
  heartbeat_timeout: "30s"
  heartbeat_interval: "10s"
  cleanup_interval: "1m"
```

#### Service Not Registered
```bash
# Manually register service
curl -X POST https://localhost:8443/serviceregistry/register \
  -H "Content-Type: application/json" \
  -d @service.json
```

## 7. Orchestration Problems

### Symptoms
- No providers found
- Wrong provider selected
- Authorization failures during orchestration

### Diagnostic Steps

```bash
# Test orchestration request
curl -X POST https://localhost:8443/orchestrator/orchestration \
  -H "Content-Type: application/json" \
  -d @orchestration-request.json

# Check authorization rules
curl -X GET https://localhost:8443/authorization/rules

# View orchestration logs
grep -i "orchestration" /var/log/arrowhead/app.log | tail -20
```

### Solutions

#### No Authorized Providers
```bash
# Create authorization rule
curl -X POST https://localhost:8443/authorization/rules \
  -H "Content-Type: application/json" \
  -d '{
    "consumer": {...},
    "providers": [...],
    "services": [...]
  }'
```

#### QoS Not Met
```yaml
# Adjust orchestration settings
orchestration:
  qos_enabled: true
  qos_weights:
    latency: 0.5
    availability: 0.3
    throughput: 0.2
```

## 8. Network Issues

### Symptoms
- Connection refused
- Connection timeout
- DNS resolution failures

### Diagnostic Steps

```bash
# Check network interfaces
ip addr show
ifconfig

# Test DNS resolution
nslookup arrowhead.local
dig arrowhead.local

# Check routing
ip route
traceroute arrowhead.local

# Test port connectivity
telnet localhost 8443
nc -zv localhost 8443

# Check firewall rules
sudo iptables -L -n
sudo ufw status verbose
```

### Solutions

#### Firewall Blocking
```bash
# Allow port (UFW)
sudo ufw allow 8443/tcp

# Allow port (iptables)
sudo iptables -A INPUT -p tcp --dport 8443 -j ACCEPT
sudo iptables-save

# Allow port (firewalld)
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --reload
```

#### DNS Resolution
```bash
# Add to /etc/hosts
echo "192.168.1.100 arrowhead.local" | sudo tee -a /etc/hosts

# Or configure DNS server
echo "nameserver 8.8.8.8" | sudo tee -a /etc/resolv.conf
```

## 9. Docker/Container Issues

### Symptoms
- Container won't start
- Can't access from host
- Volume mount issues

### Diagnostic Steps

```bash
# Check container status
docker ps -a
docker logs arrowhead-lite

# Inspect container
docker inspect arrowhead-lite

# Check network
docker network ls
docker network inspect bridge

# Enter container
docker exec -it arrowhead-lite /bin/sh
```

### Solutions

#### Container Exits Immediately
```bash
# Run with interactive terminal to see error
docker run -it --rm arrowhead-lite:latest

# Check entrypoint
docker run -it --rm --entrypoint /bin/sh arrowhead-lite:latest
```

#### Network Access Issues
```bash
# Use host network
docker run --network host arrowhead-lite:latest

# Or expose ports correctly
docker run -p 8443:8443 arrowhead-lite:latest
```

#### Volume Permissions
```bash
# Fix permissions
docker run -v $(pwd)/data:/data:Z arrowhead-lite:latest

# Or change ownership
sudo chown -R 1000:1000 ./data
```

## 10. Logging Issues

### Symptoms
- No logs generated
- Logs not rotating
- Disk space issues

### Diagnostic Steps

```bash
# Check log location
ls -la /var/log/arrowhead/

# Check disk space
df -h /var/log

# Check log rotation
ls -la /var/log/arrowhead/*.gz
cat /etc/logrotate.d/arrowhead-lite
```

### Solutions

#### No Logs
```yaml
# Enable logging
logging:
  level: debug
  output: file
  file:
    path: /var/log/arrowhead/app.log
```

#### Log Rotation
```bash
# Create logrotate config
cat > /etc/logrotate.d/arrowhead-lite << EOF
/var/log/arrowhead/*.log {
    daily
    rotate 7
    compress
    delaycompress
    notifempty
    create 0644 arrowhead arrowhead
    sharedscripts
    postrotate
        systemctl reload arrowhead-lite
    endscript
}
EOF
```

## Debug Mode

### Enable Debug Mode

```yaml
# config.debug.yaml
logging:
  level: debug
  include_caller: true

monitoring:
  profiling: true
  profiling_port: 6060

database:
  log_queries: true
```

```bash
# Run with debug
./arrowhead-lite --config config.debug.yaml --verbose

# Access profiling
go tool pprof http://localhost:6060/debug/pprof/heap
go tool pprof http://localhost:6060/debug/pprof/goroutine
```

## Emergency Recovery

### Complete System Reset

```bash
#!/bin/bash
# emergency-reset.sh

echo "Performing emergency reset..."

# Stop service
systemctl stop arrowhead-lite

# Backup current state
mkdir -p /backup/$(date +%Y%m%d)
cp -r /var/lib/arrowhead-lite /backup/$(date +%Y%m%d)/
cp -r /etc/arrowhead /backup/$(date +%Y%m%d)/

# Clear data
rm -rf /var/lib/arrowhead-lite/*
rm -rf /var/log/arrowhead-lite/*

# Regenerate certificates
cd /opt/arrowhead-lite
./scripts/generate-certs.sh

# Reset database
sqlite3 /var/lib/arrowhead-lite/arrowhead.db < schema.sql

# Start service
systemctl start arrowhead-lite

echo "Reset complete. Service restarted."
```

### Data Recovery

```bash
#!/bin/bash
# recover-data.sh

# Recover from backup
BACKUP_DATE=$1
if [ -z "$BACKUP_DATE" ]; then
    echo "Usage: $0 YYYYMMDD"
    exit 1
fi

# Stop service
systemctl stop arrowhead-lite

# Restore data
cp -r /backup/$BACKUP_DATE/arrowhead-lite/* /var/lib/arrowhead-lite/
cp -r /backup/$BACKUP_DATE/arrowhead/* /etc/arrowhead/

# Verify integrity
sqlite3 /var/lib/arrowhead-lite/arrowhead.db "PRAGMA integrity_check;"

# Start service
systemctl start arrowhead-lite
```

## Monitoring and Alerts

### Setup Monitoring

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'arrowhead'
    static_configs:
      - targets: ['localhost:9090']
    metric_relabel_configs:
      - source_labels: [__name__]
        regex: 'go_.*'
        action: drop
```

### Alert Rules

```yaml
# alerts.yml
groups:
  - name: arrowhead
    rules:
      - alert: ServiceDown
        expr: up{job="arrowhead"} == 0
        for: 5m
        annotations:
          summary: "Arrowhead service is down"
      
      - alert: HighMemoryUsage
        expr: process_resident_memory_bytes > 1e9
        for: 10m
        annotations:
          summary: "High memory usage detected"
      
      - alert: DatabaseConnectionError
        expr: database_connections_error_total > 0
        for: 1m
        annotations:
          summary: "Database connection errors"
```

## Getting Help

### Collect Diagnostic Information

```bash
#!/bin/bash
# collect-diagnostics.sh

DIAG_DIR="diagnostics-$(date +%Y%m%d-%H%M%S)"
mkdir -p $DIAG_DIR

# System info
uname -a > $DIAG_DIR/system.txt
free -h >> $DIAG_DIR/system.txt
df -h >> $DIAG_DIR/system.txt

# Service info
./arrowhead-lite --version > $DIAG_DIR/version.txt
systemctl status arrowhead-lite > $DIAG_DIR/status.txt

# Logs
journalctl -u arrowhead-lite -n 1000 > $DIAG_DIR/journal.log
cp /var/log/arrowhead/app.log $DIAG_DIR/

# Configuration (remove secrets)
grep -v -E "(password|secret|key)" config.yaml > $DIAG_DIR/config.yaml

# Network
netstat -antp > $DIAG_DIR/network.txt
ss -tulnp >> $DIAG_DIR/network.txt

# Create archive
tar czf $DIAG_DIR.tar.gz $DIAG_DIR/
echo "Diagnostics collected in $DIAG_DIR.tar.gz"
```

### Support Channels

- **GitHub Issues**: https://github.com/your-org/arrowhead-lite/issues
- **Documentation**: https://docs.arrowhead-lite.org
- **Community Forum**: https://forum.arrowhead-lite.org
- **Stack Overflow**: Tag with `arrowhead-lite`

### Reporting Issues

When reporting issues, include:
1. Arrowhead Lite version
2. Operating system and version
3. Configuration (sanitized)
4. Error messages and logs
5. Steps to reproduce
6. Diagnostic information archive