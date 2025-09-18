# Deployment Guide

## Overview

This guide covers deployment options for Arrowhead Lite, from development setups to production clusters. Choose the deployment method that best fits your infrastructure and requirements.

## Prerequisites

### System Requirements

#### Minimum Requirements
- **CPU**: 1 core (2+ cores recommended)
- **RAM**: 256MB (512MB+ recommended)
- **Storage**: 100MB for binary + database space
- **OS**: Linux, macOS, or Windows
- **Network**: IPv4/IPv6 connectivity

#### Production Requirements
- **CPU**: 2+ cores
- **RAM**: 1GB+ 
- **Storage**: SSD with 10GB+ space
- **Database**: PostgreSQL 12+ (for clustered deployments)
- **Network**: Static IP, firewall configuration

### Software Dependencies

#### Required
- Go 1.23+ (for building from source)
- Git (for source code)
- Make (for build automation)

#### Optional
- Docker 20+ & Docker Compose 2+ (for containerized deployment)
- PostgreSQL 12+ (for production database)
- Nginx/HAProxy (for load balancing)
- Prometheus & Grafana (for monitoring)

## Deployment Methods

## 1. Binary Deployment

### Building from Source

```bash
# Clone repository
git clone https://github.com/your-org/arrowhead-lite.git
cd arrowhead-lite

# Build binary
make build

# Binary created at bin/arrowhead-lite
ls -la bin/
```

### Direct Binary Execution

#### Development Mode (HTTP)
```bash
# Run with default settings
./bin/arrowhead-lite --disable-tls

# Run with custom port
./bin/arrowhead-lite --disable-tls --port 9090

# Run with verbose logging
./bin/arrowhead-lite --disable-tls --verbose
```

#### Production Mode (HTTPS/mTLS)
```bash
# Generate certificates first
./scripts/generate-certs.sh

# Run with TLS enabled
./bin/arrowhead-lite \
  --tls-cert certs/server.crt \
  --tls-key certs/server.key \
  --ca-cert certs/ca.crt

# With custom configuration
./bin/arrowhead-lite --config production.yaml
```

### Systemd Service

Create service file `/etc/systemd/system/arrowhead-lite.service`:

```ini
[Unit]
Description=Arrowhead Lite Service Mesh
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=arrowhead
Group=arrowhead
WorkingDirectory=/opt/arrowhead-lite
ExecStart=/opt/arrowhead-lite/bin/arrowhead-lite --config /etc/arrowhead/config.yaml
Restart=always
RestartSec=5
StandardOutput=append:/var/log/arrowhead-lite/service.log
StandardError=append:/var/log/arrowhead-lite/error.log

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/arrowhead-lite /var/log/arrowhead-lite

[Install]
WantedBy=multi-user.target
```

Enable and start service:
```bash
# Create user and directories
sudo useradd -r -s /bin/false arrowhead
sudo mkdir -p /opt/arrowhead-lite /etc/arrowhead /var/lib/arrowhead-lite /var/log/arrowhead-lite
sudo chown -R arrowhead:arrowhead /var/lib/arrowhead-lite /var/log/arrowhead-lite

# Copy binary and config
sudo cp bin/arrowhead-lite /opt/arrowhead-lite/
sudo cp config.yaml /etc/arrowhead/

# Start service
sudo systemctl daemon-reload
sudo systemctl enable arrowhead-lite
sudo systemctl start arrowhead-lite
sudo systemctl status arrowhead-lite
```

## 2. Docker Deployment

### Single Container

#### Build Docker Image
```bash
# Using Dockerfile
docker build -t arrowhead-lite:latest .

# Multi-stage build for smaller image
docker build -f Dockerfile.multi -t arrowhead-lite:latest .
```

#### Run Container

Development mode:
```bash
docker run -d \
  --name arrowhead-lite \
  -p 8080:8080 \
  -e ARROWHEAD_TLS_ENABLED=false \
  -v $(pwd)/data:/data \
  arrowhead-lite:latest
```

Production mode:
```bash
docker run -d \
  --name arrowhead-lite \
  -p 8443:8443 \
  -e ARROWHEAD_TLS_ENABLED=true \
  -v $(pwd)/certs:/certs:ro \
  -v $(pwd)/data:/data \
  -v $(pwd)/config.yaml:/config.yaml:ro \
  arrowhead-lite:latest --config /config.yaml
```

### Docker Compose Stack

#### Development Stack

`docker-compose.dev.yaml`:
```yaml
version: '3.8'

services:
  arrowhead-lite:
    build: .
    container_name: arrowhead-lite-dev
    ports:
      - "8080:8080"
    environment:
      - ARROWHEAD_TLS_ENABLED=false
      - ARROWHEAD_LOG_LEVEL=debug
      - ARROWHEAD_DATABASE_TYPE=sqlite
      - ARROWHEAD_DATABASE_PATH=/data/arrowhead.db
    volumes:
      - ./data:/data
      - ./logs:/logs
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

#### Production Stack

`docker-compose.prod.yaml`:
```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    container_name: arrowhead-postgres
    environment:
      - POSTGRES_USER=arrowhead
      - POSTGRES_PASSWORD=${DB_PASSWORD}
      - POSTGRES_DB=arrowhead
    volumes:
      - postgres-data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql:ro
    ports:
      - "5432:5432"
    restart: always
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U arrowhead"]
      interval: 10s
      timeout: 5s
      retries: 5

  arrowhead-lite:
    image: arrowhead-lite:latest
    container_name: arrowhead-lite-prod
    depends_on:
      postgres:
        condition: service_healthy
    ports:
      - "8443:8443"
    environment:
      - ARROWHEAD_TLS_ENABLED=true
      - ARROWHEAD_TLS_CERT=/certs/server.crt
      - ARROWHEAD_TLS_KEY=/certs/server.key
      - ARROWHEAD_CA_CERT=/certs/ca.crt
      - ARROWHEAD_DATABASE_TYPE=postgres
      - ARROWHEAD_DATABASE_HOST=postgres
      - ARROWHEAD_DATABASE_PORT=5432
      - ARROWHEAD_DATABASE_NAME=arrowhead
      - ARROWHEAD_DATABASE_USER=arrowhead
      - ARROWHEAD_DATABASE_PASSWORD=${DB_PASSWORD}
      - ARROWHEAD_LOG_LEVEL=info
    volumes:
      - ./certs:/certs:ro
      - ./config:/config:ro
      - ./logs:/logs
    restart: always
    healthcheck:
      test: ["CMD", "curl", "-f", "-k", "https://localhost:8443/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  prometheus:
    image: prom/prometheus:latest
    container_name: arrowhead-prometheus
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus-data:/prometheus
    ports:
      - "9090:9090"
    restart: always

  grafana:
    image: grafana/grafana:latest
    container_name: arrowhead-grafana
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
      - GF_INSTALL_PLUGINS=redis-datasource
    volumes:
      - grafana-data:/var/lib/grafana
      - ./grafana/dashboards:/etc/grafana/provisioning/dashboards:ro
      - ./grafana/datasources:/etc/grafana/provisioning/datasources:ro
    ports:
      - "3000:3000"
    restart: always

volumes:
  postgres-data:
  prometheus-data:
  grafana-data:
```

Start the stack:
```bash
# Development
docker-compose -f docker-compose.dev.yaml up -d

# Production
export DB_PASSWORD=secure_password
export GRAFANA_PASSWORD=admin_password
docker-compose -f docker-compose.prod.yaml up -d

# View logs
docker-compose logs -f arrowhead-lite

# Stop stack
docker-compose down
```

## 3. Kubernetes Deployment

### Namespace and ConfigMap

`arrowhead-namespace.yaml`:
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: arrowhead
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: arrowhead-config
  namespace: arrowhead
data:
  config.yaml: |
    server:
      host: 0.0.0.0
      port: 8443
      tls:
        enabled: true
        cert: /certs/tls.crt
        key: /certs/tls.key
        ca: /certs/ca.crt
    database:
      type: postgres
      host: postgres-service
      port: 5432
      name: arrowhead
      user: arrowhead
    logging:
      level: info
      format: json
```

### Secrets

```bash
# Create TLS secret
kubectl create secret tls arrowhead-tls \
  --cert=certs/server.crt \
  --key=certs/server.key \
  -n arrowhead

# Create CA secret
kubectl create secret generic arrowhead-ca \
  --from-file=ca.crt=certs/ca.crt \
  -n arrowhead

# Create database secret
kubectl create secret generic arrowhead-db \
  --from-literal=password=secure_password \
  -n arrowhead
```

### StatefulSet Deployment

`arrowhead-statefulset.yaml`:
```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: arrowhead-lite
  namespace: arrowhead
spec:
  serviceName: arrowhead-lite
  replicas: 3
  selector:
    matchLabels:
      app: arrowhead-lite
  template:
    metadata:
      labels:
        app: arrowhead-lite
    spec:
      containers:
      - name: arrowhead-lite
        image: arrowhead-lite:latest
        ports:
        - containerPort: 8443
          name: https
        - containerPort: 9090
          name: metrics
        env:
        - name: ARROWHEAD_DATABASE_PASSWORD
          valueFrom:
            secretKeyRef:
              name: arrowhead-db
              key: password
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        volumeMounts:
        - name: config
          mountPath: /config
          readOnly: true
        - name: tls-certs
          mountPath: /certs
          readOnly: true
        - name: ca-cert
          mountPath: /ca
          readOnly: true
        - name: data
          mountPath: /data
        livenessProbe:
          httpGet:
            path: /health
            port: https
            scheme: HTTPS
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: https
            scheme: HTTPS
          initialDelaySeconds: 10
          periodSeconds: 5
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "1"
      volumes:
      - name: config
        configMap:
          name: arrowhead-config
      - name: tls-certs
        secret:
          secretName: arrowhead-tls
      - name: ca-cert
        secret:
          secretName: arrowhead-ca
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 10Gi
```

### Service and Ingress

`arrowhead-service.yaml`:
```yaml
apiVersion: v1
kind: Service
metadata:
  name: arrowhead-lite
  namespace: arrowhead
spec:
  type: ClusterIP
  selector:
    app: arrowhead-lite
  ports:
  - name: https
    port: 8443
    targetPort: 8443
  - name: metrics
    port: 9090
    targetPort: 9090
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: arrowhead-ingress
  namespace: arrowhead
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - arrowhead.example.com
    secretName: arrowhead-tls-ingress
  rules:
  - host: arrowhead.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: arrowhead-lite
            port:
              number: 8443
```

### Deploy to Kubernetes

```bash
# Apply configurations
kubectl apply -f arrowhead-namespace.yaml
kubectl apply -f arrowhead-statefulset.yaml
kubectl apply -f arrowhead-service.yaml

# Check status
kubectl get pods -n arrowhead
kubectl get svc -n arrowhead
kubectl logs -f arrowhead-lite-0 -n arrowhead

# Scale deployment
kubectl scale statefulset arrowhead-lite --replicas=5 -n arrowhead
```

## 4. Cloud Deployments

### AWS Deployment

#### EC2 Instance

```bash
# Launch EC2 instance (Amazon Linux 2)
aws ec2 run-instances \
  --image-id ami-0c55b159cbfafe1f0 \
  --instance-type t3.medium \
  --key-name my-key \
  --security-group-ids sg-xxxxxx \
  --subnet-id subnet-xxxxxx \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=arrowhead-lite}]'

# Connect and install
ssh ec2-user@<instance-ip>
sudo yum update -y
sudo yum install -y git make

# Install Go
wget https://go.dev/dl/go1.23.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Deploy Arrowhead Lite
git clone https://github.com/your-org/arrowhead-lite.git
cd arrowhead-lite
make build
sudo cp bin/arrowhead-lite /usr/local/bin/
```

#### ECS Fargate

Task definition:
```json
{
  "family": "arrowhead-lite",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "containerDefinitions": [
    {
      "name": "arrowhead-lite",
      "image": "your-registry/arrowhead-lite:latest",
      "portMappings": [
        {
          "containerPort": 8443,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "ARROWHEAD_TLS_ENABLED",
          "value": "true"
        }
      ],
      "secrets": [
        {
          "name": "ARROWHEAD_DATABASE_PASSWORD",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:arrowhead-db"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/arrowhead-lite",
          "awslogs-region": "us-west-2",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

### Azure Deployment

#### Azure Container Instances

```bash
# Create resource group
az group create --name arrowhead-rg --location westus2

# Create container instance
az container create \
  --resource-group arrowhead-rg \
  --name arrowhead-lite \
  --image your-registry/arrowhead-lite:latest \
  --ports 8443 \
  --cpu 1 \
  --memory 1 \
  --environment-variables \
    ARROWHEAD_TLS_ENABLED=true \
    ARROWHEAD_DATABASE_TYPE=postgres \
  --secure-environment-variables \
    ARROWHEAD_DATABASE_PASSWORD=$DB_PASSWORD
```

### Google Cloud Platform

#### Cloud Run

```bash
# Build and push image
gcloud builds submit --tag gcr.io/PROJECT_ID/arrowhead-lite

# Deploy to Cloud Run
gcloud run deploy arrowhead-lite \
  --image gcr.io/PROJECT_ID/arrowhead-lite \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --port 8443 \
  --set-env-vars="ARROWHEAD_TLS_ENABLED=true" \
  --set-secrets="ARROWHEAD_DATABASE_PASSWORD=arrowhead-db-password:latest"
```

## High Availability Setup

### Load Balancer Configuration

#### Nginx Configuration

`/etc/nginx/sites-available/arrowhead`:
```nginx
upstream arrowhead_backend {
    least_conn;
    server arrowhead-1.internal:8443 max_fails=3 fail_timeout=30s;
    server arrowhead-2.internal:8443 max_fails=3 fail_timeout=30s;
    server arrowhead-3.internal:8443 max_fails=3 fail_timeout=30s;
}

server {
    listen 443 ssl http2;
    server_name arrowhead.example.com;

    ssl_certificate /etc/nginx/ssl/server.crt;
    ssl_certificate_key /etc/nginx/ssl/server.key;
    ssl_client_certificate /etc/nginx/ssl/ca.crt;
    ssl_verify_client on;

    location / {
        proxy_pass https://arrowhead_backend;
        proxy_ssl_verify on;
        proxy_ssl_trusted_certificate /etc/nginx/ssl/ca.crt;
        
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Client-Certificate $ssl_client_escaped_cert;
        
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    location /health {
        access_log off;
        proxy_pass https://arrowhead_backend/health;
    }
}
```

#### HAProxy Configuration

`/etc/haproxy/haproxy.cfg`:
```
global
    maxconn 4096
    log stdout local0
    ssl-default-bind-options ssl-min-ver TLSv1.2

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms
    option httplog

frontend arrowhead_frontend
    bind *:443 ssl crt /etc/haproxy/certs/server.pem ca-file /etc/haproxy/certs/ca.crt verify required
    default_backend arrowhead_backend

backend arrowhead_backend
    balance leastconn
    option httpchk GET /health
    server arrowhead-1 arrowhead-1.internal:8443 check ssl verify required ca-file /etc/haproxy/certs/ca.crt
    server arrowhead-2 arrowhead-2.internal:8443 check ssl verify required ca-file /etc/haproxy/certs/ca.crt
    server arrowhead-3 arrowhead-3.internal:8443 check ssl verify required ca-file /etc/haproxy/certs/ca.crt
```

### Database Clustering

#### PostgreSQL with Streaming Replication

Primary configuration:
```ini
# postgresql.conf on primary
listen_addresses = '*'
wal_level = replica
max_wal_senders = 3
wal_keep_segments = 64
synchronous_commit = on
synchronous_standby_names = 'standby1,standby2'
```

Standby configuration:
```ini
# recovery.conf on standby
standby_mode = 'on'
primary_conninfo = 'host=primary.internal port=5432 user=replicator'
primary_slot_name = 'standby1'
trigger_file = '/tmp/promote_to_primary'
```

## Monitoring Setup

### Prometheus Configuration

`prometheus.yml`:
```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'arrowhead-lite'
    static_configs:
      - targets: 
        - 'arrowhead-1:9090'
        - 'arrowhead-2:9090'
        - 'arrowhead-3:9090'
    metrics_path: '/metrics'
    scheme: https
    tls_config:
      ca_file: /etc/prometheus/ca.crt
      cert_file: /etc/prometheus/client.crt
      key_file: /etc/prometheus/client.key
```

### Grafana Dashboard

Import dashboard JSON from `monitoring/dashboards/arrowhead-lite.json`.

Key metrics to monitor:
- Request rate and latency
- Error rate by endpoint
- Active connections
- Database query performance
- Certificate expiration
- System resources (CPU, memory, disk)

## Backup and Recovery

### Database Backup

#### PostgreSQL
```bash
# Backup
pg_dump -h localhost -U arrowhead -d arrowhead | gzip > backup-$(date +%Y%m%d-%H%M%S).sql.gz

# Restore
gunzip < backup-20250115-120000.sql.gz | psql -h localhost -U arrowhead -d arrowhead
```

#### SQLite
```bash
# Backup
sqlite3 /data/arrowhead.db ".backup /backup/arrowhead-$(date +%Y%m%d-%H%M%S).db"

# Restore
cp /backup/arrowhead-20250115-120000.db /data/arrowhead.db
```

### Certificate Backup
```bash
# Backup certificates and keys
tar czf certs-backup-$(date +%Y%m%d).tar.gz certs/

# Store securely (example with GPG)
gpg --encrypt --recipient admin@example.com certs-backup-20250115.tar.gz
```

## Troubleshooting Deployment

### Common Issues

#### Port Already in Use
```bash
# Find process using port
lsof -i :8443
# or
netstat -tlnp | grep 8443

# Kill process if needed
kill -9 <PID>
```

#### Certificate Issues
```bash
# Verify certificate
openssl x509 -in certs/server.crt -text -noout

# Check certificate chain
openssl verify -CAfile certs/ca.crt certs/server.crt

# Test TLS connection
openssl s_client -connect localhost:8443 -CAfile certs/ca.crt
```

#### Database Connection
```bash
# Test PostgreSQL connection
psql -h localhost -U arrowhead -d arrowhead -c "SELECT 1"

# Check SQLite database
sqlite3 /data/arrowhead.db "SELECT name FROM sqlite_master WHERE type='table'"
```

### Performance Tuning

#### System Limits
```bash
# Increase file descriptors
ulimit -n 65536

# Persistent change
echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf
```

#### Network Tuning
```bash
# /etc/sysctl.conf
net.core.somaxconn = 65535
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_tw_reuse = 1
```

## Security Hardening

### Firewall Rules
```bash
# UFW example
ufw allow 8443/tcp comment 'Arrowhead HTTPS'
ufw allow 9090/tcp comment 'Prometheus metrics'
ufw enable
```

### SELinux Configuration
```bash
# Create policy module
ausearch -c 'arrowhead-lite' --raw | audit2allow -M arrowhead-lite
semodule -i arrowhead-lite.pp
```

### AppArmor Profile
```
# /etc/apparmor.d/usr.local.bin.arrowhead-lite
#include <tunables/global>

/usr/local/bin/arrowhead-lite {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  
  /usr/local/bin/arrowhead-lite mr,
  /etc/arrowhead/* r,
  /var/lib/arrowhead-lite/** rw,
  /var/log/arrowhead-lite/** rw,
  
  network inet stream,
  network inet6 stream,
}
```

## Maintenance

### Rolling Updates
```bash
# Kubernetes
kubectl set image statefulset/arrowhead-lite arrowhead-lite=arrowhead-lite:v1.2.0 -n arrowhead

# Docker Swarm
docker service update --image arrowhead-lite:v1.2.0 arrowhead-lite

# Manual rolling update
for node in node1 node2 node3; do
  ssh $node "systemctl stop arrowhead-lite"
  ssh $node "cp /new/arrowhead-lite /usr/local/bin/"
  ssh $node "systemctl start arrowhead-lite"
  sleep 30
done
```

### Health Monitoring Script
```bash
#!/bin/bash
# monitor.sh

ENDPOINTS=("https://node1:8443/health" "https://node2:8443/health" "https://node3:8443/health")

for endpoint in "${ENDPOINTS[@]}"; do
  if ! curl -f -k "$endpoint" > /dev/null 2>&1; then
    echo "Health check failed for $endpoint"
    # Send alert
    curl -X POST https://alerts.example.com/webhook \
      -H "Content-Type: application/json" \
      -d "{\"text\":\"Arrowhead node unhealthy: $endpoint\"}"
  fi
done
```