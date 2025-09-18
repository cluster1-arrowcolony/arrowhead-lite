# Configuration Guide

## Overview

Arrowhead Lite uses a flexible configuration system that supports multiple sources with clear precedence rules. Configuration can be provided through YAML files, environment variables, and command-line flags.

## Configuration Precedence

Configuration values are loaded in the following order (later sources override earlier ones):

1. Default values (built into the application)
2. Configuration file (YAML)
3. Environment variables
4. Command-line flags

## Configuration File

### Location

The configuration file can be specified using:
- `--config` flag: `./arrowhead-lite --config /path/to/config.yaml`
- Default locations searched in order:
  1. `./config.yaml`
  2. `./config/config.yaml`
  3. `/etc/arrowhead/config.yaml`
  4. `$HOME/.arrowhead/config.yaml`

### Complete Configuration Example

```yaml
# config.yaml - Complete configuration reference
# All values shown are defaults unless otherwise noted

# Server configuration
server:
  # Network binding address
  host: "0.0.0.0"
  
  # HTTP/HTTPS port
  port: 8080
  
  # Read timeout for incoming requests
  read_timeout: "30s"
  
  # Write timeout for responses
  write_timeout: "30s"
  
  # Maximum request header size
  max_header_bytes: 1048576
  
  # Enable request body size limit
  max_request_size: "10MB"
  
  # CORS configuration
  cors:
    enabled: true
    allowed_origins: ["*"]
    allowed_methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    allowed_headers: ["*"]
    exposed_headers: ["X-Total-Count"]
    allow_credentials: false
    max_age: 3600

# TLS/mTLS configuration
tls:
  # Enable TLS
  enabled: false
  
  # Server certificate path
  cert: "certs/server.crt"
  
  # Server private key path
  key: "certs/server.key"
  
  # CA certificate for client verification
  ca_cert: "certs/ca.crt"
  
  # Require client certificates
  client_auth: true
  
  # Minimum TLS version (TLS1.2, TLS1.3)
  min_version: "TLS1.2"
  
  # Cipher suites (leave empty for defaults)
  cipher_suites: []
  
  # Certificate verification depth
  verify_depth: 3

# Database configuration
database:
  # Database type (sqlite, postgres)
  type: "sqlite"
  
  # SQLite specific
  path: "data/arrowhead.db"
  
  # PostgreSQL specific
  host: "localhost"
  port: 5432
  name: "arrowhead"
  user: "arrowhead"
  password: ""  # Use environment variable in production
  
  # SSL mode for PostgreSQL (disable, require, verify-ca, verify-full)
  ssl_mode: "prefer"
  
  # Connection pool settings
  max_open_connections: 25
  max_idle_connections: 5
  connection_max_lifetime: "5m"
  
  # Query timeout
  query_timeout: "30s"
  
  # Enable query logging
  log_queries: false
  
  # Automatic migrations
  auto_migrate: true

# Authentication configuration
auth:
  # JWT token settings
  jwt:
    # Secret key for signing (use environment variable in production)
    secret: ""
    
    # Token expiration time
    expiration: "24h"
    
    # Token issuer
    issuer: "arrowhead-lite"
    
    # Refresh token expiration
    refresh_expiration: "168h"
  
  # RSA key paths for token signing
  rsa:
    private_key: "keys/private.pem"
    public_key: "keys/public.pem"
    
    # Auto-generate keys if missing
    auto_generate: true
  
  # Session configuration
  session:
    # Session timeout
    timeout: "1h"
    
    # Session cleanup interval
    cleanup_interval: "10m"
    
    # Maximum concurrent sessions per user
    max_sessions: 5
  
  # Rate limiting
  rate_limit:
    # Enable rate limiting
    enabled: true
    
    # Requests per minute
    requests: 100
    
    # Burst size
    burst: 20
    
    # Rate limit by IP or by user
    by: "ip"  # "ip" or "user"

# Service Registry configuration
registry:
  # Service heartbeat timeout
  heartbeat_timeout: "60s"
  
  # Heartbeat check interval
  heartbeat_interval: "30s"
  
  # Service cleanup interval
  cleanup_interval: "5m"
  
  # Maximum services per system
  max_services_per_system: 100
  
  # Enable service versioning
  enable_versioning: false
  
  # Default service TTL
  default_ttl: "24h"
  
  # Service discovery cache
  cache:
    enabled: true
    ttl: "5m"
    max_entries: 1000

# Authorization configuration
authorization:
  # Default authorization policy (allow, deny)
  default_policy: "deny"
  
  # Enable rule caching
  cache_enabled: true
  
  # Cache TTL
  cache_ttl: "10m"
  
  # Maximum rules per consumer
  max_rules_per_consumer: 1000
  
  # Rule evaluation timeout
  evaluation_timeout: "100ms"
  
  # Enable audit logging
  audit_logging: true
  
  # Audit log retention
  audit_retention: "30d"

# Orchestration configuration
orchestration:
  # Matchmaking algorithm (first, random, round-robin, least-connections, weighted)
  algorithm: "round-robin"
  
  # Enable QoS evaluation
  qos_enabled: false
  
  # QoS weights
  qos_weights:
    latency: 0.3
    availability: 0.3
    throughput: 0.2
    cost: 0.2
  
  # Maximum providers to return
  max_providers: 10
  
  # Provider health check
  health_check:
    enabled: true
    interval: "30s"
    timeout: "5s"
    threshold: 3
  
  # Load balancing
  load_balancing:
    enabled: false
    method: "least-connections"
    sticky_sessions: false
    session_timeout: "10m"

# Certificate Authority configuration
ca:
  # CA certificate path
  cert: "certs/ca.crt"
  
  # CA private key path
  key: "certs/ca.key"
  
  # Default certificate validity (days)
  default_validity: 365
  
  # Maximum certificate validity (days)
  max_validity: 730
  
  # Certificate fields defaults
  country: "US"
  organization: "Arrowhead"
  organizational_unit: "IoT"
  locality: "Default City"
  province: "Default State"
  
  # Enable certificate revocation
  enable_revocation: false
  
  # CRL update interval
  crl_update_interval: "24h"
  
  # OCSP responder URL
  ocsp_url: ""

# Logging configuration
logging:
  # Log level (debug, info, warn, error, fatal)
  level: "info"
  
  # Log format (text, json)
  format: "text"
  
  # Log output (stdout, file, both)
  output: "stdout"
  
  # Log file configuration
  file:
    path: "logs/arrowhead.log"
    max_size: "100MB"
    max_backups: 10
    max_age: 30
    compress: true
  
  # Include caller information
  include_caller: false
  
  # Include timestamp
  include_timestamp: true
  
  # Timestamp format
  timestamp_format: "2006-01-02T15:04:05Z07:00"
  
  # Log specific components
  components:
    server: "info"
    database: "warn"
    auth: "info"
    registry: "info"
    orchestration: "info"
    ca: "warn"

# Monitoring configuration
monitoring:
  # Enable metrics endpoint
  metrics_enabled: true
  
  # Metrics port (0 uses main port)
  metrics_port: 9090
  
  # Metrics path
  metrics_path: "/metrics"
  
  # Enable health check endpoint
  health_enabled: true
  
  # Health check path
  health_path: "/health"
  
  # Enable readiness check
  readiness_enabled: true
  
  # Readiness check path
  readiness_path: "/ready"
  
  # Tracing configuration
  tracing:
    enabled: false
    provider: "jaeger"  # jaeger, zipkin, otlp
    endpoint: "http://localhost:14268/api/traces"
    sample_rate: 0.1
    service_name: "arrowhead-lite"

# Feature flags
features:
  # Enable experimental features
  experimental: false
  
  # Enable WebSocket support
  websocket: true
  
  # Enable GraphQL endpoint
  graphql: false
  
  # Enable service mesh integration
  service_mesh: false
  
  # Enable multi-tenancy
  multi_tenancy: false
  
  # Enable event streaming
  event_streaming: false
  
  # Enable service discovery via DNS
  dns_discovery: false

# Advanced configuration
advanced:
  # Worker pool size
  worker_pool_size: 10
  
  # Event buffer size
  event_buffer_size: 1000
  
  # Cache configuration
  cache:
    type: "memory"  # memory, redis
    redis_url: "redis://localhost:6379"
    default_ttl: "5m"
    max_entries: 10000
  
  # Message queue configuration
  queue:
    type: "memory"  # memory, rabbitmq, kafka
    url: ""
    max_retries: 3
    retry_delay: "1s"
  
  # Graceful shutdown timeout
  shutdown_timeout: "30s"
  
  # Enable profiling endpoint
  profiling: false
  
  # Profiling port
  profiling_port: 6060
```

## Environment Variables

All configuration options can be set via environment variables using the `ARROWHEAD_` prefix and converting to uppercase with underscores.

### Common Environment Variables

```bash
# Server settings
export ARROWHEAD_SERVER_HOST="0.0.0.0"
export ARROWHEAD_SERVER_PORT="8443"
export ARROWHEAD_SERVER_READ_TIMEOUT="30s"
export ARROWHEAD_SERVER_WRITE_TIMEOUT="30s"

# TLS settings
export ARROWHEAD_TLS_ENABLED="true"
export ARROWHEAD_TLS_CERT="/path/to/server.crt"
export ARROWHEAD_TLS_KEY="/path/to/server.key"
export ARROWHEAD_TLS_CA_CERT="/path/to/ca.crt"
export ARROWHEAD_TLS_CLIENT_AUTH="true"

# Database settings
export ARROWHEAD_DATABASE_TYPE="postgres"
export ARROWHEAD_DATABASE_HOST="localhost"
export ARROWHEAD_DATABASE_PORT="5432"
export ARROWHEAD_DATABASE_NAME="arrowhead"
export ARROWHEAD_DATABASE_USER="arrowhead"
export ARROWHEAD_DATABASE_PASSWORD="secure_password"
export ARROWHEAD_DATABASE_SSL_MODE="require"

# Authentication settings
export ARROWHEAD_AUTH_JWT_SECRET="your-secret-key"
export ARROWHEAD_AUTH_JWT_EXPIRATION="24h"
export ARROWHEAD_AUTH_RATE_LIMIT_ENABLED="true"
export ARROWHEAD_AUTH_RATE_LIMIT_REQUESTS="100"

# Logging settings
export ARROWHEAD_LOGGING_LEVEL="info"
export ARROWHEAD_LOGGING_FORMAT="json"
export ARROWHEAD_LOGGING_OUTPUT="file"
export ARROWHEAD_LOGGING_FILE_PATH="/var/log/arrowhead/app.log"

# Feature flags
export ARROWHEAD_FEATURES_EXPERIMENTAL="false"
export ARROWHEAD_FEATURES_WEBSOCKET="true"
export ARROWHEAD_FEATURES_GRAPHQL="false"
```

### Docker Environment File

`.env` file for Docker Compose:
```bash
# Database
DB_TYPE=postgres
DB_HOST=postgres
DB_PORT=5432
DB_NAME=arrowhead
DB_USER=arrowhead
DB_PASSWORD=secure_password

# TLS
TLS_ENABLED=true
TLS_CERT_PATH=/certs/server.crt
TLS_KEY_PATH=/certs/server.key
TLS_CA_PATH=/certs/ca.crt

# Authentication
JWT_SECRET=your-jwt-secret-key
JWT_EXPIRATION=24h

# Logging
LOG_LEVEL=info
LOG_FORMAT=json

# Monitoring
METRICS_ENABLED=true
METRICS_PORT=9090
```

## Command-Line Flags

Command-line flags override all other configuration sources.

### Available Flags

```bash
# Show help
./arrowhead-lite --help

# Basic flags
./arrowhead-lite \
  --config /path/to/config.yaml \
  --host 0.0.0.0 \
  --port 8443 \
  --verbose

# TLS flags
./arrowhead-lite \
  --tls \
  --tls-cert /path/to/server.crt \
  --tls-key /path/to/server.key \
  --ca-cert /path/to/ca.crt \
  --client-auth

# Database flags
./arrowhead-lite \
  --db-type postgres \
  --db-host localhost \
  --db-port 5432 \
  --db-name arrowhead \
  --db-user arrowhead \
  --db-password secret

# Development flags
./arrowhead-lite \
  --disable-tls \
  --debug \
  --log-queries \
  --profiling

# Feature flags
./arrowhead-lite \
  --enable-experimental \
  --enable-websocket \
  --disable-auth
```

### Flag Reference

```
Usage:
  arrowhead-lite [flags]

Flags:
  Server:
    --config string          Config file path
    --host string           Server host (default "0.0.0.0")
    --port int             Server port (default 8080)
    --metrics-port int     Metrics port (default 9090)
    
  TLS:
    --tls                  Enable TLS
    --disable-tls          Disable TLS (development)
    --tls-cert string      TLS certificate path
    --tls-key string       TLS key path
    --ca-cert string       CA certificate path
    --client-auth          Require client certificates
    
  Database:
    --db-type string       Database type (sqlite, postgres)
    --db-path string       SQLite database path
    --db-host string       PostgreSQL host
    --db-port int         PostgreSQL port
    --db-name string       Database name
    --db-user string       Database user
    --db-password string   Database password
    
  Authentication:
    --jwt-secret string    JWT secret key
    --jwt-expiration duration  JWT expiration time
    --disable-auth         Disable authentication
    
  Logging:
    --log-level string     Log level (debug, info, warn, error)
    --log-format string    Log format (text, json)
    --log-file string      Log file path
    --verbose             Enable verbose logging (debug level)
    --quiet               Minimal logging (error level)
    --log-queries         Log database queries
    
  Features:
    --enable-experimental  Enable experimental features
    --enable-websocket    Enable WebSocket support
    --enable-graphql      Enable GraphQL endpoint
    --profiling          Enable profiling endpoint
    
  Other:
    --version            Show version information
    --help              Show help message
```

## Configuration Profiles

### Development Profile

`config.dev.yaml`:
```yaml
server:
  port: 8080

tls:
  enabled: false

database:
  type: sqlite
  path: "dev.db"

logging:
  level: debug
  format: text
  include_caller: true

auth:
  rate_limit:
    enabled: false

monitoring:
  metrics_enabled: true
  profiling: true
```

Run with: `./arrowhead-lite --config config.dev.yaml`

### Production Profile

`config.prod.yaml`:
```yaml
server:
  port: 8443

tls:
  enabled: true
  min_version: "TLS1.3"
  client_auth: true

database:
  type: postgres
  ssl_mode: require
  max_open_connections: 50
  log_queries: false

logging:
  level: info
  format: json
  output: file
  file:
    path: "/var/log/arrowhead/production.log"

auth:
  rate_limit:
    enabled: true
    requests: 60

monitoring:
  metrics_enabled: true
  tracing:
    enabled: true
```

Run with: `./arrowhead-lite --config config.prod.yaml`

### Testing Profile

`config.test.yaml`:
```yaml
server:
  port: 8081

tls:
  enabled: false

database:
  type: sqlite
  path: ":memory:"
  auto_migrate: true

logging:
  level: warn
  format: text

auth:
  jwt:
    expiration: "1m"
```

Run with: `./arrowhead-lite --config config.test.yaml`

## Dynamic Configuration

### Configuration Reload

Send SIGHUP to reload configuration without restart:
```bash
# Find process ID
pidof arrowhead-lite

# Send reload signal
kill -HUP <PID>
```

### Runtime Configuration API

**GET** `/admin/config`
```json
{
  "current_config": {
    "server": {...},
    "database": {...}
  }
}
```

**PUT** `/admin/config`
```json
{
  "logging": {
    "level": "debug"
  }
}
```

## Configuration Validation

### Validation Tool

```bash
# Validate configuration file
./arrowhead-lite validate --config config.yaml

# Output
Configuration validation:
✓ Server configuration valid
✓ TLS configuration valid
✓ Database connection successful
✓ Authentication keys present
✓ All required fields present
```

### Common Validation Errors

1. **Missing TLS certificates**
   ```
   Error: TLS enabled but certificate files not found
   Solution: Ensure cert and key paths are correct
   ```

2. **Database connection failure**
   ```
   Error: Cannot connect to database
   Solution: Check database credentials and network
   ```

3. **Invalid JWT secret**
   ```
   Error: JWT secret too short (minimum 32 characters)
   Solution: Generate stronger secret key
   ```

## Secret Management

### Using External Secret Stores

#### HashiCorp Vault
```yaml
secrets:
  provider: vault
  vault:
    address: "https://vault.example.com"
    token: "${VAULT_TOKEN}"
    path: "secret/arrowhead"
```

#### AWS Secrets Manager
```yaml
secrets:
  provider: aws
  aws:
    region: "us-west-2"
    secret_name: "arrowhead-secrets"
```

#### Kubernetes Secrets
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: arrowhead-secrets
type: Opaque
data:
  jwt-secret: <base64-encoded>
  db-password: <base64-encoded>
```

### Secret Rotation

```bash
# Generate new JWT secret
openssl rand -base64 32 > jwt-secret.txt

# Update configuration
export ARROWHEAD_AUTH_JWT_SECRET=$(cat jwt-secret.txt)

# Restart with zero downtime
systemctl reload arrowhead-lite
```

## Performance Tuning

### Database Connection Pool
```yaml
database:
  max_open_connections: 50  # Increase for high load
  max_idle_connections: 10  # Keep connections ready
  connection_max_lifetime: "30m"  # Refresh connections
```

### Worker Pool
```yaml
advanced:
  worker_pool_size: 20  # CPU cores * 2
  event_buffer_size: 5000  # Increase for bursty traffic
```

### Cache Settings
```yaml
registry:
  cache:
    enabled: true
    ttl: "10m"  # Longer TTL for stable environments
    max_entries: 5000  # Increase for many services
```

## Monitoring Configuration

### Metrics Collection
```yaml
monitoring:
  metrics_enabled: true
  metrics_port: 9090
  metrics_path: "/metrics"
```

### Log Aggregation
```yaml
logging:
  format: "json"  # Structured for log aggregators
  output: "both"  # stdout for containers, file for VMs
  file:
    path: "/var/log/arrowhead/app.log"
    max_size: "100MB"
    max_backups: 10
```

## Migration Guide

### From v1.x to v2.x

Configuration changes:
```yaml
# Old (v1.x)
server:
  tls_enabled: true
  tls_cert: "cert.pem"

# New (v2.x)
tls:
  enabled: true
  cert: "cert.pem"
```

Migration script:
```bash
#!/bin/bash
# migrate-config.sh

# Backup old config
cp config.yaml config.yaml.backup

# Run migration tool
./arrowhead-lite migrate-config \
  --from v1 \
  --to v2 \
  --input config.yaml.backup \
  --output config.yaml
```