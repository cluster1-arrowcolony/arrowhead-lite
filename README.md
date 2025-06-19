# Arrowhead IoT Service Mesh
A lightweight IoT service mesh node built in Go that implements the Arrowhead Framework specification in a single, unified binary.

## Features
- **Single Binary Deployment** - Everything runs in one process with minimal setup
- **REST API** - Clean HTTP/JSON API for all operations
- **Service Registry** - Register and discover IoT services
- **Authentication & Authorization** - Certificate-based auth with mTLS support
- **Service Orchestration** - Intelligent service matching and recommendations
- **PostgreSQL/SQLite Storage** - Flexible database support
- **Docker Ready** - Complete containerization support
- **Certificate Management** - Built-in CA for certificate signing

## Quick Start

### Local Development
1. **Clone and build:**
```bash
git clone ssh://github.com/cluster1-arrowcolony/arrowhead-lite.git
cd arrowhead-lite
make build
```

2. **Run the server:**
```bash
./bin/arrowhead-lite
```

3. **Access the dashboard:**
```
http://localhost:8443
```

4. **Try the demo (optional):**
```bash
./examples/demo.sh
```

The demo script showcases a mining IoT scenario with device registration, service creation, and authorization rules.

### Using Docker Compose
The complete development stack includes monitoring services:

```bash
cd docker
docker-compose up -d
```

This starts:
- **Arrowhead Lite** - Main server on port 8443
- **PostgreSQL** - Database on port 5432
- **Prometheus** - Metrics collection on port 9090
- **Grafana** - Monitoring dashboard on port 3000

**Access Points:**
- Main API: http://localhost:8443
- Grafana: http://localhost:3000 (admin/admin)
- Prometheus: http://localhost:9090

**Check Status:**
```bash
docker-compose ps
docker-compose logs arrowhead-iot-mesh
```

**Stop Services:**
```bash
docker-compose down
```

#### Using Docker Only
For minimal deployment without monitoring:

```bash
# Build the image
docker build -f docker/Dockerfile -t arrowhead-lite .

# Run with SQLite (no external database needed)
docker run -d \
  --name arrowhead-lite \
  -p 8443:8443 \
  -e ARROWHEAD_DATABASE_TYPE=sqlite \
  -e ARROWHEAD_DATABASE_PATH=/app/data/arrowhead.db \
  -v arrowhead_data:/app/data \
  arrowhead-lite

# Check logs
docker logs arrowhead-lite
```

## Certificate Generation

The included certificate generation script (`scripts/generate-certs.sh`) creates a complete set of self-signed TLS certificates and JWT signing keys for secure local development:

**Files created:**
- `certs/truststore.pem` - CA certificate (public certificate for trust verification)
- `certs/ca.key` - CA private key (for signing other certificates)
- `certs/server.pem` - Server TLS certificate (for HTTPS connections)
- `certs/server.key` - Server private key (for HTTPS connections)
- `certs/sysop.pem` - Admin client certificate (for management operations)
- `certs/sysop.key` - Admin client private key (for management operations)
- `certs/sysop.p12` - Admin client PKCS#12 bundle (for SDK integration)
- `certs/ca.p12` - CA PKCS#12 keystore (for SDK system registration)
- `certs/auth-private.pem` - JWT signing private key (for token generation)
- `certs/auth-public.pem` - JWT verification public key (for token validation)

## API Documentation

### Service Registry

#### Register a System
```bash
curl -X POST http://localhost:8443/serviceregistry/mgmt/systems \
  -H "Content-Type: application/json" \
  -d '{
    "systemName": "my-iot-device",
    "address": "192.168.1.100",
    "port": 8080
  }'
```

#### Register a Service
```bash
curl -X POST http://localhost:8443/serviceregistry/mgmt \
  -H "Content-Type: application/json" \
  -d '{
    "serviceDefinition": "temperature-reading",
    "providerSystem": {
      "systemName": "my-iot-device",
      "address": "192.168.1.100",
      "port": 8080
    },
    "serviceUri": "/api/temperature",
    "interfaces": ["HTTP-SECURE-JSON"],
    "secure": "CERTIFICATE"
  }'
```

#### List Services
```bash
curl http://localhost:8443/serviceregistry/mgmt
```

### Authentication

#### Create Authorization Rule
```bash
curl -X POST http://localhost:8443/authorization/mgmt/intracloud \
  -H "Content-Type: application/json" \
  -d '{
    "consumerId": 1,
    "providerIds": [2],
    "serviceDefinitionIds": [1],
    "interfaceIds": [1]
  }'
```

### Service Orchestration

#### Find Services
```bash
curl -X POST http://localhost:8443/orchestrator/orchestration \
  -H "Content-Type: application/json" \
  -d '{
    "requesterSystem": {
      "systemName": "my-consumer-system",
      "address": "192.168.1.101",
      "port": 8081
    },
    "requestedService": {
      "serviceDefinitionRequirement": "temperature-reading"
    },
    "orchestrationFlags": {
      "matchmaking": true,
      "metadataSearch": true
    }
  }'
```

## Configuration

Configuration can be provided via:
1. YAML file (`configs/config.yaml`)
2. Environment variables (prefix `ARROWHEAD_`)
3. Command line flags

### Key Configuration Options

```yaml
server:
  host: "0.0.0.0"
  port: 8443
  read_timeout: "30s"
  write_timeout: "30s"
  tls:
    enabled: true
    cert_file: "certs/server.pem"
    key_file: "certs/server.key"
    truststore_file: "certs/truststore.pem"

database:
  # SQLite (default)
  type: "sqlite"
  path: "./arrowhead.db"
  # PostgreSQL
  # type: "postgres"
  # host: "localhost"
  # port: 5432
  # username: "arrowhead"
  # password: "arrowhead"
  # name: "arrowhead"

auth:
  token_duration: "24h"
  private_key_file: "certs/auth-private.pem"
  public_key_file: "certs/auth-public.pem"

logging:
  level: "warn"
  format: "text"
```

### Environment Variables

**Docker Compose Environment:**
```bash
# Server configuration
ARROWHEAD_SERVER_HOST=0.0.0.0
ARROWHEAD_SERVER_PORT=8443
ARROWHEAD_SERVER_TLS_ENABLED=true
ARROWHEAD_SERVER_TLS_CERT_FILE=certs/server.pem
ARROWHEAD_SERVER_TLS_KEY_FILE=certs/server.key
ARROWHEAD_SERVER_TLS_TRUSTSTORE_FILE=certs/truststore.pem

# Database configuration (PostgreSQL)
ARROWHEAD_DATABASE_TYPE=postgres
ARROWHEAD_DATABASE_HOST=postgres
ARROWHEAD_DATABASE_PORT=5432
ARROWHEAD_DATABASE_USERNAME=arrowhead
ARROWHEAD_DATABASE_PASSWORD=arrowhead
ARROWHEAD_DATABASE_NAME=arrowhead

# Authentication (RSA key files for JWT signing)
ARROWHEAD_AUTH_TOKEN_DURATION=24h
ARROWHEAD_AUTH_PRIVATE_KEY_FILE=certs/auth-private.pem
ARROWHEAD_AUTH_PUBLIC_KEY_FILE=certs/auth-public.pem

# Logging
ARROWHEAD_LOGGING_LEVEL=info
ARROWHEAD_LOGGING_FORMAT=json
```

**Local Development (SQLite):**
```bash
export ARROWHEAD_SERVER_PORT=8443
export ARROWHEAD_SERVER_TLS_ENABLED=false
export ARROWHEAD_DATABASE_TYPE=sqlite
export ARROWHEAD_DATABASE_PATH=./arrowhead.db
export ARROWHEAD_LOGGING_LEVEL=debug
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Arrowhead Lite Service Mesh             │
├─────────────────────────────────────────────────────────────┤
│                        REST API                             │
├─────────────────────────────────────────────────────────────┤
│     Registry  │  Auth/mTLS  │  Orchestration  │  CA         │
├─────────────────────────────────────────────────────────────┤
│                PostgreSQL/SQLite Database                   │
└─────────────────────────────────────────────────────────────┘
```

### Components
- **Registry**: Service and system registration/discovery
- **Auth**: Certificate-based authentication with mTLS
- **Orchestration**: Service matching and recommendations
- **CA**: Certificate Authority for signing system certificates
- **Storage**: PostgreSQL/SQLite database with schema management

## Client Integration

Arrowhead Lite implements the standard Arrowhead 4.x REST API, making it compatible with any HTTP client that can handle certificate-based authentication.

### Example Client Usage
```bash
# Register your system first
curl -X POST https://localhost:8443/serviceregistry/mgmt/systems \
  --cert client.pem --key client.key \
  -H "Content-Type: application/json" \
  -d '{"systemName": "my-client", "address": "localhost", "port": 8080}'

# Register a service
curl -X POST https://localhost:8443/serviceregistry/mgmt \
  --cert client.pem --key client.key \
  -H "Content-Type: application/json" \
  -d '{"serviceDefinition": "my-service", "providerSystem": {"systemName": "my-client", "address": "localhost", "port": 8080}, "serviceUri": "/api/data"}'

# Discover services via orchestration
curl -X POST https://localhost:8443/orchestrator/orchestration \
  --cert client.pem --key client.key \
  -H "Content-Type: application/json" \
  -d '{"requesterSystem": {"systemName": "my-client"}, "requestedService": {"serviceDefinitionRequirement": "my-service"}}'
```

## Development

### Prerequisites
- Go 1.21+
- PostgreSQL 12+
- Make

### Building
```bash
# Download dependencies
make deps

# Build application
make build

# Run tests
make test

# Run with hot reload
make dev

# Format and lint
make check
```

### Testing
```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Open coverage report
open coverage.html
```

### Docker Development
```bash
# Start development environment with full stack
cd docker
docker-compose up -d

# View logs from all services
docker-compose logs -f

# View logs from specific service
docker-compose logs -f arrowhead-iot-mesh
docker-compose logs -f postgres

# Rebuild and restart after code changes
docker-compose up --build -d arrowhead-lite

# Stop all services
docker-compose down

# Stop and remove volumes (clean slate)
docker-compose down -v
```

**Development Workflow:**
1. Make code changes
2. Run `docker-compose up --build -d arrowhead-lite` to rebuild only the app
3. Check logs with `docker-compose logs -f arrowhead-lite`
4. Test at http://localhost:8443

**Troubleshooting:**
```bash
# Check service health
docker-compose ps

# Restart a specific service
docker-compose restart arrowhead-lite

# Access container shell for debugging
docker-compose exec arrowhead-lite sh

# Check database connection
docker-compose exec postgres psql -U arrowhead -d arrowhead -c "SELECT version();"
```

## Deployment

### Production Checklist
1. **Security**:
   - Change default JWT secret
   - Enable TLS with proper certificates
   - Configure firewall rules
   - Use non-root user

2. **Monitoring**:
   - Deploy with Prometheus/Grafana
   - Configure health checks
   - Set up log aggregation

3. **Persistence**:
   - Mount database volume
   - Configure backups
   - Monitor disk space

### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: arrowhead-lite
spec:
  replicas: 1
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
        env:
        - name: ARROWHEAD_DATABASE_HOST
          value: "postgres-service"
        - name: ARROWHEAD_DATABASE_PORT
          value: "5432"
        - name: ARROWHEAD_DATABASE_USERNAME
          value: "arrowhead"
        - name: ARROWHEAD_DATABASE_PASSWORD
          valueFrom:
            secretKeyRef:
              name: postgres-secret
              key: password
        - name: ARROWHEAD_DATABASE_NAME
          value: "arrowhead"
```

## Monitoring & Observability

### Health Checks
- Main health endpoint: `/health` - Returns server health status

### Logging
Structured logging with configurable levels:
- Request/response logging
- Service lifecycle events
- Error tracking

## Arrowhead Framework Compatibility

This implementation follows the Arrowhead Framework specification and provides full compatibility with core Arrowhead services and systems.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run `make check`
6. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

- GitHub Issues: Report bugs and feature requests
- Documentation: See `/docs` directory
- Examples: Check `/examples` directory

---

Built with ❤️ for the IoT community
