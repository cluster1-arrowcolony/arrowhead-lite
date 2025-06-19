# Arrowhead IoT Service Mesh
A lightweight IoT service mesh node built in Go that implements the Arrowhead Framework specification in a single, unified binary.

## Features
- **Single Binary Deployment** - Everything runs in one process with minimal setup
- **REST API** - Clean HTTP/JSON API for all operations
- **Service Registry** - Register and discover IoT services
- **Authentication & Authorization** - JWT-based auth with certificate support
- **Service Orchestration** - Intelligent service matching and recommendations
- **Pub/Sub Events** - Real-time event node with WebSocket support
- **Health Monitoring** - Automatic service health checking
- **Web Dashboard** - Monitoring interface
- **PostgreSQL Storage** - Reliable database with full SQL support
- **Docker Ready** - Complete containerization support
- **Prometheus Metrics** - Built-in observability

## Quick Start

### Local Development
1. **Clone and build:**
```bash
git clone <repo-url>
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

The demo script showcases a complete mining IoT scenario with device registration, service creation, and authorization rules. The script is smart:
- **With Docker Compose**: Automatically detects and uses the running server
- **Without server**: Starts its own local instance and cleans up when done

### Docker Deployment

#### Using Docker Compose (recommended)
The complete development stack includes monitoring and messaging services:

```bash
cd docker
docker-compose up -d
```

This starts:
- **Arrowhead Lite** - Main server on port 8443
- **PostgreSQL** - Database on port 5432 
- **RabbitMQ** - MQTT messaging on ports 1883, 15672 (management UI)
- **Prometheus** - Metrics collection on port 9090
- **Grafana** - Monitoring dashboard on port 3000

**Access Points:**
- Dashboard: http://localhost:8443
- Grafana: http://localhost:3000 (admin/admin)
- RabbitMQ Management: http://localhost:15672 (arrowhead/arrowhead) 
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

## Demo Script

The included demo script (`examples/demo.sh`) creates a realistic mining IoT scenario:

```bash
# Works with both Docker Compose and local development
./examples/demo.sh
```

**What it demonstrates:**
- 6 mining devices (gas detector, vibration monitor, conveyor controller, etc.)
- 6 services (sensor readings, equipment control, safety alerts)
- 8 authorization rules (inter-device communication permissions)
- Admin authentication and service management

**Intelligent behavior:**
- **Auto-detects existing server**: If you have Docker Compose running, it uses that
- **Starts local server**: If no server is found, starts a clean local instance
- **Clean database**: Prevents conflicts by clearing old data when starting locally
- **Graceful cleanup**: Only stops servers it started, leaves Docker containers alone

**Expected output:**
```
🚀 Arrowhead Lite Demo
======================
🔍 Checking if arrowhead-lite server is already running...
✅ Found existing arrowhead-lite server at http://localhost:8443
📡 Using existing server for demo
🧪 Testing Go API...
...
🎉 Demo completed successfully!
```

## API Documentation

### Service Registry

#### Register a Node
```bash
curl -X POST http://localhost:8443/api/v1/registry/nodes \
  -H "Content-Type: application/json" \
  -d '{
    "node": {
      "name": "my-iot-device",
      "address": "192.168.1.100",
      "port": 8080
    }
  }'
```

#### Register a Service
```bash
curl -X POST http://localhost:8443/api/v1/registry/services \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "service": {
      "name": "temperature-sensor",
      "node_id": "<node-id>",
      "definition": "temperature-reading",
      "uri": "/api/temperature",
      "method": "GET"
    }
  }'
```

#### List Services
```bash
curl http://localhost:8443/api/v1/registry/services
```

### Authentication

#### Create Authorization Rule
```bash
curl -X POST http://localhost:8443/api/v1/auth/rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "consumer_id": "<consumer-node-id>",
    "provider_id": "<provider-node-id>",
    "service_id": "<service-id>"
  }'
```

### Service Orchestration

#### Find Services
```bash
curl -X POST http://localhost:8443/api/v1/orchestration \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "requester_id": "<node-id>",
    "service_name": "temperature-sensor",
    "preferences": {
      "max_results": 5,
      "preferred_version": "1.0"
    }
  }'
```

### Events & Messaging

#### Publish Event
```bash
curl -X POST http://localhost:8443/api/v1/events/publish \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "type": "sensor-reading",
    "topic": "temperature",
    "payload": {
      "temperature": 23.5,
      "unit": "celsius",
      "timestamp": "2024-01-01T12:00:00Z"
    }
  }'
```

#### Subscribe to Events
```bash
curl -X POST http://localhost:8443/api/v1/events/subscribe \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "topic": "temperature",
    "endpoint": "http://my-service:8080/events",
    "filters": {
      "type": "sensor-reading"
    }
  }'
```

#### WebSocket Subscription
```javascript
const ws = new WebSocket('ws://localhost:8443/api/v1/events/subscribe/ws?topic=temperature&Authorization=Bearer%20<token>');
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Received event:', data);
};
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
  tls:
    enabled: false
    cert_file: "certs/server-cert.pem"
    key_file: "certs/server-key.pem"

database:
  type: "postgres"
  host: "localhost"
  port: 5432
  username: "arrowhead"
  password: "arrowhead"
  name: "arrowhead"

auth:
  jwt_secret: "your-secret-key"
  token_duration: "24h"

logging:
  level: "info"
  format: "json"
```

### Environment Variables

**Docker Compose Environment:**
```bash
# Server configuration
ARROWHEAD_SERVER_HOST=0.0.0.0
ARROWHEAD_SERVER_PORT=8443

# Database configuration (PostgreSQL)
ARROWHEAD_DATABASE_TYPE=postgres
ARROWHEAD_DATABASE_HOST=postgres
ARROWHEAD_DATABASE_PORT=5432
ARROWHEAD_DATABASE_USERNAME=arrowhead
ARROWHEAD_DATABASE_PASSWORD=arrowhead
ARROWHEAD_DATABASE_NAME=arrowhead

# Authentication
ARROWHEAD_AUTH_JWT_SECRET=your-super-secret-jwt-key-change-this

# Logging
ARROWHEAD_LOGGING_LEVEL=info
ARROWHEAD_LOGGING_FORMAT=json

# Health monitoring
ARROWHEAD_HEALTH_CHECK_INTERVAL=1m
ARROWHEAD_HEALTH_INACTIVE_TIMEOUT=5m
ARROWHEAD_HEALTH_CLEANUP_INTERVAL=10m
```

**Local Development (SQLite):**
```bash
export ARROWHEAD_SERVER_PORT=8443
export ARROWHEAD_DATABASE_TYPE=sqlite
export ARROWHEAD_DATABASE_PATH=./arrowhead.db
export ARROWHEAD_AUTH_JWT_SECRET=your-super-secret-key
export ARROWHEAD_LOGGING_LEVEL=debug
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Arrowhead IoT Service Mesh              │
├─────────────────────────────────────────────────────────────┤
│  Web Dashboard  │  REST API  │  WebSocket Events           │
├─────────────────────────────────────────────────────────────┤
│  Registry  │  Auth  │  Orchestration  │  Events  │ Health  │
├─────────────────────────────────────────────────────────────┤
│                   PostgreSQL Database                       │
└─────────────────────────────────────────────────────────────┘
```

### Components
- **Registry**: Service and node registration/discovery
- **Auth**: JWT tokens, certificates, authorization rules
- **Orchestration**: Service matching, recommendations, health analysis
- **Events**: Pub/sub messaging with WebSocket support
- **Health**: Automatic health monitoring and cleanup
- **Storage**: PostgreSQL database with schema management

## Python Integration

The arrowhead-lite server integrates seamlessly with the official **arrowhead-py-sdk**. This provides a clean, standardized way to build Python applications that work with the Arrowhead Framework.

### Using arrowhead-py-sdk
```bash
# Install the official Python SDK
pip install arrowhead-py-sdk

# Start arrowhead-lite server
./bin/arrowhead-lite
```

### Quick Python Example
```python
from py_arrowhead import Framework, node, service

@node("my-python-node")
class MyPythonNode:
    def __init__(self, key="python-node"):
        self.key = key
    
    @service("temperature-reading", method="GET", endpoint="/temperature")
    def get_temperature(self) -> dict:
        return {"temperature": 23.5, "unit": "celsius"}

# Start the node
if __name__ == "__main__":
    node = MyPythonNode()
    node.start(port=8080)
```

See [`examples/python-integration.md`](examples/python-integration.md) for detailed setup instructions and examples.

**Key Benefits:**
- ✅ Official Arrowhead Python SDK support
- ✅ Clean decorator-based service registration
- ✅ Automatic service discovery and health checks
- ✅ Compatible with all Arrowhead Framework features
- ✅ Simple HTTP/JSON API communication

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
3. Check logs with `docker-compose logs -f arrowhead-iot-mesh`
4. Test at http://localhost:8443

**Troubleshooting:**
```bash
# Check service health
docker-compose ps

# Restart a specific service
docker-compose restart arrowhead-iot-mesh

# Access container shell for debugging
docker-compose exec arrowhead-iot-mesh sh

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

### Metrics
Prometheus metrics available at `/metrics`:
- HTTP request duration and count
- Database connection stats
- Node and service counts
- Event processing metrics

### Health Checks
- Main health endpoint: `/health`
- Service-specific health analysis
- Automatic cleanup of inactive nodes
- Configurable health check intervals

### Logging
Structured JSON logging with configurable levels:
- Request/response logging
- Service lifecycle events
- Error tracking and alerting
- Performance metrics

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
