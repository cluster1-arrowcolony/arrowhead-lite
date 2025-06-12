# RabbitMQ MQTT Setup for Arrowhead

This document explains how to set up RabbitMQ as an MQTT broker for the Arrowhead Gateway relay functionality.

## Overview

RabbitMQ provides robust MQTT support through its MQTT plugin, making it an excellent choice for production MQTT messaging in Arrowhead deployments. It offers:

- **MQTT 3.1.1 Protocol Support**: Full compliance with MQTT standard
- **Management UI**: Web-based administration interface
- **High Availability**: Clustering and persistence options
- **WebSocket Support**: MQTT over WebSockets for web clients
- **Security**: Authentication, authorization, and TLS support

## Quick Setup

### Option 1: Automated Setup Script

```bash
# Run the setup script
./setup-rabbitmq.sh

# The script will:
# 1. Detect if Docker or local RabbitMQ is available
# 2. Set up RabbitMQ with MQTT plugin enabled
# 3. Create user and virtual host
# 4. Test the connection
```

### Option 2: Docker Compose

```bash
# Start RabbitMQ with other services
cd docker
docker-compose up -d rabbitmq

# Or start everything
docker-compose up -d
```

### Option 3: Manual Docker

```bash
# Run RabbitMQ container with MQTT support
docker run -d \
  --name arrowhead-rabbitmq \
  -p 1883:1883 \
  -p 15672:15672 \
  -p 15675:15675 \
  -e RABBITMQ_DEFAULT_USER=arrowhead \
  -e RABBITMQ_DEFAULT_PASS=arrowhead \
  rabbitmq:3-management

# Enable MQTT plugins
docker exec arrowhead-rabbitmq rabbitmq-plugins enable rabbitmq_mqtt
docker exec arrowhead-rabbitmq rabbitmq-plugins enable rabbitmq_web_mqtt
```

## Port Configuration

| Port  | Service                | Description                          |
|-------|------------------------|--------------------------------------|
| 1883  | MQTT                   | Standard MQTT protocol               |
| 15672 | Management UI          | Web-based admin interface            |
| 15675 | MQTT WebSocket         | MQTT over WebSockets                 |
| 5672  | AMQP                   | RabbitMQ native protocol (optional)  |

## Environment Variables

Configure Arrowhead to use RabbitMQ MQTT:

```bash
export ARROWHEAD_MQTT_HOST=localhost
export ARROWHEAD_MQTT_PORT=1883
export ARROWHEAD_MQTT_USERNAME=arrowhead
export ARROWHEAD_MQTT_PASSWORD=arrowhead
```

For Docker deployments, these are automatically configured in `docker-compose.yml`.

## Management Interface

Access the RabbitMQ Management UI at: http://localhost:15672

- **Username**: `arrowhead`
- **Password**: `arrowhead`

The management interface provides:
- Queue and exchange monitoring
- Connection and channel statistics
- User and permission management
- Plugin configuration
- MQTT client tracking

## Arrowhead Configuration

The existing MQTT relay implementation in Arrowhead will work seamlessly with RabbitMQ. No code changes are required.

### Gateway Message Routing

Messages are published to topics following the pattern:
```
arrowhead/gateway/{target-cloud}/messages
```

RabbitMQ will automatically create these topics as needed.

### Connection Configuration

The `MQTTRelayClient` in `internal/relay.go` connects using standard MQTT client libraries, which are fully compatible with RabbitMQ's MQTT plugin.

## Production Considerations

### Persistence

RabbitMQ persists messages and configuration by default. The Docker volume `rabbitmq_data` ensures data survives container restarts.

### Clustering

For high availability, set up RabbitMQ clustering:

```yaml
services:
  rabbitmq-1:
    image: rabbitmq:3-management
    environment:
      - RABBITMQ_ERLANG_COOKIE=arrowhead-cluster-cookie
      - RABBITMQ_DEFAULT_USER=arrowhead
      - RABBITMQ_DEFAULT_PASS=arrowhead
    # ... additional clustering configuration
```

### Security

For production deployments:

1. **Change Default Credentials**:
   ```bash
   export ARROWHEAD_MQTT_USERNAME=your-secure-username
   export ARROWHEAD_MQTT_PASSWORD=your-secure-password
   ```

2. **Enable TLS**:
   ```bash
   # Configure TLS certificates
   export ARROWHEAD_MQTT_TLS=true
   export ARROWHEAD_MQTT_CA_CERT=/path/to/ca.crt
   export ARROWHEAD_MQTT_CLIENT_CERT=/path/to/client.crt
   export ARROWHEAD_MQTT_CLIENT_KEY=/path/to/client.key
   ```

3. **Network Security**:
   - Use private networks
   - Configure firewalls
   - Limit connection access

## Troubleshooting

### Connection Issues

```bash
# Check if RabbitMQ is running
docker ps | grep rabbitmq

# Check MQTT port accessibility
nc -z localhost 1883

# View RabbitMQ logs
docker logs arrowhead-rabbitmq
```

### Plugin Issues

```bash
# Verify MQTT plugin is enabled
docker exec arrowhead-rabbitmq rabbitmq-plugins list | grep mqtt

# Enable plugins manually
docker exec arrowhead-rabbitmq rabbitmq-plugins enable rabbitmq_mqtt
```

### Performance Monitoring

Use the management interface to monitor:
- Connection counts
- Message rates
- Queue depths
- Memory usage

## Alternative MQTT Brokers

While RabbitMQ is recommended for production, the Arrowhead MQTT relay also works with:

- **Eclipse Mosquitto**: Lightweight MQTT broker
- **EMQX**: Scalable MQTT platform
- **HiveMQ**: Enterprise MQTT platform
- **Azure IoT Hub**: Cloud MQTT service
- **AWS IoT Core**: AWS managed MQTT service

Simply change the `ARROWHEAD_MQTT_HOST` and `ARROWHEAD_MQTT_PORT` environment variables to connect to any standard MQTT broker.