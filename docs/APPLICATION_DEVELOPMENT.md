# Application Development Guide

**Audience:** Application programmers building services that connect to Arrowhead Lite

This guide shows you how to integrate your applications with Arrowhead Lite for service registration, discovery, and orchestration.

> **SDK Users:** For easier integration, consider using an SDK:
> - **Python:** [Arrowhead Python SDK](https://github.com/cluster1-arrowcolony/arrowhead-python-sdk)
> - **Go:** [Arrowhead Go Client](https://github.com/eislab-cps/arrowhead-client-go)
>
> These SDKs provide high-level abstractions for registration, discovery, and orchestration. This guide shows the raw REST API for those using other languages or who want to understand the underlying protocol.

## Quick Start

### 1. Start Local Arrowhead Lite

```bash
# Download and run (development mode - no TLS)
./arrowhead-lite --disable-tls --verbose

# Or use Docker
docker run -d -p 8080:8080 -e ARROWHEAD_TLS_ENABLED=false arrowhead-lite:latest
```

Arrowhead Lite is now running at `http://localhost:8080`

### 2. Test Connection

```bash
curl http://localhost:8080/health
# Response: {"status":"healthy"}
```

### 3. Register Your First Service

Create `my-service.json`:
```json
{
  "system": {
    "systemName": "my-app",
    "address": "192.168.1.100",
    "port": 8081
  },
  "services": [{
    "serviceDefinition": "temperature",
    "interfaces": ["HTTP-SECURE-JSON"],
    "serviceUri": "/api/temperature"
  }]
}
```

Register:
```bash
curl -X POST http://localhost:8080/serviceregistry/register \
  -H "Content-Type: application/json" \
  -d @my-service.json
```

### 4. Discover Services

```bash
curl -X POST http://localhost:8080/serviceregistry/query \
  -H "Content-Type: application/json" \
  -d '{"serviceDefinitionRequirement": "temperature"}'
```

You're connected! Continue reading for complete integration patterns.

## Core Concepts

### Systems
A **system** is your application or device (e.g., a temperature sensor, control system, or data processor).

### Services
A **service** is a capability your system provides (e.g., "get temperature", "control valve", "store data").

### Service Registry
The registry is where systems register their services and discover services provided by others.

### Orchestration
The orchestrator helps your system find the right service provider based on authorization and metadata.

## Service Registration

**Visual Guide**: See the [System and Service Registration diagram](./diagrams/2-system-service-registration.md) for a complete visual walkthrough.

### Registering Your Application

**POST** `/serviceregistry/register`

```json
{
  "system": {
    "systemName": "sensor-001",
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
        "unit": "celsius",
        "location": "building-a-room-101"
      }
    }
  ]
}
```

**Response:**
```json
{
  "system": {
    "id": 1,
    "systemName": "sensor-001",
    "address": "192.168.1.100",
    "port": 8081
  },
  "services": [
    {
      "id": 1,
      "serviceDefinition": "temperature",
      "interfaces": ["HTTP-SECURE-JSON"],
      "serviceUri": "/api/temperature"
    }
  ]
}
```

### Service Metadata

Use metadata to add searchable information:
```json
{
  "metadata": {
    "unit": "celsius",
    "location": "warehouse-2",
    "accuracy": "0.1",
    "updateRate": "1Hz"
  }
}
```

### Unregistering

**DELETE** `/serviceregistry/unregister`

```json
{
  "systemName": "sensor-001",
  "address": "192.168.1.100",
  "port": 8081
}
```

## Service Discovery

### Query by Service Definition

**POST** `/serviceregistry/query`

```json
{
  "serviceDefinitionRequirement": "temperature"
}
```

### Query with Metadata Filter

```json
{
  "serviceDefinitionRequirement": "temperature",
  "metadataRequirements": {
    "location": "warehouse-2"
  }
}
```

### Query Response

```json
{
  "serviceQueryData": [
    {
      "provider": {
        "systemName": "sensor-001",
        "address": "192.168.1.100",
        "port": 8081
      },
      "serviceDefinition": "temperature",
      "interfaces": ["HTTP-SECURE-JSON"],
      "serviceUri": "/api/temperature",
      "metadata": {
        "unit": "celsius",
        "location": "warehouse-2"
      }
    }
  ]
}
```

## Orchestration

**Visual Guide**: See the [Service Orchestration Flow diagram](./diagrams/3-orchestration-flow.md) for the complete orchestration process.

### Request Orchestration

The orchestrator helps find authorized providers for your system.

**POST** `/orchestrator/orchestration`

```json
{
  "requesterSystem": {
    "systemName": "controller-001",
    "address": "192.168.1.50",
    "port": 8082
  },
  "requestedService": {
    "serviceDefinitionRequirement": "temperature",
    "interfaceRequirements": ["HTTP-SECURE-JSON"]
  },
  "orchestrationFlags": {
    "matchmaking": true,
    "metadataSearch": true
  }
}
```

### Orchestration Response

```json
{
  "response": [
    {
      "provider": {
        "systemName": "sensor-001",
        "address": "192.168.1.100",
        "port": 8081
      },
      "service": {
        "serviceDefinition": "temperature",
        "serviceUri": "/api/temperature"
      },
      "authorizationToken": "optional-token-if-configured"
    }
  ]
}
```

## Code Examples

**Visual Guide**: After orchestration, systems communicate directly. See the [Direct Service Consumption diagram](./diagrams/4-service-consumption.md) for how services interact after discovery.

### Python Example: Temperature Sensor

> **Note:** This example uses the raw REST API. For a simpler approach with automatic registration, heartbeat, and error handling, see the [Arrowhead Python SDK](https://github.com/cluster1-arrowcolony/arrowhead-python-sdk).

```python
#!/usr/bin/env python3
import time
import random
import requests
from flask import Flask, jsonify

app = Flask(__name__)

# Configuration
ARROWHEAD_URL = "http://localhost:8080"
SYSTEM_NAME = "temp-sensor-1"
SYSTEM_ADDRESS = "127.0.0.1"
SYSTEM_PORT = 8081

@app.route('/api/temperature')
def get_temperature():
    """Provide temperature data"""
    temp = round(20 + random.uniform(-5, 5), 2)
    return jsonify({
        "temperature": temp,
        "unit": "celsius",
        "timestamp": int(time.time())
    })

def register():
    """Register with Arrowhead Lite"""
    registration = {
        "system": {
            "systemName": SYSTEM_NAME,
            "address": SYSTEM_ADDRESS,
            "port": SYSTEM_PORT
        },
        "services": [{
            "serviceDefinition": "temperature",
            "interfaces": ["HTTP-SECURE-JSON"],
            "serviceUri": "/api/temperature",
            "metadata": {"unit": "celsius"}
        }]
    }

    response = requests.post(
        f"{ARROWHEAD_URL}/serviceregistry/register",
        json=registration
    )
    response.raise_for_status()
    print(f"✓ Registered: {response.json()}")

if __name__ == '__main__':
    register()
    app.run(host='0.0.0.0', port=SYSTEM_PORT)
```

Run it:
```bash
pip install flask requests
python temperature_sensor.py
```

### Python Example: Service Consumer

> **Note:** This example shows manual service discovery. The [Arrowhead Python SDK](https://github.com/cluster1-arrowcolony/arrowhead-python-sdk) provides helper methods for discovery, caching, and automatic failover.

```python
#!/usr/bin/env python3
import requests
import time

ARROWHEAD_URL = "http://localhost:8080"

def discover_temperature_service():
    """Find temperature service via Arrowhead"""
    query = {
        "serviceDefinitionRequirement": "temperature"
    }

    response = requests.post(
        f"{ARROWHEAD_URL}/serviceregistry/query",
        json=query
    )
    response.raise_for_status()

    services = response.json().get("serviceQueryData", [])
    if not services:
        return None

    # Get first available service
    service = services[0]
    provider = service["provider"]
    return f"http://{provider['address']}:{provider['port']}{service['serviceUri']}"

def read_temperature(service_url):
    """Read temperature from service"""
    response = requests.get(service_url)
    response.raise_for_status()
    return response.json()

# Main loop
service_url = discover_temperature_service()
if service_url:
    print(f"Found service: {service_url}")
    while True:
        data = read_temperature(service_url)
        print(f"Temperature: {data['temperature']}°C")
        time.sleep(5)
```

### Go Example: Service Provider

> **Note:** This example uses the raw REST API. For a more idiomatic Go experience with type-safe interfaces and automatic service lifecycle management, see the [Arrowhead Go Client](https://github.com/eislab-cps/arrowhead-client-go).

```go
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "time"
)

const (
    arrowheadURL = "http://localhost:8080"
    systemName   = "go-service"
    systemAddr   = "127.0.0.1"
    systemPort   = 8081
)

type Registration struct {
    System   System    `json:"system"`
    Services []Service `json:"services"`
}

type System struct {
    SystemName string `json:"systemName"`
    Address    string `json:"address"`
    Port       int    `json:"port"`
}

type Service struct {
    ServiceDefinition string   `json:"serviceDefinition"`
    Interfaces        []string `json:"interfaces"`
    ServiceURI        string   `json:"serviceUri"`
}

func registerService() error {
    reg := Registration{
        System: System{
            SystemName: systemName,
            Address:    systemAddr,
            Port:       systemPort,
        },
        Services: []Service{
            {
                ServiceDefinition: "hello",
                Interfaces:        []string{"HTTP-SECURE-JSON"},
                ServiceURI:        "/api/hello",
            },
        },
    }

    data, _ := json.Marshal(reg)
    resp, err := http.Post(
        arrowheadURL+"/serviceregistry/register",
        "application/json",
        bytes.NewBuffer(data),
    )
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    fmt.Println("✓ Registered with Arrowhead Lite")
    return nil
}

func helloHandler(w http.ResponseWriter, r *http.Request) {
    response := map[string]interface{}{
        "message":   "Hello from Arrowhead!",
        "timestamp": time.Now().Unix(),
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func main() {
    // Register with Arrowhead
    if err := registerService(); err != nil {
        log.Fatal(err)
    }

    // Start service
    http.HandleFunc("/api/hello", helloHandler)
    addr := fmt.Sprintf(":%d", systemPort)
    log.Printf("Service running on %s", addr)
    log.Fatal(http.ListenAndServe(addr, nil))
}
```

### Java Example: Service Provider

```java
import com.google.gson.Gson;
import java.net.http.*;
import java.net.URI;

public class ArrowheadService {
    private static final String ARROWHEAD_URL = "http://localhost:8080";
    private static final String SYSTEM_NAME = "java-service";

    static class Registration {
        System system;
        Service[] services;
    }

    static class System {
        String systemName;
        String address;
        int port;
    }

    static class Service {
        String serviceDefinition;
        String[] interfaces;
        String serviceUri;
    }

    public static void register() throws Exception {
        Registration reg = new Registration();
        reg.system = new System();
        reg.system.systemName = SYSTEM_NAME;
        reg.system.address = "127.0.0.1";
        reg.system.port = 8081;

        Service service = new Service();
        service.serviceDefinition = "data";
        service.interfaces = new String[]{"HTTP-SECURE-JSON"};
        service.serviceUri = "/api/data";
        reg.services = new Service[]{service};

        Gson gson = new Gson();
        String json = gson.toJson(reg);

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(ARROWHEAD_URL + "/serviceregistry/register"))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(json))
            .build();

        HttpResponse<String> response = client.send(request,
            HttpResponse.BodyHandlers.ofString());

        System.out.println("✓ Registered: " + response.body());
    }

    public static void main(String[] args) throws Exception {
        register();
        // Start your service here...
    }
}
```

## Authentication (Production)

When Arrowhead Lite runs with TLS enabled (production), you need client certificates.

### Using Certificates in Python

```python
import requests

session = requests.Session()
session.cert = ('client.crt', 'client.key')
session.verify = 'ca.crt'

# Now use session instead of requests
response = session.post(
    'https://localhost:8443/serviceregistry/register',
    json=registration
)
```

### Using Certificates in curl

```bash
curl --cert client.crt --key client.key --cacert ca.crt \
  https://localhost:8443/serviceregistry/register \
  -H "Content-Type: application/json" \
  -d @registration.json
```

Ask your system administrator for client certificates.

## Testing Your Integration

### Local Development

1. Start Arrowhead Lite in dev mode:
   ```bash
   ./arrowhead-lite --disable-tls --verbose
   ```

2. Register your service
3. Test discovery with curl
4. Call your service directly to verify it works

### Check Registration

```bash
# List all registered systems
curl http://localhost:8080/serviceregistry/systems

# Query for your service
curl -X POST http://localhost:8080/serviceregistry/query \
  -H "Content-Type: application/json" \
  -d '{"serviceDefinitionRequirement": "your-service-name"}'
```

### Debug Logging

Start Arrowhead Lite with verbose logging:
```bash
./arrowhead-lite --disable-tls --verbose
```

Watch logs to see registration requests and responses.

## Common Issues

| Problem | Solution |
|---------|----------|
| Connection refused | Check Arrowhead Lite is running: `curl http://localhost:8080/health` |
| Registration fails | Check JSON format, ensure system name is unique |
| Service not found | Verify exact service definition name in query |
| 401 Unauthorized | In production, use client certificates (see Authentication section) |
| Wrong address/port | Use your actual IP address, not localhost, for network access |

### Enable Debug Logging in Your App

Python:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

See request/response details to diagnose issues.

## API Quick Reference

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/health` | GET | Check if Arrowhead Lite is running |
| `/serviceregistry/register` | POST | Register your system and services |
| `/serviceregistry/unregister` | DELETE | Remove your system |
| `/serviceregistry/query` | POST | Discover services |
| `/serviceregistry/systems` | GET | List all systems |
| `/orchestrator/orchestration` | POST | Request service with authorization |
| `/authorization/check` | POST | Check if authorized |

**Full API documentation:** [API_REFERENCE.md](./API_REFERENCE.md)

## Advanced: Combining with Compute Orchestration

Arrowhead Lite excels at **service discovery and authorization**, but what about **heavy processing**? Many IoT applications need to:

- Run ML inference on camera feeds (requires GPU)
- Perform FFT analysis on sensor data (CPU-intensive)
- Execute analytics across distributed datasets (needs HPC cluster)

For these scenarios, combine Arrowhead Lite with a compute orchestration engine like [ColonyOS](https://github.com/colonyos/colonies).

**→ See [COLONYOS_INTEGRATION.md](./COLONYOS_INTEGRATION.md) for complete guide**

This integration guide covers:
- Why combine service discovery with compute orchestration
- Step-by-step examples (from simple to production patterns)
- Edge-to-cloud processing pipelines
- Deployment, troubleshooting, and performance considerations
- Real-world use case (seismic monitoring with 200 sensors + HPC)

**Quick summary:** Use Arrowhead to discover *what services exist*, use ColonyOS to decide *where to execute work*.

## Next Steps

- **Use an SDK for easier integration:**
  - Python: [Arrowhead Python SDK](https://github.com/cluster1-arrowcolony/arrowhead-python-sdk)
  - Go: [Arrowhead Go Client](https://github.com/eislab-cps/arrowhead-client-go)
- Read [API_REFERENCE.md](./API_REFERENCE.md) for complete API documentation
- See [ARCHITECTURE.md](./ARCHITECTURE.md) to understand the system design
- Contact your system administrator for production certificates and endpoints

## Getting Help

- Check [API_REFERENCE.md](./API_REFERENCE.md) for detailed endpoint documentation
- Review error messages - they indicate what's wrong with your request
- Use `--verbose` mode on Arrowhead Lite to see detailed logs
- Report integration issues at https://github.com/cluster1-arrowcolony/arrowhead-lite/issues
