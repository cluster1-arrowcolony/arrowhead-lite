# Arrowhead Lite Documentation

> **Stop hardcoding service addresses.** Arrowhead Lite lets your applications discover and connect to services dynamically, with built-in security and zero-trust authorization.

**Arrowhead Lite** is a lightweight IoT service mesh implementing the Arrowhead Framework 4.x specification. It enables secure service discovery, orchestration, and authorization for IoT systems. Think of it as **DNS + OAuth for your IoT services** - but designed for industrial automation and edge computing.

## What is Arrowhead?

Arrowhead Framework is an architectural standard for building networks of collaborating services in industrial automation and IoT environments. Instead of applications calling each other directly with hardcoded URLs and credentials, Arrowhead acts as a **service mesh** that provides:

- **Dynamic Service Discovery** - Find services by capability, not by hardcoded addresses (like DNS, but you search for "temperature sensor in warehouse-2" instead of hostnames)
- **Zero-Trust Security** - Every interaction requires authorization, even within the same network (mutual TLS certificates + authorization rules)
- **Decentralized Operation** - Services communicate directly after discovery, no central bottleneck (Arrowhead facilitates connections, but doesn't proxy your data)
- **Interoperability** - Standardized interfaces enable systems from different vendors to work together (common service definitions like "temperature", "control-valve", "energy-meter")

### Why Convert Your Services to Arrowhead?

#### Quick Comparison

| Aspect | Traditional Hardcoded | With Arrowhead |
|--------|----------------------|----------------|
| **Service Discovery** | Manual (hardcoded IPs/URLs) | Automatic (query by capability) |
| **Configuration** | Each consumer hardcodes provider addresses | Central registry, consumers discover dynamically |
| **Resilience** | Manual failover logic | Multiple providers, automatic selection |
| **Security** | Manual per-connection setup | Centralized authorization rules + mTLS |
| **Scalability** | Add provider = update all consumers | Add provider = register once, auto-discovered |
| **Observability** | Unknown who calls what | Central registry shows all services & consumers |
| **Maintenance** | Provider moves = update all consumers | Provider moves = update registration only |
| **Learning Curve** | Minimal | Small (register + query instead of hardcode) |

#### Traditional Approach: Hardcoded Service Connections

```
Your App → http://sensor1.example.com:8080/temperature
         → http://192.168.1.100:9000/api/data
         → http://device-serial-123456/status
```

**What happens when you have 50 services? 500?**

- **Infrastructure changes break everything**: Sensor moves to new IP? Update and redeploy all consumers.
- **No visibility**: Which services exist? Who's calling what? You don't know until something breaks.
- **Security nightmare**: Manual firewall rules, shared API keys, or worse - no authentication.
- **Debugging is painful**: When integration fails, you check logs across multiple services to find which hardcoded URL is wrong.
- **Zero resilience**: If the sensor at 192.168.1.100 crashes, your app crashes. No automatic failover.

#### Arrowhead Approach: Dynamic Service Discovery

```
Your App → Arrowhead: "Find me a temperature service in warehouse-2"
         ← Arrowhead: "Use sensor-A at 192.168.1.100:8080/api/temperature (authorized)"
Your App → sensor-A (direct communication, mutual TLS)
```

**Benefits:**

- **Flexibility**: Services can move, scale, or be replaced - your code stays the same
- **Discovery**: Find services by capability, location, or custom metadata (accuracy, update rate, etc.)
- **Security**: Centralized authorization rules ("controller-X can read temperature from warehouse-2 sensors"), mutual TLS for all connections
- **Observability**: Central registry shows all services, who provides them, and authorization rules
- **Resilience**: Query returns multiple providers - implement failover in your app logic

### Real-World Code Example

**Before Arrowhead: Hardcoded and Brittle**
```python
import requests

def get_temperature():
    # Hardcoded - breaks when sensor moves or fails
    response = requests.get("http://192.168.1.50:8081/temp")
    return response.json()["value"]
```

**Problems:**
- Sensor IP change requires code change and redeployment
- No failover if sensor crashes
- No authorization enforcement
- No discovery of alternative sensors

**With Arrowhead: Dynamic and Resilient**
```python
import requests

def get_temperature():
    # 1. Discover temperature services (done once or when needed)
    query = {
        "serviceDefinitionRequirement": "temperature",
        "metadataRequirements": {"location": "warehouse-2"}
    }

    response = requests.post(
        "http://arrowhead-lite:8080/serviceregistry/query",
        json=query
    )

    services = response.json().get("serviceQueryData", [])

    # 2. Try providers with automatic failover
    for service in services:
        provider = service["provider"]
        url = f"http://{provider['address']}:{provider['port']}{service['serviceUri']}"

        try:
            response = requests.get(url, timeout=2)
            return response.json()["value"]
        except requests.RequestException:
            continue  # Try next provider

    raise Exception("No temperature service available")
```

**What changed:**
- **7 lines** of registration code added to your sensor (one-time)
- **15 lines** in your consumer app for discovery + failover
- **Gained**: Dynamic discovery, automatic failover, centralized security, observability

**Now you can:**
- Add/remove sensors without touching consumer code
- Sensors can move networks or scale horizontally
- Implement automatic failover to backup sensors
- Filter by metadata (location, accuracy, vendor)
- System admin controls authorization centrally

### When Should You Use Arrowhead?

**Arrowhead is ideal for:**

- **Industrial IoT deployments** - Factories, warehouses, production lines with many interconnected devices
- **Edge computing scenarios** - Distributed systems where services run on different edge nodes
- **Multi-vendor environments** - Integrating devices and services from different manufacturers
- **Long-lived systems** - Infrastructure that will evolve over years (sensors replaced, networks reconfigured)
- **Security-critical applications** - Systems requiring mutual authentication and fine-grained authorization

**Consider alternatives if:**

- **Single service, single consumer** - Arrowhead adds overhead for simple 1-to-1 connections
- **Services never change location** - If your infrastructure is truly static, hardcoded URLs might be simpler
- **Development/prototyping only** - Direct connections are faster to set up for throwaway prototypes
- **Public cloud-only** - Cloud-native service meshes (Istio, Linkerd) may be better suited

**Migration effort:**
- **Provider**: 5-10 lines of code to register your service with Arrowhead
- **Consumer**: 10-20 lines to discover services instead of hardcoding URLs
- **Infrastructure**: Run Arrowhead Lite binary (single binary, ~20MB, SQLite or PostgreSQL)

### Common Use Cases

**Factory Automation**
- Industrial robots discover welding, assembly, and quality control services
- Central orchestration ensures only authorized robots access specific machines
- Services can be relocated or replaced during maintenance without downtime

**Smart Buildings**
- HVAC controllers discover temperature sensors by room/floor
- Lighting systems find occupancy sensors dynamically
- Building management systems implement failover when sensors fail

**Energy Management**
- Energy meters register consumption data services
- Analytics systems discover meters by location or type
- Load balancing controllers find available battery storage systems

**Warehouse Logistics**
- Automated forklifts discover inventory tracking services
- Pick-and-place robots find location services for item retrieval
- Central control systems orchestrate multi-robot collaboration

## Choose Your Guide

### I'm a **Programmer**
**Building applications that connect to Arrowhead Lite?**

→ **[APPLICATION_DEVELOPMENT.md](./APPLICATION_DEVELOPMENT.md)**

Learn how to:
- Register your services with Arrowhead Lite
- Discover and consume other services
- Use the REST API
- Integrate with Python, Go, Java, or other languages

**SDK Users:** For easier integration, check out:
- **Python:** [Arrowhead Python SDK](https://github.com/cluster1-arrowcolony/arrowhead-python-sdk)
- **Go:** [Arrowhead Go Client](https://github.com/eislab-cps/arrowhead-client-go)

---

### I'm a **System Administrator**
**Deploying or maintaining Arrowhead Lite?**

→ **[OPERATIONS_GUIDE.md](./OPERATIONS_GUIDE.md)**

Learn how to:
- Install and deploy Arrowhead Lite
- Configure for production
- Set up security (TLS, certificates, firewall)
- Monitor and troubleshoot
- Backup and upgrade

---

## Additional Documentation

### Reference Documentation
- **[API_REFERENCE.md](./API_REFERENCE.md)** - Complete REST API specification
- **[ARCHITECTURE.md](./ARCHITECTURE.md)** - System design and components
- **[diagrams/](./diagrams/README.md)** - Visual sequence diagrams of system interactions

### Specialized Topics
- **[QUICK_REFERENCE.md](./QUICK_REFERENCE.md)** - Command cheat sheet
- **[COLONYOS_INTEGRATION.md](./COLONYOS_INTEGRATION.md)** - Combining Arrowhead Lite with ColonyOS for distributed compute

## Quick Links

**Common tasks:**
- [Register a service](./APPLICATION_DEVELOPMENT.md#service-registration) (Programmers)
- [Deploy with Docker](./OPERATIONS_GUIDE.md#docker-installation) (Sysadmins)
- [Set up TLS/mTLS](./OPERATIONS_GUIDE.md#security-setup) (Sysadmins)
- [Troubleshoot issues](./OPERATIONS_GUIDE.md#troubleshooting) (Sysadmins)
- [Query services](./APPLICATION_DEVELOPMENT.md#service-discovery) (Programmers)

## Project Information

- **Repository:** https://github.com/cluster1-arrowcolony/arrowhead-lite
- **Issues:** https://github.com/cluster1-arrowcolony/arrowhead-lite/issues
- **License:** Apache 2.0

## Getting Started in 5 Minutes

### For Programmers

```bash
# Start Arrowhead Lite locally
docker run -d -p 8080:8080 -e ARROWHEAD_TLS_ENABLED=false arrowhead-lite:latest

# Register your service
curl -X POST http://localhost:8080/serviceregistry/register \
  -H "Content-Type: application/json" \
  -d '{"system":{"systemName":"my-app","address":"192.168.1.100","port":8081},"services":[{"serviceDefinition":"temperature","interfaces":["HTTP-SECURE-JSON"],"serviceUri":"/api/temperature"}]}'

# Continue with APPLICATION_DEVELOPMENT.md for complete examples
```

**SDK Users:** For easier integration, install an SDK:

**Python:**
```bash
pip install arrowhead-python-sdk
```

**Go:**
```bash
go get github.com/eislab-cps/arrowhead-client-go
```

See the respective SDK documentation for language-specific examples.

### For System Administrators

```bash
# Clone and build
git clone https://github.com/cluster1-arrowcolony/arrowhead-lite.git
cd arrowhead-lite
make build

# Run
./bin/arrowhead-lite --disable-tls

# Continue with OPERATIONS_GUIDE.md for production setup
```

## Documentation Structure

```
docs/
├── README.md                    # ← You are here (start here)
│
├── APPLICATION_DEVELOPMENT.md           # For application programmers
├── OPERATIONS_GUIDE.md          # For system administrators
│
├── API_REFERENCE.md             # Complete API documentation
├── ARCHITECTURE.md              # System design
└── QUICK_REFERENCE.md            # Command cheat sheet
```

## Need Help?

1. **Check the relevant guide** - APPLICATION_DEVELOPMENT.md or OPERATIONS_GUIDE.md
2. **Search existing issues** - https://github.com/cluster1-arrowcolony/arrowhead-lite/issues
3. **Ask a question** - Create a new issue with the `question` label
4. **Report a bug** - Create an issue with reproduction steps

## Contributing

- **[CONTRIBUTING.md](../CONTRIBUTING.md)** - How to contribute to the project
- **[DEVELOPMENT.md](./DEVELOPMENT.md)** - Development environment setup and workflows
