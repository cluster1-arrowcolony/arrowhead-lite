# Integrating Arrowhead Lite with ColonyOS

**Audience:** Application developers building IoT systems that need both service discovery and distributed compute

## Overview

Combine **Arrowhead Lite** (service discovery) with **ColonyOS** (compute orchestration) to build scalable IoT systems where edge sensors discover each other dynamically and heavy processing runs on distributed workers.

```
┌─────────────────────────────────────────────────────────────┐
│                    Your Application                          │
│              (The data coordinator/bridge)                   │
└─────────────────────────────────────────────────────────────┘
     │                    │                        │
     │ Discovery          │ Data                   │ Job Submission
     ↓                    ↓                        ↓
┌──────────┐      ┌──────────────┐       ┌──────────────────┐
│Arrowhead │      │Edge Sensors  │       │   ColonyOS       │
│  Lite    │      │(temp, camera)│       │   (orchestrator) │
└──────────┘      └──────────────┘       └──────────────────┘
                         │                        │
                         │ Store data             │ Assign work
                         ↓                        ↓
                  ┌─────────────┐         ┌─────────────┐
                  │  ColonyFS   │←────────│  Executors  │
                  │ (S3-backed) │         │  (workers)  │
                  └─────────────┘         └─────────────┘
```

**Key Pattern:** Use Arrowhead to find sensors → Use ColonyFS to store data → Use ColonyOS to process it

**When to use:** Heavy processing tasks, large datasets, need resilience/scalability
**When NOT to use:** Real-time control, trivial computations, static single-service setups

## What is ColonyOS?

[ColonyOS](https://github.com/colonyos/colonies) is a distributed compute orchestration framework that:

- **Distributes workloads** across cloud, edge, and HPC environments
- **Handles failures** automatically (if an executor crashes, job gets reassigned)
- **Manages workflows** with dependencies and retries
- **Includes ColonyFS:** A meta-filesystem (S3-backed) for efficient data transfer

**Key concepts:**
- **Colony:** A distributed runtime environment (pool of workers)
- **Executor:** A worker process that runs jobs
- **Function Spec:** A job specification describing what to compute
- **ColonyFS:** File storage system for data exchange between components

## The Integration Challenge

When combining Arrowhead (edge sensors) with ColonyOS (distributed compute), you face a fundamental question:

**How does a remote executor access data from an edge sensor?**

```
Edge Network (private)              Cloud/HPC (public IP)
┌─────────────────────┐             ┌─────────────────────┐
│  Sensor             │    ???      │  Executor           │
│  Has data           │             │  Needs data         │
└─────────────────────┘             └─────────────────────┘
```

The executor **cannot directly reach** the sensor (different networks, firewalls, NAT).

**Solution:** Your application acts as the bridge - it can reach both the sensor and ColonyFS.

## Architecture Pattern

Your application coordinates the data flow:

1. **Discover** sensors via Arrowhead
2. **Fetch** data from sensors (you can reach them)
3. **Upload** data to ColonyFS (S3-backed storage)
4. **Submit** job to ColonyOS with ColonyFS mount specification
5. **Executor** processes data via mounted ColonyFS directories
6. **Download** results from ColonyFS

## Data Movement Strategies

### Pattern A: Embed Small Data in Arguments

For simple sensor readings (temperature, status, metrics):

```python
# Fetch simple data
data = requests.get(sensor_url).json()

# Submit job with data embedded
job = colonies.submit_funcspec(FunctionSpec(
    args=["--temp", str(data["temperature"])],
    colonyname="my-colony",
    executortype="analyzer"
))
```

**Use when:** Simple values, configuration parameters

### Pattern B: ColonyFS (Recommended)

For large datasets across networks:

```bash
# Upload data to ColonyFS
colonies fs sync -l /input-label -d ./data --yes

# Submit job with ColonyFS mount
# Executor will have data mounted at /cfs/input/
```

**Use when:** Large datasets, distributed executors, most production scenarios

### Pattern C: Direct URL

For same-network streaming:

```python
# Get stream URL from sensor
stream_url = requests.get(sensor_url).json()["stream_url"]

# Submit job with URL
job = colonies.submit_funcspec(FunctionSpec(
    args=["--stream", stream_url]
))
```

**Use when:** Real-time streams, executors on same network as sensors

### Comparison

| Pattern | Data Size | Network | Setup | Best For |
|---------|-----------|---------|-------|----------|
| **A: Embed** | Small | Any | None | Simple metrics |
| **B: ColonyFS** | Large | Any | S3 bucket | Production scenarios |
| **C: Direct URL** | Any | Same/VPN | Network access | Streaming |

## Getting Started

### Prerequisites

1. **Arrowhead Lite running** - See [APPLICATION_DEVELOPMENT.md](./APPLICATION_DEVELOPMENT.md)

2. **ColonyOS server:**
```bash
docker run -d -p 50080:50080 colonyos/colonies
```

3. **ColonyFS with S3:**
```bash
# Option A: MinIO (development)
docker run -d -p 9000:9000 -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin minio/minio server /data

# Option B: AWS S3 (production)
export S3_ENDPOINT=s3.amazonaws.com
export S3_ACCESSKEY=YOUR_KEY
export S3_SECRETKEY=YOUR_SECRET
```

4. **Install dependencies:**
```bash
pip install pycolonies arrowhead-python-sdk requests
```

### Basic Workflow Example

**1. Sensor registers with Arrowhead:**
```python
registration = {
    "system": {"systemName": "temp-sensor-001"},
    "services": [{
        "serviceDefinition": "temperature-data",
        "interfaces": ["HTTP-SECURE-JSON"],
        "serviceUri": "/data"
    }]
}
requests.post(f"{ARROWHEAD_URL}/serviceregistry/register", json=registration)
```

**2. Application discovers sensor:**
```python
query = {"serviceDefinitionRequirement": "temperature-data"}
services = requests.post(f"{ARROWHEAD_URL}/serviceregistry/query", json=query).json()
sensor_url = f"http://{services[0]['provider']['address']}:{services[0]['provider']['port']}/data"
```

**3. Application uploads data to ColonyFS:**
```bash
# Fetch data from sensor, save locally
# Then upload to ColonyFS
colonies fs sync -l /temp-input-123 -d ./sensor_data --yes
```

**4. Application submits job:**
```python
spec = func_spec(
    args=["--input", "/cfs/input/data.json", "--output", "/cfs/output/result.json"],
    colonyname="my-colony",
    executortype="temp-analyzer",
    fs={
        "mount": "/cfs",
        "dirs": [
            {"label": "/temp-input-123", "dir": "/input"},
            {"label": "/temp-output-123", "dir": "/output"}
        ]
    }
)
process = colonies.submit_funcspec(spec, executor_prvkey)
```

**5. Executor processes data:**
```python
# Executor reads from /cfs/input/data.json (mounted from ColonyFS)
# Processes it
# Writes to /cfs/output/result.json (synced back to ColonyFS)
```

**6. Application downloads results:**
```bash
colonies fs sync -l /temp-output-123 -d ./results --yes
```

## Common Pitfalls

### 1. Assuming Executors Can Reach Sensors Directly

**Wrong:** Passing sensor URLs to executors in different networks
**Right:** Your app fetches data and uploads to ColonyFS

### 2. Embedding Large Data in Arguments

**Wrong:** Passing large files as job arguments
**Right:** Upload to ColonyFS and reference by label

### 3. Not Handling Job Failures

Always use try/except and check job state:
```python
try:
    result = colonies.wait(job_id, timeout=600)
    if result.state == "SUCCESS":
        process_results(result.output)
except TimeoutError:
    # Handle timeout
```

### 4. Forgetting to Clean Up

Set `keepfiles=False` for temporary data:
```python
{"label": "/temp-input", "dir": "/input", "keepfiles": False}
```

## When NOT to Use

**Don't use for:**
- Real-time control systems (use direct connections)
- Trivial computations (orchestration overhead not worth it)
- Single static service (no need for dynamic discovery)

**Use for:**
- Heavy processing (ML, FFT, image analysis)
- Large datasets
- Distributed/resilient systems
- Dynamic service discovery

## Decision Guide

```
Start: Need to process sensor data
│
├─ Is data very small (simple values)?
│  └─ YES → Pattern A (embed in args)
│
├─ Can executor reach sensor directly?
│  └─ YES → Pattern C (direct URL)
│
└─ Large data + cross-network?
   └─ YES → Pattern B (ColonyFS) ← RECOMMENDED
```

## Deployment Example

Complete stack with Docker Compose:

```yaml
services:
  arrowhead-lite:
    image: your-registry/arrowhead-lite:latest
    ports: ["8080:8080"]

  colonies-server:
    image: colonyos/colonies:latest
    ports: ["50080:50080"]

  minio:
    image: minio/minio:latest
    ports: ["9000:9000"]
    command: server /data
```

## Security Considerations

**Arrowhead mTLS:**
- Use certificates for production (see APPLICATION_DEVELOPMENT.md)
- Never disable TLS in production

**ColonyOS Authentication:**
- Store keys securely (environment variables, secrets manager)
- Rotate keys regularly
- Use separate keys for colony admin vs. executors

**Network Security:**
- Configure firewall rules appropriately
- Use VPN for multi-site deployments
- Keep sensitive data off public internet

## Troubleshooting

**ColonyFS upload fails:**
- Check S3 credentials (`$S3_ENDPOINT`, `$S3_ACCESSKEY`)
- Verify bucket exists
- Test S3 connectivity

**Executor can't find input files:**
- Verify ColonyFS mount in function spec
- Check label exists: `colonies fs ls -l /your-label`
- Ensure file uploaded correctly

**Job stays in queue:**
- Check executor is running: `colonies executor ls`
- Verify executor type matches
- Check executor credentials

**Arrowhead discovery returns empty:**
- Verify sensor is registered and running
- Check metadata matches exactly
- Test Arrowhead endpoint: `curl http://localhost:8080/serviceregistry/echo`

## Monitoring

**ColonyOS jobs:**
```bash
colonies process ls --colonyname my-colony --count 20
colonies process get --processid PROCESS_ID
```

**ColonyFS:**
```bash
colonies fs label ls
colonies fs ls -l /your-label
```

**Arrowhead services:**
```bash
curl http://localhost:8080/serviceregistry/query \
  -H "Content-Type: application/json" \
  -d '{"serviceDefinitionRequirement": "temperature-data"}'
```

## Data Lifecycle

**Automatic cleanup:**
```python
# Set keepfiles=False for temporary data
fs={"dirs": [{"label": "/temp", "keepfiles": False, ...}]}
```

**Manual cleanup:**
```bash
colonies fs label rm --label /old-label
```

**S3 lifecycle policies:**
Configure your S3 bucket to automatically expire old data or transition to cheaper storage tiers.

## Performance

Performance depends on:
- Hardware resources (CPU, memory, network)
- Data size and network bandwidth
- S3 upload/download speed
- Executor availability

**Primary bottlenecks:**
- Executor availability (add more executors to scale)
- Data transfer speed (optimize network, use compression)
- S3 performance (use appropriate storage class)

**Not typically bottlenecks:**
- Service discovery (Arrowhead)
- Job submission (ColonyOS)

Always benchmark your specific deployment.

## Summary

### Use Arrowhead Lite For:
- Service discovery (find sensors, processors, storage)
- Authorization (who can access what)
- Dynamic service registration and lifecycle

### Use ColonyOS For:
- Compute distribution (where to run heavy jobs)
- Workflow orchestration (dependencies, retries)
- Failure handling and job reassignment

### Use ColonyFS For:
- Data transfer between edge and remote systems
- Large file storage
- Reliable, S3-backed file synchronization

### Your Application's Role:
- Bridge between sensors (Arrowhead) and executors (ColonyOS)
- Discover sensors dynamically
- Upload sensor data to ColonyFS
- Submit jobs with ColonyFS mount specifications
- Download and present results

### Key Success Factors:
1. Use ColonyFS for large datasets and cross-network scenarios
2. Configure S3 credentials properly
3. Set `keepfiles=False` for temporary data
4. Use proper error handling and retry logic
5. Monitor job states and ColonyFS labels
6. Secure credentials appropriately

**The fundamental pattern:** Arrowhead finds services → Your app uploads data to ColonyFS → ColonyOS distributes compute → Executors process via mounted filesystems → Results downloaded from ColonyFS

## Learn More

### Arrowhead Lite Documentation:
- [APPLICATION_DEVELOPMENT.md](./APPLICATION_DEVELOPMENT.md) - Service integration guide
- [OPERATIONS_GUIDE.md](./OPERATIONS_GUIDE.md) - Deployment guide
- [ARCHITECTURE.md](./ARCHITECTURE.md) - System design
- [API_REFERENCE.md](./API_REFERENCE.md) - Complete API specification
- [Sequence Diagrams](./diagrams/README.md) - Visual workflows

**SDKs:**
- [Python SDK](https://github.com/cluster1-arrowcolony/arrowhead-python-sdk) - Easier Arrowhead integration
- [Go Client](https://github.com/eislab-cps/arrowhead-client-go) - Go library for Arrowhead

### ColonyOS Resources:
- [Repository](https://github.com/colonyos/colonies) - Source code and CLI
- [Tutorials](https://github.com/colonyos/tutorials) - Step-by-step guides including ColonyFS
- [Python SDK](https://github.com/colonyos/pycolonies) - PyColonies library
- [Documentation](https://colonyos.io) - Official docs

### Related Diagrams:
- [System Registration](./diagrams/2-system-service-registration.md) - How sensors register with Arrowhead
- [Orchestration Flow](./diagrams/3-orchestration-flow.md) - Service discovery and matching
- [Service Consumption](./diagrams/4-service-consumption.md) - Direct communication after orchestration
