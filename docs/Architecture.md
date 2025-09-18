# Arrowhead Lite Architecture

## System Overview

Arrowhead Lite is a lightweight, single-binary implementation of the Arrowhead Framework 4.x specification designed for IoT service mesh deployments. It consolidates multiple Arrowhead core services into a unified application, reducing deployment complexity while maintaining full compatibility with the framework specification.

## Architecture Principles

### Design Goals
- **Simplicity**: Single binary deployment with minimal dependencies
- **Compatibility**: Full Arrowhead Framework 4.x specification compliance
- **Flexibility**: Support for both development (HTTP) and production (HTTPS/mTLS) modes
- **Scalability**: Efficient resource usage suitable for edge deployments
- **Modularity**: Clean separation between core services

### Technology Stack
- **Language**: Go 1.23+
- **Web Framework**: Gin HTTP framework
- **Database**: SQLite (default) / PostgreSQL (production)
- **Configuration**: Viper (YAML, ENV, flags)
- **Logging**: Logrus structured logging
- **Authentication**: mTLS certificates + JWT tokens

## Component Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Client Applications                     │
│                    (IoT Devices, Services)                   │
└─────────────────────────────────────────────────────────────┘
                                │
                    ┌───────────┴───────────┐
                    │   REST API (Gin)      │
                    │  HTTP/HTTPS + mTLS     │
                    └───────────┬───────────┘
                                │
        ┌───────────────────────┴───────────────────────┐
        │           Authentication Middleware            │
        │         (Certificate + JWT Validation)         │
        └───────────────────────┬───────────────────────┘
                                │
    ┌───────────────────────────┴───────────────────────────┐
    │                    API Handlers Layer                   │
    ├──────────┬──────────┬──────────┬──────────┬──────────┤
    │ Registry │   Auth   │  Orch    │    CA    │  Health  │
    │ Handlers │ Handlers │ Handlers │ Handlers │  Check   │
    └──────────┴──────────┴──────────┴──────────┴──────────┘
                                │
    ┌───────────────────────────┴───────────────────────────┐
    │                  Core Services Layer                    │
    ├──────────┬──────────┬──────────┬──────────┬──────────┤
    │ Service  │  Auth    │  Orch    │   Cert   │  Event   │
    │ Registry │  Service │  Service │    CA    │   Bus    │
    └──────────┴──────────┴──────────┴──────────┴──────────┘
                                │
    ┌───────────────────────────┴───────────────────────────┐
    │                   Storage Layer                         │
    │              (Database Interface + Models)              │
    └───────────────────────┬───────────────────────────────┘
                            │
                ┌───────────┴───────────┐
                │   Database Backend     │
                │  SQLite / PostgreSQL   │
                └───────────────────────┘
```

## Core Components

### 1. Main Application (`cmd/main.go`)

The entry point that orchestrates:
- Configuration loading and validation
- Database initialization and migrations
- Service component instantiation
- HTTP/HTTPS server configuration
- Graceful shutdown handling

Key responsibilities:
- Parse command-line flags
- Load configuration from multiple sources
- Initialize logging system
- Set up TLS/mTLS if enabled
- Start HTTP server with configured routes
- Handle OS signals for graceful shutdown

### 2. API Layer (`api/`)

#### Router Configuration
- Gin middleware setup (CORS, logging, recovery)
- Route registration for all services
- Conditional authentication middleware application
- Request/response serialization

#### Handlers
Each service has dedicated handlers:
- **Registry Handlers**: System registration, service discovery
- **Authorization Handlers**: Rule management, permission checks
- **Orchestration Handlers**: Service matching, provider recommendations
- **CA Handlers**: Certificate signing, chain management

### 3. Internal Services (`internal/`)

#### Service Registry (`internal/registry/`)
Manages system and service lifecycle:
- System registration with metadata
- Service definition and interface management
- Service discovery with filtering
- Heartbeat monitoring for liveness
- Event emission for registry changes

Data structures:
```go
type System struct {
    ID                 int64
    SystemName         string
    Address            string
    Port               int
    AuthenticationInfo string
}

type Service struct {
    ID               int64
    ServiceDefinition string
    Interfaces        []string
    ServiceURI        string
    Metadata          map[string]string
}
```

#### Authorization Service (`internal/auth/`)
Handles access control:
- Authorization rule CRUD operations
- Token generation and validation
- Certificate-based authentication
- JWT token management
- Permission evaluation engine

Key features:
- Intracloud authorization
- Token-based temporary permissions
- Certificate thumbprint validation
- Rule priority and conflict resolution

#### Orchestration Service (`internal/orchestration/`)
Provides service matching:
- Service requirement analysis
- Provider capability matching
- QoS-based selection
- Load balancing considerations
- Stored orchestration rules

Orchestration flow:
1. Receive service request with requirements
2. Query registry for matching services
3. Check authorization for each candidate
4. Apply QoS and preference filters
5. Return ranked provider list

#### Certificate Authority (`internal/ca/`)
Manages PKI infrastructure:
- CSR validation and signing
- Certificate lifecycle management
- Chain of trust maintenance
- Certificate revocation (planned)

Certificate types:
- System certificates for mTLS
- Service certificates for specific operations
- Temporary certificates for testing

### 4. Database Layer (`internal/database/`)

#### Storage Interface
Abstract storage operations:
```go
type Storage interface {
    // System operations
    CreateSystem(system *models.System) error
    GetSystem(id int64) (*models.System, error)
    UpdateSystem(system *models.System) error
    DeleteSystem(id int64) error
    
    // Service operations
    CreateService(service *models.Service) error
    QueryServices(criteria QueryCriteria) ([]*models.Service, error)
    
    // Authorization operations
    CreateAuthRule(rule *models.AuthRule) error
    CheckAuthorization(consumer, provider, service) (bool, error)
    
    // Transaction support
    BeginTx() (*sql.Tx, error)
    CommitTx(tx *sql.Tx) error
    RollbackTx(tx *sql.Tx) error
}
```

#### Database Backends
- **SQLite**: Default for development and edge deployments
- **PostgreSQL**: Recommended for production clusters
- Migration system for schema management
- Connection pooling and prepared statements

### 5. Models (`pkg/models/`)

Arrowhead 4.x compatible data structures:
- System and SystemList
- Service and ServiceQueryResult
- AuthorizationRequest and Response
- OrchestrationRequest and Response
- Certificate signing structures

## Communication Patterns

### Synchronous Communication
- REST API for all client interactions
- Request-response pattern
- JSON serialization
- HTTP status codes for error signaling

### Asynchronous Events
- Internal event bus for service coordination
- WebSocket support for real-time updates
- Event types:
  - Service registration/deregistration
  - System online/offline
  - Authorization changes
  - Certificate events

### Security Communication
- mTLS for service-to-service communication
- JWT tokens for session management
- Certificate validation chain
- Encrypted sensitive data in database

## Data Flow

### Service Registration Flow
1. System sends registration request with certificate
2. Authentication middleware validates certificate
3. Registry service creates/updates system record
4. Services are registered with metadata
5. Event emitted to notify subscribers
6. Response with registration confirmation

### Service Discovery Flow
1. Consumer requests services matching criteria
2. Registry queries database with filters
3. Results filtered by authorization rules
4. Metadata enriched from cache
5. Sorted results returned to consumer

### Authorization Flow
1. Consumer requests access to provider service
2. Authorization service checks existing rules
3. If authorized, JWT token generated
4. Token includes claims and expiration
5. Token returned for service consumption

### Orchestration Flow
1. Consumer requests service orchestration
2. Orchestrator queries available services
3. Authorization checked for each candidate
4. QoS metrics evaluated
5. Providers ranked by suitability
6. Recommendations returned with tokens

## Deployment Architecture

### Single Node Deployment
```
┌─────────────────────┐
│   Arrowhead Lite    │
│  ┌───────────────┐  │
│  │   SQLite DB   │  │
│  └───────────────┘  │
│  ┌───────────────┐  │
│  │  All Services │  │
│  └───────────────┘  │
└─────────────────────┘
```

### Clustered Deployment
```
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ Arrowhead    │  │ Arrowhead    │  │ Arrowhead    │
│ Lite Node 1  │  │ Lite Node 2  │  │ Lite Node 3  │
└──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       │                 │                 │
       └─────────────────┼─────────────────┘
                         │
                ┌────────┴────────┐
                │   PostgreSQL    │
                │    Cluster      │
                └─────────────────┘
```

### Edge Deployment
```
        ┌─────────────────┐
        │   Cloud Core    │
        │  (PostgreSQL)   │
        └────────┬────────┘
                 │
    ┌────────────┼────────────┐
    │            │            │
┌───┴───┐  ┌────┴───┐  ┌────┴───┐
│ Edge  │  │  Edge  │  │  Edge  │
│ Node  │  │  Node  │  │  Node  │
│(SQLite)  │(SQLite)│  │(SQLite)│
└───┬───┘  └────┬───┘  └────┬───┘
    │           │            │
 Devices     Devices      Devices
```

## Performance Considerations

### Caching Strategy
- In-memory cache for frequently accessed data
- Service discovery results cached with TTL
- Authorization decisions cached per session
- Certificate validation results cached

### Database Optimization
- Indexed columns for common queries
- Prepared statements for repeated operations
- Connection pooling for PostgreSQL
- Batch operations where possible

### Resource Management
- Goroutine pools for concurrent operations
- Memory limits for cache sizes
- Request timeout configurations
- Circuit breakers for external calls

## Scalability Patterns

### Horizontal Scaling
- Stateless service design
- Shared database for state
- Load balancer compatibility
- Session affinity not required

### Vertical Scaling
- Configurable worker pools
- Database connection limits
- Memory allocation tuning
- CPU affinity options

## Monitoring and Observability

### Metrics
- Prometheus-compatible metrics endpoint
- Service-level metrics (requests, latency, errors)
- System metrics (CPU, memory, goroutines)
- Database metrics (connections, queries, latency)

### Logging
- Structured logging with Logrus
- Configurable log levels
- File and stdout outputs
- Log rotation support

### Health Checks
- Liveness probe endpoint
- Readiness probe endpoint
- Dependency health checks
- Graceful degradation

## Security Architecture

### Authentication Layers
1. **Transport Layer**: TLS/mTLS encryption
2. **Application Layer**: JWT token validation
3. **Service Layer**: Authorization rule enforcement

### Certificate Management
- Self-signed CA for development
- External CA integration for production
- Certificate rotation support
- Revocation list management (planned)

### Data Protection
- Sensitive data encryption at rest
- TLS for data in transit
- Secret management via environment variables
- No hardcoded credentials

## Extension Points

### Plugin System (Future)
- Custom service implementations
- Additional authentication methods
- External storage backends
- Custom orchestration algorithms

### Integration Points
- Webhook notifications
- External event streams
- Custom metrics exporters
- Third-party service discovery

## Development Workflow

### Local Development
1. Run with `--disable-tls` flag
2. Use SQLite for persistence
3. Access via HTTP on port 8080
4. Use demo script for testing

### Testing Strategy
- Unit tests for components
- Integration tests for workflows
- Load tests for performance
- Security tests for vulnerabilities

### CI/CD Pipeline
1. Code commit triggers build
2. Run tests and security scans
3. Build Docker image
4. Deploy to test environment
5. Run smoke tests
6. Promote to production
