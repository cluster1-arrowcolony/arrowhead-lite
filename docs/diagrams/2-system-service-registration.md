# Diagram 2: System and Service Registration

This diagram shows the two-stage process for a client application to become a known entity within the Arrowhead cloud. First, the system itself must be registered. Second, the specific services it provides are registered. Both steps require mTLS authentication using a pre-provisioned client certificate.

```mermaid
sequenceDiagram
    participant Client as Client Application<br/>(Temperature Sensor)
    participant API as arrowhead-lite API
    participant Auth as AuthMiddleware
    participant Registry as Registry Module
    participant DB as Database

    Note over Client, DB: Phase 1: System Registration
    
    Client->>API: POST /serviceregistry/mgmt/systems<br/>(mTLS client certificate)
    API->>Auth: Validate client certificate
    Auth->>Auth: Check certificate against truststore
    Auth-->>API: Certificate valid ✅
    
    API->>Registry: RegisterSystem(req)
    Registry->>DB: Check if system exists
    DB-->>Registry: System not found
    Registry->>DB: CREATE system entry
    DB-->>Registry: System created (ID: 123)
    Registry-->>API: System object (ID: 123)
    API-->>Client: 201 Created<br/>{"id": 123, "systemName": "temp-sensor", ...}
    
    Note over Client, DB: Phase 2: Service Registration
    
    Client->>API: POST /serviceregistry/mgmt/services<br/>(mTLS client certificate)
    API->>Auth: Validate client certificate
    Auth-->>API: Certificate valid ✅
    
    API->>Registry: RegisterServiceMgmt(req)
    Registry->>Registry: Get or create provider system
    Registry->>Registry: Get or create service definition
    Registry->>Registry: Get or create interfaces
    
    Registry->>DB: CREATE service entry
    Registry->>DB: CREATE service definition (if new)
    Registry->>DB: CREATE interfaces (if new)
    
    DB-->>Registry: Service created (ID: 456)
    Registry-->>API: Service object (ID: 456)
    API-->>Client: 201 Created<br/>{"id": 456, "serviceDefinition": "temperature-reading", ...}
    
    Note over Client, DB: System and service are now registered and discoverable
```

### Step-by-Step Explanation

1. **System Registration Request**: A `Client Application` (e.g., a temperature sensor) initiates contact by sending a `POST` request to the `/serviceregistry/mgmt/systems` endpoint. The request is authenticated using its client certificate.
2. **Authentication**: The `arrowhead-lite API`'s middleware intercepts the request. It verifies that the client's certificate was signed by a trusted CA (as defined in the server's `truststore.pem`). If valid, the system's identity (from the certificate's Common Name) is extracted.
3. **Registry Logic**: The API handler passes the request to the internal `Registry Module`.
4. **Database Write**: The `Registry Module` creates a new record for the system in the `Database`.
5. **Confirmation**: A `201 Created` response is sent back to the client, confirming that the system is now registered.
6. **Service Registration Request**: With the system now registered, the client can register the services it offers. It sends a `POST` request to `/serviceregistry/mgmt/services`, detailing the `serviceDefinition` (e.g., "temperature-reading") and `interface` (e.g., "HTTP-SECURE-JSON") it provides.
7. **Authentication (Again)**: This request is also authenticated via mTLS.
8. **Registry & Database**: The `Registry Module` processes the request, creating entries for the service and linking it to the provider system and its interfaces in the `Database`. If the `serviceDefinition` or `interface` are new, `arrowhead-lite`'s registry will create them automatically.
9. **Final Confirmation**: A `201 Created` response is returned, confirming the service is now discoverable by other systems.

## Key Points

1. **mTLS Authentication**: All requests require valid client certificates
2. **Two-Step Process**: Systems must be registered before their services
3. **Automatic Creation**: Related entities (service definitions, interfaces) are created automatically
4. **Database Persistence**: All registration data is stored in the database for discovery

## Authentication Flow

The `AuthMiddleware` validates client certificates by:
- Checking certificate validity and trust chain
- Extracting system name from certificate Common Name
- Looking up system in database (unless it's a sysop certificate)
- Setting authentication context for the request