# Arrowhead Lite Core Specification

Specification of the core system for the Arrowhead Lite framework.

## 1. Introduction

This document specifies the Arrowhead Lite core system, a lightweight framework for IoT service mesh functionalities, including service registry, orchestration, authentication, and authorization. This specification establishes the normative requirements for such a system and adheres to the principles outlined in `docs/META-SPEC.md`.

## 2. Core Concepts

### 2.1 System
A `System` is a network-addressable entity (e.g., an IoT device, application, or service provider) that can both provide and/or consume services within the Arrowhead Lite ecosystem. Systems are identified by a unique combination of `systemName`, `address`, and `port`.

### 2.2 Service
A `Service` represents a function or capability exposed by a `System` as a RESTful API. Each service is uniquely identified by a combination of its `ServiceDefinition`, `ProviderSystem`, and `ServiceURI`, and can specify various attributes such as security requirements, metadata, and supported interfaces.

### 2.3 Service Definition
A `ServiceDefinition` is a unique, descriptive name (e.g., "temperature-reading", "methane-co-gas-detector") that categorizes a type of service. Multiple systems can provide services under the same definition.

### 2.4 Interface
An `Interface` defines a communication protocol or data format supported by a service (e.g., "HTTP-SECURE-JSON", "HTTP-JSON").

### 2.5 Authorization
`Authorization` refers to the access control rules that dictate whether a `ConsumerSystem` is permitted to access a service provided by a `ProviderSystem`. Rules are established by an administrator and are verified during service orchestration.

### 2.6 Orchestration
`Orchestration` is the core "matchmaking" process where a `ConsumerSystem` dynamically discovers and obtains access to a suitable `ProviderSystem` for a requested service, based on service definition, interface requirements, security, and established authorization rules.

### 2.7 Mutual TLS (mTLS)
`mTLS` is the primary mechanism for secure communication and entity authentication within Arrowhead Lite. Both the server and client present and verify certificates during TLS handshake, ensuring mutual trust.

### 2.8 JSON Web Token (JWT)
`JWTs` are used as authorization tokens. Upon successful orchestration, the Orchestrator issues a JWT that a Consumer System can present directly to a `ProviderSystem` to prove authorization for service consumption, without further involvement from the core system.

## 3. Architecture Overview

The system's core functionalities are logically separated into distinct components, regardless of its deployment architecture (e.g., single binary or distributed services):

*   **Registry**: Manages the registration and discovery of `Systems`, `ServiceDefinitions`, and `Interfaces`.
*   **Orchestrator**: Handles service discovery requests, applies filtering and ranking, and generates authorization tokens.
*   **Authentication**: Manages identity validation (e.g., mTLS client certificate validation) and authorization tokens (e.g., JSON Web Token (JWT) signing and verification).
*   **Data Store**: Provides data persistence for system entities.
*   **API Interface**: Exposes the system's functionalities via a RESTful HTTP/JSON API.

## 4. System Configuration

The system's configuration is managed through a hierarchy, allowing parameters to be supplied via various mechanisms (e.g., environment variables, configuration files, or command-line arguments), with defined precedence rules.

### 4.1 System Configuration Sources
The system's configuration parameters are applied in the following order of precedence, where sources with higher numbers override those with lower numbers:
1.  **Defaults**: Hardcoded default values within the system.
2.  **Configuration File**: Parameters loaded from a YAML configuration file.
3.  **Environment Variables**: Parameters provided via environment variables.
4.  **Command Line Flags**: Parameters provided via command line arguments.

### 4.2 Configuration Parameters

The following section details the structure and types of the system's key configurable parameters. These parameters can be provided via any of the configured sources.

```yaml
server:
  host: "0.0.0.0"
  port: 8443
  read_timeout: "30s"
  write_timeout: "30s"
  tls:
    cert_file: "string" # Path to the server's public certificate file
    key_file: "string" # Path to the server's private key file
    truststore_file: "string" # Path to file containing trusted CA certificates
  cors:
    allow_origins: ["string"] # Origins allowed. E.g., ["*"]
    allow_methods: ["string"] # Methods allowed. E.g., ["GET", "POST"]
    allow_headers: ["string"] # Headers allowed. E.g., ["Content-Type"]

database:
  type: "string" # Type of database: "sqlite" or "postgresql"
  path: "string" # Path to the SQLite database file
  host: "string" # Hostname or IP for PostgreSQL
  port: "integer" # Port for PostgreSQL
  username: "string" # Username for PostgreSQL
  password: "string" # Password for PostgreSQL
  name: "string" # Database name for PostgreSQL

auth:
  token_duration: "duration" # Duration for which JWT tokens are valid (e.g., "24h")
  private_key_file: "string" # Path to the JWT signing private key file
  public_key_file: "string" # Path to the JWT verification public key file

logging:
  level: "string" # Logging level: "debug", "info", "warn", "error", "panic"
  format: "string" # Logging format: "text" or "json"
  file: "string" # Path to log file. Empty string means stdout.

gateway:
  enabled: "boolean" # Whether gateway functionality is enabled
  cloud_id: "string" # Unique identifier for the local cloud
  certificate_file: "string" # Path to the gateway's TLS certificate
  private_key_file: "string" # Path to the gateway's TLS private key
  trust_store: "string" # Path to directory of trusted CA certificates
  trust_anchors: # List of trusted remote clouds with their certificates
    - cloud_id: "string"
      certificate_file: "string"
```

### 4.3 Environment Variables
Configuration parameters can also be set via environment variables. These variables override values found in the configuration file. The mapping from configuration parameter to environment variable follows a convention: `ARROWHEAD_` prefix, uppercase names, and dots (`.`) replaced by underscores (`_`).

| Configuration Parameter      | Environment Variable                   | Description                                        |
| :--------------------------- | :------------------------------------- | :------------------------------------------------- |
| `server.host`                | `ARROWHEAD_SERVER_HOST`                | Host address for the server.                       |
| `server.port`                | `ARROWHEAD_SERVER_PORT`                | Port for the server.                               |
| `server.read_timeout`        | `ARROWHEAD_SERVER_READ_TIMEOUT`        | Read timeout for HTTP requests.                    |
| `server.write_timeout`       | `ARROWHEAD_SERVER_WRITE_TIMEOUT`       | Write timeout for HTTP responses.                  |
| `server.tls.enabled`         | `ARROWHEAD_SERVER_TLS_ENABLED`         | Enables or disables TLS.                           |
| `server.tls.cert_file`       | `ARROWHEAD_SERVER_TLS_CERT_FILE`       | Path to the server's public certificate file.      |
| `server.tls.key_file`        | `ARROWHEAD_SERVER_TLS_KEY_FILE`        | Path to the server's private key file.             |
| `server.tls.truststore_file` | `ARROWHEAD_SERVER_TLS_TRUSTSTORE_FILE` | Path to file containing trusted CA certificates.   |
| `server.cors.allow_origins`  | `ARROWHEAD_SERVER_CORS_ALLOW_ORIGINS`  | Comma-separated list of allowed origins.           |
| `server.cors.allow_methods`  | `ARROWHEAD_SERVER_CORS_ALLOW_METHODS`  | Comma-separated list of allowed HTTP methods.      |
| `server.cors.allow_headers`  | `ARROWHEAD_SERVER_CORS_ALLOW_HEADERS`  | Comma-separated list of allowed HTTP headers.      |
| `database.type`              | `ARROWHEAD_DATABASE_TYPE`              | Type of database (`sqlite` or `postgresql`).       |
| `database.path`              | `ARROWHEAD_DATABASE_PATH`              | Path to the SQLite database file.                  |
| `database.host`              | `ARROWHEAD_DATABASE_HOST`              | Hostname or IP for PostgreSQL.                     |
| `database.port`              | `ARROWHEAD_DATABASE_PORT`              | Port for PostgreSQL.                               |
| `database.username`          | `ARROWHEAD_DATABASE_USERNAME`          | Username for PostgreSQL.                           |
| `database.password`          | `ARROWHEAD_DATABASE_PASSWORD`          | Password for PostgreSQL.                           |
| `database.name`              | `ARROWHEAD_DATABASE_NAME`              | Database name for PostgreSQL.                      |
| `auth.jwt_secret`            | `ARROWHEAD_AUTH_JWT_SECRET`            | Symmetric JWT signing secret.                      |
| `auth.token_duration`        | `ARROWHEAD_AUTH_TOKEN_DURATION`        | Duration for which JWT tokens are valid.           |
| `auth.private_key_file`      | `ARROWHEAD_AUTH_PRIVATE_KEY_FILE`      | Path to the JWT signing private key file.          |
| `auth.public_key_file`       | `ARROWHEAD_AUTH_PUBLIC_KEY_FILE`       | Path to the JWT verification public key file.      |
| `logging.level`              | `ARROWHEAD_LOGGING_LEVEL`              | Logging level.                                     |
| `logging.format`             | `ARROWHEAD_LOGGING_FORMAT`             | Logging format.                                    |
| `logging.file`               | `ARROWHEAD_LOGGING_FILE`               | Path to log file.                                  |
| `health.check_interval`      | `ARROWHEAD_HEALTH_CHECK_INTERVAL`      | Interval for health checks.                        |
| `health.inactive_timeout`    | `ARROWHEAD_HEALTH_INACTIVE_TIMEOUT`    | Timeout for considering systems inactive.          |
| `health.cleanup_interval`    | `ARROWHEAD_HEALTH_CLEANUP_INTERVAL`    | Interval for cleaning up inactive systems.         |
| `gateway.enabled`            | `ARROWHEAD_GATEWAY_ENABLED`            | Whether gateway functionality is enabled.          |
| `gateway.cloud_id`           | `ARROWHEAD_GATEWAY_CLOUD_ID`           | Unique identifier for the local cloud.             |
| `gateway.certificate_file`   | `ARROWHEAD_GATEWAY_CERTIFICATE_FILE`   | Path to the gateway's TLS certificate.             |
| `gateway.private_key_file`   | `ARROWHEAD_GATEWAY_PRIVATE_KEY_FILE`   | Path to the gateway's TLS private key.             |
| `gateway.trust_store`        | `ARROWHEAD_GATEWAY_TRUST_STORE`        | Path to directory of trusted CA certificates.      |
| `ARROWHEAD_CONFIG`           | `ARROWHEAD_CONFIG`                     | Specifies the path to a custom configuration file. |

### 4.4 Command Line Flags
Command line flags are processed after environment variables and configuration files, potentially overriding some settings. These are primarily for immediate operational control.

| Flag        | Description                                                                                                                          |
| :---------- | :----------------------------------------------------------------------------------------------------------------------------------- |
| `--quiet`   | Disables all logging output by setting the effective logging level to `panic`.                                                       |
| `--verbose` | Enables verbose logging by setting the effective logging level to `debug`.                                                           |
| `--clean`   | Deletes the SQLite database file (`arrowhead.db`) if it exists before the application starts. This is useful for development resets. |

## 5. Data Models

The following are the primary data structures used for requests and responses within the Arrowhead Lite system. All timestamps are represented as `datetime` objects (UTC).

### 5.1 `SystemRegistration`
Represents a request to register a system.

```json
{
  "systemName": "string",
  "address": "string",
  "port": "integer",
  "authenticationInfo": "string",
  "metadata": {
    "string": "string"
  }
}
```

### 5.2 `System`
Represents a registered Arrowhead system.

```json
{
  "id": "integer",
  "systemName": "string",
  "address": "string",
  "port": "integer",
  "authenticationInfo": "string",
  "createdAt": "string", # RFC3339 datetime format (e.g., "2024-01-01T12:00:00Z")
  "updatedAt": "string", # RFC3339 datetime format (e.g., "2024-01-01T12:00:00Z")
  "metadata": {
    "string": "string"
  }
}
```

### 5.3 `SystemsResponse`
A paginated response for listing systems.

```json
{
  "data": [
    { /* System object */ }
  ],
  "count": "integer"
}
```

### 5.4 `ServiceDefinition`
Represents a unique service definition.

```json
{
  "id": "integer",
  "serviceDefinition": "string",
  "createdAt": "string", # RFC3339 datetime format (e.g., "2024-01-01T12:00:00Z")
  "updatedAt": "string" # RFC3339 datetime format (e.g., "2024-01-01T12:00:00Z")
}
```

### 5.5 `Interface`
Represents a supported communication interface.

```json
{
  "id": "integer",
  "interfaceName": "string",
  "createdAt": "string", # RFC3339 datetime format (e.g., "2024-01-01T12:00:00Z")
  "updatedAt": "string" # RFC3339 datetime format (e.g., "2024-01-01T12:00:00Z")
}
```

### 5.6 `Provider`
Represents a system acting as a service provider. It includes all fields of a `System` object, indicating its role as a service provider within the ecosystem.

```json
{
  "id": "integer",
  "systemName": "string",
  "address": "string",
  "port": "integer",
  "authenticationInfo": "string",
  "createdAt": "string", # RFC3339 datetime format (e.g., "2024-01-01T12:00:00Z")
  "updatedAt": "string", # RFC3339 datetime format (e.g., "2024-01-01T12:00:00Z")
  "metadata": {
    "string": "string"
  }
}
```

### 5.7 `ProviderSystem`
Represents the details of a system intended to act as a service provider, as provided in service registration or orchestration requests. This data transfer object (DTO) specifies the system's external identifiers, not its internal system-managed identifiers or timestamps.

```json
{
  "systemName": "string",
  "address": "string",
  "port": "integer",
  "authenticationInfo": "string",
  "metadata": {
    "string": "string"
  }
}
```

### 5.8 `ServiceRegistrationRequest`
Represents a request to register a service.

```json
{
  "serviceDefinition": "string",
  "providerSystem": { /* ProviderSystemRequest object */ },
  "serviceUri": "string",
  "endOfValidity": "string" # RFC3339 datetime format (e.g., "2024-01-01T12:00:00Z"),
  "secure": "string", # "CERTIFICATE" or "TOKEN"
  "metadata": {
    "string": "string"
  },
  "version": "string", # A string representing an integer version number.
  "interfaces": [
    "string"
  ]
}
```

### 5.9 `Service`
Represents a registered service.

```json
{
  "id": "integer",
  "serviceDefinition": { /* ServiceDefinition object */ },
  "provider": { /* Provider object */ },
  "serviceUri": "string",
  "endOfValidity": "string", # RFC3339 datetime format (e.g., "2024-01-01T12:00:00Z")
  "secure": "string", # "CERTIFICATE" or "TOKEN"
  "metadata": {
    "string": "string"
  },
  "version": "integer",
  "interfaces": [
    { /* Interface object */ }
  ],
  "createdAt": "string", # RFC3339 datetime format (e.g., "2024-01-01T12:00:00Z")
  "updatedAt": "string" # RFC3339 datetime format (e.g., "2024-01-01T12:00:00Z")
}
```

### 5.10 `ServicesResponse`
A paginated response for listing services.

```json
{
  "data": [
    { /* Service object */ }
  ],
  "count": "integer"
}
```

### 5.11 `AddAuthorizationRequest`
Represents a request to create one or more authorization rules.

```json
{
  "consumerId": "integer",
  "providerIds": [
    "integer"
  ],
  "interfaceIds": [
    "integer"
  ],
  "serviceDefinitionIds": [
    "integer"
  ]
}
```

### 5.12 `Authorization`
Represents an authorization rule.

```json
{
  "id": "integer",
  "consumerSystem": { /* System object */ },
  "providerSystem": { /* Provider object */ },
  "serviceDefinition": { /* ServiceDefinition object */ },
  "interfaces": [
    { /* Interface object */ }
  ],
  "createdAt": "string", # RFC3339 datetime format (e.g., "2024-01-01T12:00:00Z")
  "updatedAt": "string" # RFC3339 datetime format (e.g., "2024-01-01T12:00:00Z")
}
```

### 5.13 `AuthorizationsResponse`
A paginated response for listing authorizations.

```json
{
  "data": [
    { /* Authorization object */ }
  ],
  "count": "integer"
}
```

### 5.14 `RequesterSystem`
Represents the details of the system initiating an orchestration request. This DTO specifies the system's external identifiers, not its internal system-managed identifiers or timestamps.

```json
{
  "systemName": "string",
  "address": "string",
  "port": "integer",
  "authenticationInfo": "string",
  "metadata": {
    "string": "string"
  }
}
```

### 5.15 `OrchestrationFlags`
Flags to control orchestration behavior.

```json
{
  "onlyPreferred": "boolean",
  "overrideStore": "boolean",
  "externalServiceRequest": "boolean",
  "enableInterCloud": "boolean",
  "enableQoS": "boolean",
  "matchmaking": "boolean",
  "metadataSearch": "boolean",
  "triggerInterCloud": "boolean",
  "pingProviders": "boolean"
}
```

### 5.16 `PreferredProvider`
Defines a preferred provider for orchestration, including its cloud and system details.

```json
{
  "providerCloud": {
    "authenticationInfo": "string",
    "gatekeeperRelayIDs": [],
    "gatewayRelayIDs": [],
    "name": "string",
    "neighbor": false,
    "operator": "string",
    "secure": false
  },
  "providerSystem": { /* See Section 5.2 System */ }
}
```

### 5.17 `RequestedService`
Defines the criteria for a service being requested during orchestration.

```json
{
  "serviceDefinitionRequirement": "string",
  "interfaceRequirements": [
    "string"
  ],
  "securityRequirements": [
    "string"
  ],
  "metadataRequirements": {
    "string": "string"
  },
  "versionRequirement": "integer",
  "maxVersionRequirement": "integer",
  "minVersionRequirement": "integer",
  "pingProviders": "boolean"
}
```

### 5.18 `OrchestrationRequest`
Full request payload for service orchestration.

```json
{
  "requesterSystem": { /* RequesterSystem object */ },
  "requestedService": { /* RequestedService object */ },
  "orchestrationFlags": { /* OrchestrationFlags object */ },
  "preferredProviders": [
    { /* PreferredProvider object */ }
  ],
  "qosRequirements": {
    "string": "string"
  }
}
```

### 5.19 `MatchedService`
Represents a service returned by the Orchestrator that matches the request and is authorized.

```json
{
  "provider": { /* Provider object */ },
  "service": { /* ServiceDefinition object */ },
  "serviceUri": "string",
  "secure": "string", # "CERTIFICATE" or "TOKEN"
  "metadata": {
    "string": "string"
  },
  "interfaces": [
    { /* Interface object */ }
  ],
  "version": "integer",
  "authorizationTokens": {
    "string": "string"
  },
  "warnings": [
    "string"
  ]
}
```

### 5.20 `OrchestrationResponse`
Response payload from service orchestration.

```json
{
  "response": [
    { /* MatchedService object */ }
  ]
}
```

### 5.21 `Metrics`
System-wide operational metrics.

### 5.22 `HealthStatus`
Represents the basic health check response of the system.

```json
{
  "status": "string",
  "timestamp": "string", #RFC3339 formatted timestamp
  "service": "string"
}
```

```json
{
  "total_systems": "integer",
  "total_services": "integer",
  "active_systems": "integer",
  "active_services": "integer"
}
```

## 6. API Specification

Arrowhead Lite exposes a RESTful API. Arrowhead Lite exposes a RESTful HTTP/JSON API. All API interactions requiring authentication enforce Mutual TLS (mTLS) authentication. Endpoints are documented below.

### 6.1 API Authentication and Authorization Derivation

The API enforces mTLS authentication for endpoints requiring client authentication. It derives client identity and authorization context as follows:

*   **Client Certificate Requirement**: A client certificate is presented by the connecting peer.
*   **Certificate Validation**: The presented client certificate is signed by a trusted Certificate Authority (CA) configured in the system's truststore.
*   **Identity Extraction**: The `Common Name (CN)` from the client certificate's Subject field is extracted as the `system_name`.
*   **Admin Role Assignment**: If the `system_name` is "sysop" (case-insensitive), the client is granted administrative privileges (admin role).
*   **System Lookup**: For non-admin clients, the `system_name` is used to look up a corresponding `System` in the persistence layer. If a `System` is found, its `system_id` is associated with the request context. If no `System` is found, a `401 Unauthorized` response is returned, unless the endpoint is specifically designed for public registration of new systems.
*   **Authentication Info Derivation**: The system associates the client certificate's raw base64-encoded form as the `authentication_info` attribute for the client.

### 6.2 Error Handling

API responses for errors conform to a standardized JSON structure and HTTP status codes.

```json
{
  "error": "string" (a code representing the error type, e.g., BAD_REQUEST),
  "message": "string" (a human-readable description of the error)
}
```

Common HTTP status codes and their corresponding abstract error types:

*   `400 Bad Request`: Signifies a client-side error, such as a malformed request body or invalid parameters.
*   `401 Unauthorized`: Indicates that authentication is required or has failed (e.g., missing or invalid mTLS certificate).
*   `403 Forbidden`: Denotes that the authenticated client does not have the necessary permissions to perform the requested operation.
*   `404 Not Found`: Occurs when the requested resource (e.g., system, service, authorization rule) does not exist.
*   `409 Conflict`: Arises when a request conflicts with the current state of the server (e.g., attempting to create a duplicate resource).
*   `500 Internal Server Error`: Represents an unexpected server-side error, such as a component failure or an unhandled exception.

### 6.3 Health and Metrics Endpoints

#### `GET /health`
*   **Description**: Provides a basic health check for the Arrowhead Lite system.
*   **Authentication**: Requires an mTLS client certificate (any valid client).
*   **Response (`200 OK`)**: A JSON object indicating the system's health status. Example:
    ```json
    {
      "status": "string",
      "timestamp": "string", #RFC3339 formatted timestamp
      "service": "string"
    }
    ```

#### `GET /metrics`
*   **Description**: Exposes Prometheus-compatible metrics for monitoring.
*   **Authentication**: Requires an mTLS client certificate (any valid client).
*   **Response (`200 OK`)**: Metrics data in a machine-readable exposition format (e.g., Prometheus compatible).

### 6.4 System Registry Endpoints

#### `POST /serviceregistry/mgmt/systems`
*   **Description**: Registers a new system or updates an existing one. This endpoint is designed for management operations.
*   **Authentication**: Requires an mTLS client certificate (Admin or Registered System).
*   **Request Body**: `SystemRegistration` object.
*   **Response (`201 Created`)**: `System` object.

#### `POST /serviceregistry/mgmt/systems/batch`
*   **Description**: Registers or updates multiple systems in a single batch request.
*   **Authentication**: Requires an mTLS client certificate (Admin or Registered System).
*   **Request Body**: Array of `SystemRegistration` objects.
*   **Response (`201 Created`)**: Array of `System` objects.

#### `POST /serviceregistry/register-system`
*   **Description**: Public endpoint for a system to register itself. The `authenticationInfo` field in the request payload is always overridden by the base64-encoded raw form of the client's mTLS certificate. The `systemName`, `address`, and `port` are taken from the request payload.
*   **Authentication**: Requires an mTLS client certificate (New or Registered System).
*   **Request Body**: `SystemRegistration` object.
*   **Response (`201 Created`)**: `System` object.

#### `GET /serviceregistry/mgmt/systems`
*   **Description**: Lists all registered systems.
*   **Authentication**: Requires an mTLS client certificate (Any valid client).
*   **Query Parameters**:
    *   `sort_field`: (Optional) Field to sort by (e.g., `id`, `system_name`, `address`, `port`, `createdAt`, `updatedAt`). Default: `id`.
    *   `direction`: (Optional) Sort direction (`ASC` or `DESC`). Default: `ASC`.
*   **Response (`200 OK`)**: `SystemsResponse` object.

#### `GET /serviceregistry/mgmt/systems/:id`
*   **Description**: Retrieves a specific system by its unique ID.
*   **Authentication**: Requires an mTLS client certificate (Any valid client).
*   **Path Parameters**:
    *   `id`: The integer ID of the system.
*   **Response (`200 OK`)**: `System` object.

#### `DELETE /serviceregistry/mgmt/systems/:id`
*   **Description**: Unregisters a system by its unique ID. This is a privileged operation.
*   **Authentication**: Requires an mTLS client certificate (Admin or Registered System).
*   **Path Parameters**:
    *   `id`: The integer ID of the system to unregister.
*   **Response (`200 OK`)**: Acknowledges successful unregistration. Example: `{"message": "System unregistered successfully"}`.

#### `DELETE /serviceregistry/unregister-system`
*   **Description**: Public endpoint for a system to unregister itself using its identifying parameters.
*   **Authentication**: Requires an mTLS client certificate (Registered System).
*   **Query Parameters**:
    *   `system_name`: The name of the system.
    *   `address`: The network address of the system.
    *   `port`: The port of the system.
*   **Response (`200 OK`)**: Acknowledges successful unregistration. Example: `{"message": "System unregistered successfully"}`.

### 6.5 Service Registry Endpoints

#### `POST /serviceregistry/mgmt/services`
*   **Description**: Registers a new service or updates an existing one. This endpoint is designed for management operations.
*   **Authentication**: Requires an mTLS client certificate (Admin or Registered System).
*   **Request Body**: `ServiceRegistrationRequest` object.
*   **Response (`201 Created`)**: `Service` object.

#### `POST /serviceregistry/mgmt/services/batch`
*   **Description**: Registers or updates multiple services in a single batch request.
*   **Authentication**: Requires an mTLS client certificate (Admin or Registered System).
*   **Request Body**: Array of `ServiceRegistrationRequest` objects.
*   **Response (`201 Created`)**: Array of `Service` objects.

#### `POST /serviceregistry/register`
*   **Description**: Public endpoint for a system to register its service. The `providerSystem.systemName` is automatically populated from the client's mTLS certificate Common Name (CN), overriding any value provided in the request payload. Similarly, `providerSystem.authenticationInfo` is populated from the base64-encoded raw form of the client certificate, also overriding the payload. Other `providerSystem` fields (`address`, `port`, `metadata`) are taken from the request payload.
*   **Authentication**: Requires an mTLS client certificate (Registered System).
*   **Request Body**: `ServiceRegistrationRequest` object.
*   **Response (`201 Created`)**: `Service` object.

#### `GET /serviceregistry/mgmt/services`
*   **Description**: Lists all registered services.
*   **Authentication**: Requires an mTLS client certificate (Any valid client).
*   **Query Parameters**:
    *   `sort_field`: (Optional) Field to sort by (e.g., `id`, `createdAt`, `updatedAt`, `uri`, `version`). Default: `id`.
    *   `direction`: (Optional) Sort direction (`ASC` or `DESC`). Default: `ASC`.
*   **Response (`200 OK`)**: `ServicesResponse` object.

#### `GET /serviceregistry/mgmt/services/:id`
*   **Description**: Retrieves a specific service by its unique ID.
*   **Authentication**: Requires an mTLS client certificate (Any valid client).
*   **Path Parameters**:
    *   `id`: The integer ID of the service.
*   **Response (`200 OK`)**: `Service` object.

#### `DELETE /serviceregistry/mgmt/services/:id`
*   **Description**: Unregisters a service by its unique ID. This is a privileged operation.
*   **Authentication**: Requires an mTLS client certificate (Admin or Registered System).
*   **Path Parameters**:
    *   `id`: The integer ID of the service to unregister.
*   **Response (`200 OK`)**: `{"message": "Service unregistered successfully"}`.

#### `DELETE /serviceregistry/unregister`
*   **Description**: Public endpoint for a system to unregister its service using identifying parameters.
*   **Authentication**: Requires an mTLS client certificate (Registered System).
*   **Query Parameters**:
    *   `system_name`: The name of the provider system.
    *   `service_uri`: The URI of the service.
    *   `service_definition`: The definition of the service.
    *   `address`: The network address of the provider system.
    *   `port`: The port of the provider system.
*   **Response (`200 OK`)**: `{"message": "Service unregistered successfully"}`.

### 6.6 Authorization Endpoints

#### `POST /authorization/mgmt/intracloud`
*   **Description**: Creates one or more authorization rules. This is an administrative operation.
*   **Authentication**: Requires an mTLS client certificate (Admin Only).
*   **Request Body**: `AddAuthorizationRequest` object.
*   **Response (`201 Created`)**: `AuthorizationsResponse` object, detailing the created rules.

#### `POST /authorization/mgmt/intracloud/batch`
*   **Description**: Creates multiple authorization rules in a single batch request. This is an administrative operation.
*   **Authentication**: Requires an mTLS client certificate (Admin Only).
*   **Request Body**: Array of `AddAuthorizationRequest` objects.
*   **Response (`201 Created`)**: `AuthorizationsResponse` object, detailing the created rules.

#### `GET /authorization/mgmt/intracloud`
*   **Description**: Lists all authorization rules.
*   **Authentication**: Requires an mTLS client certificate (Admin Only).
*   **Query Parameters**:
    *   `sort_field`: (Optional) Field to sort by (e.g., `id`, `createdAt`, `updatedAt`). Default: `id`.
    *   `direction`: (Optional) Sort direction (`ASC` or `DESC`). Default: `ASC`.
*   **Response (`200 OK`)**: `AuthorizationsResponse` object.

#### `DELETE /authorization/mgmt/intracloud/:id`
*   **Description**: Removes an authorization rule by its unique ID. This is an administrative operation.
*   **Authentication**: Requires an mTLS client certificate (Admin Only).
*   **Path Parameters**:
    *   `id`: The integer ID of the authorization rule to remove.
*   **Response (`200 OK`)**: `{"message": "Authorization removed successfully"}`.

### 6.7 Orchestration Endpoints

#### `POST /orchestrator/orchestration`
*   **Description**: Initiates a service orchestration request to discover and obtain access to services.
*   **Authentication**: Requires an mTLS client certificate (Registered System).
*   **Request Body**: `OrchestrationRequest` object. The `requesterSystem.systemName` and `requesterSystem.authenticationInfo` fields are populated from the client's mTLS certificate (Common Name and base64-encoded raw form, respectively) *if they are not provided* in the request payload. Other `requesterSystem` fields (`address`, `port`, `metadata`) are taken from the request payload.
*   **Response (`200 OK`)**: `OrchestrationResponse` object, containing matched services and authorization tokens.

## 7. Functional Specification

### 7.1 System Registration

1.  A `SystemRegistration` request is received. Depending on the endpoint, the client's identity and authentication information (e.g., from an mTLS client certificate) may be used to populate or override parts of the request (e.g., `authenticationInfo`).
2.  The system verifies its data store for an existing `System` with the same `systemName`, `address`, and `port`.
3.  If an existing system is found, its details (e.g., `authenticationInfo`, `metadata`, `updatedAt`) are updated.
4.  If no existing system is found, a new `System` entry is recorded in the system's data store, assigning a unique `id`.

### 7.2 Service Registration

1.  A `ServiceRegistrationRequest` is received.
2.  The system first resolves the `Provider` for the service:
    *   If the request is made via a public endpoint (`/serviceregistry/register`), the `Provider`'s `systemName` is derived from the client certificate's Common Name (CN), and its `authenticationInfo` is derived from the base64-encoded raw form of the client certificate. These values override any corresponding fields in the request payload.
    *   If the request is made via a management endpoint (`/serviceregistry/mgmt/services`), the `Provider` details are taken directly from the request body.
3.  The system attempts to identify an existing `System` in its data store corresponding to the `Provider` details (by `systemName`, `address`, `port`). If no such `System` is found, a new `System` entry is recorded.
4.  The system attempts to identify an existing `ServiceDefinition` by its `serviceDefinition` name. If no `ServiceDefinition` is found, a new `ServiceDefinition` entry is recorded.
5.  For each `interfaceName` specified in the request, the system attempts to identify an existing `Interface`. If no `Interface` is found, a new `Interface` entry is recorded.
6.  A new `Service` entry is recorded in the system's data store, linking to the resolved `ServiceDefinition`, `Provider`, and `Interfaces`.

### 7.3 Authorization Logic

1.  An `AddAuthorizationRequest` is received from an administrative client.
2.  The system validates that the `Consumer`, `Provider(s)`, `ServiceDefinition(s)`, and `Interface(s)` referenced by their IDs exist in the persistence layer.
3.  For every valid combination of `ProviderID` and `ServiceDefinitionID` specified in the request, a new `Authorization` rule is created in the persistence layer. If specific `InterfaceIDs` are provided, they are linked to the newly created authorization rule. This batch creation mechanism is used for both single and multiple rule requests.
4.  The system verifies if a given `ConsumerSystem` is authorized to access a `Service` from a `ProviderSystem` for a specific `ServiceDefinition` and a set of `Interfaces` by querying its data store for an `Authorization` rule that explicitly matches the `ConsumerSystem`'s ID, `ProviderSystem`'s ID, `ServiceDefinition`'s ID, and all specified `Interface` IDs.

### 7.4 Orchestration Logic

1.  An `OrchestrationRequest` is received from a `RequesterSystem`. The system populates the `RequesterSystem` details (e.g., `systemName`) from the client's mTLS certificate if these details are not provided in the request payload.
2.  The Orchestration component queries the Registry component to find all `Service` entries that match the `RequestedService.ServiceDefinitionRequirement`.
3.  **Filtering**: For each candidate service, the Orchestrator filters based on:
    *   `InterfaceRequirements`
    *   `SecurityRequirements`
    *   `VersionRequirement`, `MinVersionRequirement`, `MaxVersionRequirement`
    *   **Authorization**: The system's authorization mechanism is used to verify that the `RequesterSystem` is authorized to consume the `Service` from its `Provider`. Services for which no authorization exists are filtered out.
    *   `MetadataRequirements` (if `orchestrationFlags.metadataSearch` is true).
4.  **Ranking**: The remaining, authorized services are ranked based on `PreferredProviders` and other `OrchestrationFlags` (e.g., `onlyPreferred`).
5.  **Token Generation**: For each `MatchedService`, the system generates a short-lived `AuthorizationToken` (e.g., a JSON Web Token - JWT).
6.  **Response**: An `OrchestrationResponse` is returned, containing a list of `MatchedService` objects, each including relevant provider details, service details, and the generated `AuthorizationTokens`.

## 8. Security Model

The system's security is built upon Mutual TLS (mTLS) for API access and JWTs for decentralized service consumption authorization.

### 8.1 Mutual TLS (mTLS)

*   **Server Identity**: The Arrowhead Lite system (server) presents its configured public TLS certificate and uses its corresponding private key during the TLS handshake to identify itself to clients.
*   **Client Identity**: All clients (e.g., administrators, `ConsumerSystems`, `ProviderSystems`) present a valid client certificate signed by a trusted Certificate Authority (CA) to access Arrowhead Lite API endpoints.
*   **Trust Root**: The system is configured with a set of trusted CA certificates, which are used by the server to verify client certificates and by clients to verify the server's certificate.

### 8.2 Role-Based Access Control (RBAC)

*   **Administrator (`sysop`)**: A client whose mTLS certificate has a Common Name (CN) exactly matching "sysop" (case-insensitive) is granted full administrative privileges. This role allows access to all management API endpoints (e.g., batch system registration, authorization rule creation/deletion). An administrative user does not require a corresponding `System` entry in the data store.
*   **Registered Systems**: Clients presenting certificates with `CN`s matching a registered `System.SystemName` are granted permissions to manage their own system and services, and to initiate orchestration requests.

### 8.3 JSON Web Token (JWT) for Service Consumption

*   **Issuance**: Upon successful orchestration, the Orchestration component issues a JWT signed with its configured JWT private key. This JWT attests that the specific `ConsumerSystem` is authorized to access a specific `Service` from a specific `ProviderSystem`.
*   **Validation**: When a `ConsumerSystem` makes a direct call to a `ProviderSystem`, the `ProviderSystem` validates the received JWT by verifying its signature using the corresponding configured JWT public key. The JWT payload contains information (e.g., consumer ID, provider ID, service ID) for the provider to make an access decision.
*   **Decentralized Consumption**: After orchestration and JWT issuance, the system is not involved in the direct data plane communication between `Consumer` and `Provider` systems.

## 9. Persistence

The system uses a relational database for persistent storage of all core entities.

*   **Supported Databases**: Configurable for `sqlite` or `postgresql`.
*   **Schema Management**: The database schema is automatically initialized upon application startup if tables do not exist.
*   **Entities**: The persistence layer stores data for core entities including Systems, Service Definitions, Interfaces, Services (managing their relationships to providers, definitions, and interfaces), and Authorization rules (managing their relationships to consumers, providers, service definitions, and interfaces).
