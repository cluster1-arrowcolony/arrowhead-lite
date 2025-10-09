# Arrowhead Lite API Documentation

## Overview

Arrowhead Lite implements the Arrowhead Framework 4.x REST API specification, providing service registry, authorization, orchestration, and certificate authority functionality through a unified HTTP/HTTPS interface.

## Base URL

- Development: `http://localhost:8080`
- Production: `https://localhost:8443` (with mTLS)

## Authentication

### Development Mode (TLS Disabled)
- No authentication required
- Direct API access for testing

### Production Mode (TLS Enabled)
- mTLS client certificate authentication required
- Optional JWT token support for additional authorization
- Client certificates must be signed by the same CA

## Core Services

### Service Registry API

#### Register System

**POST** `/serviceregistry/register`

Registers a new system in the service registry.

Request Body:
```json
{
  "system": {
    "systemName": "sensor-system",
    "address": "192.168.1.100",
    "port": 8080,
    "authenticationInfo": "certificate-thumbprint"
  },
  "services": [
    {
      "serviceDefinition": "temperature",
      "interfaces": ["HTTP-SECURE-JSON"],
      "serviceUri": "/temperature",
      "metadata": {
        "unit": "celsius",
        "accuracy": "0.1"
      }
    }
  ]
}
```

Response: `201 Created`
```json
{
  "id": 1,
  "system": {
    "id": 1,
    "systemName": "sensor-system",
    "address": "192.168.1.100",
    "port": 8080
  },
  "services": [
    {
      "id": 1,
      "serviceDefinition": "temperature",
      "interfaces": ["HTTP-SECURE-JSON"]
    }
  ]
}
```

#### Query Services

**POST** `/serviceregistry/query`

Search for available services based on criteria.

Request Body:
```json
{
  "serviceDefinitionRequirement": "temperature",
  "interfaceRequirements": ["HTTP-SECURE-JSON"],
  "metadataRequirements": {
    "unit": "celsius"
  }
}
```

Response: `200 OK`
```json
{
  "serviceQueryData": [
    {
      "id": 1,
      "serviceDefinition": {
        "id": 1,
        "serviceDefinition": "temperature"
      },
      "provider": {
        "id": 1,
        "systemName": "sensor-system",
        "address": "192.168.1.100",
        "port": 8080
      },
      "interfaces": ["HTTP-SECURE-JSON"],
      "serviceUri": "/temperature",
      "metadata": {
        "unit": "celsius"
      }
    }
  ]
}
```

#### Unregister System

**DELETE** `/serviceregistry/unregister`

Remove a system and its services from the registry.

Request Body:
```json
{
  "systemName": "sensor-system",
  "address": "192.168.1.100",
  "port": 8080
}
```

Response: `204 No Content`

#### List All Systems

**GET** `/serviceregistry/systems`

Retrieve all registered systems.

Response: `200 OK`
```json
[
  {
    "id": 1,
    "systemName": "sensor-system",
    "address": "192.168.1.100",
    "port": 8080,
    "authenticationInfo": "certificate-thumbprint",
    "createdAt": "2025-01-15T10:00:00Z",
    "updatedAt": "2025-01-15T10:00:00Z"
  }
]
```

### Authorization API

#### Check Authorization

**POST** `/authorization/check`

Verify if a consumer can access a service from a provider.

Request Body:
```json
{
  "consumer": {
    "systemName": "consumer-system",
    "address": "192.168.1.101",
    "port": 8081
  },
  "provider": {
    "systemName": "sensor-system",
    "address": "192.168.1.100",
    "port": 8080
  },
  "service": {
    "serviceDefinition": "temperature",
    "interfaces": ["HTTP-SECURE-JSON"]
  }
}
```

Response: `200 OK`
```json
{
  "authorized": true,
  "authorizationToken": "jwt-token-here",
  "validUntil": "2025-01-16T10:00:00Z"
}
```

#### Create Authorization Rule

**POST** `/authorization/rules`

Create a new authorization rule.

Request Body:
```json
{
  "consumer": {
    "systemName": "consumer-system",
    "address": "192.168.1.101",
    "port": 8081
  },
  "providers": [
    {
      "systemName": "sensor-system",
      "address": "192.168.1.100",
      "port": 8080
    }
  ],
  "services": [
    {
      "serviceDefinition": "temperature",
      "interfaces": ["HTTP-SECURE-JSON"]
    }
  ]
}
```

Response: `201 Created`
```json
{
  "id": 1,
  "consumer": {
    "id": 2,
    "systemName": "consumer-system"
  },
  "providers": [
    {
      "id": 1,
      "systemName": "sensor-system"
    }
  ],
  "services": [
    {
      "id": 1,
      "serviceDefinition": "temperature"
    }
  ],
  "createdAt": "2025-01-15T10:00:00Z"
}
```

#### List Authorization Rules

**GET** `/authorization/rules`

Retrieve all authorization rules.

Response: `200 OK`
```json
[
  {
    "id": 1,
    "consumer": {
      "systemName": "consumer-system"
    },
    "providers": [
      {
        "systemName": "sensor-system"
      }
    ],
    "services": [
      {
        "serviceDefinition": "temperature"
      }
    ]
  }
]
```

#### Delete Authorization Rule

**DELETE** `/authorization/rules/{id}`

Remove an authorization rule.

Response: `204 No Content`

### Orchestration API

#### Request Orchestration

**POST** `/orchestrator/orchestration`

Request service orchestration recommendations.

Request Body:
```json
{
  "requesterSystem": {
    "systemName": "consumer-system",
    "address": "192.168.1.101",
    "port": 8081
  },
  "requestedService": {
    "serviceDefinitionRequirement": "temperature",
    "interfaceRequirements": ["HTTP-SECURE-JSON"],
    "metadataRequirements": {
      "unit": "celsius"
    }
  },
  "preferredProviders": [],
  "orchestrationFlags": {
    "overrideStore": false,
    "matchmaking": true
  }
}
```

Response: `200 OK`
```json
{
  "response": [
    {
      "provider": {
        "id": 1,
        "systemName": "sensor-system",
        "address": "192.168.1.100",
        "port": 8080
      },
      "service": {
        "id": 1,
        "serviceDefinition": "temperature",
        "interfaces": ["HTTP-SECURE-JSON"],
        "serviceUri": "/temperature"
      },
      "authorizationToken": "jwt-token",
      "warnings": []
    }
  ]
}
```

#### Store Orchestration Rules

**POST** `/orchestrator/store`

Store orchestration rules for automatic service matching.

Request Body:
```json
{
  "consumer": {
    "systemName": "consumer-system",
    "address": "192.168.1.101",
    "port": 8081
  },
  "providerSystem": {
    "systemName": "sensor-system",
    "address": "192.168.1.100",
    "port": 8080
  },
  "serviceDefinition": "temperature",
  "interfaces": ["HTTP-SECURE-JSON"],
  "priority": 1
}
```

Response: `201 Created`

### Certificate Authority API

#### Sign Certificate Request

**POST** `/ca/sign`

Sign a certificate signing request (CSR).

Request Body:
```json
{
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----",
  "systemName": "new-system",
  "validityDays": 365
}
```

Response: `200 OK`
```json
{
  "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "certificateChain": [
    "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
  ],
  "validUntil": "2026-01-15T10:00:00Z"
}
```

#### Get CA Certificate

**GET** `/ca/certificate`

Retrieve the CA's public certificate.

Response: `200 OK`
```json
{
  "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "fingerprint": "SHA256:abc123...",
  "validUntil": "2030-01-15T10:00:00Z"
}
```

## Error Responses

All endpoints use consistent error response format:

```json
{
  "error": "NotFoundError",
  "message": "System not found",
  "details": {
    "systemName": "unknown-system"
  },
  "timestamp": "2025-01-15T10:00:00Z"
}
```

### Common Error Codes

- `400 Bad Request` - Invalid request parameters
- `401 Unauthorized` - Missing or invalid authentication
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `409 Conflict` - Resource already exists
- `500 Internal Server Error` - Server error

## Rate Limiting

- Default: 100 requests per minute per client
- Configurable via `ARROWHEAD_RATELIMIT_REQUESTS` environment variable
- Headers included in response:
  - `X-RateLimit-Limit`: Maximum requests
  - `X-RateLimit-Remaining`: Requests remaining
  - `X-RateLimit-Reset`: Reset timestamp

## Versioning

API version is included in response headers:
- `X-API-Version`: Current API version (e.g., "4.6.0")
- `X-Arrowhead-Version`: Framework version compatibility

## Health Check

**GET** `/health`

Check service health status.

Response: `200 OK`
```json
{
  "status": "healthy",
  "services": {
    "database": "connected",
    "tls": "enabled",
    "registry": "operational",
    "authorization": "operational",
    "orchestration": "operational",
    "ca": "operational"
  },
  "uptime": "2h30m15s",
  "version": "1.0.0"
}
```

## WebSocket Support

For real-time updates (service registration events, authorization changes):

**WS** `/ws/events`

Message format:
```json
{
  "type": "service.registered",
  "data": {
    "system": "sensor-system",
    "service": "temperature"
  },
  "timestamp": "2025-01-15T10:00:00Z"
}
```

Event types:
- `service.registered`
- `service.unregistered`
- `authorization.created`
- `authorization.revoked`
- `system.online`
- `system.offline`