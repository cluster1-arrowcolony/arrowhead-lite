# Arrowhead Lite System Interaction Diagrams

This directory contains Mermaid sequence diagrams that visually document the key interactions within the arrowhead-lite system and between the system and its clients.

## Diagram Overview

### [1. Development Certificate Generation](./1-cert-generation-dev.md)
Shows how the `generate-certs.sh` script creates a complete PKI infrastructure for local development, including CA, server certificates, client certificates, and JWT signing keys.

### [2. System and Service Registration](./2-system-service-registration.md)
Illustrates the two-phase process for IoT devices to register themselves and their services with the Arrowhead framework using mTLS authentication.

### [3. Service Orchestration Flow](./3-orchestration-flow.md) 
Documents the core "matchmaking" process where consumers discover authorized providers for specific services through the orchestrator's filtering and authorization logic.

### [4. Direct Service Consumption](./4-service-consumption.md)
Demonstrates how systems communicate directly after orchestration, using JWT tokens for authorization while bypassing the arrowhead-lite core for data transfer.

### [5. Authorization Rule Creation](./5-authorization-rule-creation.md)
Details the administrative process of creating access control rules that govern which consumers can access which provider services.

## Viewing the Diagrams

### Online Rendering
The Mermaid diagrams can be viewed in:
- **GitHub**: Automatically renders Mermaid diagrams in markdown files
- **Mermaid Live Editor**: Copy the diagram code to [mermaid.live](https://mermaid.live)
- **VS Code**: Install the Mermaid Preview extension

### Local Rendering
If you have mermaid-cli installed, you can generate PNG/SVG images:

```bash
# Install mermaid-cli globally
npm install -g @mermaid-js/mermaid-cli

# Generate PNG images for all diagrams
cd docs/diagrams
mmdc -i 1-cert-generation-dev.md -o 1-cert-generation-dev.png
mmdc -i 2-system-service-registration.md -o 2-system-service-registration.png
mmdc -i 3-orchestration-flow.md -o 3-orchestration-flow.png
mmdc -i 4-service-consumption.md -o 4-service-consumption.png
mmdc -i 5-authorization-rule-creation.md -o 5-authorization-rule-creation.png
```

## Key Concepts Illustrated

- **mTLS Authentication**: All interactions use certificate-based authentication
- **Separation of Concerns**: Clear boundaries between registration, orchestration, and consumption
- **Direct Communication**: After orchestration, traffic flows directly between edge systems
- **Token-Based Authorization**: JWT tokens enable stateless, decentralized authorization
- **Administrative Control**: Sysop certificates provide privileged access for system management

## Integration with Documentation

These diagrams complement the main README.md and provide visual context for:
- API usage examples in the main documentation
- SDK integration patterns
- Security architecture and certificate flows
- Operational procedures for system administration

For implementation details, refer to the source code in the respective modules:
- Certificate generation: `scripts/generate-certs.sh`
- Registration logic: `internal/registry/`
- Orchestration logic: `internal/orchestration/`
- Authentication: `internal/auth/`