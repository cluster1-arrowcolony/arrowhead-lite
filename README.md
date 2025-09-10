# Arrowhead IoT Service Mesh
A lightweight IoT service mesh node built in Go that implements the Arrowhead Framework specification in a single, unified binary.

## What is Arrowhead?
Arrowhead builds on the following concepts:
* **System**: A network-addressable process that can provide and/or consume services.
* **Service**: A function provided by a system, exposed as a RESTful API and identifiable by a unique name. Multiple systems can provide the same service.
* **Zero-trust**: All systems must be authorized to use services, even within the same network. This is enforced through mutual TLS (mTLS) authentication and authorization rules.

## What is `arrowhead-lite`?

`arrowhead-lite` is a lightweight Go-based implementation of the Arrowhead Framework, provided as a single binary.

Out-of-the-box, `arrowhead-lite` provides the following services:
* **System Registration**: Register a new system.
* **Service Registration**: Registers a new service provided by a system.
* **Authorization**: Allow a system to consume a service provided by another system.
* **Orchestration**: Finds the systems that provide a requested service.

For certificate management, this repository includes two scripts:
* `scripts/generate-certs.sh`: Establishes a local Certificate Authority (CA) and generates the initial server and administrative certificates required to run the system.
* `scripts/generate-system-cert.sh`: Issues a unique TLS certificate for any new system that needs to join the framework, signed by the local CA.

Persistent data within `arrowhead-lite` is by default stored inside a SQLite, but can be configured to use PostgreSQL as well.
## Quick Start

### Local Development
1. **Clone and build:**
```bash
git clone ssh://github.com/cluster1-arrowcolony/arrowhead-lite.git
cd arrowhead-lite
make build
```

2. **Generate certificates:**
```bash
./scripts/generate-certs.sh
```

3. **Run the server:**
```bash
./bin/arrowhead-lite
```

4. **Access the dashboard:**
```
http://localhost:8443
```

**Note**: Accessing the dashboard requires a one-time setup because the server uses high-security mutual TLS (mTLS) with self-signed certificates. If you want to access the dashboard, you must (on macOS):
* **Trust the server CA**: In the **Keychain Access** app, select the `System` keychain (top-left), then go to `File` -> `Import Items` and import `arrowhead-lite/certs/truststore.pem`. Find the new `ArrowheadLiteLocalCA` certificate in the `Certificates` tab, double-click it, expand the `Trust` section, and change the setting to `Always Trust`.
* **Import client certificate**: In the **Keychain Access** app, select the `login` keychain (top-left), then go to `File` > `Import Items` and import `arrowhead-lite/certs/sysop.p12`. The certificate password is `123456`. When you reload the page in Chrome, a pop-up will appear; select the sysop certificate to continue. You may need to enter your macOS password to allow access to the private key.

Other OS's follow similar steps to trust the CA and import the client certificate, but use other apps than **Keychain Access**.

5. **Try the demo (optional):**
```bash
./examples/demo.sh
```

The demo script showcases a mining IoT scenario with device registration, service creation, and authorization rules.

## Interacting with `arrowhead-lite`

To interact with `arrowhead-lite`, the recommended method is to use the [Python SDK](https://github.com/cluster1-arrowcolony/arrowhead-python-sdk). In the future, more SDKs may be provided. To use arrowhead-lite manually, see the [Manual](./docs/manual.md).

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
