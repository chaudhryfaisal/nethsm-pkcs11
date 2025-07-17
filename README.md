# Modular PKCS#11 Architecture for NetHSM

[![codecov.io][codecov-badge]][codecov-url]

[codecov-badge]: https://codecov.io/gh/nitrokey/nethsm-pkcs11/branch/main/graph/badge.svg
[codecov-url]: https://app.codecov.io/gh/nitrokey/nethsm-pkcs11/tree/main

A modular PKCS#11 implementation that provides a clean abstraction layer between the PKCS#11 protocol and cryptographic backends. This architecture enables support for multiple backend implementations while maintaining full PKCS#11 C API compatibility.

## Features

- **Modular Architecture**: Clean separation between PKCS#11 protocol and backend implementations
- **Multiple Backends**: Support for NetHSM, mock implementations, and custom backends
- **Full PKCS#11 Compliance**: Complete implementation of PKCS#11 C API
- **Thread Safety**: Safe concurrent access across multiple threads
- **Comprehensive Testing**: Extensive test suite with mock backend for CI/CD
- **Production Ready**: Battle-tested NetHSM integration

See the [list of supported features](./features.md) for more details.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    PKCS#11 C API Layer                     │
├─────────────────────────────────────────────────────────────┤
│                    pkcs11_core Library                     │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │   API Module    │  │  Backend Traits │  │ Common Types│ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                Backend Implementations                      │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │  NetHSM SDK     │  │   Mock Backend  │  │   Custom    │ │
│  │  Implementation │  │                 │  │   Backend   │ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Components

- **[`pkcs11_core`](./pkcs11_core/)**: Core library with PKCS#11 protocol implementation and backend abstraction
- **[`pkcs11_impl_nethsm_sdk`](./pkcs11_impl_nethsm_sdk/)**: Production NetHSM backend using the NetHSM SDK
- **[`pkcs11_impl_mock`](./pkcs11_impl_mock/)**: Mock backend for testing and development

## Quick Start

### Using NetHSM Backend

1. **Download the latest release**:
   ```bash
   wget https://github.com/Nitrokey/nethsm-pkcs11/releases/latest/download/libpkcs11_impl_nethsm_sdk.so
   ```

2. **Create configuration file** (`p11nethsm.conf`):
   ```yaml
   slots:
     - label: "NetHSM"
       instances:
         - url: "https://nethsm.example.com/api/v1"
       operator:
         username: "operator"
         password: "opPassphrase"
   ```

3. **Use with PKCS#11 applications**:
   ```bash
   pkcs11-tool --module ./libpkcs11_impl_nethsm_sdk.so --list-slots
   ```

### Using Mock Backend for Testing

1. **Build the mock backend**:
   ```bash
   cargo build --release --package pkcs11_impl_mock
   ```

2. **Create test configuration**:
   ```yaml
   backend:
     type: "mock"
   mock:
     deterministic: true
     token_label: "Test Token"
   ```

3. **Run tests**:
   ```bash
   pkcs11-tool --module ./target/release/libpkcs11_impl_mock.so --list-slots
   ```

## Documentation

- **[API Documentation](./docs/API.md)**: Comprehensive API reference and backend abstraction layer
- **[Configuration Guide](./docs/CONFIGURATION.md)**: Complete configuration options for all backends
- **[Development Guide](./docs/DEVELOPMENT.md)**: Development setup, testing, and contribution guidelines
- **[Examples](./examples/)**: Practical examples and integration guides
- **[Migration Guide](./examples/migration/)**: Migrating from the monolithic implementation

For NetHSM-specific setup, see the [official documentation](https://docs.nitrokey.com/nethsm/pkcs11-setup.html).

## Backends

### NetHSM Backend (`pkcs11_impl_nethsm_sdk`)

Production-ready backend for [Nitrokey NetHSM](https://www.nitrokey.com/products/nethsm) devices.

**Features:**
- Full NetHSM SDK integration
- High availability with multiple instances
- Hardware-backed cryptographic operations
- TLS certificate validation
- Automatic failover and retry logic

**Supported Operations:**
- RSA signing and encryption (PKCS#1, PSS, OAEP)
- ECDSA signing (P-256, P-384, P-521)
- EdDSA signing (Ed25519)
- AES encryption/decryption (CBC)
- Key generation and management
- Certificate management

### Mock Backend (`pkcs11_impl_mock`)

Comprehensive testing backend for development and CI/CD.

**Features:**
- Deterministic behavior for reproducible tests
- Configurable error injection
- Operation delay simulation
- In-memory storage
- Complete PKCS#11 operation coverage

**Use Cases:**
- Unit and integration testing
- CI/CD pipelines
- Development without hardware
- Performance testing
- Error handling validation

## Installation

### From Releases

Download the latest binary from the [release page](https://github.com/Nitrokey/nethsm-pkcs11/releases):

```bash
# NetHSM backend
wget https://github.com/Nitrokey/nethsm-pkcs11/releases/latest/download/libpkcs11_impl_nethsm_sdk.so

# Mock backend
wget https://github.com/Nitrokey/nethsm-pkcs11/releases/latest/download/libpkcs11_impl_mock.so
```

### From Source

```bash
git clone https://github.com/Nitrokey/nethsm-pkcs11.git
cd nethsm-pkcs11

# Build NetHSM backend
cargo build --release --package pkcs11_impl_nethsm_sdk

# Build mock backend
cargo build --release --package pkcs11_impl_mock

# Build all backends
cargo build --release
```

## Debug Options

Set the `RUST_LOG` env variable to `trace`, `debug`, `info`, `warn` or `err` to change the logging level.

## Docker Examples

For testing and development purposes there are two examples using the PKCS11 driver with Nginx and Apache.

They require each a certificate built with the `container/<server>/generate.sh`.

They can be built with:

```bash
# Building the images 
docker build -t nginx-testing -f container/nginx/Dockerfile .
docker build -t apache-testing -f container/apache/Dockerfile .
```

Assuming that a NetHSM is runnig on localhost:8443, they can then be run with :

```bash
docker run --net=host nginx-testing:latest
docker run --net=host apache-testing:latest
```

The NetHSM is expected to have be provisionned with the following configuration:

```bash
nitropy nethsm --host localhost:8443 --no-verify-tls provision -u 0123456789 -a Administrator
nitropy nethsm --host localhost:8443 --no-verify-tls add-user -n Operator -u operator -p opPassphrase -r Operator
```

## Testing retries

There is a set of tests that run with multiple instances and test the retry and timeout mechanisms.
They require: access to `sudo` (or being run as root) and `podman`.
You can run the command:

```bash
USE_SUDO=true cargo t -p nethsm_pkcs11 --test basic -- multi_instance_retries
# Or remove the use of sudo if running as root
cargo t -p nethsm_pkcs11 --test basic -- multi_instance_retries
```

## Building

Required are `gcc` and a working Rust toolchain of at least version (MSRV) 1.70.

```
cargo build --release
```

The dynamic library will be in `${CARGO_TARGET_DIR:-target}/release/libnethsm_pkcs11.so`.

### Alpine Linux

You need to install `musl-dev` and `gcc`:

```
apk add musl-dev gcc
```

To build on Alpine Linux you will need to add the C argument `target-feature=-crt-static`:

```
RUSTFLAGS="-C target-feature=-crt-static" cargo build --release
```
