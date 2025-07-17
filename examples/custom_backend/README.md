# Custom Backend Implementation Example

This example demonstrates how to create a custom backend implementation for the modular PKCS#11 architecture.

## Overview

This example shows a complete custom backend implementation that:

- Implements the `CryptoBackend` trait
- Provides custom configuration handling
- Exports the PKCS#11 C API
- Includes comprehensive error handling
- Demonstrates testing strategies

## Files

- **[`Cargo.toml`](./Cargo.toml)**: Project configuration
- **[`src/lib.rs`](./src/lib.rs)**: Main library with C API exports
- **[`src/backend.rs`](./src/backend.rs)**: Custom backend implementation
- **[`src/config.rs`](./src/config.rs)**: Configuration handling
- **[`src/error.rs`](./src/error.rs)**: Error types and handling
- **[`src/storage.rs`](./src/storage.rs)**: In-memory storage implementation
- **[`tests/`](./tests/)**: Test suite
- **[`examples/`](./examples/)**: Usage examples

## Features

### Custom Backend Features

- **File-based storage**: Keys and certificates stored in files
- **Configurable encryption**: Optional encryption of stored data
- **Audit logging**: Comprehensive operation logging
- **Rate limiting**: Configurable operation rate limits
- **Custom mechanisms**: Support for custom cryptographic mechanisms

### Architecture

```
Custom Backend
├── Configuration Layer
│   ├── File-based config
│   ├── Environment variables
│   └── Validation
├── Storage Layer
│   ├── File system storage
│   ├── Encryption at rest
│   └── Atomic operations
├── Crypto Layer
│   ├── Software crypto
│   ├── Custom mechanisms
│   └── Key derivation
└── Audit Layer
    ├── Operation logging
    ├── Security events
    └── Performance metrics
```

## Building

```bash
# Build the custom backend
cd examples/custom_backend
cargo build --release

# The resulting library will be at:
# target/release/libpkcs11_impl_custom.so (Linux)
# target/release/libpkcs11_impl_custom.dylib (macOS)
# target/release/pkcs11_impl_custom.dll (Windows)
```

## Configuration

### Basic Configuration

```yaml
# config/custom.yaml
backend:
  type: "custom"

custom:
  # Storage configuration
  storage:
    type: "filesystem"
    path: "/var/lib/custom-pkcs11"
    encryption:
      enabled: true
      algorithm: "AES-256-GCM"
      key_derivation: "PBKDF2"
  
  # Token configuration
  token:
    label: "Custom PKCS#11 Token"
    manufacturer: "Custom Implementation"
    model: "Custom HSM v1.0"
    serial_number: "CUSTOM-001"
  
  # Security settings
  security:
    require_auth: true
    session_timeout: 3600  # seconds
    max_failed_logins: 3
    lockout_duration: 300  # seconds
  
  # Performance settings
  performance:
    max_sessions: 100
    max_objects: 10000
    cache_size: 1000
    rate_limit:
      operations_per_second: 1000
      burst_size: 100
  
  # Audit settings
  audit:
    enabled: true
    log_file: "/var/log/custom-pkcs11.log"
    log_level: "info"
    log_operations: true
    log_security_events: true
```

### Advanced Configuration

```yaml
# config/advanced.yaml
backend:
  type: "custom"

custom:
  # Multiple storage backends
  storage:
    primary:
      type: "filesystem"
      path: "/var/lib/custom-pkcs11/primary"
      encryption:
        enabled: true
        key_file: "/etc/custom-pkcs11/storage.key"
    
    backup:
      type: "filesystem"
      path: "/var/lib/custom-pkcs11/backup"
      sync_interval: 300  # seconds
  
  # Custom mechanisms
  mechanisms:
    # Standard mechanisms
    CKM_RSA_PKCS:
      enabled: true
      key_sizes: [1024, 2048, 3072, 4096]
    
    CKM_ECDSA:
      enabled: true
      curves: ["P-256", "P-384", "P-521"]
    
    # Custom mechanisms
    CKM_CUSTOM_HASH:
      enabled: true
      algorithm: "BLAKE3"
      output_size: 32
    
    CKM_CUSTOM_KDF:
      enabled: true
      algorithm: "HKDF-SHA256"
      max_output_length: 1024
  
  # Network configuration (for distributed mode)
  network:
    enabled: false
    listen_address: "0.0.0.0:8443"
    tls:
      cert_file: "/etc/custom-pkcs11/server.crt"
      key_file: "/etc/custom-pkcs11/server.key"
    
    peers:
      - address: "peer1.example.com:8443"
        public_key: "peer1-public-key"
      - address: "peer2.example.com:8443"
        public_key: "peer2-public-key"
```

## Usage

### Basic Usage

```rust
use pkcs11_impl_custom::{CustomBackend, CustomConfig};
use pkcs11_core::backend::CryptoBackend;

// Load configuration
let config = CustomConfig::load_from_file("config/custom.yaml")?;

// Initialize backend
let mut backend = CustomBackend::initialize(config)?;

// Use backend for PKCS#11 operations
let slots = backend.get_slot_list(true)?;
// ... perform operations
```

### Using as PKCS#11 Library

```bash
# Use with pkcs11-tool
pkcs11-tool --module ./target/release/libpkcs11_impl_custom.so --list-slots

# Use with OpenSSL
openssl engine -t pkcs11 -pre MODULE_PATH:./target/release/libpkcs11_impl_custom.so

# Use with applications
export PKCS11_MODULE=./target/release/libpkcs11_impl_custom.so
my-application
```

## Implementation Details

### Backend Trait Implementation

The custom backend implements all required methods of the `CryptoBackend` trait:

```rust
impl CryptoBackend for CustomBackend {
    type Config = CustomConfig;
    type Error = CustomError;

    // Lifecycle management
    fn initialize(config: Self::Config) -> Result<Self, Self::Error> { ... }
    fn finalize(&mut self) -> Result<(), Self::Error> { ... }
    fn is_initialized(&self) -> bool { ... }

    // Slot and token management
    fn get_slot_list(&self, token_present: bool) -> Result<Vec<SlotId>, Self::Error> { ... }
    fn get_slot_info(&self, slot_id: SlotId) -> Result<SlotInfo, Self::Error> { ... }
    fn get_token_info(&self, slot_id: SlotId) -> Result<TokenInfo, Self::Error> { ... }

    // Session management
    fn open_session(&mut self, slot_id: SlotId, flags: SessionFlags) -> Result<SessionHandle, Self::Error> { ... }
    fn close_session(&mut self, session: SessionHandle) -> Result<(), Self::Error> { ... }

    // Authentication
    fn login(&mut self, session: SessionHandle, user_type: UserType, pin: &str) -> Result<(), Self::Error> { ... }
    fn logout(&mut self, session: SessionHandle) -> Result<(), Self::Error> { ... }

    // Key management
    fn generate_key(&mut self, session: SessionHandle, spec: &KeyGenerationSpec) -> Result<KeyHandle, Self::Error> { ... }
    fn generate_key_pair(&mut self, session: SessionHandle, spec: &KeyGenerationSpec) -> Result<(KeyHandle, KeyHandle), Self::Error> { ... }
    fn import_key(&mut self, session: SessionHandle, key_data: &KeyImportData) -> Result<KeyHandle, Self::Error> { ... }
    fn delete_key(&mut self, session: SessionHandle, key: KeyHandle) -> Result<(), Self::Error> { ... }
    fn list_keys(&self, session: SessionHandle, filter: Option<&KeyFilter>) -> Result<Vec<KeyInfo>, Self::Error> { ... }
    fn get_key_info(&self, session: SessionHandle, key: KeyHandle) -> Result<KeyInfo, Self::Error> { ... }

    // Cryptographic operations
    fn sign(&mut self, session: SessionHandle, key: KeyHandle, mechanism: &SignMechanism, data: &[u8]) -> Result<Vec<u8>, Self::Error> { ... }
    fn verify(&mut self, session: SessionHandle, key: KeyHandle, mechanism: &SignMechanism, data: &[u8], signature: &[u8]) -> Result<bool, Self::Error> { ... }
    fn encrypt(&mut self, session: SessionHandle, key: KeyHandle, mechanism: &EncryptMechanism, data: &[u8]) -> Result<Vec<u8>, Self::Error> { ... }
    fn decrypt(&mut self, session: SessionHandle, key: KeyHandle, mechanism: &EncryptMechanism, data: &[u8]) -> Result<Vec<u8>, Self::Error> { ... }
    fn digest(&mut self, session: SessionHandle, mechanism: &MechanismType, data: &[u8]) -> Result<Vec<u8>, Self::Error> { ... }
    fn generate_random(&mut self, session: SessionHandle, length: usize) -> Result<Vec<u8>, Self::Error> { ... }
}
```

### Storage Implementation

The custom backend uses a pluggable storage system:

```rust
pub trait Storage: Send + Sync {
    fn store_key(&mut self, key_info: &KeyInfo, key_data: &[u8]) -> Result<(), StorageError>;
    fn load_key(&self, handle: KeyHandle) -> Result<(KeyInfo, Vec<u8>), StorageError>;
    fn delete_key(&mut self, handle: KeyHandle) -> Result<(), StorageError>;
    fn list_keys(&self, filter: Option<&KeyFilter>) -> Result<Vec<KeyInfo>, StorageError>;
    
    fn store_certificate(&mut self, cert_info: &CertificateInfo, cert_data: &[u8]) -> Result<(), StorageError>;
    fn load_certificate(&self, handle: CertificateHandle) -> Result<(CertificateInfo, Vec<u8>), StorageError>;
    fn delete_certificate(&mut self, handle: CertificateHandle) -> Result<(), StorageError>;
    fn list_certificates(&self, filter: Option<&CertificateFilter>) -> Result<Vec<CertificateInfo>, StorageError>;
}
```

### Error Handling

Comprehensive error handling with conversion to PKCS#11 error codes:

```rust
#[derive(Debug, thiserror::Error)]
pub enum CustomError {
    #[error("Configuration error: {message}")]
    Configuration { message: String },
    
    #[error("Storage error: {message}")]
    Storage { message: String },
    
    #[error("Cryptographic error: {message}")]
    Crypto { message: String },
    
    #[error("Authentication error: {message}")]
    Authentication { message: String },
    
    #[error("Network error: {message}")]
    Network { message: String },
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("Session timeout")]
    SessionTimeout,
    
    #[error("Account locked")]
    AccountLocked,
}

impl Into<BackendError> for CustomError {
    fn into(self) -> BackendError {
        match self {
            CustomError::Configuration { message } => BackendError::ConfigurationError { reason: message },
            CustomError::Storage { message } => BackendError::InternalError { reason: message },
            CustomError::Crypto { message } => BackendError::CryptoOperationFailed { operation: message },
            CustomError::Authentication { message } => BackendError::AuthenticationFailed { message },
            CustomError::Network { message } => BackendError::NetworkError { reason: message },
            CustomError::RateLimitExceeded => BackendError::PermissionDenied { operation: "Rate limit exceeded".to_string() },
            CustomError::SessionTimeout => BackendError::InvalidSession,
            CustomError::AccountLocked => BackendError::AuthenticationFailed { message: "Account locked".to_string() },
        }
    }
}
```

## Testing

### Unit Tests

```bash
# Run unit tests
cargo test --lib

# Run with coverage
cargo test --lib -- --test-threads=1
```

### Integration Tests

```bash
# Run integration tests
cargo test --test integration

# Run specific test
cargo test --test integration test_key_generation
```

### PKCS#11 Compliance Tests

```bash
# Run PKCS#11 compliance tests
cargo test --test pkcs11_compliance

# Test with external tools
pkcs11-tool --module ./target/release/libpkcs11_impl_custom.so --test
```

### Performance Tests

```bash
# Run performance benchmarks
cargo bench

# Profile performance
cargo build --release
perf record --call-graph=dwarf ./target/release/custom_backend_benchmark
perf report
```

## Security Considerations

### Data Protection

- **Encryption at rest**: All stored keys and certificates are encrypted
- **Secure key derivation**: PBKDF2 with configurable iterations
- **Memory protection**: Sensitive data is cleared from memory
- **Access control**: File permissions and user authentication

### Audit and Monitoring

- **Operation logging**: All operations are logged with timestamps
- **Security events**: Failed logins, rate limiting, and errors are logged
- **Performance metrics**: Operation timing and resource usage
- **Compliance**: Logs can be used for compliance reporting

### Network Security

- **TLS encryption**: All network communication is encrypted
- **Certificate validation**: Peer certificates are validated
- **Rate limiting**: Protection against DoS attacks
- **Authentication**: Mutual authentication between peers

## Deployment

### Systemd Service

```ini
# /etc/systemd/system/custom-pkcs11.service
[Unit]
Description=Custom PKCS#11 Backend
After=network.target

[Service]
Type=forking
User=pkcs11
Group=pkcs11
ExecStart=/usr/local/bin/custom-pkcs11-daemon
PIDFile=/var/run/custom-pkcs11.pid
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Docker Container

```dockerfile
FROM rust:1.70 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/libpkcs11_impl_custom.so /usr/lib/
COPY --from=builder /app/config/custom.yaml /etc/custom-pkcs11/

EXPOSE 8443
CMD ["/usr/lib/libpkcs11_impl_custom.so"]
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: custom-pkcs11
spec:
  replicas: 3
  selector:
    matchLabels:
      app: custom-pkcs11
  template:
    metadata:
      labels:
        app: custom-pkcs11
    spec:
      containers:
      - name: custom-pkcs11
        image: custom-pkcs11:latest
        ports:
        - containerPort: 8443
        volumeMounts:
        - name: config
          mountPath: /etc/custom-pkcs11
        - name: storage
          mountPath: /var/lib/custom-pkcs11
      volumes:
      - name: config
        configMap:
          name: custom-pkcs11-config
      - name: storage
        persistentVolumeClaim:
          claimName: custom-pkcs11-storage
```

## Contributing

When extending this custom backend:

1. **Follow the architecture**: Maintain separation between layers
2. **Add tests**: Ensure new features are tested
3. **Update documentation**: Keep documentation current
4. **Security review**: Consider security implications
5. **Performance testing**: Benchmark new features

For more information, see the [Development Guide](../../docs/DEVELOPMENT.md).