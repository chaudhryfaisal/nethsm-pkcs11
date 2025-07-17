# Basic Usage Examples

This directory contains simple examples demonstrating the core functionality of the modular PKCS#11 architecture.

## Examples

- **[`mock_backend.rs`](./mock_backend.rs)**: Basic operations using the mock backend
- **[`nethsm_backend.rs`](./nethsm_backend.rs)**: Basic operations using the NetHSM backend
- **[`configuration.rs`](./configuration.rs)**: Configuration loading and validation
- **[`error_handling.rs`](./error_handling.rs)**: Proper error handling patterns
- **[`key_operations.rs`](./key_operations.rs)**: Key generation, import, and management
- **[`crypto_operations.rs`](./crypto_operations.rs)**: Signing, encryption, and verification
- **[`session_management.rs`](./session_management.rs)**: Session lifecycle management

## Configuration Files

- **[`config/mock.yaml`](./config/mock.yaml)**: Mock backend configuration
- **[`config/nethsm.yaml`](./config/nethsm.yaml)**: NetHSM backend configuration
- **[`config/development.yaml`](./config/development.yaml)**: Development configuration

## Running Examples

### Prerequisites

```bash
# Build the project
cargo build --release

# Set up configuration
export P11NETHSM_CONFIG_FILE=examples/basic_usage/config/mock.yaml
```

### Run Individual Examples

```bash
# Mock backend example
cargo run --example mock_backend

# NetHSM backend example (requires NetHSM instance)
export P11NETHSM_CONFIG_FILE=examples/basic_usage/config/nethsm.yaml
cargo run --example nethsm_backend

# Configuration example
cargo run --example configuration

# Error handling example
cargo run --example error_handling

# Key operations example
cargo run --example key_operations

# Crypto operations example
cargo run --example crypto_operations

# Session management example
cargo run --example session_management
```

### Run All Examples

```bash
# Run all basic usage examples
cargo test --examples basic_usage
```

## Example Descriptions

### Mock Backend Example

Demonstrates basic operations using the mock backend:
- Backend initialization
- Session management
- Key generation
- Signing operations
- Cleanup

### NetHSM Backend Example

Shows how to use the NetHSM backend:
- NetHSM connection
- Authentication
- Key operations
- Certificate management
- Error handling

### Configuration Example

Illustrates configuration loading and validation:
- Loading from different sources
- Environment variable override
- Configuration validation
- Backend selection

### Error Handling Example

Demonstrates proper error handling:
- Backend error types
- Error conversion
- Retry logic
- Graceful degradation

### Key Operations Example

Shows comprehensive key management:
- Key generation (RSA, ECDSA, AES)
- Key import/export
- Key enumeration
- Key deletion

### Crypto Operations Example

Demonstrates cryptographic operations:
- Digital signatures
- Encryption/decryption
- Hash computation
- Random number generation

### Session Management Example

Illustrates session lifecycle:
- Session creation
- Authentication
- Session state management
- Session cleanup

## Common Patterns

### Backend Initialization

```rust
use pkcs11_core::backend::{CryptoBackend, registry};
use pkcs11_impl_mock::{MockBackend, MockConfig};

// Initialize mock backend
let config = MockConfig::new()
    .with_deterministic(true)
    .with_token_label("Example Token");

let mut backend = MockBackend::initialize(config)?;
```

### Session Management

```rust
// Open session
let slots = backend.get_slot_list(true)?;
let slot_id = slots[0];

let session_flags = SessionFlags {
    rw_session: true,
    serial_session: true,
};

let session = backend.open_session(slot_id, session_flags)?;

// Login
backend.login(session, UserType::User, "123456")?;

// Perform operations...

// Cleanup
backend.logout(session)?;
backend.close_session(session)?;
```

### Key Generation

```rust
use pkcs11_core::backend::types::*;

let key_spec = KeyGenerationSpec {
    key_type: KeyType::Rsa,
    key_size: 2048,
    label: Some("example-key".to_string()),
    id: None,
    usage: KeyUsage {
        sign: true,
        verify: true,
        encrypt: false,
        decrypt: false,
        derive: false,
        extractable: false,
        sensitive: true,
    },
};

let key_handle = backend.generate_key(session, &key_spec)?;
```

### Signing Operation

```rust
let mechanism = SignMechanism {
    mechanism_type: MechanismType(cryptoki_sys::CKM_RSA_PKCS as u32),
    parameters: None,
};

let data = b"Hello, World!";
let signature = backend.sign(session, key_handle, &mechanism, data)?;

// Verify signature
let is_valid = backend.verify(session, key_handle, &mechanism, data, &signature)?;
assert!(is_valid);
```

## Testing

### Unit Tests

```bash
# Run unit tests for examples
cargo test --examples --lib
```

### Integration Tests

```bash
# Run integration tests
cargo test --examples --test integration
```

### Mock Backend Tests

```bash
# Test with mock backend
P11NETHSM_CONFIG_FILE=examples/basic_usage/config/mock.yaml cargo test --examples
```

### NetHSM Backend Tests

```bash
# Test with NetHSM (requires running NetHSM instance)
export NETHSM_URL=https://localhost:8443/api/v1
export NETHSM_OPERATOR_PASS=opPassphrase
P11NETHSM_CONFIG_FILE=examples/basic_usage/config/nethsm.yaml cargo test --examples
```

## Troubleshooting

### Common Issues

1. **Configuration not found**:
   ```bash
   export P11NETHSM_CONFIG_FILE=examples/basic_usage/config/mock.yaml
   ```

2. **Backend initialization failed**:
   ```bash
   export RUST_LOG=debug
   cargo run --example mock_backend
   ```

3. **NetHSM connection failed**:
   - Check NetHSM URL and credentials
   - Verify network connectivity
   - Check TLS certificate configuration

### Debug Output

```bash
# Enable debug logging
export RUST_LOG=debug

# Enable trace logging for specific modules
export RUST_LOG=pkcs11_core=trace,pkcs11_impl_mock=debug

# Run with debug output
cargo run --example mock_backend 2>&1 | tee debug.log
```

### Validation

```bash
# Validate configuration
cargo run --example configuration

# Test backend connectivity
cargo run --example test_connection

# Verify operations
cargo run --example crypto_operations
```

For more advanced examples, see the other directories in the [`examples/`](../) folder.