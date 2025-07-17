# Mock PKCS#11 Implementation

This crate provides a comprehensive mock implementation of the PKCS#11 interface for testing and development purposes. It simulates HSM behavior without requiring actual hardware, providing deterministic and configurable mock operations.

## Features

- **Complete PKCS#11 Implementation**: Implements all standard PKCS#11 operations including key generation, signing, encryption, and session management
- **Deterministic Behavior**: Configurable deterministic mode for reproducible testing scenarios
- **Error Injection**: Configurable error injection system for testing error handling paths
- **In-Memory Storage**: Fast in-memory storage for keys, certificates, and sessions with proper lifecycle management
- **Mock Cryptography**: Realistic mock cryptographic operations with predictable outputs
- **Configurable Mechanisms**: Support for RSA, ECDSA, AES, and hash mechanisms with configurable parameters
- **Session Management**: Complete session lifecycle management with authentication support
- **Thread Safety**: Thread-safe implementation suitable for multi-threaded applications

## Supported Operations

### Key Management
- Key generation (RSA, ECDSA, AES)
- Key pair generation
- Key import/export
- Key deletion
- Key enumeration with filtering

### Cryptographic Operations
- **Signing**: RSA PKCS#1 v1.5, RSA PSS, ECDSA
- **Verification**: All supported signing mechanisms
- **Encryption**: RSA PKCS#1 v1.5, AES CBC
- **Decryption**: All supported encryption mechanisms
- **Digest**: SHA-256, SHA-384, SHA-512
- **Random Number Generation**: Configurable deterministic or random

### Session Management
- Session creation and destruction
- User authentication (PIN-based)
- Session state management
- Multi-session support

## Usage

### Basic Usage

```rust
use pkcs11_impl_mock::{MockConfig, initialize_mock_provider_default};

// Initialize with default configuration
initialize_mock_provider_default().unwrap();

// The mock provider is now ready to be used by any PKCS#11 application
```

### Custom Configuration

```rust
use pkcs11_impl_mock::{MockConfig, initialize_mock_provider, error::ErrorInjectionConfig};

let config = MockConfig::new()
    .with_deterministic(true)
    .with_random_seed(12345)
    .with_token_label("Test Token")
    .with_default_pin("123456")
    .with_max_sessions(50)
    .with_max_objects(500)
    .with_verbose_logging(true);

initialize_mock_provider(config).unwrap();
```

### Error Injection for Testing

```rust
use pkcs11_impl_mock::{MockConfig, error::ErrorInjectionConfig};

let error_config = ErrorInjectionConfig::new()
    .with_probability(0.1) // 10% chance of error
    .inject_on("sign")     // Only inject errors on signing operations
    .with_message("Test error injection");

let config = MockConfig::new()
    .with_error_injection(error_config);

initialize_mock_provider(config).unwrap();
```

### Operation Delays for Performance Testing

```rust
use pkcs11_impl_mock::MockConfig;

let config = MockConfig::new()
    .with_operation_delay("sign", 100)      // 100ms delay for signing
    .with_operation_delay("generate_key", 500); // 500ms delay for key generation

initialize_mock_provider(config).unwrap();
```

## Configuration Options

### MockConfig

- `deterministic`: Enable deterministic behavior for reproducible tests
- `random_seed`: Seed for deterministic random number generation
- `max_sessions`: Maximum number of concurrent sessions
- `max_objects`: Maximum number of stored objects (keys, certificates)
- `default_pin`: Default PIN for authentication
- `require_auth`: Whether authentication is required for operations
- `token_label`: Simulated token label
- `manufacturer_id`: Simulated manufacturer identifier
- `model`: Simulated device model
- `serial_number`: Simulated device serial number
- `firmware_version`: Simulated firmware version
- `mechanisms`: Configuration for supported cryptographic mechanisms
- `error_injection`: Error injection configuration for testing
- `verbose_logging`: Enable detailed operation logging
- `operation_delays`: Simulated delays for performance testing

### Mechanism Configuration

Each cryptographic mechanism can be individually configured:

```rust
use pkcs11_impl_mock::config::MechanismConfig;

let rsa_config = MechanismConfig::new()
    .enabled()
    .with_key_size_range(1024, 4096)
    .with_default_key_size(2048)
    .with_signing()
    .with_encryption()
    .with_key_generation();
```

## Testing Scenarios

### Deterministic Testing

```rust
// Configure for deterministic behavior
let config = MockConfig::new()
    .with_deterministic(true)
    .with_random_seed(42);

// All operations will produce the same results across test runs
```

### Error Handling Testing

```rust
// Test error handling with configurable error injection
let error_config = ErrorInjectionConfig::new()
    .deterministic(5) // Inject error on 5th operation
    .inject_on("encrypt")
    .with_message("Simulated hardware failure");

let config = MockConfig::new()
    .with_error_injection(error_config);
```

### Performance Testing

```rust
// Simulate slow operations for performance testing
let config = MockConfig::new()
    .with_operation_delay("sign", 1000)
    .with_operation_delay("verify", 500);
```

## Building

This crate produces a `cdylib` that can be used as a PKCS#11 provider library.

```bash
cargo build --release --package pkcs11_impl_mock
```

The resulting library can be found at `target/release/libpkcs11_impl_mock.so` (Linux) or equivalent on other platforms.

## Integration with PKCS#11 Applications

This mock implementation can be used as a drop-in replacement for any PKCS#11 provider. It exports the standard PKCS#11 C API functions and can be loaded by PKCS#11-compatible applications.

### Using with cryptoki-rs

```rust
use cryptoki::{context::Pkcs11, session::UserType};

// The mock provider will be automatically used if it's the only one loaded
let pkcs11 = Pkcs11::new("path/to/libpkcs11_impl_mock.so").unwrap();
pkcs11.initialize(cryptoki::context::CInitializeArgs::OsThreads).unwrap();

let slots = pkcs11.get_slots_with_token().unwrap();
let session = pkcs11.open_rw_session(slots[0]).unwrap();
session.login(UserType::User, Some("123456")).unwrap();

// Use standard PKCS#11 operations...
```

### Using with C Applications

```c
// Example usage in C
#include <pkcs11.h>

CK_FUNCTION_LIST_PTR functions;
CK_RV rv = C_GetFunctionList(&functions);
if (rv == CKR_OK) {
    rv = functions->C_Initialize(NULL);
    
    // Get slots and open session
    CK_SLOT_ID slots[10];
    CK_ULONG slot_count = 10;
    rv = functions->C_GetSlotList(CK_TRUE, slots, &slot_count);
    
    CK_SESSION_HANDLE session;
    rv = functions->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, 
                                  NULL, NULL, &session);
    
    // Login and perform operations
    rv = functions->C_Login(session, CKU_USER, (CK_UTF8CHAR*)"123456", 6);
    
    // ... use PKCS#11 functions for testing
    
    functions->C_Finalize(NULL);
}
```

## Architecture

The mock implementation is built on a modular architecture:

- **Backend** (`backend.rs`): Implements the `CryptoBackend` trait from `pkcs11_core`
- **Storage** (`storage.rs`): In-memory storage for sessions, keys, and certificates
- **Crypto** (`crypto.rs`): Mock cryptographic operations with deterministic behavior
- **Config** (`config.rs`): Comprehensive configuration system
- **Error** (`error.rs`): Error handling and injection system

## Use Cases

- **Testing**: Validate PKCS#11 applications without HSM hardware
- **Development**: Develop and debug PKCS#11 applications locally
- **CI/CD**: Run automated tests in environments without HSM access
- **Prototyping**: Quickly prototype PKCS#11-based solutions
- **Education**: Learn PKCS#11 concepts without hardware requirements
- **Error Testing**: Test application error handling with configurable error injection
- **Performance Testing**: Simulate slow operations and capacity limits

## Security Notice

⚠️ **WARNING**: This is a mock implementation intended for testing and development only. It does not provide real cryptographic security and should never be used in production environments where actual security is required.

The mock cryptographic operations are designed to be realistic in terms of API behavior and data formats, but they do not provide actual cryptographic security. All "encrypted" data and "signatures" are deterministic transformations that can be easily reversed.

## License

This project is licensed under the Apache License 2.0 or MIT License, at your option.