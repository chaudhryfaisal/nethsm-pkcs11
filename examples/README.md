# Examples

This directory contains comprehensive examples demonstrating the modular PKCS#11 architecture and its various backends.

## Directory Structure

- **[`basic_usage/`](./basic_usage/)**: Simple usage examples for getting started
- **[`custom_backend/`](./custom_backend/)**: Complete example of implementing a custom backend
- **[`testing/`](./testing/)**: Testing examples using the mock implementation
- **[`migration/`](./migration/)**: Migration guides from the monolithic implementation
- **[`integration/`](./integration/)**: Integration examples with popular PKCS#11 tools

## Quick Start

### NetHSM Backend Example

```bash
cd examples/basic_usage/nethsm
cargo run --example basic_operations
```

### Mock Backend Example

```bash
cd examples/basic_usage/mock
cargo run --example deterministic_testing
```

### Custom Backend Example

```bash
cd examples/custom_backend
cargo build --release
./target/release/libpkcs11_impl_custom.so
```

## Example Categories

### 1. Basic Usage Examples

Simple examples demonstrating core functionality:

- **NetHSM Operations**: Key generation, signing, encryption
- **Mock Testing**: Deterministic testing scenarios
- **Configuration**: Various configuration patterns
- **Error Handling**: Proper error handling techniques

### 2. Custom Backend Implementation

Complete example showing how to create a custom backend:

- **Backend Trait Implementation**: Full `CryptoBackend` implementation
- **Configuration System**: Custom configuration handling
- **Error Types**: Custom error definitions
- **C API Export**: PKCS#11 C API compatibility
- **Testing**: Comprehensive test suite

### 3. Testing Examples

Advanced testing scenarios using the mock backend:

- **Unit Testing**: Testing individual components
- **Integration Testing**: End-to-end testing
- **Error Injection**: Testing error handling paths
- **Performance Testing**: Benchmarking operations
- **CI/CD Integration**: Automated testing pipelines

### 4. Migration Examples

Guides for migrating from the monolithic implementation:

- **Configuration Migration**: Converting old configurations
- **Code Migration**: Updating application code
- **Testing Migration**: Adapting test suites
- **Deployment Migration**: Production deployment strategies

### 5. Integration Examples

Real-world integration examples:

- **OpenSSL Integration**: Using with OpenSSL applications
- **GnuTLS Integration**: TLS certificate operations
- **SSH Integration**: SSH key operations
- **Web Server Integration**: HTTPS certificate management
- **Container Integration**: Docker and Kubernetes deployment

## Running Examples

### Prerequisites

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install system dependencies
sudo apt-get install build-essential pkg-config libssl-dev

# Clone repository
git clone https://github.com/Nitrokey/nethsm-pkcs11.git
cd nethsm-pkcs11
```

### Build All Examples

```bash
# Build all examples
cargo build --examples

# Build specific example
cargo build --example basic_operations

# Build with release optimizations
cargo build --release --examples
```

### Run Examples

```bash
# Run with default configuration
cargo run --example basic_operations

# Run with custom configuration
P11NETHSM_CONFIG_FILE=examples/config/test.yaml cargo run --example basic_operations

# Run with environment variables
RUST_LOG=debug cargo run --example basic_operations
```

### Test Examples

```bash
# Test all examples
cargo test --examples

# Test specific example
cargo test --example basic_operations

# Test with mock backend
cargo test --features mock-backend --examples
```

## Configuration Examples

### NetHSM Configuration

```yaml
# examples/config/nethsm.yaml
backend:
  type: "nethsm"

slots:
  - label: "Example-NetHSM"
    instances:
      - url: "https://nethsm.example.com/api/v1"
        danger_insecure_cert: false
    operator:
      username: "operator"
      password: "opPassphrase"
```

### Mock Configuration

```yaml
# examples/config/mock.yaml
backend:
  type: "mock"

mock:
  deterministic: true
  random_seed: 42
  token_label: "Example Token"
  require_auth: true
  default_pin: "123456"
```

### Development Configuration

```yaml
# examples/config/development.yaml
backend:
  type: "mock"

mock:
  deterministic: true
  verbose_logging: true
  require_auth: false
  operation_delays: {}
  error_injection:
    enabled: false
```

## Common Patterns

### Error Handling

```rust
use pkcs11_core::backend::{CryptoBackend, BackendError};

fn handle_backend_operation() -> Result<(), BackendError> {
    match backend.some_operation() {
        Ok(result) => {
            println!("Operation successful: {:?}", result);
            Ok(())
        }
        Err(BackendError::AuthenticationFailed { message }) => {
            eprintln!("Authentication failed: {}", message);
            Err(BackendError::AuthenticationFailed { message })
        }
        Err(BackendError::NetworkError { reason }) => {
            eprintln!("Network error: {}", reason);
            // Implement retry logic
            Err(BackendError::NetworkError { reason })
        }
        Err(e) => {
            eprintln!("Unexpected error: {}", e);
            Err(e)
        }
    }
}
```

### Configuration Loading

```rust
use pkcs11_core::config::Config;

fn load_configuration() -> Result<Config, Box<dyn std::error::Error>> {
    // Try environment variable first
    if let Ok(config_path) = std::env::var("P11NETHSM_CONFIG_FILE") {
        return Config::load_from_file(&config_path);
    }
    
    // Try standard locations
    let standard_paths = [
        "p11nethsm.conf",
        "/etc/p11nethsm/p11nethsm.conf",
        "~/.config/p11nethsm/p11nethsm.conf",
    ];
    
    for path in &standard_paths {
        if std::path::Path::new(path).exists() {
            return Config::load_from_file(path);
        }
    }
    
    // Use default configuration
    Ok(Config::default())
}
```

### Backend Initialization

```rust
use pkcs11_core::backend::{CryptoBackend, registry};

fn initialize_backend() -> Result<Box<dyn CryptoBackend>, Box<dyn std::error::Error>> {
    let config = load_configuration()?;
    let backend = registry::create_backend(&config)?;
    Ok(backend)
}
```

## Troubleshooting

### Common Issues

1. **Configuration Not Found**
   ```bash
   export P11NETHSM_CONFIG_FILE=examples/config/mock.yaml
   ```

2. **Build Errors**
   ```bash
   cargo clean
   cargo build
   ```

3. **Runtime Errors**
   ```bash
   export RUST_LOG=debug
   cargo run --example basic_operations
   ```

### Debug Mode

```bash
# Enable debug logging
export RUST_LOG=debug

# Enable backend-specific logging
export RUST_LOG=pkcs11_core=debug,pkcs11_impl_mock=trace

# Run with debug output
cargo run --example basic_operations 2>&1 | tee debug.log
```

### Validation

```bash
# Validate configuration
cargo run --example validate_config

# Test backend connectivity
cargo run --example test_connection

# Verify PKCS#11 compliance
cargo run --example pkcs11_compliance
```

## Contributing Examples

When contributing new examples:

1. **Follow the structure**: Place examples in appropriate subdirectories
2. **Include documentation**: Add comprehensive README files
3. **Provide configuration**: Include example configuration files
4. **Add tests**: Ensure examples are tested
5. **Update this README**: Document new examples

### Example Template

```rust
//! Example: [Brief Description]
//!
//! This example demonstrates [detailed description].
//!
//! ## Usage
//!
//! ```bash
//! cargo run --example example_name
//! ```
//!
//! ## Configuration
//!
//! Uses configuration from `examples/config/example.yaml`

use pkcs11_core::backend::CryptoBackend;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example implementation
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_example() {
        // Test implementation
    }
}
```

For more detailed information, see the [Development Guide](../docs/DEVELOPMENT.md).