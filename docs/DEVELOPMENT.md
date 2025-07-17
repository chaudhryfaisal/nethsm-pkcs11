# Development Guide

This document provides comprehensive development guidelines for the modular NetHSM PKCS#11 architecture.

## Table of Contents

- [Overview](#overview)
- [Architecture and Design](#architecture-and-design)
- [Development Environment Setup](#development-environment-setup)
- [Building the Project](#building-the-project)
- [Testing](#testing)
- [Creating Custom Backends](#creating-custom-backends)
- [Contributing Guidelines](#contributing-guidelines)
- [Debugging and Troubleshooting](#debugging-and-troubleshooting)
- [Performance Optimization](#performance-optimization)
- [Security Considerations](#security-considerations)

## Overview

The modular PKCS#11 architecture is designed to provide a clean separation between the PKCS#11 protocol implementation and cryptographic backends. This enables:

- **Extensibility**: Easy addition of new backend implementations
- **Testability**: Comprehensive testing with mock backends
- **Maintainability**: Clear separation of concerns
- **Flexibility**: Support for different deployment scenarios

## Architecture and Design

### Core Components

```
pkcs11_core/
├── src/
│   ├── api/           # PKCS#11 C API implementations
│   ├── backend/       # Backend abstraction layer
│   │   ├── mod.rs     # CryptoBackend trait definition
│   │   ├── types.rs   # Common types and structures
│   │   ├── error.rs   # Unified error handling
│   │   └── registry.rs # Backend registration system
│   ├── config/        # Configuration management
│   └── data.rs        # Global state management
```

### Backend Implementations

```
pkcs11_impl_nethsm_sdk/
├── src/
│   ├── backend.rs     # NetHSM backend implementation
│   ├── config.rs      # NetHSM-specific configuration
│   └── error.rs       # NetHSM error handling

pkcs11_impl_mock/
├── src/
│   ├── backend.rs     # Mock backend implementation
│   ├── config.rs      # Mock configuration
│   ├── crypto.rs      # Mock cryptographic operations
│   ├── storage.rs     # In-memory storage
│   └── error.rs       # Mock error handling
```

### Design Principles

1. **Trait-Based Abstraction**: The [`CryptoBackend`](../pkcs11_core/src/backend/mod.rs:54) trait defines the interface
2. **Type Safety**: Strong typing throughout the API
3. **Error Handling**: Unified error types with automatic conversion
4. **Thread Safety**: All backends must be `Send + Sync`
5. **Configuration-Driven**: Backend selection via configuration
6. **Backward Compatibility**: Full PKCS#11 C API compliance

## Development Environment Setup

### Prerequisites

- **Rust**: Version 1.70 or later (MSRV)
- **GCC**: For C compilation
- **Git**: For version control
- **Optional**: Docker for containerized testing

### Installation

1. **Install Rust**:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source ~/.cargo/env
   ```

2. **Install additional tools**:
   ```bash
   # For development
   cargo install cargo-watch
   cargo install cargo-expand
   cargo install cargo-audit
   
   # For testing
   cargo install cargo-nextest
   ```

3. **Clone the repository**:
   ```bash
   git clone https://github.com/Nitrokey/nethsm-pkcs11.git
   cd nethsm-pkcs11
   ```

4. **Install system dependencies**:
   ```bash
   # Ubuntu/Debian
   sudo apt-get install build-essential pkg-config libssl-dev
   
   # Alpine Linux
   apk add musl-dev gcc
   
   # macOS
   xcode-select --install
   ```

### IDE Setup

#### VS Code

Recommended extensions:
- `rust-analyzer`: Rust language support
- `CodeLLDB`: Debugging support
- `Better TOML`: TOML syntax highlighting
- `YAML`: YAML syntax highlighting

Configuration (`.vscode/settings.json`):
```json
{
    "rust-analyzer.cargo.features": "all",
    "rust-analyzer.checkOnSave.command": "clippy",
    "rust-analyzer.cargo.loadOutDirsFromCheck": true
}
```

#### IntelliJ IDEA / CLion

Install the Rust plugin and configure:
- Enable external linter (Clippy)
- Set up run configurations for tests
- Configure debugging with GDB/LLDB

## Building the Project

### Basic Build

```bash
# Build all workspace members
cargo build

# Build with optimizations
cargo build --release

# Build specific backend
cargo build --package pkcs11_impl_nethsm_sdk
cargo build --package pkcs11_impl_mock
```

### Build Features

The project uses Cargo features for conditional compilation:

```bash
# Build with all features
cargo build --all-features

# Build with specific features
cargo build --features "nethsm-backend"
cargo build --features "mock-backend"

# Build without default features
cargo build --no-default-features
```

### Cross-Compilation

```bash
# Add target
rustup target add x86_64-unknown-linux-musl

# Build for target
cargo build --target x86_64-unknown-linux-musl --release
```

### Alpine Linux Build

```bash
RUSTFLAGS="-C target-feature=-crt-static" cargo build --release
```

## Testing

### Test Structure

```
tests/
├── integration_tests.rs    # Integration tests
├── common/
│   ├── mod.rs              # Common test utilities
│   ├── backend_testing.rs  # Backend test helpers
│   ├── config_helpers.rs   # Configuration helpers
│   └── test_data.rs        # Test data generation

pkcs11_core/tests/
├── backend_abstraction.rs  # Backend trait tests
├── backend_registry.rs     # Registry tests
└── basic.rs                # Basic functionality tests

pkcs11_impl_mock/tests/
├── backend_tests.rs        # Mock backend tests
└── mod.rs                  # Test utilities
```

### Running Tests

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_backend_initialization

# Run tests for specific package
cargo test --package pkcs11_impl_mock

# Run integration tests only
cargo test --test integration_tests

# Run with specific features
cargo test --features "mock-backend"
```

### Test Categories

#### Unit Tests
```bash
# Run unit tests only
cargo test --lib
```

#### Integration Tests
```bash
# Run integration tests
cargo test --test integration_tests
```

#### Backend Tests
```bash
# Test mock backend
cargo test --package pkcs11_impl_mock

# Test NetHSM backend (requires NetHSM instance)
NETHSM_URL=https://localhost:8443/api/v1 cargo test --package pkcs11_impl_nethsm_sdk
```

#### Performance Tests
```bash
# Run with release optimizations
cargo test --release

# Run specific performance tests
cargo test --release performance_
```

### Test Configuration

Create test configuration files:

**`tests/config/mock.yaml`**:
```yaml
backend:
  type: "mock"
mock:
  deterministic: true
  random_seed: 42
```

**`tests/config/nethsm.yaml`**:
```yaml
backend:
  type: "nethsm"
slots:
  - label: "Test-NetHSM"
    instances:
      - url: "${NETHSM_URL}"
        danger_insecure_cert: true
    operator:
      username: "operator"
      password: "opPassphrase"
```

### Continuous Integration

The project uses GitHub Actions for CI. Local CI simulation:

```bash
# Run the same checks as CI
cargo fmt --check
cargo clippy -- -D warnings
cargo test --all-features
cargo audit
```

## Creating Custom Backends

### Backend Implementation Steps

1. **Create a new crate**:
   ```bash
   cargo new --lib pkcs11_impl_custom
   cd pkcs11_impl_custom
   ```

2. **Add dependencies** (`Cargo.toml`):
   ```toml
   [dependencies]
   pkcs11_core = { path = "../pkcs11_core" }
   thiserror = "2.0"
   log = "0.4"
   
   [lib]
   crate-type = ["cdylib", "lib"]
   ```

3. **Implement the backend**:

```rust
// src/lib.rs
use pkcs11_core::backend::{CryptoBackend, BackendConfig, types::*};

#[derive(Debug, Clone)]
pub struct CustomConfig {
    // Your configuration fields
    pub endpoint: String,
    pub timeout: u64,
}

impl BackendConfig for CustomConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.endpoint.is_empty() {
            return Err(ConfigError::InvalidConfig("Endpoint cannot be empty".to_string()));
        }
        Ok(())
    }
    
    fn backend_type(&self) -> BackendType {
        BackendType::Custom("custom".to_string())
    }
}

pub struct CustomBackend {
    config: CustomConfig,
    initialized: bool,
    // Your backend state
}

impl CryptoBackend for CustomBackend {
    type Config = CustomConfig;
    type Error = CustomError;

    fn initialize(config: Self::Config) -> Result<Self, Self::Error> {
        config.validate().map_err(|e| CustomError::Configuration(e.to_string()))?;
        
        Ok(CustomBackend {
            config,
            initialized: true,
        })
    }

    fn finalize(&mut self) -> Result<(), Self::Error> {
        self.initialized = false;
        Ok(())
    }

    fn is_initialized(&self) -> bool {
        self.initialized
    }

    // Implement all other required methods...
    fn get_slot_list(&self, _token_present: bool) -> Result<Vec<SlotId>, Self::Error> {
        Ok(vec![SlotId(0)])
    }

    // ... implement remaining methods
}

// Error type
#[derive(Debug, thiserror::Error)]
pub enum CustomError {
    #[error("Configuration error: {0}")]
    Configuration(String),
    
    #[error("Connection error: {0}")]
    Connection(String),
    
    // Add more error variants as needed
}

impl Into<BackendError> for CustomError {
    fn into(self) -> BackendError {
        match self {
            CustomError::Configuration(msg) => BackendError::ConfigurationError { reason: msg },
            CustomError::Connection(msg) => BackendError::NetworkError { reason: msg },
        }
    }
}

// Export C API functions
use pkcs11_core::api::*;

#[no_mangle]
pub extern "C" fn C_GetFunctionList(
    pp_fn_list: *mut *mut cryptoki_sys::CK_FUNCTION_LIST,
) -> cryptoki_sys::CK_RV {
    pkcs11_core::api::C_GetFunctionList(pp_fn_list)
}

// Export other required C functions...
```

4. **Add configuration support**:

```rust
// src/config.rs
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomConfig {
    pub endpoint: String,
    pub timeout: u64,
    pub api_key: Option<String>,
}

impl CustomConfig {
    pub fn load_from_file(path: &str) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = serde_yaml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }
}
```

5. **Add tests**:

```rust
// tests/backend_tests.rs
use pkcs11_impl_custom::{CustomBackend, CustomConfig};
use pkcs11_core::backend::CryptoBackend;

#[test]
fn test_backend_initialization() {
    let config = CustomConfig {
        endpoint: "https://api.example.com".to_string(),
        timeout: 30,
        api_key: None,
    };
    
    let backend = CustomBackend::initialize(config);
    assert!(backend.is_ok());
}

#[test]
fn test_slot_operations() {
    let config = CustomConfig {
        endpoint: "https://api.example.com".to_string(),
        timeout: 30,
        api_key: None,
    };
    
    let backend = CustomBackend::initialize(config).unwrap();
    let slots = backend.get_slot_list(false).unwrap();
    assert!(!slots.is_empty());
}
```

### Backend Registration

Register your backend with the core library:

```rust
// In pkcs11_core/src/backend/registry.rs
use pkcs11_impl_custom::{CustomBackend, CustomConfig};

pub fn create_backend(backend_type: &str, config: &Config) -> Result<Box<dyn ErasedCryptoBackend>, BackendError> {
    match backend_type {
        "nethsm" => {
            let config = NetHsmConfig::from_config(config)?;
            let backend = NetHsmBackend::initialize(config)?;
            Ok(Box::new(backend))
        }
        "mock" => {
            let config = MockConfig::from_config(config)?;
            let backend = MockBackend::initialize(config)?;
            Ok(Box::new(backend))
        }
        "custom" => {
            let config = CustomConfig::from_config(config)?;
            let backend = CustomBackend::initialize(config)?;
            Ok(Box::new(backend))
        }
        _ => Err(BackendError::ConfigurationError {
            reason: format!("Unknown backend type: {}", backend_type),
        }),
    }
}
```

## Contributing Guidelines

### Code Style

1. **Follow Rust conventions**:
   ```bash
   # Format code
   cargo fmt
   
   # Check with Clippy
   cargo clippy -- -D warnings
   ```

2. **Documentation**:
   ```rust
   /// Brief description of the function.
   ///
   /// More detailed description if needed.
   ///
   /// # Arguments
   ///
   /// * `param` - Description of parameter
   ///
   /// # Returns
   ///
   /// Description of return value
   ///
   /// # Errors
   ///
   /// Description of possible errors
   ///
   /// # Examples
   ///
   /// ```
   /// use pkcs11_core::backend::CryptoBackend;
   /// // Example usage
   /// ```
   pub fn example_function(param: &str) -> Result<String, Error> {
       // Implementation
   }
   ```

3. **Error handling**:
   ```rust
   // Use thiserror for error types
   #[derive(Debug, thiserror::Error)]
   pub enum MyError {
       #[error("Configuration error: {message}")]
       Configuration { message: String },
       
       #[error("Network error: {source}")]
       Network { #[from] source: std::io::Error },
   }
   ```

### Commit Guidelines

1. **Commit message format**:
   ```
   type(scope): brief description
   
   Longer description if needed.
   
   Fixes #123
   ```

2. **Types**:
   - `feat`: New feature
   - `fix`: Bug fix
   - `docs`: Documentation changes
   - `style`: Code style changes
   - `refactor`: Code refactoring
   - `test`: Test additions/changes
   - `chore`: Maintenance tasks

3. **Scopes**:
   - `core`: Changes to pkcs11_core
   - `nethsm`: Changes to NetHSM backend
   - `mock`: Changes to mock backend
   - `config`: Configuration changes
   - `api`: PKCS#11 API changes

### Pull Request Process

1. **Create feature branch**:
   ```bash
   git checkout -b feature/my-new-feature
   ```

2. **Make changes and test**:
   ```bash
   cargo test --all-features
   cargo fmt
   cargo clippy -- -D warnings
   ```

3. **Update documentation**:
   - Update relevant documentation files
   - Add examples if applicable
   - Update CHANGELOG.md

4. **Submit pull request**:
   - Clear description of changes
   - Reference related issues
   - Include test results

### Code Review Checklist

- [ ] Code follows style guidelines
- [ ] All tests pass
- [ ] Documentation is updated
- [ ] Error handling is appropriate
- [ ] Thread safety is maintained
- [ ] Performance impact is considered
- [ ] Security implications are reviewed

## Debugging and Troubleshooting

### Logging

Enable detailed logging:

```bash
# Set log level
export RUST_LOG=debug

# Backend-specific logging
export RUST_LOG=pkcs11_core=debug,pkcs11_impl_mock=trace

# Log to file
export RUST_LOG=debug
cargo test 2>&1 | tee debug.log
```

### Debugging with GDB/LLDB

```bash
# Build with debug symbols
cargo build

# Debug with GDB
gdb --args target/debug/my_test

# Debug with LLDB
lldb target/debug/my_test
```

### Common Issues

#### 1. Backend Not Found

**Error**: `Unknown backend type`

**Solution**:
- Check backend registration in registry
- Verify configuration file syntax
- Ensure backend crate is compiled

#### 2. Configuration Loading Failed

**Error**: `Failed to load configuration`

**Solution**:
- Validate YAML syntax
- Check file permissions
- Verify environment variables

#### 3. Symbol Not Found

**Error**: `undefined symbol`

**Solution**:
- Check C API exports
- Verify linking configuration
- Ensure all required functions are implemented

### Memory Debugging

```bash
# Use Valgrind (Linux)
valgrind --tool=memcheck --leak-check=full ./target/debug/my_test

# Use AddressSanitizer
RUSTFLAGS="-Z sanitizer=address" cargo test

# Use ThreadSanitizer
RUSTFLAGS="-Z sanitizer=thread" cargo test
```

## Performance Optimization

### Profiling

```bash
# Install profiling tools
cargo install cargo-profdata
cargo install flamegraph

# Profile with perf
cargo build --release
perf record --call-graph=dwarf ./target/release/my_benchmark
perf report

# Generate flame graph
cargo flamegraph --bin my_benchmark
```

### Benchmarking

```rust
// benches/backend_benchmark.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pkcs11_impl_mock::{MockBackend, MockConfig};

fn benchmark_key_generation(c: &mut Criterion) {
    let config = MockConfig::new().with_deterministic(true);
    let mut backend = MockBackend::initialize(config).unwrap();
    
    c.bench_function("generate_rsa_key", |b| {
        b.iter(|| {
            let spec = KeyGenerationSpec {
                key_type: KeyType::Rsa,
                key_size: 2048,
                // ... other fields
            };
            black_box(backend.generate_key(session, &spec))
        })
    });
}

criterion_group!(benches, benchmark_key_generation);
criterion_main!(benches);
```

### Optimization Guidelines

1. **Minimize allocations**:
   ```rust
   // Use string slices instead of owned strings where possible
   fn process_data(data: &[u8]) -> &str {
       // Process without allocation
   }
   ```

2. **Use efficient data structures**:
   ```rust
   // Use HashMap for O(1) lookups
   use std::collections::HashMap;
   
   // Use Vec for sequential access
   use std::vec::Vec;
   ```

3. **Avoid unnecessary cloning**:
   ```rust
   // Pass by reference when possible
   fn process_config(config: &Config) -> Result<(), Error> {
       // Process without cloning
   }
   ```

## Security Considerations

### Secure Coding Practices

1. **Input validation**:
   ```rust
   fn validate_pin(pin: &str) -> Result<(), Error> {
       if pin.len() < 4 || pin.len() > 32 {
           return Err(Error::InvalidPin);
       }
       // Additional validation
       Ok(())
   }
   ```

2. **Memory safety**:
   ```rust
   // Use secure memory clearing
   use zeroize::Zeroize;
   
   struct SecretKey {
       data: Vec<u8>,
   }
   
   impl Drop for SecretKey {
       fn drop(&mut self) {
           self.data.zeroize();
       }
   }
   ```

3. **Error handling**:
   ```rust
   // Don't leak sensitive information in errors
   match authenticate(credentials) {
       Ok(session) => Ok(session),
       Err(_) => Err(Error::AuthenticationFailed), // Generic error
   }
   ```

### Security Testing

```bash
# Run security audit
cargo audit

# Check for unsafe code
cargo geiger

# Static analysis
cargo clippy -- -W clippy::all
```

### Threat Model

Consider these security aspects:

1. **Memory safety**: Rust's ownership system prevents many vulnerabilities
2. **Input validation**: Validate all external inputs
3. **Error handling**: Don't leak sensitive information
4. **Cryptographic operations**: Use established libraries
5. **Network security**: Validate TLS certificates
6. **Configuration security**: Protect configuration files

## Release Process

### Version Management

1. **Update version numbers**:
   ```toml
   # Cargo.toml
   [package]
   version = "1.2.3"
   ```

2. **Update CHANGELOG.md**:
   ```markdown
   ## [1.2.3] - 2024-01-15
   
   ### Added
   - New feature description
   
   ### Changed
   - Changed feature description
   
   ### Fixed
   - Bug fix description
   ```

3. **Create release**:
   ```bash
   git tag v1.2.3
   git push origin v1.2.3
   ```

### Build Artifacts

```bash
# Build release artifacts
cargo build --release --all-features

# Create distribution package
tar -czf nethsm-pkcs11-v1.2.3.tar.gz target/release/lib*.so docs/ examples/
```

This development guide provides comprehensive information for contributing to and extending the modular NetHSM PKCS#11 architecture. For specific examples and use cases, see the [examples directory](../examples/).