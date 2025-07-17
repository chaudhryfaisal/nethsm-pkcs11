# Testing Examples

This directory contains comprehensive testing examples demonstrating how to use the mock implementation for various testing scenarios.

## Overview

The mock backend provides powerful testing capabilities including:

- **Deterministic behavior** for reproducible tests
- **Error injection** for testing error handling
- **Performance simulation** with configurable delays
- **Comprehensive coverage** of all PKCS#11 operations
- **CI/CD integration** without hardware dependencies

## Examples

- **[`unit_testing.rs`](./unit_testing.rs)**: Unit testing patterns with mock backend
- **[`integration_testing.rs`](./integration_testing.rs)**: Integration testing strategies
- **[`error_injection.rs`](./error_injection.rs)**: Error injection and handling tests
- **[`performance_testing.rs`](./performance_testing.rs)**: Performance and load testing
- **[`deterministic_testing.rs`](./deterministic_testing.rs)**: Reproducible test scenarios
- **[`ci_cd_integration.rs`](./ci_cd_integration.rs)**: CI/CD pipeline integration
- **[`compliance_testing.rs`](./compliance_testing.rs)**: PKCS#11 compliance verification

## Configuration Files

- **[`config/unit_test.yaml`](./config/unit_test.yaml)**: Unit testing configuration
- **[`config/integration_test.yaml`](./config/integration_test.yaml)**: Integration testing configuration
- **[`config/error_injection.yaml`](./config/error_injection.yaml)**: Error injection configuration
- **[`config/performance_test.yaml`](./config/performance_test.yaml)**: Performance testing configuration

## Running Tests

### Prerequisites

```bash
# Build the mock backend
cargo build --release --package pkcs11_impl_mock

# Set up test environment
export P11NETHSM_CONFIG_FILE=examples/testing/config/unit_test.yaml
export RUST_LOG=debug
```

### Run Individual Test Examples

```bash
# Unit testing example
cargo run --example unit_testing

# Integration testing example
cargo run --example integration_testing

# Error injection testing
cargo run --example error_injection

# Performance testing
cargo run --example performance_testing

# Deterministic testing
cargo run --example deterministic_testing

# CI/CD integration example
cargo run --example ci_cd_integration

# Compliance testing
cargo run --example compliance_testing
```

### Run Test Suite

```bash
# Run all testing examples
cargo test --examples testing

# Run with specific configuration
P11NETHSM_CONFIG_FILE=examples/testing/config/error_injection.yaml \
  cargo test --examples testing

# Run performance tests
cargo test --release --examples testing performance_
```

## Testing Strategies

### 1. Unit Testing

Unit tests focus on individual components and operations:

```rust
use pkcs11_impl_mock::{MockBackend, MockConfig};
use pkcs11_core::backend::CryptoBackend;

#[test]
fn test_key_generation() {
    let config = MockConfig::new()
        .with_deterministic(true)
        .with_random_seed(42);
    
    let mut backend = MockBackend::initialize(config).unwrap();
    
    // Test key generation
    let slots = backend.get_slot_list(true).unwrap();
    let session = backend.open_session(slots[0], SessionFlags::default()).unwrap();
    
    let key_spec = KeyGenerationSpec {
        key_type: KeyType::Rsa,
        key_size: 2048,
        // ... other fields
    };
    
    let key_handle = backend.generate_key(session, &key_spec).unwrap();
    assert!(key_handle.0 > 0);
    
    backend.close_session(session).unwrap();
    backend.finalize().unwrap();
}
```

### 2. Integration Testing

Integration tests verify end-to-end functionality:

```rust
#[test]
fn test_complete_workflow() {
    let config = MockConfig::new()
        .with_deterministic(true)
        .with_require_auth(true);
    
    let mut backend = MockBackend::initialize(config).unwrap();
    
    // Complete workflow: init -> login -> generate -> sign -> verify -> cleanup
    let slots = backend.get_slot_list(true).unwrap();
    let session = backend.open_session(slots[0], SessionFlags {
        rw_session: true,
        serial_session: true,
    }).unwrap();
    
    // Login
    backend.login(session, UserType::User, "123456").unwrap();
    
    // Generate key pair
    let (private_key, public_key) = backend.generate_key_pair(session, &key_spec).unwrap();
    
    // Sign data
    let data = b"test data";
    let mechanism = SignMechanism {
        mechanism_type: MechanismType(cryptoki_sys::CKM_RSA_PKCS as u32),
        parameters: None,
    };
    let signature = backend.sign(session, private_key, &mechanism, data).unwrap();
    
    // Verify signature
    let is_valid = backend.verify(session, public_key, &mechanism, data, &signature).unwrap();
    assert!(is_valid);
    
    // Cleanup
    backend.delete_key(session, private_key).unwrap();
    backend.delete_key(session, public_key).unwrap();
    backend.logout(session).unwrap();
    backend.close_session(session).unwrap();
    backend.finalize().unwrap();
}
```

### 3. Error Injection Testing

Test error handling with configurable error injection:

```rust
#[test]
fn test_error_handling() {
    let error_config = ErrorInjectionConfig::new()
        .with_probability(1.0) // 100% error rate
        .inject_on("sign")
        .with_message("Simulated signing error");
    
    let config = MockConfig::new()
        .with_error_injection(error_config);
    
    let mut backend = MockBackend::initialize(config).unwrap();
    
    // Set up session and key
    let slots = backend.get_slot_list(true).unwrap();
    let session = backend.open_session(slots[0], SessionFlags::default()).unwrap();
    let key_handle = backend.generate_key(session, &key_spec).unwrap();
    
    // This should fail due to error injection
    let result = backend.sign(session, key_handle, &mechanism, b"data");
    assert!(result.is_err());
    
    // Verify error type
    match result.unwrap_err() {
        MockError::Signature(msg) => assert_eq!(msg, "Simulated signing error"),
        _ => panic!("Unexpected error type"),
    }
    
    backend.close_session(session).unwrap();
    backend.finalize().unwrap();
}
```

### 4. Performance Testing

Test performance characteristics and limits:

```rust
#[test]
fn test_performance_limits() {
    let config = MockConfig::new()
        .with_max_sessions(10)
        .with_max_objects(100)
        .with_operation_delay("generate_key", 100); // 100ms delay
    
    let mut backend = MockBackend::initialize(config).unwrap();
    
    // Test session limits
    let slots = backend.get_slot_list(true).unwrap();
    let mut sessions = Vec::new();
    
    for i in 0..10 {
        let session = backend.open_session(slots[0], SessionFlags::default()).unwrap();
        sessions.push(session);
    }
    
    // 11th session should fail
    let result = backend.open_session(slots[0], SessionFlags::default());
    assert!(result.is_err());
    
    // Test operation timing
    let start = std::time::Instant::now();
    let _key = backend.generate_key(sessions[0], &key_spec).unwrap();
    let duration = start.elapsed();
    
    // Should take at least 100ms due to configured delay
    assert!(duration >= std::time::Duration::from_millis(100));
    
    // Cleanup
    for session in sessions {
        backend.close_session(session).unwrap();
    }
    backend.finalize().unwrap();
}
```

### 5. Deterministic Testing

Ensure reproducible test results:

```rust
#[test]
fn test_deterministic_behavior() {
    let config = MockConfig::new()
        .with_deterministic(true)
        .with_random_seed(12345);
    
    // Run the same test twice
    let result1 = run_test_scenario(config.clone());
    let result2 = run_test_scenario(config);
    
    // Results should be identical
    assert_eq!(result1, result2);
}

fn run_test_scenario(config: MockConfig) -> Vec<u8> {
    let mut backend = MockBackend::initialize(config).unwrap();
    let slots = backend.get_slot_list(true).unwrap();
    let session = backend.open_session(slots[0], SessionFlags::default()).unwrap();
    
    // Generate random data (should be deterministic)
    let random_data = backend.generate_random(session, 32).unwrap();
    
    backend.close_session(session).unwrap();
    backend.finalize().unwrap();
    
    random_data
}
```

## CI/CD Integration

### GitHub Actions Example

```yaml
# .github/workflows/test.yml
name: PKCS#11 Tests

on: [push, pull_request]

jobs:
  test-mock:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        test-config:
          - unit_test
          - integration_test
          - error_injection
          - performance_test
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          override: true
      
      - name: Cache dependencies
        uses: actions/cache@v3
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            target
          key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}
      
      - name: Build mock backend
        run: cargo build --release --package pkcs11_impl_mock
      
      - name: Run tests
        env:
          P11NETHSM_CONFIG_FILE: examples/testing/config/${{ matrix.test-config }}.yaml
          RUST_LOG: debug
        run: |
          cargo test --package pkcs11_impl_mock
          cargo run --example ${{ matrix.test-config }}
      
      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: test-results-${{ matrix.test-config }}
          path: target/debug/test-results/
```

### Jenkins Pipeline Example

```groovy
// Jenkinsfile
pipeline {
    agent any
    
    environment {
        RUST_LOG = 'debug'
    }
    
    stages {
        stage('Build') {
            steps {
                sh 'cargo build --release --package pkcs11_impl_mock'
            }
        }
        
        stage('Unit Tests') {
            environment {
                P11NETHSM_CONFIG_FILE = 'examples/testing/config/unit_test.yaml'
            }
            steps {
                sh 'cargo test --package pkcs11_impl_mock'
                sh 'cargo run --example unit_testing'
            }
        }
        
        stage('Integration Tests') {
            environment {
                P11NETHSM_CONFIG_FILE = 'examples/testing/config/integration_test.yaml'
            }
            steps {
                sh 'cargo run --example integration_testing'
            }
        }
        
        stage('Error Injection Tests') {
            environment {
                P11NETHSM_CONFIG_FILE = 'examples/testing/config/error_injection.yaml'
            }
            steps {
                sh 'cargo run --example error_injection'
            }
        }
        
        stage('Performance Tests') {
            environment {
                P11NETHSM_CONFIG_FILE = 'examples/testing/config/performance_test.yaml'
            }
            steps {
                sh 'cargo run --example performance_testing'
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'target/debug/test-results/**', allowEmptyArchive: true
            publishTestResults testResultsPattern: 'target/debug/test-results/*.xml'
        }
    }
}
```

## Test Configuration Examples

### Unit Test Configuration

```yaml
# config/unit_test.yaml
backend:
  type: "mock"

mock:
  deterministic: true
  random_seed: 42
  token_label: "Unit Test Token"
  require_auth: false
  verbose_logging: false
  
  max_sessions: 10
  max_objects: 100
  
  error_injection:
    enabled: false
  
  operation_delays: {}
  
  mechanisms:
    CKM_RSA_PKCS:
      enabled: true
      supports_signing: true
      supports_verification: true
      supports_key_generation: true
    CKM_SHA256:
      enabled: true
```

### Error Injection Configuration

```yaml
# config/error_injection.yaml
backend:
  type: "mock"

mock:
  deterministic: true
  random_seed: 123
  token_label: "Error Injection Test Token"
  require_auth: true
  default_pin: "123456"
  
  error_injection:
    enabled: true
    probability: 0.1  # 10% error rate
    operations:
      - "sign"
      - "encrypt"
      - "generate_key"
    message: "Simulated error for testing"
    
    deterministic_errors:
      - operation: "sign"
        after_calls: 5
        message: "Deterministic signing failure"
      - operation: "generate_key"
        after_calls: 3
        message: "Key generation limit reached"
```

### Performance Test Configuration

```yaml
# config/performance_test.yaml
backend:
  type: "mock"

mock:
  deterministic: true
  token_label: "Performance Test Token"
  require_auth: false
  
  max_sessions: 1000
  max_objects: 10000
  
  operation_delays:
    sign: 10           # 10ms
    verify: 5          # 5ms
    encrypt: 15        # 15ms
    decrypt: 15        # 15ms
    generate_key: 100  # 100ms
    generate_key_pair: 200  # 200ms
  
  mechanisms:
    CKM_RSA_PKCS:
      enabled: true
      min_key_size: 1024
      max_key_size: 4096
    CKM_ECDSA:
      enabled: true
    CKM_AES_CBC:
      enabled: true
```

## Best Practices

### 1. Test Organization

```rust
// Organize tests by functionality
mod key_management_tests {
    use super::*;
    
    #[test]
    fn test_key_generation() { /* ... */ }
    
    #[test]
    fn test_key_import() { /* ... */ }
    
    #[test]
    fn test_key_deletion() { /* ... */ }
}

mod crypto_operation_tests {
    use super::*;
    
    #[test]
    fn test_signing() { /* ... */ }
    
    #[test]
    fn test_encryption() { /* ... */ }
}
```

### 2. Test Data Management

```rust
// Use deterministic test data
fn create_test_key_spec() -> KeyGenerationSpec {
    KeyGenerationSpec {
        key_type: KeyType::Rsa,
        key_size: 2048,
        label: Some("test-key".to_string()),
        id: Some(b"test-key-001".to_vec()),
        usage: KeyUsage {
            sign: true,
            verify: true,
            encrypt: false,
            decrypt: false,
            derive: false,
            extractable: false,
            sensitive: true,
        },
    }
}

// Use test fixtures
struct TestFixture {
    backend: MockBackend,
    session: SessionHandle,
}

impl TestFixture {
    fn new() -> Self {
        let config = MockConfig::new().with_deterministic(true);
        let mut backend = MockBackend::initialize(config).unwrap();
        let slots = backend.get_slot_list(true).unwrap();
        let session = backend.open_session(slots[0], SessionFlags::default()).unwrap();
        
        Self { backend, session }
    }
}

impl Drop for TestFixture {
    fn drop(&mut self) {
        self.backend.close_session(self.session).unwrap();
        self.backend.finalize().unwrap();
    }
}
```

### 3. Error Testing

```rust
// Test specific error conditions
#[test]
fn test_invalid_pin() {
    let config = MockConfig::new().with_require_auth(true);
    let mut backend = MockBackend::initialize(config).unwrap();
    
    let slots = backend.get_slot_list(true).unwrap();
    let session = backend.open_session(slots[0], SessionFlags::default()).unwrap();
    
    // Test with invalid PIN
    let result = backend.login(session, UserType::User, "wrong-pin");
    assert!(matches!(result, Err(MockError::Authentication(_))));
    
    backend.close_session(session).unwrap();
    backend.finalize().unwrap();
}
```

### 4. Performance Testing

```rust
// Benchmark operations
#[test]
fn test_operation_performance() {
    let config = MockConfig::new();
    let mut backend = MockBackend::initialize(config).unwrap();
    
    let slots = backend.get_slot_list(true).unwrap();
    let session = backend.open_session(slots[0], SessionFlags::default()).unwrap();
    
    // Benchmark key generation
    let start = std::time::Instant::now();
    let iterations = 100;
    
    for _ in 0..iterations {
        let key = backend.generate_key(session, &create_test_key_spec()).unwrap();
        backend.delete_key(session, key).unwrap();
    }
    
    let duration = start.elapsed();
    let avg_duration = duration / iterations;
    
    println!("Average key generation time: {:?}", avg_duration);
    
    // Assert reasonable performance
    assert!(avg_duration < std::time::Duration::from_millis(100));
    
    backend.close_session(session).unwrap();
    backend.finalize().unwrap();
}
```

## Troubleshooting

### Common Testing Issues

1. **Non-deterministic test failures**
   ```rust
   // Always use deterministic configuration
   let config = MockConfig::new()
       .with_deterministic(true)
       .with_random_seed(42);
   ```

2. **Resource leaks in tests**
   ```rust
   // Always clean up resources
   #[test]
   fn test_with_cleanup() {
       let mut backend = setup_backend();
       
       // Test code here
       
       // Cleanup (consider using Drop trait)
       cleanup_backend(backend);
   }
   ```

3. **Flaky performance tests**
   ```rust
   // Use relative timing assertions
   let start = std::time::Instant::now();
   perform_operation();
   let duration = start.elapsed();
   
   // Allow for some variance
   assert!(duration >= expected_min_duration);
   assert!(duration <= expected_max_duration);
   ```

For more testing examples and patterns, see the individual example files in this directory.