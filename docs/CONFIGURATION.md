# Configuration Guide

This document provides comprehensive configuration guides for the modular NetHSM PKCS#11 architecture.

## Table of Contents

- [Overview](#overview)
- [Configuration File Format](#configuration-file-format)
- [NetHSM Configuration](#nethsm-configuration)
- [Mock Implementation Configuration](#mock-implementation-configuration)
- [Environment Variables](#environment-variables)
- [Configuration Examples](#configuration-examples)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## Overview

The modular PKCS#11 architecture supports multiple configuration formats and backend-specific settings. Configuration can be provided through:

1. **Configuration files** (YAML format)
2. **Environment variables**
3. **Programmatic configuration** (for custom backends)

## Configuration File Format

The primary configuration format is YAML. The configuration file should be named `p11nethsm.conf` and placed in one of these locations:

1. Current working directory
2. `/etc/p11nethsm/`
3. `~/.config/p11nethsm/`
4. Path specified by `P11NETHSM_CONFIG_FILE` environment variable

### Basic Structure

```yaml
# Backend selection (optional, defaults to "nethsm")
backend:
  type: "nethsm"  # or "mock" for testing

# Global settings
enable_set_attribute_value: false
log_level: "info"  # trace, debug, info, warn, error

# Backend-specific configuration
slots:
  - label: "NetHSM-1"
    # ... backend-specific settings
```

## NetHSM Configuration

### Complete NetHSM Configuration

```yaml
backend:
  type: "nethsm"

# Global NetHSM settings
enable_set_attribute_value: false

# Slot configuration
slots:
  - label: "NetHSM-Primary"
    description: "Primary NetHSM Device"
    
    # NetHSM instances (for high availability)
    instances:
      - url: "https://nethsm-1.example.com/api/v1"
        danger_insecure_cert: false
        sha256_fingerprints:
          - "31:92:8E:A4:5E:16:5C:A7:33:44:E8:E9:8E:64:C4:AE:7B:2A:57:E5:77:43:49:F3:69:C9:8F:C4:2F:3A:3B:6E"
      - url: "https://nethsm-2.example.com/api/v1"
        danger_insecure_cert: false
        sha256_fingerprints:
          - "42:A3:9F:B5:6F:27:6D:B8:44:55:F9:FA:9F:75:D5:BF:8C:3B:68:F6:88:54:5A:G4:7A:DA:AF:E5:40:4B:4C:7F"
    
    # User credentials
    operator:
      username: "operator"
      password: "opPassphrase"
    
    administrator:
      username: "admin"
      password: "adminPassphrase"
    
    # Connection settings
    retries:
      count: 3
      delay_seconds: 1
    timeout_seconds: 30
    
    # Certificate format
    certificate_format: "DER"  # or "PEM"

  - label: "NetHSM-Secondary"
    description: "Secondary NetHSM Device"
    instances:
      - url: "https://nethsm-3.example.com/api/v1"
        danger_insecure_cert: false
    operator:
      username: "operator"
      password: "opPassphrase"
```

### NetHSM Configuration Options

#### Instance Configuration

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `url` | string | Yes | NetHSM API endpoint URL |
| `danger_insecure_cert` | boolean | No | Skip TLS certificate validation (development only) |
| `sha256_fingerprints` | array | No | Expected certificate fingerprints for validation |

#### User Configuration

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `username` | string | Yes | NetHSM username |
| `password` | string | Yes | NetHSM password |

#### Connection Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `retries.count` | integer | 3 | Number of retry attempts |
| `retries.delay_seconds` | integer | 1 | Delay between retries |
| `timeout_seconds` | integer | 30 | Request timeout |

#### Certificate Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `certificate_format` | string | "DER" | Certificate format ("DER" or "PEM") |

### High Availability Configuration

For high availability, configure multiple NetHSM instances per slot:

```yaml
slots:
  - label: "HA-NetHSM"
    instances:
      - url: "https://primary.nethsm.example.com/api/v1"
        sha256_fingerprints:
          - "primary-cert-fingerprint"
      - url: "https://secondary.nethsm.example.com/api/v1"
        sha256_fingerprints:
          - "secondary-cert-fingerprint"
    # Failover will automatically occur if primary is unavailable
```

## Mock Implementation Configuration

The mock implementation is designed for testing and development. It provides configurable behavior for comprehensive testing scenarios.

### Complete Mock Configuration

```yaml
backend:
  type: "mock"

# Mock-specific settings
mock:
  # Basic configuration
  deterministic: true
  random_seed: 12345
  token_label: "Mock PKCS#11 Token"
  manufacturer_id: "Mock Manufacturer"
  model: "Mock HSM v1.0"
  serial_number: "MOCK-12345"
  firmware_version: "1.0.0"
  
  # Capacity limits
  max_sessions: 100
  max_objects: 1000
  
  # Authentication
  require_auth: true
  default_pin: "123456"
  
  # Logging
  verbose_logging: true
  
  # Error injection for testing
  error_injection:
    enabled: true
    probability: 0.05  # 5% chance of error
    operations:
      - "sign"
      - "encrypt"
    message: "Simulated error for testing"
    
    # Deterministic error injection
    deterministic_errors:
      - operation: "sign"
        after_calls: 10
        message: "Simulated signing failure"
  
  # Operation delays for performance testing
  operation_delays:
    sign: 100          # 100ms delay
    verify: 50         # 50ms delay
    encrypt: 75        # 75ms delay
    decrypt: 75        # 75ms delay
    generate_key: 500  # 500ms delay
  
  # Mechanism configuration
  mechanisms:
    CKM_RSA_PKCS:
      enabled: true
      supports_signing: true
      supports_verification: true
      supports_encryption: true
      supports_decryption: true
      supports_key_generation: true
      min_key_size: 1024
      max_key_size: 4096
      default_key_size: 2048
    
    CKM_RSA_PKCS_PSS:
      enabled: true
      supports_signing: true
      supports_verification: true
      min_key_size: 1024
      max_key_size: 4096
    
    CKM_ECDSA:
      enabled: true
      supports_signing: true
      supports_verification: true
      supports_key_generation: true
      supported_curves:
        - "P-256"
        - "P-384"
        - "P-521"
    
    CKM_AES_CBC:
      enabled: true
      supports_encryption: true
      supports_decryption: true
      supports_key_generation: true
      supported_key_sizes:
        - 128
        - 192
        - 256
    
    CKM_SHA256:
      enabled: true
    
    CKM_SHA384:
      enabled: true
    
    CKM_SHA512:
      enabled: true
```

### Mock Configuration Options

#### Basic Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `deterministic` | boolean | false | Enable deterministic behavior |
| `random_seed` | integer | random | Seed for deterministic RNG |
| `token_label` | string | "Mock Token" | Simulated token label |
| `manufacturer_id` | string | "Mock Manufacturer" | Simulated manufacturer |
| `model` | string | "Mock HSM" | Simulated device model |
| `serial_number` | string | "MOCK-001" | Simulated serial number |
| `firmware_version` | string | "1.0.0" | Simulated firmware version |

#### Capacity Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `max_sessions` | integer | 100 | Maximum concurrent sessions |
| `max_objects` | integer | 1000 | Maximum stored objects |

#### Authentication Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `require_auth` | boolean | true | Require authentication for operations |
| `default_pin` | string | "123456" | Default PIN for authentication |

#### Error Injection Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `error_injection.enabled` | boolean | false | Enable error injection |
| `error_injection.probability` | float | 0.0 | Random error probability (0.0-1.0) |
| `error_injection.operations` | array | [] | Operations to inject errors on |
| `error_injection.message` | string | "Injected error" | Error message |

#### Operation Delay Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `operation_delays.<operation>` | integer | 0 | Delay in milliseconds |

## Environment Variables

### Global Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `P11NETHSM_CONFIG_FILE` | Path to configuration file | Auto-detected |
| `RUST_LOG` | Logging level | "info" |
| `P11NETHSM_LOG_LEVEL` | PKCS#11 specific log level | Uses RUST_LOG |

### NetHSM Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `NETHSM_URL` | Override NetHSM URL | `https://nethsm.example.com/api/v1` |
| `NETHSM_OPERATOR_USER` | Override operator username | `operator` |
| `NETHSM_OPERATOR_PASS` | Override operator password | `password` |
| `NETHSM_ADMIN_USER` | Override admin username | `admin` |
| `NETHSM_ADMIN_PASS` | Override admin password | `password` |
| `NETHSM_TIMEOUT` | Override timeout (seconds) | `30` |
| `NETHSM_RETRIES` | Override retry count | `3` |

### Mock Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `MOCK_DETERMINISTIC` | Enable deterministic mode | `true` |
| `MOCK_RANDOM_SEED` | Set random seed | `12345` |
| `MOCK_DEFAULT_PIN` | Set default PIN | `123456` |
| `MOCK_ERROR_RATE` | Set error injection rate | `0.05` |

## Configuration Examples

### Development Configuration

```yaml
backend:
  type: "mock"

mock:
  deterministic: true
  random_seed: 42
  token_label: "Development Token"
  require_auth: false
  verbose_logging: true
  
  # Fast operations for development
  operation_delays: {}
  
  # No error injection for development
  error_injection:
    enabled: false
```

### Testing Configuration

```yaml
backend:
  type: "mock"

mock:
  deterministic: true
  random_seed: 12345
  token_label: "Test Token"
  require_auth: true
  default_pin: "testpin"
  
  # Error injection for robustness testing
  error_injection:
    enabled: true
    probability: 0.1
    operations: ["sign", "encrypt", "generate_key"]
    message: "Test error injection"
  
  # Simulate slow operations
  operation_delays:
    sign: 50
    generate_key: 200
```

### Production NetHSM Configuration

```yaml
backend:
  type: "nethsm"

enable_set_attribute_value: false

slots:
  - label: "Production-HSM"
    description: "Production NetHSM Cluster"
    
    instances:
      - url: "https://hsm-primary.company.com/api/v1"
        sha256_fingerprints:
          - "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
      - url: "https://hsm-secondary.company.com/api/v1"
        sha256_fingerprints:
          - "BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA"
    
    operator:
      username: "prod-operator"
      password: "${NETHSM_OPERATOR_PASS}"
    
    administrator:
      username: "prod-admin"
      password: "${NETHSM_ADMIN_PASS}"
    
    retries:
      count: 5
      delay_seconds: 2
    timeout_seconds: 60
    
    certificate_format: "DER"
```

### Multi-Tenant Configuration

```yaml
backend:
  type: "nethsm"

slots:
  - label: "Tenant-A"
    description: "HSM for Tenant A"
    instances:
      - url: "https://hsm-tenant-a.company.com/api/v1"
    operator:
      username: "tenant-a-operator"
      password: "${TENANT_A_OPERATOR_PASS}"
    
  - label: "Tenant-B"
    description: "HSM for Tenant B"
    instances:
      - url: "https://hsm-tenant-b.company.com/api/v1"
    operator:
      username: "tenant-b-operator"
      password: "${TENANT_B_OPERATOR_PASS}"
```

## Best Practices

### Security Best Practices

1. **Use Environment Variables for Secrets**
   ```yaml
   operator:
     username: "operator"
     password: "${NETHSM_OPERATOR_PASS}"
   ```

2. **Enable Certificate Validation**
   ```yaml
   instances:
     - url: "https://nethsm.example.com/api/v1"
       danger_insecure_cert: false
       sha256_fingerprints:
         - "certificate-fingerprint"
   ```

3. **Use Appropriate Timeouts**
   ```yaml
   timeout_seconds: 30
   retries:
     count: 3
     delay_seconds: 1
   ```

4. **Restrict File Permissions**
   ```bash
   chmod 600 /etc/p11nethsm/p11nethsm.conf
   chown root:root /etc/p11nethsm/p11nethsm.conf
   ```

### Performance Best Practices

1. **Configure Appropriate Timeouts**
   - Set `timeout_seconds` based on network latency
   - Adjust `retries` for reliability vs. performance

2. **Use Connection Pooling**
   - Multiple instances provide automatic load balancing
   - Configure health checks for failover

3. **Monitor Resource Usage**
   - Set appropriate `max_sessions` and `max_objects` for mock backend
   - Monitor memory usage in production

### Development Best Practices

1. **Use Mock Backend for Development**
   ```yaml
   backend:
     type: "mock"
   mock:
     deterministic: true
     verbose_logging: true
   ```

2. **Enable Comprehensive Logging**
   ```bash
   export RUST_LOG=debug
   ```

3. **Use Error Injection for Testing**
   ```yaml
   mock:
     error_injection:
       enabled: true
       probability: 0.05
   ```

## Troubleshooting

### Common Configuration Issues

#### 1. Configuration File Not Found

**Error**: `Failed to load configuration file`

**Solutions**:
- Check file exists in expected locations
- Set `P11NETHSM_CONFIG_FILE` environment variable
- Verify file permissions

#### 2. Invalid YAML Syntax

**Error**: `Failed to parse configuration`

**Solutions**:
- Validate YAML syntax
- Check indentation (use spaces, not tabs)
- Verify quotes around strings with special characters

#### 3. NetHSM Connection Failed

**Error**: `Failed to connect to NetHSM`

**Solutions**:
- Verify URL is correct and accessible
- Check network connectivity
- Validate credentials
- Review certificate configuration

#### 4. Authentication Failed

**Error**: `Authentication failed`

**Solutions**:
- Verify username and password
- Check user permissions on NetHSM
- Ensure user is not locked out

### Debugging Configuration

#### Enable Debug Logging

```bash
export RUST_LOG=debug
```

#### Validate Configuration

```bash
# Test configuration loading
pkcs11-tool --module ./target/release/libpkcs11_impl_nethsm_sdk.so --list-slots
```

#### Check Environment Variables

```bash
env | grep -E "(NETHSM|P11NETHSM|RUST_LOG)"
```

### Configuration Validation

The library provides built-in configuration validation:

```rust
use pkcs11_impl_nethsm_sdk::NetHsmConfig;

let config = NetHsmConfig::load_from_file("p11nethsm.conf")?;
config.validate()?; // Will return detailed validation errors
```

### Migration from Legacy Configuration

See the [Migration Guide](../examples/migration/README.md) for detailed instructions on migrating from the legacy configuration format.

## Advanced Configuration

### Custom Backend Configuration

For custom backend implementations, implement the `BackendConfig` trait:

```rust
use pkcs11_core::backend::{BackendConfig, ConfigError, BackendType};

#[derive(Debug, Clone)]
pub struct CustomConfig {
    // Your configuration fields
}

impl BackendConfig for CustomConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        // Implement validation logic
        Ok(())
    }
    
    fn backend_type(&self) -> BackendType {
        BackendType::Custom("my-backend".to_string())
    }
}
```

### Dynamic Configuration

Configuration can be updated at runtime for certain backends:

```rust
// Example: Update connection timeout
backend.update_config(|config| {
    config.timeout_seconds = 60;
})?;
```

### Configuration Profiles

Use different configuration files for different environments:

```bash
# Development
P11NETHSM_CONFIG_FILE=config/development.yaml

# Testing
P11NETHSM_CONFIG_FILE=config/testing.yaml

# Production
P11NETHSM_CONFIG_FILE=/etc/p11nethsm/production.yaml