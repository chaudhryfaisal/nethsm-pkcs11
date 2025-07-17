# Migration Guide

This guide provides comprehensive instructions for migrating from the monolithic NetHSM PKCS#11 implementation to the new modular architecture.

## Overview

The modular architecture provides several benefits over the monolithic implementation:

- **Better testability** with mock backends
- **Easier maintenance** with clear separation of concerns
- **Extensibility** for custom backends
- **Improved error handling** with unified error types
- **Enhanced configuration** with validation and environment variable support

## Migration Checklist

- [ ] [Assess current deployment](#assessment)
- [ ] [Update configuration files](#configuration-migration)
- [ ] [Update application code](#code-migration)
- [ ] [Migrate test suites](#testing-migration)
- [ ] [Update deployment scripts](#deployment-migration)
- [ ] [Validate functionality](#validation)
- [ ] [Monitor performance](#performance-monitoring)

## Assessment

### Current Implementation Analysis

First, analyze your current implementation to understand what needs to be migrated:

```bash
# Check current library version
strings /path/to/current/libnethsm_pkcs11.so | grep -i version

# List current configuration files
find /etc -name "*nethsm*" -o -name "*pkcs11*" 2>/dev/null

# Check application dependencies
ldd /path/to/your/application | grep pkcs11
```

### Compatibility Matrix

| Feature | Monolithic | Modular | Migration Required |
|---------|------------|---------|-------------------|
| Basic PKCS#11 operations | ✓ | ✓ | No |
| NetHSM integration | ✓ | ✓ | Configuration only |
| Configuration format | YAML | YAML | Minor updates |
| Environment variables | Limited | Full | Optional |
| Error handling | Basic | Enhanced | Code updates recommended |
| Testing support | Limited | Full | Test migration recommended |
| Custom backends | ✗ | ✓ | New feature |

## Configuration Migration

### Old Configuration Format

```yaml
# Old format (still supported)
slots:
  - label: "NetHSM-1"
    instances:
      - url: "https://nethsm.example.com/api/v1"
        danger_insecure_cert: false
    operator:
      username: "operator"
      password: "opPassphrase"
    administrator:
      username: "admin"
      password: "adminPassphrase"

enable_set_attribute_value: false
```

### New Configuration Format

```yaml
# New format (recommended)
backend:
  type: "nethsm"  # Explicit backend selection

# Global settings
enable_set_attribute_value: false
log_level: "info"

# NetHSM-specific configuration
slots:
  - label: "NetHSM-1"
    description: "Primary NetHSM Device"
    instances:
      - url: "https://nethsm.example.com/api/v1"
        danger_insecure_cert: false
        sha256_fingerprints:
          - "31:92:8E:A4:5E:16:5C:A7:33:44:E8:E9:8E:64:C4:AE:7B:2A:57:E5:77:43:49:F3:69:C9:8F:C4:2F:3A:3B:6E"
    
    operator:
      username: "operator"
      password: "${NETHSM_OPERATOR_PASS}"  # Environment variable support
    
    administrator:
      username: "admin"
      password: "${NETHSM_ADMIN_PASS}"
    
    # Enhanced connection settings
    retries:
      count: 3
      delay_seconds: 1
    timeout_seconds: 30
    certificate_format: "DER"
```

### Migration Script

```bash
#!/bin/bash
# migrate_config.sh - Configuration migration script

set -e

OLD_CONFIG="${1:-/etc/p11nethsm.conf}"
NEW_CONFIG="${2:-/etc/p11nethsm/p11nethsm.conf}"

if [ ! -f "$OLD_CONFIG" ]; then
    echo "Error: Old configuration file not found: $OLD_CONFIG"
    exit 1
fi

echo "Migrating configuration from $OLD_CONFIG to $NEW_CONFIG"

# Create backup
cp "$OLD_CONFIG" "${OLD_CONFIG}.backup.$(date +%Y%m%d_%H%M%S)"

# Create new configuration directory
mkdir -p "$(dirname "$NEW_CONFIG")"

# Add backend type if not present
if ! grep -q "^backend:" "$OLD_CONFIG"; then
    echo "backend:" > "$NEW_CONFIG"
    echo "  type: \"nethsm\"" >> "$NEW_CONFIG"
    echo "" >> "$NEW_CONFIG"
fi

# Copy existing configuration
cat "$OLD_CONFIG" >> "$NEW_CONFIG"

echo "Configuration migrated successfully"
echo "Please review and update: $NEW_CONFIG"
echo "Backup saved as: ${OLD_CONFIG}.backup.*"
```

### Configuration Validation

```bash
# Validate new configuration
cargo run --example validate_config -- --config /etc/p11nethsm/p11nethsm.conf

# Test configuration loading
P11NETHSM_CONFIG_FILE=/etc/p11nethsm/p11nethsm.conf \
  pkcs11-tool --module ./target/release/libpkcs11_impl_nethsm_sdk.so --list-slots
```

## Code Migration

### Application Code Changes

Most applications won't require code changes, but some improvements are recommended:

#### Error Handling

**Old approach:**
```c
// Basic error checking
CK_RV rv = C_Initialize(NULL);
if (rv != CKR_OK) {
    printf("Initialization failed: %lu\n", rv);
    return -1;
}
```

**New approach:**
```c
// Enhanced error handling with detailed messages
CK_RV rv = C_Initialize(NULL);
if (rv != CKR_OK) {
    switch (rv) {
        case CKR_CRYPTOKI_NOT_INITIALIZED:
            printf("PKCS#11 library not initialized\n");
            break;
        case CKR_DEVICE_ERROR:
            printf("Device communication error - check NetHSM connectivity\n");
            break;
        case CKR_GENERAL_ERROR:
            printf("General error - check configuration and logs\n");
            break;
        default:
            printf("Initialization failed with error: %lu\n", rv);
    }
    return -1;
}
```

#### Library Loading

**Old approach:**
```c
// Direct library loading
void *lib = dlopen("libnethsm_pkcs11.so", RTLD_LAZY);
```

**New approach:**
```c
// Backend-specific library loading
const char *backend = getenv("PKCS11_BACKEND");
char lib_name[256];

if (backend && strcmp(backend, "mock") == 0) {
    snprintf(lib_name, sizeof(lib_name), "libpkcs11_impl_mock.so");
} else {
    snprintf(lib_name, sizeof(lib_name), "libpkcs11_impl_nethsm_sdk.so");
}

void *lib = dlopen(lib_name, RTLD_LAZY);
```

### Rust Application Migration

**Old approach:**
```rust
// Direct NetHSM usage
use nethsm_pkcs11::*;

let mut context = initialize_context()?;
```

**New approach:**
```rust
// Backend abstraction usage
use pkcs11_core::backend::{CryptoBackend, registry};
use pkcs11_impl_nethsm_sdk::{NetHsmBackend, NetHsmConfig};

let config = NetHsmConfig::load_from_file("p11nethsm.conf")?;
let mut backend = NetHsmBackend::initialize(config)?;
```

## Testing Migration

### Unit Test Migration

**Old test structure:**
```rust
#[cfg(test)]
mod tests {
    use nethsm_pkcs11::*;
    
    #[test]
    fn test_key_generation() {
        // Direct NetHSM testing (requires hardware)
        let context = initialize_context().unwrap();
        // ... test implementation
    }
}
```

**New test structure:**
```rust
#[cfg(test)]
mod tests {
    use pkcs11_core::backend::CryptoBackend;
    use pkcs11_impl_mock::{MockBackend, MockConfig};
    
    #[test]
    fn test_key_generation() {
        // Mock backend testing (no hardware required)
        let config = MockConfig::new().with_deterministic(true);
        let mut backend = MockBackend::initialize(config).unwrap();
        
        // ... test implementation
    }
    
    #[test]
    #[ignore] // Run only with actual NetHSM
    fn test_key_generation_nethsm() {
        // NetHSM integration test
        let config = NetHsmConfig::load_from_env().unwrap();
        let mut backend = NetHsmBackend::initialize(config).unwrap();
        
        // ... test implementation
    }
}
```

### CI/CD Pipeline Migration

**Old CI configuration:**
```yaml
# .github/workflows/test.yml (old)
name: Test
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run tests
        run: |
          # Tests require NetHSM instance
          docker run -d --name nethsm nethsm:latest
          cargo test
```

**New CI configuration:**
```yaml
# .github/workflows/test.yml (new)
name: Test
on: [push, pull_request]

jobs:
  test-mock:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run mock tests
        run: |
          # Fast tests with mock backend
          cargo test --package pkcs11_impl_mock
          cargo test --features mock-backend
  
  test-integration:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Setup NetHSM
        run: |
          docker run -d --name nethsm -p 8443:8443 nethsm:latest
          # Wait for NetHSM to be ready
          sleep 30
      - name: Run integration tests
        env:
          NETHSM_URL: https://localhost:8443/api/v1
          NETHSM_OPERATOR_PASS: opPassphrase
        run: |
          cargo test --package pkcs11_impl_nethsm_sdk
```

## Deployment Migration

### Library Replacement

```bash
#!/bin/bash
# deploy_new_library.sh - Library deployment script

set -e

OLD_LIB="/usr/lib/libnethsm_pkcs11.so"
NEW_LIB="/usr/lib/libpkcs11_impl_nethsm_sdk.so"
BACKUP_DIR="/usr/lib/pkcs11-backup"

echo "Deploying new modular PKCS#11 library"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup old library
if [ -f "$OLD_LIB" ]; then
    echo "Backing up old library..."
    cp "$OLD_LIB" "$BACKUP_DIR/libnethsm_pkcs11.so.$(date +%Y%m%d_%H%M%S)"
fi

# Install new library
echo "Installing new library..."
cp "$NEW_LIB" "$OLD_LIB"

# Update library cache
ldconfig

# Verify installation
echo "Verifying installation..."
if ldd "$OLD_LIB" | grep -q "not found"; then
    echo "Error: Missing dependencies"
    exit 1
fi

echo "Library deployment completed successfully"
```

### Service Configuration Update

**Old systemd service:**
```ini
# /etc/systemd/system/myapp.service (old)
[Unit]
Description=My PKCS#11 Application
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/myapp
Environment=PKCS11_MODULE=/usr/lib/libnethsm_pkcs11.so

[Install]
WantedBy=multi-user.target
```

**New systemd service:**
```ini
# /etc/systemd/system/myapp.service (new)
[Unit]
Description=My PKCS#11 Application
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/myapp
Environment=PKCS11_MODULE=/usr/lib/libpkcs11_impl_nethsm_sdk.so
Environment=P11NETHSM_CONFIG_FILE=/etc/p11nethsm/p11nethsm.conf
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
```

### Docker Migration

**Old Dockerfile:**
```dockerfile
FROM debian:bookworm-slim
COPY libnethsm_pkcs11.so /usr/lib/
COPY p11nethsm.conf /etc/
CMD ["/usr/bin/myapp"]
```

**New Dockerfile:**
```dockerfile
FROM debian:bookworm-slim
COPY libpkcs11_impl_nethsm_sdk.so /usr/lib/
COPY p11nethsm.conf /etc/p11nethsm/
ENV P11NETHSM_CONFIG_FILE=/etc/p11nethsm/p11nethsm.conf
ENV RUST_LOG=info
CMD ["/usr/bin/myapp"]
```

## Validation

### Functional Testing

```bash
#!/bin/bash
# validate_migration.sh - Migration validation script

set -e

CONFIG_FILE="${P11NETHSM_CONFIG_FILE:-/etc/p11nethsm/p11nethsm.conf}"
MODULE_PATH="${PKCS11_MODULE:-/usr/lib/libpkcs11_impl_nethsm_sdk.so}"

echo "Validating PKCS#11 migration..."

# Test 1: Library loading
echo "1. Testing library loading..."
if ! pkcs11-tool --module "$MODULE_PATH" --list-slots >/dev/null 2>&1; then
    echo "   ✗ Failed to load library"
    exit 1
fi
echo "   ✓ Library loaded successfully"

# Test 2: Configuration loading
echo "2. Testing configuration..."
if ! pkcs11-tool --module "$MODULE_PATH" --list-slots | grep -q "NetHSM"; then
    echo "   ✗ Configuration not loaded correctly"
    exit 1
fi
echo "   ✓ Configuration loaded successfully"

# Test 3: Basic operations
echo "3. Testing basic operations..."
if ! pkcs11-tool --module "$MODULE_PATH" --list-mechanisms >/dev/null 2>&1; then
    echo "   ✗ Failed to list mechanisms"
    exit 1
fi
echo "   ✓ Basic operations working"

# Test 4: Authentication
echo "4. Testing authentication..."
if ! pkcs11-tool --module "$MODULE_PATH" --login --pin 123456 --list-objects >/dev/null 2>&1; then
    echo "   ✗ Authentication failed"
    exit 1
fi
echo "   ✓ Authentication working"

echo "Migration validation completed successfully!"
```

### Performance Comparison

```bash
#!/bin/bash
# performance_comparison.sh - Compare old vs new performance

echo "Performance comparison: Old vs New implementation"

# Benchmark old implementation
echo "Benchmarking old implementation..."
OLD_TIME=$(time pkcs11-tool --module /usr/lib/libnethsm_pkcs11.so.backup \
  --keygen --key-type rsa:2048 --label test-old 2>&1 | grep real | awk '{print $2}')

# Benchmark new implementation
echo "Benchmarking new implementation..."
NEW_TIME=$(time pkcs11-tool --module /usr/lib/libpkcs11_impl_nethsm_sdk.so \
  --keygen --key-type rsa:2048 --label test-new 2>&1 | grep real | awk '{print $2}')

echo "Results:"
echo "  Old implementation: $OLD_TIME"
echo "  New implementation: $NEW_TIME"

# Clean up test keys
pkcs11-tool --module /usr/lib/libpkcs11_impl_nethsm_sdk.so \
  --delete-object --type privkey --label test-old 2>/dev/null || true
pkcs11-tool --module /usr/lib/libpkcs11_impl_nethsm_sdk.so \
  --delete-object --type privkey --label test-new 2>/dev/null || true
```

## Performance Monitoring

### Metrics Collection

```bash
# Monitor key performance indicators
watch -n 5 'echo "=== PKCS#11 Performance Metrics ===" && \
  pkcs11-tool --module /usr/lib/libpkcs11_impl_nethsm_sdk.so --list-slots && \
  echo "Memory usage:" && \
  ps aux | grep myapp | grep -v grep && \
  echo "Network connections:" && \
  netstat -an | grep :8443'
```

### Logging Configuration

```yaml
# Enhanced logging configuration
backend:
  type: "nethsm"

# Global logging settings
log_level: "info"  # trace, debug, info, warn, error

slots:
  - label: "NetHSM-1"
    # ... other configuration
    
    # Per-slot logging
    logging:
      level: "debug"
      operations: true
      performance: true
      errors: true
```

## Rollback Plan

### Emergency Rollback

```bash
#!/bin/bash
# rollback.sh - Emergency rollback script

set -e

BACKUP_DIR="/usr/lib/pkcs11-backup"
CURRENT_LIB="/usr/lib/libpkcs11_impl_nethsm_sdk.so"
OLD_LIB="/usr/lib/libnethsm_pkcs11.so"

echo "Performing emergency rollback..."

# Find latest backup
BACKUP_FILE=$(ls -t "$BACKUP_DIR"/libnethsm_pkcs11.so.* | head -1)

if [ -z "$BACKUP_FILE" ]; then
    echo "Error: No backup found"
    exit 1
fi

echo "Restoring from backup: $BACKUP_FILE"

# Stop services
systemctl stop myapp

# Restore old library
cp "$BACKUP_FILE" "$OLD_LIB"

# Remove new library
rm -f "$CURRENT_LIB"

# Update library cache
ldconfig

# Restart services
systemctl start myapp

echo "Rollback completed successfully"
```

## Troubleshooting

### Common Issues

#### 1. Configuration Not Found

**Error:** `Failed to load configuration file`

**Solution:**
```bash
# Check configuration file location
export P11NETHSM_CONFIG_FILE=/etc/p11nethsm/p11nethsm.conf

# Verify file exists and is readable
ls -la /etc/p11nethsm/p11nethsm.conf
```

#### 2. Library Loading Failed

**Error:** `cannot open shared object file`

**Solution:**
```bash
# Check library dependencies
ldd /usr/lib/libpkcs11_impl_nethsm_sdk.so

# Update library cache
sudo ldconfig

# Check library path
export LD_LIBRARY_PATH=/usr/lib:$LD_LIBRARY_PATH
```

#### 3. NetHSM Connection Failed

**Error:** `Device communication error`

**Solution:**
```bash
# Test NetHSM connectivity
curl -k https://nethsm.example.com/api/v1/health

# Check configuration
grep -A 10 "instances:" /etc/p11nethsm/p11nethsm.conf

# Verify credentials
export NETHSM_OPERATOR_PASS=your_password
```

### Debug Mode

```bash
# Enable debug logging
export RUST_LOG=debug

# Run with verbose output
pkcs11-tool --module /usr/lib/libpkcs11_impl_nethsm_sdk.so \
  --list-slots --verbose

# Check system logs
journalctl -u myapp -f
```

## Support and Resources

- **Documentation**: [docs/](../../docs/)
- **Examples**: [examples/](../)
- **Issues**: [GitHub Issues](https://github.com/Nitrokey/nethsm-pkcs11/issues)
- **Community**: [Nitrokey Community](https://community.nitrokey.com/)

For additional help with migration, please consult the [Development Guide](../../docs/DEVELOPMENT.md) or open an issue on GitHub.