# NetHSM SDK PKCS#11 Implementation

This crate provides a concrete PKCS#11 implementation using the NetHSM SDK for communication with NetHSM devices.

## Overview

The `pkcs11_impl_nethsm_sdk` crate implements the PKCS#11 interface by:

- Using the NetHSM SDK (`nethsm-sdk-rs`) for backend communication
- Delegating to the `pkcs11_core` library for PKCS#11 protocol handling
- Providing the C API exports required for PKCS#11 compliance

## Features

- Full PKCS#11 C API compatibility
- NetHSM device integration via SDK
- Support for all NetHSM cryptographic operations:
  - RSA signing and encryption (PKCS#1, PSS, OAEP)
  - ECDSA signing
  - EdDSA signing
  - AES encryption/decryption
  - Key generation and management
  - Certificate management

## Configuration

This implementation uses the same configuration format as the original NetHSM PKCS#11 driver, ensuring backward compatibility.

Example configuration:
```yaml
slots:
  - label: "NetHSM-1"
    description: "Primary NetHSM"
    instances:
      - url: "https://nethsm.example.com/api/v1"
        danger_insecure_cert: false
    operator:
      username: "operator"
      password: "opPassphrase"
    administrator:
      username: "admin"
      password: "adminPassphrase"
```

## Building

This crate produces a `cdylib` that can be used as a PKCS#11 provider library.

```bash
cargo build --release --package pkcs11_impl_nethsm_sdk
```

The resulting library can be found at `target/release/libpkcs11_impl_nethsm_sdk.so` (Linux) or equivalent on other platforms.

## Usage

Load this library as a PKCS#11 provider in your application. The library exports the standard PKCS#11 C API functions.

## Development Status

This implementation is currently in development as part of the modular architecture refactoring. Currently, it delegates all functionality to the `pkcs11_core` library. During the refactoring process:

1. NetHSM-specific logic will be migrated from `pkcs11_core`
2. Backend abstraction interfaces will be implemented
3. Direct NetHSM SDK integration will be added
4. The implementation will become fully independent

## Backward Compatibility

This implementation maintains full backward compatibility with existing NetHSM PKCS#11 configurations and applications.