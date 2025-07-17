# PKCS#11 Core Library

This is the core PKCS#11 library that provides the foundational types, traits, and functionality for the modular NetHSM PKCS#11 architecture.

## Overview

The `pkcs11_core` crate contains:

- Core PKCS#11 types and constants
- Backend abstraction traits (to be added during refactoring)
- Common utilities and error handling
- PKCS#11 protocol implementation logic

This crate serves as the foundation for concrete PKCS#11 implementations and is designed to be backend-agnostic.

## Architecture

The core library is organized into several modules:

- `api/` - PKCS#11 C API implementations
- `backend/` - Core business logic and backend integration
- `config/` - Configuration management
- `data.rs` - Global state management
- `defs.rs` - Constants and definitions
- `lib.rs` - Library entry point
- `utils.rs` - Utility functions

## Usage

This crate is not intended to be used directly as a PKCS#11 provider. Instead, use one of the concrete implementations:

- `pkcs11_impl_nethsm_sdk` - NetHSM SDK-based implementation
- `pkcs11_impl_mock` - Mock implementation for testing

## Development

This crate is part of the modular PKCS#11 architecture refactoring. During the refactoring process, backend-specific logic will be moved to separate implementation crates while keeping the core PKCS#11 protocol logic here.

## Migration Status

Currently, this crate contains the existing NetHSM PKCS#11 implementation. During the refactoring:

1. Backend-specific logic will be extracted to implementation crates
2. Core PKCS#11 protocol handling will remain here
3. Backend abstraction traits will be added
4. The crate type will change from `cdylib` to `lib`