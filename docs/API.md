# PKCS#11 API Documentation

This document provides comprehensive API documentation for the modular NetHSM PKCS#11 architecture.

## Table of Contents

- [Overview](#overview)
- [Backend Abstraction Layer](#backend-abstraction-layer)
- [Core Types](#core-types)
- [Backend Implementations](#backend-implementations)
- [Error Handling](#error-handling)
- [Examples](#examples)

## Overview

The modular PKCS#11 architecture provides a clean separation between the PKCS#11 protocol implementation and cryptographic backends. This allows for multiple backend implementations while maintaining a consistent API.

### Architecture Components

```
┌─────────────────────────────────────────────────────────────┐
│                    PKCS#11 C API Layer                     │
├─────────────────────────────────────────────────────────────┤
│                    pkcs11_core Library                     │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │   API Module    │  │  Backend Traits │  │ Common Types│ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                Backend Implementations                      │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │  NetHSM SDK     │  │   Mock Backend  │  │   Custom    │ │
│  │  Implementation │  │                 │  │   Backend   │ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Backend Abstraction Layer

### CryptoBackend Trait

The [`CryptoBackend`](../pkcs11_core/src/backend/mod.rs:54) trait defines the interface that all backend implementations must provide.

```rust
pub trait CryptoBackend: Send + Sync {
    type Config: BackendConfig;
    type Error: Into<BackendError> + Send + Sync;

    // Lifecycle Management
    fn initialize(config: Self::Config) -> Result<Self, Self::Error>
    where
        Self: Sized;
    fn finalize(&mut self) -> Result<(), Self::Error>;
    fn is_initialized(&self) -> bool;

    // Slot and Token Management
    fn get_slot_list(&self, token_present: bool) -> Result<Vec<SlotId>, Self::Error>;
    fn get_slot_info(&self, slot_id: SlotId) -> Result<SlotInfo, Self::Error>;
    fn get_token_info(&self, slot_id: SlotId) -> Result<TokenInfo, Self::Error>;
    
    // Session Management
    fn open_session(&mut self, slot_id: SlotId, flags: SessionFlags) -> Result<SessionHandle, Self::Error>;
    fn close_session(&mut self, session: SessionHandle) -> Result<(), Self::Error>;
    
    // Authentication
    fn login(&mut self, session: SessionHandle, user_type: UserType, pin: &str) -> Result<(), Self::Error>;
    fn logout(&mut self, session: SessionHandle) -> Result<(), Self::Error>;
    
    // Key Management
    fn generate_key(&mut self, session: SessionHandle, spec: &KeyGenerationSpec) -> Result<KeyHandle, Self::Error>;
    fn generate_key_pair(&mut self, session: SessionHandle, spec: &KeyGenerationSpec) -> Result<(KeyHandle, KeyHandle), Self::Error>;
    fn import_key(&mut self, session: SessionHandle, key_data: &KeyImportData) -> Result<KeyHandle, Self::Error>;
    fn delete_key(&mut self, session: SessionHandle, key: KeyHandle) -> Result<(), Self::Error>;
    fn list_keys(&self, session: SessionHandle, filter: Option<&KeyFilter>) -> Result<Vec<KeyInfo>, Self::Error>;
    
    // Cryptographic Operations
    fn sign(&mut self, session: SessionHandle, key: KeyHandle, mechanism: &SignMechanism, data: &[u8]) -> Result<Vec<u8>, Self::Error>;
    fn verify(&mut self, session: SessionHandle, key: KeyHandle, mechanism: &SignMechanism, data: &[u8], signature: &[u8]) -> Result<bool, Self::Error>;
    fn encrypt(&mut self, session: SessionHandle, key: KeyHandle, mechanism: &EncryptMechanism, data: &[u8]) -> Result<Vec<u8>, Self::Error>;
    fn decrypt(&mut self, session: SessionHandle, key: KeyHandle, mechanism: &EncryptMechanism, data: &[u8]) -> Result<Vec<u8>, Self::Error>;
    fn digest(&mut self, session: SessionHandle, mechanism: &MechanismType, data: &[u8]) -> Result<Vec<u8>, Self::Error>;
    fn generate_random(&mut self, session: SessionHandle, length: usize) -> Result<Vec<u8>, Self::Error>;
}
```

### BackendConfig Trait

The [`BackendConfig`](../pkcs11_core/src/backend/types.rs) trait defines configuration requirements for backends:

```rust
pub trait BackendConfig: Clone + Send + Sync + std::fmt::Debug {
    fn validate(&self) -> Result<(), ConfigError>;
    fn backend_type(&self) -> BackendType;
}
```

## Core Types

### Session Types

#### SessionHandle
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionHandle(pub u64);
```

#### SessionFlags
```rust
#[derive(Debug, Clone, Copy)]
pub struct SessionFlags {
    pub rw_session: bool,
    pub serial_session: bool,
}
```

#### SessionState
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    RoPublicSession,
    RoUserSession,
    RwPublicSession,
    RwUserSession,
    RwSoSession,
}
```

### Key Types

#### KeyHandle
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyHandle(pub u64);
```

#### KeyType
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Rsa,
    EcP256,
    EcP384,
    EcP521,
    Ed25519,
    Aes,
    Generic,
}
```

#### KeyInfo
```rust
#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub handle: KeyHandle,
    pub key_type: KeyType,
    pub key_size: u32,
    pub label: Option<String>,
    pub id: Option<Vec<u8>>,
    pub usage: KeyUsage,
}
```

#### KeyUsage
```rust
#[derive(Debug, Clone, Copy)]
pub struct KeyUsage {
    pub sign: bool,
    pub verify: bool,
    pub encrypt: bool,
    pub decrypt: bool,
    pub derive: bool,
    pub extractable: bool,
    pub sensitive: bool,
}
```

#### KeyGenerationSpec
```rust
#[derive(Debug, Clone)]
pub struct KeyGenerationSpec {
    pub key_type: KeyType,
    pub key_size: u32,
    pub label: Option<String>,
    pub id: Option<Vec<u8>>,
    pub usage: KeyUsage,
}
```

#### KeyImportData
```rust
#[derive(Debug, Clone)]
pub struct KeyImportData {
    pub key_type: KeyType,
    pub label: Option<String>,
    pub id: Option<Vec<u8>>,
    pub usage: KeyUsage,
    pub key_material: KeyMaterial,
}
```

#### KeyMaterial
```rust
#[derive(Debug, Clone)]
pub enum KeyMaterial {
    Rsa {
        modulus: Vec<u8>,
        public_exponent: Vec<u8>,
        private_exponent: Option<Vec<u8>>,
    },
    EllipticCurve {
        curve: EcCurve,
        public_point: Vec<u8>,
        private_scalar: Option<Vec<u8>>,
    },
    Symmetric {
        key_data: Vec<u8>,
    },
}
```

### Mechanism Types

#### MechanismType
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MechanismType(pub u32);
```

#### SignMechanism
```rust
#[derive(Debug, Clone)]
pub struct SignMechanism {
    pub mechanism_type: MechanismType,
    pub parameters: Option<Vec<u8>>,
}
```

#### EncryptMechanism
```rust
#[derive(Debug, Clone)]
pub struct EncryptMechanism {
    pub mechanism_type: MechanismType,
    pub parameters: Option<Vec<u8>>,
}
```

### Slot and Token Types

#### SlotId
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SlotId(pub u32);
```

#### SlotInfo
```rust
#[derive(Debug, Clone)]
pub struct SlotInfo {
    pub slot_description: String,
    pub manufacturer_id: String,
    pub flags: SlotFlags,
    pub hardware_version: Version,
    pub firmware_version: Version,
}
```

#### TokenInfo
```rust
#[derive(Debug, Clone)]
pub struct TokenInfo {
    pub label: String,
    pub manufacturer_id: String,
    pub model: String,
    pub serial_number: String,
    pub flags: TokenFlags,
    pub hardware_version: Version,
    pub firmware_version: Version,
}
```

## Backend Implementations

### NetHSM Backend

The [`NetHsmBackend`](../pkcs11_impl_nethsm_sdk/src/backend.rs:28) provides integration with NetHSM devices:

```rust
impl CryptoBackend for NetHsmBackend {
    type Config = NetHsmConfig;
    type Error = NetHsmError;
    
    // Implementation details...
}
```

**Features:**
- Full NetHSM SDK integration
- Support for multiple NetHSM instances
- Hardware-backed cryptographic operations
- Production-ready implementation

### Mock Backend

The [`MockBackend`](../pkcs11_impl_mock/src/backend.rs:17) provides a testing implementation:

```rust
impl CryptoBackend for MockBackend {
    type Config = MockConfig;
    type Error = MockError;
    
    // Implementation details...
}
```

**Features:**
- Deterministic behavior for testing
- Error injection capabilities
- In-memory storage
- Configurable operation delays
- Complete PKCS#11 operation simulation

## Error Handling

### BackendError

The unified [`BackendError`](../pkcs11_core/src/backend/error.rs) type provides consistent error handling:

```rust
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("Authentication failed: {message}")]
    AuthenticationFailed { message: String },
    
    #[error("Key not found: {key_id}")]
    KeyNotFound { key_id: String },
    
    #[error("Mechanism not supported: {mechanism}")]
    MechanismNotSupported { mechanism: String },
    
    #[error("Invalid key specification: {reason}")]
    InvalidKeySpec { reason: String },
    
    #[error("Cryptographic operation failed: {operation}")]
    CryptoOperationFailed { operation: String },
    
    #[error("Configuration error: {reason}")]
    ConfigurationError { reason: String },
    
    #[error("Network error: {reason}")]
    NetworkError { reason: String },
    
    #[error("Permission denied: {operation}")]
    PermissionDenied { operation: String },
    
    #[error("Backend not initialized")]
    NotInitialized,
    
    #[error("Session invalid or expired")]
    InvalidSession,
    
    #[error("Internal backend error: {reason}")]
    InternalError { reason: String },
}
```

### Error Conversion

Backend errors are automatically converted to PKCS#11 return codes:

```rust
impl From<BackendError> for cryptoki_sys::CK_RV {
    fn from(err: BackendError) -> Self {
        match err {
            BackendError::AuthenticationFailed { .. } => cryptoki_sys::CKR_USER_NOT_LOGGED_IN,
            BackendError::KeyNotFound { .. } => cryptoki_sys::CKR_KEY_HANDLE_INVALID,
            BackendError::MechanismNotSupported { .. } => cryptoki_sys::CKR_MECHANISM_INVALID,
            BackendError::InvalidKeySpec { .. } => cryptoki_sys::CKR_ATTRIBUTE_VALUE_INVALID,
            BackendError::CryptoOperationFailed { .. } => cryptoki_sys::CKR_FUNCTION_FAILED,
            BackendError::ConfigurationError { .. } => cryptoki_sys::CKR_GENERAL_ERROR,
            BackendError::NetworkError { .. } => cryptoki_sys::CKR_DEVICE_ERROR,
            BackendError::PermissionDenied { .. } => cryptoki_sys::CKR_USER_NOT_LOGGED_IN,
            BackendError::NotInitialized => cryptoki_sys::CKR_CRYPTOKI_NOT_INITIALIZED,
            BackendError::InvalidSession => cryptoki_sys::CKR_SESSION_HANDLE_INVALID,
            BackendError::InternalError { .. } => cryptoki_sys::CKR_GENERAL_ERROR,
        }
    }
}
```

## Examples

### Basic Backend Usage

```rust
use pkcs11_core::backend::{CryptoBackend, types::*};
use pkcs11_impl_mock::{MockBackend, MockConfig};

// Initialize backend
let config = MockConfig::new()
    .with_deterministic(true)
    .with_token_label("Test Token");

let mut backend = MockBackend::initialize(config)?;

// Get available slots
let slots = backend.get_slot_list(true)?;
let slot_id = slots[0];

// Open a session
let session_flags = SessionFlags {
    rw_session: true,
    serial_session: true,
};
let session = backend.open_session(slot_id, session_flags)?;

// Login
backend.login(session, UserType::User, "123456")?;

// Generate a key
let key_spec = KeyGenerationSpec {
    key_type: KeyType::Rsa,
    key_size: 2048,
    label: Some("test-key".to_string()),
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

// Sign data
let mechanism = SignMechanism {
    mechanism_type: MechanismType(cryptoki_sys::CKM_RSA_PKCS as u32),
    parameters: None,
};

let data = b"Hello, World!";
let signature = backend.sign(session, key_handle, &mechanism, data)?;

// Verify signature
let is_valid = backend.verify(session, key_handle, &mechanism, data, &signature)?;
assert!(is_valid);

// Cleanup
backend.logout(session)?;
backend.close_session(session)?;
backend.finalize()?;
```

### Custom Backend Implementation

```rust
use pkcs11_core::backend::{CryptoBackend, BackendConfig, types::*};

#[derive(Debug, Clone)]
pub struct CustomConfig {
    // Your configuration fields
}

impl BackendConfig for CustomConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        // Validate configuration
        Ok(())
    }
    
    fn backend_type(&self) -> BackendType {
        BackendType::Custom("my-backend".to_string())
    }
}

pub struct CustomBackend {
    // Your backend state
}

impl CryptoBackend for CustomBackend {
    type Config = CustomConfig;
    type Error = CustomError; // Your error type

    fn initialize(config: Self::Config) -> Result<Self, Self::Error> {
        // Initialize your backend
        Ok(CustomBackend {
            // Initialize fields
        })
    }

    fn finalize(&mut self) -> Result<(), Self::Error> {
        // Cleanup resources
        Ok(())
    }

    fn is_initialized(&self) -> bool {
        // Return initialization state
        true
    }

    // Implement all other required methods...
}
```

## PKCS#11 C API Compatibility

The modular architecture maintains full PKCS#11 C API compatibility. All standard PKCS#11 functions are supported:

### Initialization Functions
- `C_Initialize`
- `C_Finalize`
- `C_GetInfo`
- `C_GetFunctionList`

### Slot and Token Functions
- `C_GetSlotList`
- `C_GetSlotInfo`
- `C_GetTokenInfo`
- `C_GetMechanismList`
- `C_GetMechanismInfo`

### Session Functions
- `C_OpenSession`
- `C_CloseSession`
- `C_CloseAllSessions`
- `C_GetSessionInfo`
- `C_Login`
- `C_Logout`

### Object Functions
- `C_CreateObject`
- `C_DestroyObject`
- `C_FindObjectsInit`
- `C_FindObjects`
- `C_FindObjectsFinal`
- `C_GetAttributeValue`
- `C_SetAttributeValue`

### Key Management Functions
- `C_GenerateKey`
- `C_GenerateKeyPair`
- `C_WrapKey`
- `C_UnwrapKey`
- `C_DeriveKey`

### Cryptographic Functions
- `C_EncryptInit` / `C_Encrypt`
- `C_DecryptInit` / `C_Decrypt`
- `C_DigestInit` / `C_Digest`
- `C_SignInit` / `C_Sign`
- `C_VerifyInit` / `C_Verify`
- `C_GenerateRandom`

### Multi-part Operations
- `C_EncryptUpdate` / `C_EncryptFinal`
- `C_DecryptUpdate` / `C_DecryptFinal`
- `C_DigestUpdate` / `C_DigestFinal`
- `C_SignUpdate` / `C_SignFinal`
- `C_VerifyUpdate` / `C_VerifyFinal`

## Thread Safety

The backend abstraction layer is designed to be thread-safe:

- All backend implementations must implement `Send + Sync`
- The [`ThreadSafeBackend`](../pkcs11_core/src/backend/mod.rs:239) wrapper provides additional safety
- Session management is handled safely across threads
- Error handling is thread-safe

## Performance Considerations

- Backend operations are designed to be efficient
- Async operations can be wrapped for sync compatibility
- Connection pooling and caching can be implemented in backends
- Error paths are optimized for minimal overhead

## Migration Guide

See [Migration Guide](../examples/migration/README.md) for detailed information on migrating from the monolithic implementation to the modular architecture.