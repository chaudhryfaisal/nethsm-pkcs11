# NetHSM PKCS#11 Backend Abstraction Layer - Architectural Design

## Executive Summary

This document outlines the architectural design for refactoring the current NetHSM PKCS#11 implementation to support a modular backend abstraction layer. The goal is to create a generic interface that can support multiple cryptographic backends while maintaining the existing NetHSM functionality.

## Current Architecture Analysis

### 1. Project Structure Overview

The current implementation is organized as follows:

```
pkcs11/src/
├── api/                    # PKCS#11 C API implementations
├── backend/                # Core business logic and NetHSM integration
├── config/                 # Configuration management
├── data.rs                 # Global state management
├── defs.rs                 # Constants and definitions
├── lib.rs                  # Library entry point
├── ureq/                   # HTTP client customizations
└── utils.rs                # Utility functions
```

### 2. Current Component Analysis

#### 2.1 API Layer (`pkcs11/src/api/`)
**Purpose**: PKCS#11 C API compliance layer
**Components**:
- `mod.rs` - Core PKCS#11 functions (C_Initialize, C_Finalize, C_GetInfo)
- `decrypt.rs` - Decryption operations (C_DecryptInit, C_Decrypt, etc.)
- `digest.rs` - Digest operations (C_DigestInit, C_Digest, etc.)
- `encrypt.rs` - Encryption operations (C_EncryptInit, C_Encrypt, etc.)
- `generation.rs` - Key generation (C_GenerateKey, C_GenerateKeyPair)
- `object.rs` - Object management (C_CreateObject, C_FindObjects, etc.)
- `pin.rs` - PIN management (C_InitPIN, C_SetPIN)
- `session.rs` - Session management (C_OpenSession, C_CloseSession, etc.)
- `sign.rs` - Signing operations (C_SignInit, C_Sign, etc.)
- `token.rs` - Token operations (C_GetSlotList, C_GetTokenInfo, etc.)
- `verify.rs` - Verification operations (C_VerifyInit, C_Verify, etc.)

**Classification**: PKCS#11-specific (should remain unchanged)

#### 2.2 Backend Layer (`pkcs11/src/backend/`)
**Purpose**: Core cryptographic operations and NetHSM integration
**Components**:
- `mod.rs` - Error handling and common types
- `decrypt.rs` - Decryption context and operations
- `encrypt.rs` - Encryption context and operations  
- `events.rs` - Event management and slot state
- `key.rs` - Key management and NetHSM key operations
- `login.rs` - Authentication and user management
- `mechanism.rs` - Cryptographic mechanism handling
- `object.rs` - Object enumeration and requirements
- `session.rs` - Session state management
- `sign.rs` - Signing context and operations
- `slot.rs` - Slot management

**Classification**: Mixed (needs separation into PKCS#11-specific and backend-specific)

#### 2.3 Database Layer (`pkcs11/src/backend/db/`)
**Purpose**: Object storage and attribute management
**Components**:
- `mod.rs` - Database interface and object storage
- `attr.rs` - PKCS#11 attribute handling
- `object.rs` - Object creation and attribute mapping

**Classification**: PKCS#11-specific with some backend-agnostic elements

### 3. Key Dependencies and Integrations

#### 3.1 NetHSM SDK Integration
- **Location**: Throughout `backend/` modules
- **Usage**: Direct API calls via `nethsm_sdk_rs::apis::default_api`
- **Operations**: Key management, cryptographic operations, authentication
- **Abstraction Level**: Low (direct SDK calls)

#### 3.2 Cryptographic Operations
Current operations directly integrated with NetHSM:
- **Signing**: RSA PKCS#1, RSA PSS, ECDSA, EdDSA
- **Encryption/Decryption**: RSA PKCS#1, RSA OAEP, AES-CBC
- **Key Generation**: RSA, EC, Ed25519, AES
- **Digest**: MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512

#### 3.3 Session and State Management
- **Session Manager**: Global session storage and lifecycle
- **Login Context**: User authentication and authorization
- **Object Database**: In-memory object cache with NetHSM synchronization

### 4. Component Classification Analysis

#### 4.1 PKCS#11-Specific Components
These components handle PKCS#11 protocol specifics and should remain unchanged:
- **API Layer**: All C API implementations
- **Attribute Handling**: PKCS#11 attribute templates and validation
- **Object Database**: PKCS#11 object storage and handle management
- **Mechanism Mapping**: PKCS#11 mechanism type conversions
- **Session Management**: PKCS#11 session state and lifecycle

#### 4.2 Backend-Specific Components
These components contain NetHSM-specific logic and need abstraction:
- **Authentication**: NetHSM user login and credential management
- **Key Operations**: NetHSM key creation, import, and management
- **Cryptographic Operations**: Direct NetHSM API calls for crypto operations
- **Network Communication**: HTTP client configuration and retry logic
- **Error Handling**: NetHSM-specific error codes and responses

#### 4.3 Mixed Components (Require Refactoring)
These components contain both PKCS#11 and backend logic:
- **Session Context**: Contains both PKCS#11 session state and NetHSM login context
- **Mechanism Handling**: PKCS#11 mechanism parsing + NetHSM mechanism mapping
- **Object Lifecycle**: PKCS#11 object management + NetHSM key synchronization

## Proposed Backend Abstraction Architecture

### 1. Core Design Principles

1. **Separation of Concerns**: Clear distinction between PKCS#11 protocol handling and cryptographic backend operations
2. **Trait-Based Abstraction**: Use Rust traits to define backend interfaces
3. **Async-Ready**: Design for potential async operations (with sync wrappers for C API)
4. **Error Handling**: Unified error types across backends
5. **Configuration-Driven**: Backend selection via configuration
6. **Backward Compatibility**: Maintain existing NetHSM functionality

### 2. Proposed Directory Structure

```
pkcs11/src/
├── api/                    # PKCS#11 C API (unchanged)
│   ├── mod.rs
│   ├── decrypt.rs
│   ├── encrypt.rs
│   ├── sign.rs
│   └── ...
├── core/                   # Core PKCS#11 logic (refactored from backend/)
│   ├── mod.rs
│   ├── session.rs          # PKCS#11 session management
│   ├── object.rs           # PKCS#11 object lifecycle
│   ├── mechanism.rs        # PKCS#11 mechanism handling
│   └── db/                 # PKCS#11 object database
│       ├── mod.rs
│       ├── attr.rs
│       └── object.rs
├── backend/                # Backend abstraction layer
│   ├── mod.rs              # Backend trait definitions
│   ├── error.rs            # Unified error types
│   ├── types.rs            # Common backend types
│   ├── factory.rs          # Backend factory
│   └── nethsm/             # NetHSM implementation
│       ├── mod.rs
│       ├── crypto.rs       # Cryptographic operations
│       ├── key.rs          # Key management
│       ├── auth.rs         # Authentication
│       ├── session.rs      # NetHSM session handling
│       └── config.rs       # NetHSM-specific configuration
├── config/                 # Configuration (enhanced)
│   ├── mod.rs
│   ├── backend.rs          # Backend configuration
│   └── ...
├── data.rs                 # Global state
├── defs.rs                 # Constants
├── lib.rs                  # Library entry point
└── utils.rs                # Utilities
```

### 3. Backend Trait Definitions

#### 3.1 Core Backend Trait

```rust
use async_trait::async_trait;

#[async_trait]
pub trait CryptoBackend: Send + Sync {
    type Config: BackendConfig;
    type Error: Into<crate::backend::error::BackendError>;
    
    // Lifecycle
    async fn initialize(config: Self::Config) -> Result<Self, Self::Error>
    where
        Self: Sized;
    async fn finalize(&mut self) -> Result<(), Self::Error>;
    
    // Authentication
    async fn authenticate(&mut self, credentials: &Credentials) -> Result<BackendSession, Self::Error>;
    async fn logout(&mut self, session: &BackendSession) -> Result<(), Self::Error>;
    
    // Key Management
    async fn generate_key(
        &mut self, 
        session: &BackendSession, 
        spec: &KeyGenerationSpec
    ) -> Result<KeyHandle, Self::Error>;
    
    async fn import_key(
        &mut self, 
        session: &BackendSession, 
        key_data: &KeyImportData
    ) -> Result<KeyHandle, Self::Error>;
    
    async fn delete_key(
        &mut self, 
        session: &BackendSession, 
        handle: &KeyHandle
    ) -> Result<(), Self::Error>;
    
    async fn list_keys(
        &mut self, 
        session: &BackendSession, 
        filter: Option<&KeyFilter>
    ) -> Result<Vec<KeyInfo>, Self::Error>;
    
    async fn get_key_info(
        &mut self, 
        session: &BackendSession, 
        handle: &KeyHandle
    ) -> Result<KeyInfo, Self::Error>;
    
    // Cryptographic Operations
    async fn sign(
        &mut self, 
        session: &BackendSession, 
        key: &KeyHandle, 
        mechanism: &SignMechanism, 
        data: &[u8]
    ) -> Result<Vec<u8>, Self::Error>;
    
    async fn verify(
        &mut self, 
        session: &BackendSession, 
        key: &KeyHandle, 
        mechanism: &SignMechanism, 
        data: &[u8], 
        signature: &[u8]
    ) -> Result<bool, Self::Error>;
    
    async fn encrypt(
        &mut self, 
        session: &BackendSession, 
        key: &KeyHandle, 
        mechanism: &EncryptMechanism, 
        data: &[u8]
    ) -> Result<Vec<u8>, Self::Error>;
    
    async fn decrypt(
        &mut self, 
        session: &BackendSession, 
        key: &KeyHandle, 
        mechanism: &EncryptMechanism, 
        data: &[u8]
    ) -> Result<Vec<u8>, Self::Error>;
    
    // Certificate Management
    async fn import_certificate(
        &mut self, 
        session: &BackendSession, 
        cert_data: &CertificateData
    ) -> Result<CertificateHandle, Self::Error>;
    
    async fn get_certificate(
        &mut self, 
        session: &BackendSession, 
        handle: &CertificateHandle
    ) -> Result<Vec<u8>, Self::Error>;
    
    async fn delete_certificate(
        &mut self, 
        session: &BackendSession, 
        handle: &CertificateHandle
    ) -> Result<(), Self::Error>;
}
```

#### 3.2 Supporting Traits

```rust
pub trait BackendConfig: Clone + Send + Sync + std::fmt::Debug {
    fn validate(&self) -> Result<(), ConfigError>;
    fn backend_type(&self) -> BackendType;
}

#[derive(Debug, Clone, PartialEq)]
pub enum BackendType {
    NetHsm,
    SoftHsm,
    Pkcs11Proxy,
    // Future backends
}
```

### 4. Backend-Agnostic Types

#### 4.1 Core Types

```rust
#[derive(Debug, Clone, PartialEq)]
pub struct KeyHandle {
    pub id: String,
    pub key_type: KeyType,
    pub size: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub handle: KeyHandle,
    pub label: Option<String>,
    pub mechanisms: Vec<MechanismType>,
    pub attributes: KeyAttributes,
}

#[derive(Debug, Clone)]
pub struct KeyAttributes {
    pub extractable: bool,
    pub sensitive: bool,
    pub sign: bool,
    pub verify: bool,
    pub encrypt: bool,
    pub decrypt: bool,
    pub derive: bool,
    pub wrap: bool,
    pub unwrap: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum KeyType {
    Rsa { bits: u32 },
    EcP256,
    EcP384,
    EcP521,
    Ed25519,
    Aes { bits: u32 },
    Generic { bits: u32 },
}

#[derive(Debug, Clone)]
pub struct KeyGenerationSpec {
    pub key_type: KeyType,
    pub label: Option<String>,
    pub mechanisms: Vec<MechanismType>,
    pub attributes: KeyAttributes,
    pub id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct KeyImportData {
    pub key_type: KeyType,
    pub label: Option<String>,
    pub mechanisms: Vec<MechanismType>,
    pub attributes: KeyAttributes,
    pub key_material: KeyMaterial,
    pub id: Option<String>,
}

#[derive(Debug, Clone)]
pub enum KeyMaterial {
    Rsa {
        modulus: Vec<u8>,
        public_exponent: Vec<u8>,
        private_exponent: Option<Vec<u8>>,
        prime1: Option<Vec<u8>>,
        prime2: Option<Vec<u8>>,
    },
    Ec {
        curve: EcCurve,
        public_point: Vec<u8>,
        private_scalar: Option<Vec<u8>>,
    },
    Symmetric {
        key_data: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum EcCurve {
    P256,
    P384,
    P521,
    Ed25519,
}
```

#### 4.2 Mechanism Types

```rust
#[derive(Debug, Clone, PartialEq)]
pub enum MechanismType {
    RsaPkcs,
    RsaPss { hash_alg: HashAlgorithm },
    RsaOaep { hash_alg: HashAlgorithm },
    Ecdsa { hash_alg: Option<HashAlgorithm> },
    EdDsa,
    AesCbc { iv: Option<[u8; 16]> },
    // Key generation mechanisms
    RsaKeyGen,
    EcKeyGen,
    AesKeyGen,
    GenericKeyGen,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HashAlgorithm {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug, Clone)]
pub struct SignMechanism {
    pub mechanism_type: MechanismType,
    pub parameters: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct EncryptMechanism {
    pub mechanism_type: MechanismType,
    pub parameters: Option<Vec<u8>>,
}
```

#### 4.3 Session and Authentication

```rust
#[derive(Debug, Clone)]
pub struct BackendSession {
    pub session_id: String,
    pub user_type: UserType,
    pub authenticated: bool,
}

#[derive(Debug, Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    pub user_type: UserType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum UserType {
    Operator,
    Administrator,
    Guest,
}
```

#### 4.4 Error Handling

```rust
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    
    #[error("Certificate not found: {0}")]
    CertificateNotFound(String),
    
    #[error("Mechanism not supported: {0:?}")]
    MechanismNotSupported(MechanismType),
    
    #[error("Invalid key specification: {0}")]
    InvalidKeySpec(String),
    
    #[error("Invalid key material: {0}")]
    InvalidKeyMaterial(String),
    
    #[error("Cryptographic operation failed: {0}")]
    CryptoOperationFailed(String),
    
    #[error("Backend configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    
    #[error("Backend not initialized")]
    NotInitialized,
    
    #[error("Session invalid or expired")]
    InvalidSession,
    
    #[error("Internal backend error: {0}")]
    InternalError(String),
}

// Conversion to PKCS#11 error codes
impl From<BackendError> for cryptoki_sys::CK_RV {
    fn from(err: BackendError) -> Self {
        match err {
            BackendError::AuthenticationFailed(_) => cryptoki_sys::CKR_USER_NOT_LOGGED_IN,
            BackendError::KeyNotFound(_) => cryptoki_sys::CKR_KEY_HANDLE_INVALID,
            BackendError::CertificateNotFound(_) => cryptoki_sys::CKR_OBJECT_HANDLE_INVALID,
            BackendError::MechanismNotSupported(_) => cryptoki_sys::CKR_MECHANISM_INVALID,
            BackendError::InvalidKeySpec(_) => cryptoki_sys::CKR_ATTRIBUTE_VALUE_INVALID,
            BackendError::InvalidKeyMaterial(_) => cryptoki_sys::CKR_ATTRIBUTE_VALUE_INVALID,
            BackendError::CryptoOperationFailed(_) => cryptoki_sys::CKR_FUNCTION_FAILED,
            BackendError::ConfigurationError(_) => cryptoki_sys::CKR_GENERAL_ERROR,
            BackendError::NetworkError(_) => cryptoki_sys::CKR_DEVICE_ERROR,
            BackendError::PermissionDenied(_) => cryptoki_sys::CKR_USER_NOT_LOGGED_IN,
            BackendError::NotInitialized => cryptoki_sys::CKR_CRYPTOKI_NOT_INITIALIZED,
            BackendError::InvalidSession => cryptoki_sys::CKR_SESSION_HANDLE_INVALID,
            BackendError::InternalError(_) => cryptoki_sys::CKR_GENERAL_ERROR,
        }
    }
}
```

### 5. NetHSM Backend Implementation

#### 5.1 NetHSM Backend Structure

```rust
pub struct NetHsmBackend {
    config: NetHsmConfig,
    slots: Vec<NetHsmSlot>,
    initialized: bool,
}

#[derive(Debug, Clone)]
pub struct NetHsmConfig {
    pub slots: Vec<SlotConfig>,
    pub enable_set_attribute_value: bool,
}

#[derive(Debug, Clone)]
pub struct SlotConfig {
    pub label: String,
    pub instances: Vec<InstanceConfig>,
    pub operator: Option<UserConfig>,
    pub administrator: Option<UserConfig>,
    pub retries: Option<RetryConfig>,
    pub timeout_seconds: Option<u64>,
    pub certificate_format: CertificateFormat,
}

impl BackendConfig for NetHsmConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.slots.is_empty() {
            return Err(ConfigError::InvalidConfig("No slots configured".to_string()));
        }
        
        for slot in &self.slots {
            if slot.instances.is_empty() {
                return Err(ConfigError::InvalidConfig(
                    format!("No instances configured for slot '{}'", slot.label)
                ));
            }
            
            if slot.operator.is_none() && slot.administrator.is_none() {
                return Err(ConfigError::InvalidConfig(
                    format!("No users configured for slot '{}'", slot.label)
                ));
            }
        }
        
        Ok(())
    }
    
    fn backend_type(&self) -> BackendType {
        BackendType::NetHsm
    }
}

impl CryptoBackend for NetHsmBackend {
    type Config = NetHsmConfig;
    type Error = NetHsmError;
    
    async fn initialize(config: Self::Config) -> Result<Self, Self::Error> {
        config.validate().map_err(NetHsmError::Configuration)?;
        
        let mut slots = Vec::new();
        for slot_config in &config.slots {
            let slot = NetHsmSlot::new(slot_config.clone()).await?;
            slots.push(slot);
        }
        
        Ok(NetHsmBackend {
            config,
            slots,
            initialized: true,
        })
    }
    
    // Implementation of other trait methods...
}
```

#### 5.2 Migration Strategy

The NetHSM backend implementation will:

1. **Phase 1 - Wrapper Implementation**: 
   - Create NetHSM backend that wraps existing code
   - Minimal changes to current logic
   - Focus on interface compliance

2. **Phase 2 - Gradual Refactoring**:
   - Move authentication logic from `backend/login.rs`
   - Migrate key management from `backend/key.rs`
   - Extract crypto operations from `backend/sign.rs`, `backend/encrypt.rs`, etc.

3. **Phase 3 - Optimization**:
   - Remove duplicate code
   - Optimize for new architecture
   - Add backend-specific optimizations

### 6. Configuration Enhancement

#### 6.1 Backend Selection Configuration

```yaml
# Enhanced configuration format
backend:
  type: "nethsm"
  
# NetHSM-specific configuration (maintains backward compatibility)
slots:
  - label: "NetHSM-1"
    description: "Primary NetHSM"
    instances:
      - url: "https://nethsm.example.com/api/v1"
        danger_insecure_cert: false
        sha256_fingerprints:
          - "31:92:8E:A4:5E:16:5C:A7:33:44:E8:E9:8E:64:C4:AE:7B:2A:57:E5:77:43:49:F3:69:C9:8F:C4:2F:3A:3B:6E"
    operator:
      username: "operator"
      password: "opPassphrase"
    administrator:
      username: "admin"
      password: "adminPassphrase"
    certificate_format: "DER"
    retries:
      count: 3
      delay_seconds: 1
    timeout_seconds: 30

# Global settings
enable_set_attribute_value: false
```

#### 6.2 Backend Factory

```rust
pub struct BackendFactory;

impl BackendFactory {
    pub async fn create_backend(
        config: &crate::config::Config
    ) -> Result<Box<dyn CryptoBackend<Error = BackendError>>, BackendError> {
        match config.backend_type() {
            BackendType::NetHsm => {
                let nethsm_config = NetHsmConfig::from_config(config)
                    .map_err(|e| BackendError::ConfigurationError(e.to_string()))?;
                let backend = NetHsmBackend::initialize(nethsm_config)
                    .await
                    .map_err(|e| BackendError::InternalError(e.to_string()))?;
                Ok(Box::new(backend))
            }
            _ => Err(BackendError::ConfigurationError(
                format!("Unsupported backend type: {:?}", config.backend_type())
            )),
        }
    }
}
```

### 7. Core Layer Refactoring

#### 7.1 Session Management Integration

```rust
// pkcs11/src/core/session.rs
pub struct SessionManager {
    sessions: HashMap<CK_SESSION_HANDLE, Arc<Mutex<PkcsSession>>>,
    backend: Arc<Mutex<Box<dyn CryptoBackend<Error = BackendError>>>>,
    next_handle: CK_SESSION_HANDLE,
}

pub struct PkcsSession {
    pub handle: CK_SESSION_HANDLE,
    pub slot_id: CK_SLOT_ID,
    pub flags: CK_FLAGS,
    pub backend_session: Option<BackendSession>,
    pub state: SessionState,
    
    // Operation contexts
    pub sign_ctx: Option<SignContext>,
    pub encrypt_ctx: Option<EncryptContext>,
    pub decrypt_ctx: Option<DecryptContext>,
    pub find_ctx: Option<FindContext>,
}

impl SessionManager {
    pub async fn create_session(
        &mut self,
        slot_id: CK_SLOT_ID,
        flags: CK_FLAGS,
    ) -> Result<CK_SESSION_HANDLE, BackendError> {
        let handle = self.next_handle;
        self.next_handle += 1;
        
        let session = PkcsSession {
            handle,
            slot_id,
            flags,
            backend_session: None,
            state: SessionState::Public,
            sign_ctx: None,
            encrypt_ctx: None,
            decrypt_ctx: None,
            find_ctx: None,
        };
        
        self.sessions.insert(handle, Arc::new(Mutex::new(session)));
        Ok(handle)
    }
    
    pub async fn login(
        &mut self,
        session_handle: CK_SESSION_HANDLE,
        user_type: CK_USER_TYPE,
        pin: &str,
    ) -> Result<(), BackendError> {
        let session_arc = self.sessions.get(&session_handle)
            .ok_or(BackendError::InvalidSession)?
            .clone();
        
        let mut session = session_arc.lock().unwrap();
        
        let credentials = Credentials {
            username: self.get_username_for_slot(session.slot_id, user_type)?,
            password: pin.to_string(),
            user_type: self.convert_user_type(user_type)?,
        };
        
        let backend_session = self.backend.lock().unwrap()
            .authenticate(&credentials).await?;
        
        session.backend_session = Some(backend_session);
        session.state = match user_type {
            cryptoki_sys::CKU_USER => SessionState::UserLoggedIn,
            cryptoki_sys::CKU_SO => SessionState::AdminLoggedIn,
            _ => return Err(BackendError::InvalidKeySpec("Invalid user type".to_string())),
        };
        
        Ok(())
    }
}
```

#### 7.2 Object Lifecycle Integration

```rust
// pkcs11/src/core/object.rs
pub struct ObjectManager {
    backend: Arc<Mutex<Box<dyn CryptoBackend<Error = BackendError>>>>,
    object_db: Arc<Mutex<ObjectDatabase>>,
}

impl ObjectManager {
    pub async fn create_object(
        &mut self,
        session: &PkcsSession,
        template: &CkRawAttrTemplate,
    ) -> Result<CK_OBJECT_HANDLE, BackendError> {
        let backend_session = session.backend_session.as_ref()
            .ok_or(BackendError::InvalidSession)?;
        
        let object_spec = self.parse_creation_template(template)?;
        
        match object_spec.object_class {
            ObjectClass::PrivateKey | ObjectClass::SecretKey => {
                let key_spec = KeyGenerationSpec::from_template(template)?;
                let key_handle = self.backend.lock().unwrap()
                    .generate_key(backend_session, &key_spec).await?;
                
                let pkcs_object = PkcsObject::from_key_handle(key_handle, template)?;
                let handle = self.object_db.lock().unwrap().add_object(pkcs_object);
                Ok(handle)
            }
            ObjectClass::Certificate => {
                let cert_data = CertificateData::from_template(template)?;
                let cert_handle = self.backend.lock().unwrap()
                    .import_certificate(backend_session, &cert_data).await?;
                
                let pkcs_object = PkcsObject::from_cert_handle(cert_handle, template)?;
                let handle = self.object_db.lock().unwrap().add_object(pkcs_object);
                Ok(handle)
            }
            _ => Err(BackendError::InvalidKeySpec("Unsupported object class".to_string())),
        }
    }
    
    pub async fn find_objects(
        &mut self,
        session: &PkcsSession,
        template: Option<&CkRawAttrTemplate>,
    ) -> Result<Vec<CK_OBJECT_HANDLE>, BackendError> {
        let backend_session = session.backend_session.as_ref()
            .ok_or(BackendError::InvalidSession)?;
        
        // First, sync with backend
        let filter = template.map(KeyFilter::from_template).transpose()?;
        let backend_keys = self.backend.lock().unwrap()
            .list_keys(backend_session, filter.as_ref()).await?;
        
        // Update local object database
        let mut object_db = self.object_db.lock().unwrap();
        for key_info in backend_keys {
            let pkcs_object = PkcsObject::from_key_info(key_info);
            object_db.add_or_update_object(pkcs_object);
        }
        
        // Return matching handles
        Ok(object_db.find_objects(template))
    }
}
```

## Implementation Phases

### Phase 1: Foundation (Weeks 1-2)
**Goal**: Establish the basic architecture and interfaces

**Tasks**:
- [ ] Create new directory structure (`backend/`, `core/`)
- [ ] Define core backend traits (`CryptoBackend`, `BackendConfig`)
- [ ] Implement common types (`KeyHandle`, `KeyInfo`, `MechanismType`, etc.)
- [ ] Create unified error handling (`BackendError`)
- [ ] Set up backend factory pattern
- [ ] Enhance configuration framework for backend selection

**Deliverables**:
- Backend trait definitions
- Common type system
- Configuration enhancement
- Error handling framework

### Phase 2: NetHSM Backend Migration (Weeks 3-5)
**Goal**: Create NetHSM backend implementation

**Tasks**:
- [ ] Create `NetHsmBackend` struct and basic implementation
- [ ] Migrate authentication logic from `backend/login.rs`
- [ ] Migrate key management from `backend/key.rs`
- [ ] Migrate cryptographic operations:
  - [ ] Signing operations from `backend/sign.rs`
  - [ ] Encryption operations from `backend/encrypt.rs`
  - [ ] Decryption operations from `backend/decrypt.rs`
- [ ] Migrate mechanism handling from `backend/mechanism.rs`
- [ ] Implement certificate
- [ ] Implement certificate management operations
- [ ] Add error handling and conversion logic
- [ ] Create sync wrappers for async operations (C API compatibility)

**Deliverables**:
- Complete NetHSM backend implementation
- Migration of existing NetHSM logic
- Backward compatibility maintained

### Phase 3: Core Layer Refactoring (Weeks 6-7)
**Goal**: Refactor core PKCS#11 logic to use backend abstraction

**Tasks**:
- [ ] Refactor session management to use backend abstraction
- [ ] Update object lifecycle management
- [ ] Modify PKCS#11 API layer to use new backend interface
- [ ] Update database layer for backend-agnostic object storage
- [ ] Implement mechanism conversion between PKCS#11 and backend types
- [ ] Add async-to-sync adapters for C API compatibility

**Deliverables**:
- Refactored core layer
- Updated API layer integration
- Backend-agnostic object management

### Phase 4: Integration and Testing (Week 8)
**Goal**: Ensure system integration and backward compatibility

**Tasks**:
- [ ] Integration testing with existing test suite
- [ ] Performance benchmarking against current implementation
- [ ] Backward compatibility verification
- [ ] Documentation updates
- [ ] Code cleanup and optimization

**Deliverables**:
- Fully integrated system
- Test suite passing
- Performance benchmarks
- Updated documentation

### Phase 5: Future Backend Support (Future)
**Goal**: Enable additional backend implementations

**Tasks**:
- [ ] SoftHSM backend implementation
- [ ] Generic PKCS#11 proxy backend
- [ ] Hardware token backend support
- [ ] Cloud HSM backend implementations

## Risk Assessment and Mitigation

### 1. Technical Risks

#### 1.1 Async/Sync Impedance Mismatch
**Risk**: PKCS#11 C API is synchronous, but backend operations may be async
**Mitigation**: 
- Use `tokio::runtime::Handle::block_on()` for sync wrappers
- Implement timeout mechanisms
- Consider thread pool for async operations

#### 1.2 Performance Degradation
**Risk**: Additional abstraction layers may impact performance
**Mitigation**:
- Benchmark against current implementation
- Optimize hot paths
- Use zero-cost abstractions where possible
- Profile and optimize bottlenecks

#### 1.3 Backward Compatibility
**Risk**: Changes may break existing applications
**Mitigation**:
- Maintain existing configuration format support
- Extensive testing with real applications
- Gradual migration approach
- Feature flags for new functionality

### 2. Implementation Risks

#### 2.1 Complexity Management
**Risk**: Increased codebase complexity
**Mitigation**:
- Clear separation of concerns
- Comprehensive documentation
- Code review processes
- Modular design

#### 2.2 Error Handling Consistency
**Risk**: Inconsistent error handling across backends
**Mitigation**:
- Unified error type system
- Comprehensive error mapping
- Consistent error reporting
- Error handling guidelines

## Future Extensibility

### 1. Additional Backend Types

The architecture is designed to support various backend types:

#### 1.1 SoftHSM Backend
- Local software-based HSM
- File-based key storage
- Software cryptographic operations

#### 1.2 Hardware Token Backend
- PKCS#11 hardware tokens
- Smart cards and USB tokens
- Hardware-based cryptographic operations

#### 1.3 Cloud HSM Backend
- AWS CloudHSM
- Azure Dedicated HSM
- Google Cloud HSM
- Other cloud-based HSM services

#### 1.4 Distributed Backend
- Multi-instance key distribution
- Load balancing across multiple HSMs
- Failover and redundancy support

### 2. Advanced Features

#### 2.1 Key Escrow and Recovery
- Backup and restore mechanisms
- Key sharing and splitting
- Disaster recovery procedures

#### 2.2 Audit and Compliance
- Comprehensive audit logging
- Compliance reporting
- Regulatory requirement support

#### 2.3 High Availability
- Automatic failover
- Load balancing
- Health monitoring

## Conclusion

This architectural design provides a comprehensive plan for refactoring the NetHSM PKCS#11 implementation to support a modular backend abstraction layer. The design:

1. **Maintains Backward Compatibility**: Existing NetHSM functionality is preserved
2. **Enables Future Extensibility**: New backends can be easily added
3. **Improves Code Organization**: Clear separation between PKCS#11 and backend logic
4. **Provides Robust Error Handling**: Unified error types and consistent handling
5. **Supports Modern Rust Patterns**: Async-ready with trait-based abstractions

The phased implementation approach ensures minimal disruption while providing a solid foundation for future enhancements. The architecture is designed to be flexible, maintainable, and extensible, supporting the long-term evolution of the PKCS#11 library.

### Key Benefits

- **Modularity**: Clear separation of concerns between PKCS#11 protocol and crypto backends
- **Extensibility**: Easy addition of new cryptographic backends
- **Maintainability**: Improved code organization and reduced coupling
- **Testability**: Better isolation for unit and integration testing
- **Performance**: Optimized for both current and future use cases
- **Compliance**: Maintains PKCS#11 standard compliance while enabling backend flexibility

This design serves as the foundation for implementing a robust, extensible, and maintainable PKCS#11 library that can adapt to evolving cryptographic backend requirements while maintaining compatibility with existing applications and workflows.