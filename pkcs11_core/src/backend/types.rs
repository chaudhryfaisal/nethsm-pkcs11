//! Backend-agnostic types for the PKCS#11 abstraction layer.
//!
//! This module defines types that abstract away backend-specific implementations
//! while providing a unified interface for PKCS#11 operations.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// A backend-agnostic handle for cryptographic keys
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyHandle(pub u64);

/// Information about a cryptographic key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    /// The key handle
    pub handle: KeyHandle,
    /// Key type (RSA, EC, AES, etc.)
    pub key_type: KeyType,
    /// Key size in bits
    pub key_size: u32,
    /// Key label/identifier
    pub label: Option<String>,
    /// Key ID
    pub id: Option<Vec<u8>>,
    /// Key usage attributes
    pub usage: KeyUsage,
}

/// Supported key types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    /// RSA key
    Rsa,
    /// Elliptic Curve key
    EllipticCurve,
    /// AES symmetric key
    Aes,
    /// Generic secret key
    GenericSecret,
}

/// Backend-agnostic mechanism type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MechanismType(pub u32);

/// Information about a cryptographic mechanism
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MechanismInfo {
    /// The mechanism type
    pub mechanism_type: MechanismType,
    /// Minimum key size in bits
    pub min_key_size: u32,
    /// Maximum key size in bits
    pub max_key_size: u32,
    /// Supported flags
    pub flags: MechanismFlags,
}

/// Mechanism capability flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MechanismFlags {
    /// Can be used for encryption
    pub encrypt: bool,
    /// Can be used for decryption
    pub decrypt: bool,
    /// Can be used for signing
    pub sign: bool,
    /// Can be used for signature verification
    pub verify: bool,
    /// Can be used for key generation
    pub generate: bool,
}

impl Default for MechanismFlags {
    fn default() -> Self {
        Self {
            encrypt: false,
            decrypt: false,
            sign: false,
            verify: false,
            generate: false,
        }
    }
}

/// Backend-agnostic session handle
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionHandle(pub u64);

/// Backend-agnostic slot ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SlotId(pub u32);

/// Session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Session handle
    pub handle: SessionHandle,
    /// Slot ID
    pub slot_id: SlotId,
    /// Session state
    pub state: SessionState,
    /// Session flags
    pub flags: SessionFlags,
}

/// Session state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    /// Read-only public session
    RoPublicSession,
    /// Read-only user session
    RoUserSession,
    /// Read-write public session
    RwPublicSession,
    /// Read-write user session
    RwUserSession,
    /// Read-write security officer session
    RwSoSession,
}

/// Session flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionFlags {
    /// Read-write session
    pub rw_session: bool,
    /// Serial session
    pub serial_session: bool,
}

/// Token information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    /// Token label
    pub label: String,
    /// Manufacturer ID
    pub manufacturer_id: String,
    /// Model
    pub model: String,
    /// Serial number
    pub serial_number: String,
    /// Token flags
    pub flags: TokenFlags,
    /// Hardware version
    pub hardware_version: Version,
    /// Firmware version
    pub firmware_version: Version,
}

/// Token capability flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenFlags {
    /// Random number generator
    pub rng: bool,
    /// Write protected
    pub write_protected: bool,
    /// Login required
    pub login_required: bool,
    /// User PIN initialized
    pub user_pin_initialized: bool,
    /// Token initialized
    pub token_initialized: bool,
}

impl Default for TokenFlags {
    fn default() -> Self {
        Self {
            rng: false,
            write_protected: false,
            login_required: false,
            user_pin_initialized: false,
            token_initialized: false,
        }
    }
}

/// Version information
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Version {
    /// Major version
    pub major: u8,
    /// Minor version
    pub minor: u8,
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl From<cryptoki_sys::CK_VERSION> for Version {
    fn from(ck_version: cryptoki_sys::CK_VERSION) -> Self {
        Self {
            major: ck_version.major,
            minor: ck_version.minor,
        }
    }
}

/// Slot information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotInfo {
    /// Slot description
    pub slot_description: String,
    /// Manufacturer ID
    pub manufacturer_id: String,
    /// Slot flags
    pub flags: SlotFlags,
    /// Hardware version
    pub hardware_version: Version,
    /// Firmware version
    pub firmware_version: Version,
}

/// Slot capability flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotFlags {
    /// Token present
    pub token_present: bool,
    /// Removable device
    pub removable_device: bool,
    /// Hardware slot
    pub hardware_slot: bool,
}

impl Default for SlotFlags {
    fn default() -> Self {
        Self {
            token_present: false,
            removable_device: false,
            hardware_slot: false,
        }
    }
}

/// User type for authentication
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserType {
    /// Security Officer
    So,
    /// Regular user
    User,
    /// Context specific
    ContextSpecific,
}

/// Authentication credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    /// Username
    pub username: String,
    /// Password/PIN
    pub password: String,
    /// User type
    pub user_type: UserType,
}

/// Backend session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendSession {
    /// Session identifier
    pub session_id: String,
    /// User type
    pub user_type: UserType,
    /// Whether the session is authenticated
    pub authenticated: bool,
}

/// Key generation specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyGenerationSpec {
    /// Key type to generate
    pub key_type: KeyType,
    /// Key size in bits
    pub key_size: u32,
    /// Key label
    pub label: Option<String>,
    /// Key ID
    pub id: Option<Vec<u8>>,
    /// Key usage attributes
    pub usage: KeyUsage,
}

/// Key usage attributes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyUsage {
    /// Can be used for signing
    pub sign: bool,
    /// Can be used for verification
    pub verify: bool,
    /// Can be used for encryption
    pub encrypt: bool,
    /// Can be used for decryption
    pub decrypt: bool,
    /// Can be used for key derivation
    pub derive: bool,
    /// Key is extractable
    pub extractable: bool,
    /// Key is sensitive
    pub sensitive: bool,
}

impl Default for KeyUsage {
    fn default() -> Self {
        Self {
            sign: false,
            verify: false,
            encrypt: false,
            decrypt: false,
            derive: false,
            extractable: false,
            sensitive: true,
        }
    }
}

/// Key import data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyImportData {
    /// Key type
    pub key_type: KeyType,
    /// Key material
    pub key_material: KeyMaterial,
    /// Key label
    pub label: Option<String>,
    /// Key ID
    pub id: Option<Vec<u8>>,
    /// Key usage attributes
    pub usage: KeyUsage,
}

/// Key material for import/export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyMaterial {
    /// RSA key material
    Rsa {
        /// Modulus
        modulus: Vec<u8>,
        /// Public exponent
        public_exponent: Vec<u8>,
        /// Private exponent (for private keys)
        private_exponent: Option<Vec<u8>>,
    },
    /// Elliptic Curve key material
    EllipticCurve {
        /// Curve parameters
        curve: EcCurve,
        /// Public point
        public_point: Vec<u8>,
        /// Private scalar (for private keys)
        private_scalar: Option<Vec<u8>>,
    },
    /// Symmetric key material
    Symmetric {
        /// Key data
        key_data: Vec<u8>,
    },
}

/// Elliptic curve types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EcCurve {
    /// NIST P-256 (secp256r1)
    P256,
    /// NIST P-384 (secp384r1)
    P384,
    /// NIST P-521 (secp521r1)
    P521,
    /// Ed25519
    Ed25519,
}

/// Key filter for searching
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyFilter {
    /// Filter by key type
    pub key_type: Option<KeyType>,
    /// Filter by label
    pub label: Option<String>,
    /// Filter by ID
    pub id: Option<Vec<u8>>,
    /// Filter by usage
    pub usage: Option<KeyUsage>,
}

/// Certificate handle
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CertificateHandle(pub u64);

/// Certificate data for import
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateData {
    /// Certificate format
    pub format: CertificateFormat,
    /// Certificate data
    pub data: Vec<u8>,
    /// Certificate label
    pub label: Option<String>,
    /// Certificate ID
    pub id: Option<Vec<u8>>,
}

/// Certificate format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertificateFormat {
    /// DER encoded
    Der,
    /// PEM encoded
    Pem,
}

/// Cryptographic mechanism for signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignMechanism {
    /// Mechanism type
    pub mechanism_type: MechanismType,
    /// Mechanism parameters
    pub parameters: Option<Vec<u8>>,
}

/// Cryptographic mechanism for encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptMechanism {
    /// Mechanism type
    pub mechanism_type: MechanismType,
    /// Mechanism parameters
    pub parameters: Option<Vec<u8>>,
}

/// Backend configuration trait
pub trait BackendConfig: Send + Sync + std::fmt::Debug {
    /// Validate the configuration
    fn validate(&self) -> Result<(), crate::backend::error::BackendError>;
    
    /// Get the backend type
    fn backend_type(&self) -> BackendType;
    
    /// Clone the configuration
    fn clone_config(&self) -> Box<dyn BackendConfig>;
    
    /// Get as Any for downcasting
    fn as_any(&self) -> &dyn std::any::Any;
}

/// Backend type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BackendType {
    /// NetHSM backend
    NetHsm,
    /// Mock backend for testing
    Mock,
    /// SoftHSM backend
    SoftHsm,
    /// PKCS#11 proxy backend
    Pkcs11Proxy,
}

impl fmt::Display for BackendType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackendType::NetHsm => write!(f, "nethsm"),
            BackendType::Mock => write!(f, "mock"),
            BackendType::SoftHsm => write!(f, "softhsm"),
            BackendType::Pkcs11Proxy => write!(f, "pkcs11-proxy"),
        }
    }
}

/// Device information from the backend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub product: String,
    pub vendor: String,
    pub device_id: Option<String>,
    pub hardware_version: Option<String>,
    pub software_version: Option<String>,
}

/// System state information
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SystemState {
    Unprovisioned,
    Operational,
    Locked,
    Unknown,
}