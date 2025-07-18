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
    /// Generic key (alias for GenericSecret)
    Generic,
    /// NIST P-224 elliptic curve
    EcP224,
    /// NIST P-256 elliptic curve
    EcP256,
    /// NIST P-384 elliptic curve
    EcP384,
    /// NIST P-521 elliptic curve
    EcP521,
    /// Curve25519 (Ed25519)
    Curve25519,
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
    /// Mechanism type for generation
    pub mechanism: MechanismType,
    /// Key generation parameters
    pub parameters: Option<KeyParameters>,
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
            sensitive: false,
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
    pub parameters: Option<SignParameters>,
}

/// Cryptographic mechanism for encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptMechanism {
    /// Mechanism type
    pub mechanism_type: MechanismType,
    /// Mechanism parameters
    pub parameters: Option<EncryptParameters>,
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BackendType {
    /// NetHSM backend
    NetHsm,
    /// Mock backend for testing
    Mock,
    /// SoftHSM backend
    SoftHsm,
    /// PKCS#11 proxy backend
    Pkcs11Proxy,
    /// Custom backend with name
    Custom(String),
}

impl fmt::Display for BackendType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackendType::NetHsm => write!(f, "NetHsm"),
            BackendType::Mock => write!(f, "mock"),
            BackendType::SoftHsm => write!(f, "softhsm"),
            BackendType::Pkcs11Proxy => write!(f, "pkcs11-proxy"),
            BackendType::Custom(name) => write!(f, "Custom({})", name),
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
    Maintenance,
    Error,
    Unknown,
}

/// Key generation parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyParameters {
    /// Elliptic curve parameters
    EllipticCurve {
        /// Curve type
        curve: EllipticCurve,
    },
    /// RSA parameters
    Rsa {
        /// Public exponent
        public_exponent: Vec<u8>,
    },
}

/// Elliptic curve types (alias for EcCurve for backward compatibility)
pub type EllipticCurve = EcCurve;

/// Signing mechanism parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignParameters {
    /// RSA PSS parameters
    RsaPss {
        /// Hash algorithm
        hash_algorithm: MechanismType,
        /// Mask generation function
        mgf: MechanismType,
        /// Salt length
        salt_length: u32,
    },
}

/// Encryption mechanism parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EncryptParameters {
    /// AES CBC parameters
    AesCbc {
        /// Initialization vector
        iv: Vec<u8>,
    },
}

/// Private key representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateKey {
    /// Key type
    pub key_type: KeyType,
    /// Key material
    pub key_material: KeyMaterial,
    /// Key metadata
    pub metadata: KeyMetadata,
}

/// Key metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Key label
    pub label: Option<String>,
    /// Key ID
    pub id: Option<Vec<u8>>,
    /// Key usage attributes
    pub usage: KeyUsage,
    /// Key size in bits
    pub key_size: u32,
}

/// Public key representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    /// Key type
    pub key_type: KeyType,
    /// Key material (public components only)
    pub key_material: KeyMaterial,
    /// Key metadata
    pub metadata: KeyMetadata,
}

/// Key item for storage and retrieval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyItem {
    /// Key handle
    pub handle: KeyHandle,
    /// Key information
    pub info: KeyInfo,
    /// Private key data (if available)
    pub private_key: Option<PrivateKey>,
    /// Public key data
    pub public_key: Option<PublicKey>,
}

/// Key private data for internal use
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPrivateData {
    /// Private key material
    pub private_material: Vec<u8>,
    /// Key derivation parameters
    pub derivation_params: Option<KeyDerivationParams>,
}

/// Key derivation parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyDerivationParams {
    /// PBKDF2 parameters
    Pbkdf2 {
        /// Salt
        salt: Vec<u8>,
        /// Iteration count
        iterations: u32,
        /// Hash function
        hash: MechanismType,
    },
}

/// Key generation request data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyGenerateRequestData {
    /// Key generation specification
    pub spec: KeyGenerationSpec,
    /// Additional parameters
    pub params: Option<HashMap<String, serde_json::Value>>,
}

/// Sign mode enumeration for backend operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignMode {
    /// PKCS#1 v1.5 with MD5
    PkcsMd5,
    /// PKCS#1 v1.5 with SHA-1
    PkcsSha1,
    /// PKCS#1 v1.5 with SHA-224
    PkcsSha224,
    /// PKCS#1 v1.5 with SHA-256
    PkcsSha256,
    /// PKCS#1 v1.5 with SHA-384
    PkcsSha384,
    /// PKCS#1 v1.5 with SHA-512
    PkcsSha512,
    /// PKCS#1 v1.5 (generic)
    Pkcs1,
    /// PSS with MD5
    PssMd5,
    /// PSS with SHA-1
    PssSha1,
    /// PSS with SHA-224
    PssSha224,
    /// PSS with SHA-256
    PssSha256,
    /// PSS with SHA-384
    PssSha384,
    /// PSS with SHA-512
    PssSha512,
    /// ECDSA signature
    Ecdsa,
    /// EdDSA signature
    EdDsa,
}

/// Encrypt mode enumeration for backend operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptMode {
    /// AES CBC encryption
    AesCbc,
    /// RSA PKCS#1 v1.5 encryption
    RsaPkcs1,
    /// RSA OAEP encryption
    RsaOaep,
}

/// Decrypt mode enumeration for backend operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecryptMode {
    /// AES CBC decryption
    AesCbc,
    /// RSA raw decryption
    Raw,
    /// RSA PKCS#1 v1.5 decryption
    Pkcs1,
    /// RSA OAEP with MD5
    OaepMd5,
    /// RSA OAEP with SHA-1
    OaepSha1,
    /// RSA OAEP with SHA-224
    OaepSha224,
    /// RSA OAEP with SHA-256
    OaepSha256,
    /// RSA OAEP with SHA-384
    OaepSha384,
    /// RSA OAEP with SHA-512
    OaepSha512,
}

/// Key mechanism enumeration for backend operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyMechanism {
    /// AES decryption CBC
    AesDecryptionCbc,
    /// AES encryption CBC
    AesEncryptionCbc,
    /// ECDSA signature
    EcdsaSignature,
    /// EdDSA signature
    EdDsaSignature,
    /// RSA decryption OAEP MD5
    RsaDecryptionOaepMd5,
    /// RSA decryption OAEP SHA-1
    RsaDecryptionOaepSha1,
    /// RSA decryption OAEP SHA-224
    RsaDecryptionOaepSha224,
    /// RSA decryption OAEP SHA-256
    RsaDecryptionOaepSha256,
    /// RSA decryption OAEP SHA-384
    RsaDecryptionOaepSha384,
    /// RSA decryption OAEP SHA-512
    RsaDecryptionOaepSha512,
    /// RSA decryption PKCS#1
    RsaDecryptionPkcs1,
    /// RSA decryption raw
    RsaDecryptionRaw,
    /// RSA signature PKCS#1
    RsaSignaturePkcs1,
    /// RSA signature PSS MD5
    RsaSignaturePssMd5,
    /// RSA signature PSS SHA-1
    RsaSignaturePssSha1,
    /// RSA signature PSS SHA-224
    RsaSignaturePssSha224,
    /// RSA signature PSS SHA-256
    RsaSignaturePssSha256,
    /// RSA signature PSS SHA-384
    RsaSignaturePssSha384,
    /// RSA signature PSS SHA-512
    RsaSignaturePssSha512,
}

/// Device configuration and state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    /// Device information
    pub info: DeviceInfo,
    /// System state
    pub state: SystemState,
    /// Available slots
    pub slots: Vec<Slot>,
    /// Device configuration
    pub config: DeviceConfig,
}

/// Device configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConfig {
    /// Device label
    pub label: String,
    /// Maximum sessions
    pub max_sessions: u32,
    /// Supported mechanisms
    pub mechanisms: Vec<MechanismInfo>,
    /// Enable set attribute value operation
    pub enable_set_attribute_value: bool,
}

/// Slot representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Slot {
    /// Slot ID
    pub id: SlotId,
    /// Slot information
    pub info: SlotInfo,
    /// Token information (if present)
    pub token: Option<TokenInfo>,
    /// Whether slot is available
    pub available: bool,
}

/// Instance data for device management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceData {
    /// Instance identifier
    pub instance_id: String,
    /// Device reference
    pub device: Device,
    /// Active sessions
    pub sessions: HashMap<SessionHandle, SessionInfo>,
    /// Authentication state
    pub auth_state: AuthenticationState,
}

/// Weak reference to instance data
#[derive(Debug, Clone)]
pub struct WeakInstanceData {
    /// Weak reference to instance
    pub instance_ref: std::sync::Weak<std::sync::RwLock<InstanceData>>,
}

/// Authentication state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationState {
    /// Whether authenticated
    pub authenticated: bool,
    /// User type
    pub user_type: Option<UserType>,
    /// Session handle
    pub session_handle: Option<SessionHandle>,
}
impl KeyMaterial {
    pub fn get_public_key(&self) -> Option<&[u8]> {
        match self {
            KeyMaterial::Rsa { modulus, .. } => Some(modulus),
            KeyMaterial::EllipticCurve { public_point, .. } => Some(public_point),
            KeyMaterial::Symmetric { .. } => None,
        }
    }

    pub fn get_private_key(&self) -> Option<&[u8]> {
        match self {
            KeyMaterial::Rsa { private_exponent, .. } => private_exponent.as_deref(),
            KeyMaterial::EllipticCurve { private_scalar, .. } => private_scalar.as_deref(),
            KeyMaterial::Symmetric { key_data } => Some(key_data),
        }
    }

    pub fn get_symmetric_key(&self) -> Option<&[u8]> {
        match self {
            KeyMaterial::Symmetric { key_data } => Some(key_data),
            _ => None,
        }
    }

    pub fn key_type(&self) -> KeyType {
        match self {
            KeyMaterial::Rsa { .. } => KeyType::Rsa,
            KeyMaterial::EllipticCurve { .. } => KeyType::EllipticCurve,
            KeyMaterial::Symmetric { .. } => KeyType::GenericSecret,
        }
    }
}