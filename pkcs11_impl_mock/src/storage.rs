//! In-memory storage system for the mock PKCS#11 implementation.

use crate::error::{MockError, MockResult};
use pkcs11_core::backend::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// In-memory storage for mock objects and sessions.
#[derive(Debug)]
pub struct MockStorage {
    /// Session storage
    sessions: Arc<Mutex<HashMap<SessionHandle, MockSession>>>,
    /// Key storage
    keys: Arc<Mutex<HashMap<KeyHandle, MockKey>>>,
    /// Certificate storage
    certificates: Arc<Mutex<HashMap<CertificateHandle, MockCertificate>>>,
    /// Next handle counters
    next_session_handle: Arc<Mutex<u64>>,
    next_key_handle: Arc<Mutex<u64>>,
    next_cert_handle: Arc<Mutex<u64>>,
    /// Configuration
    max_sessions: u32,
    max_objects: u32,
}

/// Mock session information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockSession {
    /// Session handle
    pub handle: SessionHandle,
    /// Slot ID
    pub slot_id: SlotId,
    /// Session flags
    pub flags: SessionFlags,
    /// Session state
    pub state: SessionState,
    /// User type if logged in
    pub user_type: Option<UserType>,
    /// Whether the session is authenticated
    pub authenticated: bool,
    /// Session creation timestamp
    pub created_at: std::time::SystemTime,
    /// Last activity timestamp
    pub last_activity: std::time::SystemTime,
}

/// Mock key information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockKey {
    /// Key handle
    pub handle: KeyHandle,
    /// Key information
    pub info: KeyInfo,
    /// Key material (for mock operations)
    pub material: MockKeyMaterial,
    /// Creation timestamp
    pub created_at: std::time::SystemTime,
    /// Last used timestamp
    pub last_used: Option<std::time::SystemTime>,
}

/// Mock key material for cryptographic operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MockKeyMaterial {
    /// RSA key material
    Rsa {
        /// Key size in bits
        key_size: u32,
        /// Mock modulus (deterministic based on key ID)
        modulus: Vec<u8>,
        /// Mock public exponent
        public_exponent: Vec<u8>,
        /// Mock private exponent (if private key)
        private_exponent: Option<Vec<u8>>,
    },
    /// Elliptic Curve key material
    EllipticCurve {
        /// Curve type
        curve: EcCurve,
        /// Mock public point
        public_point: Vec<u8>,
        /// Mock private scalar (if private key)
        private_scalar: Option<Vec<u8>>,
    },
    /// Symmetric key material
    Symmetric {
        /// Key size in bits
        key_size: u32,
        /// Mock key data
        key_data: Vec<u8>,
    },
}

/// Mock certificate information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockCertificate {
    /// Certificate handle
    pub handle: CertificateHandle,
    /// Certificate data
    pub data: CertificateData,
    /// Creation timestamp
    pub created_at: std::time::SystemTime,
}

impl MockStorage {
    /// Create a new mock storage instance.
    pub fn new(max_sessions: u32, max_objects: u32) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            keys: Arc::new(Mutex::new(HashMap::new())),
            certificates: Arc::new(Mutex::new(HashMap::new())),
            next_session_handle: Arc::new(Mutex::new(1)),
            next_key_handle: Arc::new(Mutex::new(1)),
            next_cert_handle: Arc::new(Mutex::new(1)),
            max_sessions,
            max_objects,
        }
    }

    // === Session Management ===

    /// Create a new session.
    pub fn create_session(
        &self,
        slot_id: SlotId,
        flags: SessionFlags,
    ) -> MockResult<SessionHandle> {
        let mut sessions = self.sessions.lock().map_err(|_| {
            MockError::Storage("Failed to acquire sessions lock".to_string())
        })?;

        if sessions.len() >= self.max_sessions as usize {
            return Err(MockError::Storage(
                "Maximum number of sessions reached".to_string()
            ));
        }

        let mut next_handle = self.next_session_handle.lock().map_err(|_| {
            MockError::Storage("Failed to acquire session handle lock".to_string())
        })?;

        let handle = SessionHandle(*next_handle);
        *next_handle += 1;

        let session = MockSession {
            handle,
            slot_id,
            flags,
            state: if flags.rw_session {
                SessionState::RwPublicSession
            } else {
                SessionState::RoPublicSession
            },
            user_type: None,
            authenticated: false,
            created_at: std::time::SystemTime::now(),
            last_activity: std::time::SystemTime::now(),
        };

        sessions.insert(handle, session);
        Ok(handle)
    }

    /// Get session information.
    pub fn get_session(&self, handle: SessionHandle) -> MockResult<MockSession> {
        let sessions = self.sessions.lock().map_err(|_| {
            MockError::Storage("Failed to acquire sessions lock".to_string())
        })?;

        sessions.get(&handle).cloned().ok_or_else(|| {
            MockError::Session(format!("Session not found: {}", handle.0))
        })
    }

    /// Update session information.
    pub fn update_session(&self, session: MockSession) -> MockResult<()> {
        let mut sessions = self.sessions.lock().map_err(|_| {
            MockError::Storage("Failed to acquire sessions lock".to_string())
        })?;

        sessions.insert(session.handle, session);
        Ok(())
    }

    /// Remove a session.
    pub fn remove_session(&self, handle: SessionHandle) -> MockResult<()> {
        let mut sessions = self.sessions.lock().map_err(|_| {
            MockError::Storage("Failed to acquire sessions lock".to_string())
        })?;

        sessions.remove(&handle).ok_or_else(|| {
            MockError::Session(format!("Session not found: {}", handle.0))
        })?;

        Ok(())
    }

    /// Remove all sessions for a slot.
    pub fn remove_sessions_for_slot(&self, slot_id: SlotId) -> MockResult<()> {
        let mut sessions = self.sessions.lock().map_err(|_| {
            MockError::Storage("Failed to acquire sessions lock".to_string())
        })?;

        sessions.retain(|_, session| session.slot_id != slot_id);
        Ok(())
    }

    /// List all sessions.
    pub fn list_sessions(&self) -> MockResult<Vec<MockSession>> {
        let sessions = self.sessions.lock().map_err(|_| {
            MockError::Storage("Failed to acquire sessions lock".to_string())
        })?;

        Ok(sessions.values().cloned().collect())
    }

    // === Key Management ===

    /// Store a new key.
    pub fn store_key(&self, info: KeyInfo, material: MockKeyMaterial) -> MockResult<KeyHandle> {
        let mut keys = self.keys.lock().map_err(|_| {
            MockError::Storage("Failed to acquire keys lock".to_string())
        })?;

        if keys.len() >= self.max_objects as usize {
            return Err(MockError::Storage(
                "Maximum number of objects reached".to_string()
            ));
        }

        let mut next_handle = self.next_key_handle.lock().map_err(|_| {
            MockError::Storage("Failed to acquire key handle lock".to_string())
        })?;

        let handle = KeyHandle(*next_handle);
        *next_handle += 1;

        let mut key_info = info;
        key_info.handle = handle;

        let key = MockKey {
            handle,
            info: key_info,
            material,
            created_at: std::time::SystemTime::now(),
            last_used: None,
        };

        keys.insert(handle, key);
        Ok(handle)
    }

    /// Get key information.
    pub fn get_key(&self, handle: KeyHandle) -> MockResult<MockKey> {
        let keys = self.keys.lock().map_err(|_| {
            MockError::Storage("Failed to acquire keys lock".to_string())
        })?;

        keys.get(&handle).cloned().ok_or_else(|| {
            MockError::ObjectNotFound(format!("Key not found: {}", handle.0))
        })
    }

    /// Update key last used timestamp.
    pub fn update_key_last_used(&self, handle: KeyHandle) -> MockResult<()> {
        let mut keys = self.keys.lock().map_err(|_| {
            MockError::Storage("Failed to acquire keys lock".to_string())
        })?;

        if let Some(key) = keys.get_mut(&handle) {
            key.last_used = Some(std::time::SystemTime::now());
            Ok(())
        } else {
            Err(MockError::ObjectNotFound(format!("Key not found: {}", handle.0)))
        }
    }

    /// Remove a key.
    pub fn remove_key(&self, handle: KeyHandle) -> MockResult<()> {
        let mut keys = self.keys.lock().map_err(|_| {
            MockError::Storage("Failed to acquire keys lock".to_string())
        })?;

        keys.remove(&handle).ok_or_else(|| {
            MockError::ObjectNotFound(format!("Key not found: {}", handle.0))
        })?;

        Ok(())
    }

    /// List keys matching a filter.
    pub fn list_keys(&self, filter: Option<&KeyFilter>) -> MockResult<Vec<KeyInfo>> {
        let keys = self.keys.lock().map_err(|_| {
            MockError::Storage("Failed to acquire keys lock".to_string())
        })?;

        let mut result = Vec::new();
        for key in keys.values() {
            if let Some(filter) = filter {
                // Apply filter criteria
                if let Some(key_type) = filter.key_type {
                    if key.info.key_type != key_type {
                        continue;
                    }
                }
                if let Some(ref label) = filter.label {
                    if key.info.label.as_ref() != Some(label) {
                        continue;
                    }
                }
                if let Some(ref id) = filter.id {
                    if key.info.id.as_ref() != Some(id) {
                        continue;
                    }
                }
                if let Some(usage) = filter.usage {
                    if key.info.usage != usage {
                        continue;
                    }
                }
            }
            result.push(key.info.clone());
        }

        Ok(result)
    }

    // === Certificate Management ===

    /// Store a new certificate.
    pub fn store_certificate(&self, data: CertificateData) -> MockResult<CertificateHandle> {
        let mut certificates = self.certificates.lock().map_err(|_| {
            MockError::Storage("Failed to acquire certificates lock".to_string())
        })?;

        if certificates.len() >= self.max_objects as usize {
            return Err(MockError::Storage(
                "Maximum number of objects reached".to_string()
            ));
        }

        let mut next_handle = self.next_cert_handle.lock().map_err(|_| {
            MockError::Storage("Failed to acquire certificate handle lock".to_string())
        })?;

        let handle = CertificateHandle(*next_handle);
        *next_handle += 1;

        let certificate = MockCertificate {
            handle,
            data,
            created_at: std::time::SystemTime::now(),
        };

        certificates.insert(handle, certificate);
        Ok(handle)
    }

    /// Get certificate information.
    pub fn get_certificate(&self, handle: CertificateHandle) -> MockResult<MockCertificate> {
        let certificates = self.certificates.lock().map_err(|_| {
            MockError::Storage("Failed to acquire certificates lock".to_string())
        })?;

        certificates.get(&handle).cloned().ok_or_else(|| {
            MockError::ObjectNotFound(format!("Certificate not found: {}", handle.0))
        })
    }

    /// Remove a certificate.
    pub fn remove_certificate(&self, handle: CertificateHandle) -> MockResult<()> {
        let mut certificates = self.certificates.lock().map_err(|_| {
            MockError::Storage("Failed to acquire certificates lock".to_string())
        })?;

        certificates.remove(&handle).ok_or_else(|| {
            MockError::ObjectNotFound(format!("Certificate not found: {}", handle.0))
        })?;

        Ok(())
    }

    /// List all certificates.
    pub fn list_certificates(&self) -> MockResult<Vec<MockCertificate>> {
        let certificates = self.certificates.lock().map_err(|_| {
            MockError::Storage("Failed to acquire certificates lock".to_string())
        })?;

        Ok(certificates.values().cloned().collect())
    }

    // === Utility Methods ===

    /// Clear all stored data.
    pub fn clear_all(&self) -> MockResult<()> {
        let mut sessions = self.sessions.lock().map_err(|_| {
            MockError::Storage("Failed to acquire sessions lock".to_string())
        })?;
        let mut keys = self.keys.lock().map_err(|_| {
            MockError::Storage("Failed to acquire keys lock".to_string())
        })?;
        let mut certificates = self.certificates.lock().map_err(|_| {
            MockError::Storage("Failed to acquire certificates lock".to_string())
        })?;

        sessions.clear();
        keys.clear();
        certificates.clear();

        // Reset handle counters
        *self.next_session_handle.lock().unwrap() = 1;
        *self.next_key_handle.lock().unwrap() = 1;
        *self.next_cert_handle.lock().unwrap() = 1;

        Ok(())
    }

    /// Get storage statistics.
    pub fn get_statistics(&self) -> MockResult<StorageStatistics> {
        let sessions = self.sessions.lock().map_err(|_| {
            MockError::Storage("Failed to acquire sessions lock".to_string())
        })?;
        let keys = self.keys.lock().map_err(|_| {
            MockError::Storage("Failed to acquire keys lock".to_string())
        })?;
        let certificates = self.certificates.lock().map_err(|_| {
            MockError::Storage("Failed to acquire certificates lock".to_string())
        })?;

        Ok(StorageStatistics {
            session_count: sessions.len() as u32,
            key_count: keys.len() as u32,
            certificate_count: certificates.len() as u32,
            max_sessions: self.max_sessions,
            max_objects: self.max_objects,
        })
    }
}

/// Storage statistics for monitoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStatistics {
    /// Current number of sessions
    pub session_count: u32,
    /// Current number of keys
    pub key_count: u32,
    /// Current number of certificates
    pub certificate_count: u32,
    /// Maximum allowed sessions
    pub max_sessions: u32,
    /// Maximum allowed objects
    pub max_objects: u32,
}

impl MockKeyMaterial {
    /// Generate deterministic mock key material based on key type and size.
    pub fn generate_deterministic(key_type: KeyType, key_size: u32, seed: u64) -> Self {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

        match key_type {
            KeyType::Rsa => {
                let modulus_size = (key_size / 8) as usize;
                let mut modulus = vec![0u8; modulus_size];
                rng.fill(&mut modulus[..]);
                // Ensure MSB is set for proper key size
                modulus[0] |= 0x80;

                let public_exponent = vec![0x01, 0x00, 0x01]; // Common RSA public exponent (65537)
                
                let mut private_exponent = vec![0u8; modulus_size];
                rng.fill(&mut private_exponent[..]);

                Self::Rsa {
                    key_size,
                    modulus,
                    public_exponent,
                    private_exponent: Some(private_exponent),
                }
            }
            KeyType::EllipticCurve => {
                let curve = match key_size {
                    256 => EcCurve::P256,
                    384 => EcCurve::P384,
                    521 => EcCurve::P521,
                    _ => EcCurve::P256, // Default to P256
                };

                let point_size = match curve {
                    EcCurve::P256 => 65, // Uncompressed point: 1 + 32 + 32
                    EcCurve::P384 => 97, // Uncompressed point: 1 + 48 + 48
                    EcCurve::P521 => 133, // Uncompressed point: 1 + 66 + 66
                    EcCurve::Ed25519 => 32, // Compressed point
                };

                let scalar_size = match curve {
                    EcCurve::P256 => 32,
                    EcCurve::P384 => 48,
                    EcCurve::P521 => 66,
                    EcCurve::Ed25519 => 32,
                };

                let mut public_point = vec![0u8; point_size];
                let mut private_scalar = vec![0u8; scalar_size];
                
                rng.fill(&mut public_point[..]);
                rng.fill(&mut private_scalar[..]);

                // Set uncompressed point indicator for NIST curves
                if matches!(curve, EcCurve::P256 | EcCurve::P384 | EcCurve::P521) {
                    public_point[0] = 0x04;
                }

                Self::EllipticCurve {
                    curve,
                    public_point,
                    private_scalar: Some(private_scalar),
                }
            }
            KeyType::Aes | KeyType::GenericSecret => {
                let key_data_size = (key_size / 8) as usize;
                let mut key_data = vec![0u8; key_data_size];
                rng.fill(&mut key_data[..]);

                Self::Symmetric {
                    key_size,
                    key_data,
                }
            }
        }
    }

    /// Get the key size in bits.
    pub fn key_size(&self) -> u32 {
        match self {
            Self::Rsa { key_size, .. } => *key_size,
            Self::EllipticCurve { curve, .. } => match curve {
                EcCurve::P256 => 256,
                EcCurve::P384 => 384,
                EcCurve::P521 => 521,
                EcCurve::Ed25519 => 256,
            },
            Self::Symmetric { key_size, .. } => *key_size,
        }
    }

    /// Check if this is a private key.
    pub fn is_private(&self) -> bool {
        match self {
            Self::Rsa { private_exponent, .. } => private_exponent.is_some(),
            Self::EllipticCurve { private_scalar, .. } => private_scalar.is_some(),
            Self::Symmetric { .. } => true, // Symmetric keys are always considered private
        }
    }
}