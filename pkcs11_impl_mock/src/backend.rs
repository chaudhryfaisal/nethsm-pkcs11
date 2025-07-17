//! Mock backend implementation using the CryptoBackend trait.

use crate::{
    config::MockConfig,
    crypto::MockCrypto,
    error::{MockError, MockResult},
    storage::{MockStorage, MockKeyMaterial, MockSession},
};
use pkcs11_core::backend::{
    error::BackendError,
    types::*,
    CryptoBackend,
};
use std::sync::{Arc, Mutex};

/// Mock backend implementation that provides a complete PKCS#11 provider.
pub struct MockBackend {
    /// Configuration
    config: MockConfig,
    /// Initialization state
    initialized: bool,
    /// Storage for sessions, keys, and certificates
    storage: Arc<MockStorage>,
    /// Cryptographic operations provider
    crypto: Arc<MockCrypto>,
    /// Operation counter for error injection
    operation_counter: Arc<Mutex<u32>>,
}

impl MockBackend {
    /// Create a new mock backend instance.
    pub fn new(config: MockConfig) -> MockResult<Self> {
        let storage = Arc::new(MockStorage::new(config.max_sessions, config.max_objects));
        let crypto = Arc::new(MockCrypto::new(config.deterministic, config.random_seed));
        
        Ok(Self {
            config,
            initialized: false,
            storage,
            crypto,
            operation_counter: Arc::new(Mutex::new(0)),
        })
    }

    /// Check for error injection.
    fn check_error_injection(&self, operation: &str) -> MockResult<()> {
        if let Some(ref error_config) = self.config.error_injection {
            let mut counter = self.operation_counter.lock().unwrap();
            *counter += 1;
            
            if error_config.should_inject(operation, *counter) {
                return Err(error_config.create_error());
            }
        }
        Ok(())
    }

    /// Simulate operation delay if configured.
    fn simulate_delay(&self, operation: &str) {
        if let Some(delay_ms) = self.config.get_operation_delay(operation) {
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        }
    }

    /// Validate session and get session info.
    fn get_session(&self, session: SessionHandle) -> MockResult<MockSession> {
        self.storage.get_session(session)
    }

    /// Check if authentication is required and session is authenticated.
    fn check_authentication(&self, session: SessionHandle) -> MockResult<()> {
        if self.config.require_auth {
            let session_info = self.get_session(session)?;
            if !session_info.authenticated {
                return Err(MockError::Authentication("Authentication required".to_string()));
            }
        }
        Ok(())
    }
}

impl CryptoBackend for MockBackend {
    type Config = MockConfig;
    type Error = MockError;

    fn initialize(config: Self::Config) -> Result<Self, Self::Error> {
        config.validate().map_err(|e| MockError::Configuration(e.to_string()))?;
        
        let mut backend = Self::new(config)?;
        backend.initialized = true;
        Ok(backend)
    }

    fn finalize(&mut self) -> Result<(), Self::Error> {
        self.check_error_injection("finalize")?;
        self.simulate_delay("finalize");
        
        self.initialized = false;
        self.storage.clear_all()?;
        Ok(())
    }

    fn is_initialized(&self) -> bool {
        self.initialized
    }

    // === Slot and Token Management ===

    fn get_slot_list(&self, _token_present: bool) -> Result<Vec<SlotId>, Self::Error> {
        self.check_error_injection("get_slot_list")?;
        self.simulate_delay("get_slot_list");
        
        // Mock implementation always returns one slot
        Ok(vec![SlotId(0)])
    }

    fn get_slot_info(&self, slot_id: SlotId) -> Result<SlotInfo, Self::Error> {
        self.check_error_injection("get_slot_info")?;
        self.simulate_delay("get_slot_info");
        
        if slot_id.0 != 0 {
            return Err(MockError::ObjectNotFound("Invalid slot ID".to_string()));
        }

        let mut flags = SlotFlags::default();
        flags.token_present = true;
        flags.hardware_slot = false; // Mock is software-based

        Ok(SlotInfo {
            slot_description: "Mock PKCS#11 Slot".to_string(),
            manufacturer_id: self.config.manufacturer_id.clone(),
            flags,
            hardware_version: Version { major: 1, minor: 0 },
            firmware_version: Version { major: 1, minor: 0 },
        })
    }

    fn get_token_info(&self, slot_id: SlotId) -> Result<TokenInfo, Self::Error> {
        self.check_error_injection("get_token_info")?;
        self.simulate_delay("get_token_info");
        
        if slot_id.0 != 0 {
            return Err(MockError::ObjectNotFound("Invalid slot ID".to_string()));
        }

        let mut flags = TokenFlags::default();
        flags.rng = true;
        flags.token_initialized = true;
        flags.user_pin_initialized = true;
        flags.login_required = self.config.require_auth;

        Ok(TokenInfo {
            label: self.config.token_label.clone(),
            manufacturer_id: self.config.manufacturer_id.clone(),
            model: self.config.model.clone(),
            serial_number: self.config.serial_number.clone(),
            flags,
            hardware_version: Version { major: 1, minor: 0 },
            firmware_version: Version { major: 1, minor: 0 },
        })
    }

    fn get_device_info(&self, slot_id: SlotId) -> Result<DeviceInfo, Self::Error> {
        self.check_error_injection("get_device_info")?;
        self.simulate_delay("get_device_info");
        
        if slot_id.0 != 0 {
            return Err(MockError::ObjectNotFound("Invalid slot ID".to_string()));
        }

        Ok(DeviceInfo {
            product: self.config.model.clone(),
            vendor: self.config.manufacturer_id.clone(),
            device_id: Some(self.config.serial_number.clone()),
            hardware_version: Some("1.0".to_string()),
            software_version: Some(self.config.firmware_version.clone()),
        })
    }

    fn get_system_state(&self, slot_id: SlotId) -> Result<SystemState, Self::Error> {
        self.check_error_injection("get_system_state")?;
        self.simulate_delay("get_system_state");
        
        if slot_id.0 != 0 {
            return Err(MockError::ObjectNotFound("Invalid slot ID".to_string()));
        }

        Ok(SystemState::Operational)
    }

    fn get_mechanism_list(&self, slot_id: SlotId) -> Result<Vec<MechanismType>, Self::Error> {
        self.check_error_injection("get_mechanism_list")?;
        self.simulate_delay("get_mechanism_list");
        
        if slot_id.0 != 0 {
            return Err(MockError::ObjectNotFound("Invalid slot ID".to_string()));
        }

        let mut mechanisms = Vec::new();
        for (name, config) in &self.config.mechanisms {
            if config.enabled {
                let mechanism_type = match name.as_str() {
                    "CKM_RSA_PKCS" => MechanismType(cryptoki_sys::CKM_RSA_PKCS as u32),
                    "CKM_RSA_PKCS_PSS" => MechanismType(cryptoki_sys::CKM_RSA_PKCS_PSS as u32),
                    "CKM_ECDSA" => MechanismType(cryptoki_sys::CKM_ECDSA as u32),
                    "CKM_AES_CBC" => MechanismType(cryptoki_sys::CKM_AES_CBC as u32),
                    "CKM_SHA256" => MechanismType(cryptoki_sys::CKM_SHA256 as u32),
                    "CKM_SHA384" => MechanismType(cryptoki_sys::CKM_SHA384 as u32),
                    "CKM_SHA512" => MechanismType(cryptoki_sys::CKM_SHA512 as u32),
                    _ => continue, // Skip unknown mechanisms
                };
                mechanisms.push(mechanism_type);
            }
        }

        Ok(mechanisms)
    }

    fn get_mechanism_info(
        &self,
        slot_id: SlotId,
        mechanism_type: MechanismType,
    ) -> Result<MechanismInfo, Self::Error> {
        self.check_error_injection("get_mechanism_info")?;
        self.simulate_delay("get_mechanism_info");
        
        if slot_id.0 != 0 {
            return Err(MockError::ObjectNotFound("Invalid slot ID".to_string()));
        }

        // Find mechanism configuration
        let mechanism_name = match mechanism_type.0 {
            x if x == cryptoki_sys::CKM_RSA_PKCS as u32 => "CKM_RSA_PKCS",
            x if x == cryptoki_sys::CKM_RSA_PKCS_PSS as u32 => "CKM_RSA_PKCS_PSS",
            x if x == cryptoki_sys::CKM_ECDSA as u32 => "CKM_ECDSA",
            x if x == cryptoki_sys::CKM_AES_CBC as u32 => "CKM_AES_CBC",
            x if x == cryptoki_sys::CKM_SHA256 as u32 => "CKM_SHA256",
            x if x == cryptoki_sys::CKM_SHA384 as u32 => "CKM_SHA384",
            x if x == cryptoki_sys::CKM_SHA512 as u32 => "CKM_SHA512",
            _ => return Err(MockError::NotSupported(format!("Mechanism not supported: {}", mechanism_type.0))),
        };

        if let Some(config) = self.config.get_mechanism_config(mechanism_name) {
            if !config.enabled {
                return Err(MockError::NotSupported(format!("Mechanism disabled: {}", mechanism_name)));
            }

            let flags = MechanismFlags {
                encrypt: config.supports_encryption,
                decrypt: config.supports_decryption,
                sign: config.supports_signing,
                verify: config.supports_verification,
                generate: config.supports_key_generation,
            };

            Ok(MechanismInfo {
                mechanism_type,
                min_key_size: config.min_key_size.unwrap_or(0),
                max_key_size: config.max_key_size.unwrap_or(u32::MAX),
                flags,
            })
        } else {
            Err(MockError::NotSupported(format!("Mechanism not configured: {}", mechanism_name)))
        }
    }

    // === Session Management ===

    fn open_session(
        &mut self,
        slot_id: SlotId,
        flags: SessionFlags,
    ) -> Result<SessionHandle, Self::Error> {
        self.check_error_injection("open_session")?;
        self.simulate_delay("open_session");
        
        if slot_id.0 != 0 {
            return Err(MockError::ObjectNotFound("Invalid slot ID".to_string()));
        }

        self.storage.create_session(slot_id, flags)
    }

    fn close_session(&mut self, session: SessionHandle) -> Result<(), Self::Error> {
        self.check_error_injection("close_session")?;
        self.simulate_delay("close_session");
        
        self.storage.remove_session(session)
    }

    fn close_all_sessions(&mut self, slot_id: SlotId) -> Result<(), Self::Error> {
        self.check_error_injection("close_all_sessions")?;
        self.simulate_delay("close_all_sessions");
        
        if slot_id.0 != 0 {
            return Err(MockError::ObjectNotFound("Invalid slot ID".to_string()));
        }

        self.storage.remove_sessions_for_slot(slot_id)
    }

    fn get_session_info(&self, session: SessionHandle) -> Result<SessionInfo, Self::Error> {
        self.check_error_injection("get_session_info")?;
        self.simulate_delay("get_session_info");
        
        let session_data = self.storage.get_session(session)?;
        Ok(SessionInfo {
            handle: session_data.handle,
            slot_id: session_data.slot_id,
            state: session_data.state,
            flags: session_data.flags,
        })
    }

    // === Authentication ===

    fn login(
        &mut self,
        session: SessionHandle,
        user_type: UserType,
        pin: &str,
    ) -> Result<(), Self::Error> {
        self.check_error_injection("login")?;
        self.simulate_delay("login");
        
        let mut session_data = self.storage.get_session(session)?;
        
        // Validate PIN
        if pin != self.config.default_pin {
            return Err(MockError::Authentication("Invalid PIN".to_string()));
        }

        // Update session state based on user type and session flags
        session_data.state = match (user_type, session_data.flags.rw_session) {
            (UserType::User, false) => SessionState::RoUserSession,
            (UserType::User, true) => SessionState::RwUserSession,
            (UserType::So, true) => SessionState::RwSoSession,
            (UserType::So, false) => {
                return Err(MockError::Authentication("SO login requires read-write session".to_string()));
            }
            (UserType::ContextSpecific, _) => session_data.state, // Keep current state
        };

        session_data.user_type = Some(user_type);
        session_data.authenticated = true;
        session_data.last_activity = std::time::SystemTime::now();

        self.storage.update_session(session_data)
    }

    fn logout(&mut self, session: SessionHandle) -> Result<(), Self::Error> {
        self.check_error_injection("logout")?;
        self.simulate_delay("logout");
        
        let mut session_data = self.storage.get_session(session)?;
        
        // Reset to public session state
        session_data.state = if session_data.flags.rw_session {
            SessionState::RwPublicSession
        } else {
            SessionState::RoPublicSession
        };
        
        session_data.user_type = None;
        session_data.authenticated = false;
        session_data.last_activity = std::time::SystemTime::now();

        self.storage.update_session(session_data)
    }

    fn init_pin(&mut self, _session: SessionHandle, _pin: &str) -> Result<(), Self::Error> {
        self.check_error_injection("init_pin")?;
        self.simulate_delay("init_pin");
        
        // Mock implementation doesn't support PIN initialization
        Err(MockError::NotSupported("PIN initialization not supported in mock".to_string()))
    }

    fn set_pin(
        &mut self,
        _session: SessionHandle,
        old_pin: &str,
        _new_pin: &str,
    ) -> Result<(), Self::Error> {
        self.check_error_injection("set_pin")?;
        self.simulate_delay("set_pin");
        
        // Validate old PIN
        if old_pin != self.config.default_pin {
            return Err(MockError::Authentication("Invalid old PIN".to_string()));
        }

        // Mock implementation doesn't actually change the PIN
        // In a real implementation, this would update the stored PIN
        Ok(())
    }

    // === Key Management ===

    fn generate_key(
        &mut self,
        session: SessionHandle,
        spec: &KeyGenerationSpec,
    ) -> Result<KeyHandle, Self::Error> {
        self.check_error_injection("generate_key")?;
        self.simulate_delay("generate_key");
        self.check_authentication(session)?;

        // Generate symmetric key
        let key_material = self.crypto.generate_symmetric_key(spec)?;
        
        let key_info = KeyInfo {
            handle: KeyHandle(0), // Will be set by storage
            key_type: spec.key_type,
            key_size: spec.key_size,
            label: spec.label.clone(),
            id: spec.id.clone(),
            usage: spec.usage,
        };

        self.storage.store_key(key_info, key_material)
    }

    fn generate_key_pair(
        &mut self,
        session: SessionHandle,
        spec: &KeyGenerationSpec,
    ) -> Result<(KeyHandle, KeyHandle), Self::Error> {
        self.check_error_injection("generate_key_pair")?;
        self.simulate_delay("generate_key_pair");
        self.check_authentication(session)?;

        // Generate key pair
        let (private_material, public_material) = self.crypto.generate_key_pair(spec)?;
        
        // Store private key
        let private_key_info = KeyInfo {
            handle: KeyHandle(0), // Will be set by storage
            key_type: spec.key_type,
            key_size: spec.key_size,
            label: spec.label.clone(),
            id: spec.id.clone(),
            usage: spec.usage,
        };

        let private_handle = self.storage.store_key(private_key_info, private_material)?;

        // Store public key
        let public_key_info = KeyInfo {
            handle: KeyHandle(0), // Will be set by storage
            key_type: spec.key_type,
            key_size: spec.key_size,
            label: spec.label.as_ref().map(|l| format!("{}_pub", l)),
            id: spec.id.as_ref().map(|id| {
                let mut pub_id = id.clone();
                pub_id.push(0x01); // Differentiate public key ID
                pub_id
            }),
            usage: KeyUsage {
                sign: false,
                verify: true,
                encrypt: spec.usage.encrypt,
                decrypt: false,
                derive: false,
                extractable: true,
                sensitive: false,
            },
        };

        let public_handle = self.storage.store_key(public_key_info, public_material)?;

        Ok((private_handle, public_handle))
    }

    fn import_key(
        &mut self,
        session: SessionHandle,
        key_data: &KeyImportData,
    ) -> Result<KeyHandle, Self::Error> {
        self.check_error_injection("import_key")?;
        self.simulate_delay("import_key");
        self.check_authentication(session)?;

        // Convert import data to mock key material
        let key_material = match &key_data.key_material {
            KeyMaterial::Rsa { modulus, public_exponent, private_exponent } => {
                MockKeyMaterial::Rsa {
                    key_size: (modulus.len() * 8) as u32,
                    modulus: modulus.clone(),
                    public_exponent: public_exponent.clone(),
                    private_exponent: private_exponent.clone(),
                }
            }
            KeyMaterial::EllipticCurve { curve, public_point, private_scalar } => {
                MockKeyMaterial::EllipticCurve {
                    curve: *curve,
                    public_point: public_point.clone(),
                    private_scalar: private_scalar.clone(),
                }
            }
            KeyMaterial::Symmetric { key_data } => {
                MockKeyMaterial::Symmetric {
                    key_size: (key_data.len() * 8) as u32,
                    key_data: key_data.clone(),
                }
            }
        };

        let key_info = KeyInfo {
            handle: KeyHandle(0), // Will be set by storage
            key_type: key_data.key_type,
            key_size: key_material.key_size(),
            label: key_data.label.clone(),
            id: key_data.id.clone(),
            usage: key_data.usage,
        };

        self.storage.store_key(key_info, key_material)
    }

    fn delete_key(&mut self, session: SessionHandle, key: KeyHandle) -> Result<(), Self::Error> {
        self.check_error_injection("delete_key")?;
        self.simulate_delay("delete_key");
        self.check_authentication(session)?;

        self.storage.remove_key(key)
    }

    fn list_keys(
        &self,
        session: SessionHandle,
        filter: Option<&KeyFilter>,
    ) -> Result<Vec<KeyInfo>, Self::Error> {
        self.check_error_injection("list_keys")?;
        self.simulate_delay("list_keys");
        self.check_authentication(session)?;

        self.storage.list_keys(filter)
    }

    fn get_key_info(
        &self,
        session: SessionHandle,
        key: KeyHandle,
    ) -> Result<KeyInfo, Self::Error> {
        self.check_error_injection("get_key_info")?;
        self.simulate_delay("get_key_info");
        self.check_authentication(session)?;

        let key_data = self.storage.get_key(key)?;
        Ok(key_data.info)
    }

    // === Cryptographic Operations ===

    fn sign(
        &mut self,
        session: SessionHandle,
        key: KeyHandle,
        mechanism: &SignMechanism,
        data: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.check_error_injection("sign")?;
        self.simulate_delay("sign");
        self.check_authentication(session)?;

        let key_data = self.storage.get_key(key)?;
        
        // Check if key can be used for signing
        if !key_data.info.usage.sign {
            return Err(MockError::Signature("Key cannot be used for signing".to_string()));
        }

        // Update key last used timestamp
        self.storage.update_key_last_used(key)?;

        self.crypto.sign(&key_data.material, mechanism, data)
    }

    fn verify(
        &mut self,
        session: SessionHandle,
        key: KeyHandle,
        mechanism: &SignMechanism,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, Self::Error> {
        self.check_error_injection("verify")?;
        self.simulate_delay("verify");
        self.check_authentication(session)?;

        let key_data = self.storage.get_key(key)?;
        
        // Check if key can be used for verification
        if !key_data.info.usage.verify {
            return Err(MockError::Signature("Key cannot be used for verification".to_string()));
        }

        // Update key last used timestamp
        self.storage.update_key_last_used(key)?;

        self.crypto.verify(&key_data.material, mechanism, data, signature)
    }

    fn encrypt(
        &mut self,
        session: SessionHandle,
        key: KeyHandle,
        mechanism: &EncryptMechanism,
        data: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.check_error_injection("encrypt")?;
        self.simulate_delay("encrypt");
        self.check_authentication(session)?;

        let key_data = self.storage.get_key(key)?;
        
        // Check if key can be used for encryption
        if !key_data.info.usage.encrypt {
            return Err(MockError::Encryption("Key cannot be used for encryption".to_string()));
        }

        // Update key last used timestamp
        self.storage.update_key_last_used(key)?;

        self.crypto.encrypt(&key_data.material, mechanism, data)
    }

    fn decrypt(
        &mut self,
        session: SessionHandle,
        key: KeyHandle,
        mechanism: &EncryptMechanism,
        data: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.check_error_injection("decrypt")?;
        self.simulate_delay("decrypt");
        self.check_authentication(session)?;

        let key_data = self.storage.get_key(key)?;
        
        // Check if key can be used for decryption
        if !key_data.info.usage.decrypt {
            return Err(MockError::Decryption("Key cannot be used for decryption".to_string()));
        }

        // Update key last used timestamp
        self.storage.update_key_last_used(key)?;

        self.crypto.decrypt(&key_data.material, mechanism, data)
    }

    fn digest(
        &mut self,
        session: SessionHandle,
        mechanism: &MechanismType,
        data: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.check_error_injection("digest")?;
        self.simulate_delay("digest");
        self.check_authentication(session)?;

        self.crypto.digest(mechanism, data)
    }

    fn generate_random(
        &mut self,
        session: SessionHandle,
        length: usize,
    ) -> Result<Vec<u8>, Self::Error> {
        self.check_error_injection("generate_random")?;
        self.simulate_delay("generate_random");
        self.check_authentication(session)?;

        self.crypto.generate_random(length)
    }
}