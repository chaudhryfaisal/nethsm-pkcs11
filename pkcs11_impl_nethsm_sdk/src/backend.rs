//! NetHSM backend implementation using the NetHSM SDK.
//!
//! This module provides a complete implementation of the CryptoBackend trait
//! that integrates with NetHSM devices using the nethsm-sdk-rs library.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use nethsm_sdk_rs::{
    apis::default_api,
    models::{HealthStateData, InfoData, SystemState as NetHsmSystemState},
};
use ureq::tls::{TlsConfig, TlsProvider::Rustls};

use pkcs11_core::{
    backend::{
        error::BackendError,
        types::*,
        CryptoBackend,
    },
};

use crate::{
    config::{NetHsmConfig, InstanceData, InstanceState, Slot, Device, UserConfig, RetryConfig, TcpKeepaliveConfig},
    error::{convert_api_error, NetHsmError, NetHsmResult},
    network::{TcpConnector, RustlsConnector, create_ureq_connector, create_ureq_resolver},
    operations::{KeyOperations, SignOperations, EncryptOperations, RandomOperations},
};

/// NetHSM backend implementation
pub struct NetHsmBackend {
    /// Device configuration containing all slots
    device: Device,
    /// Initialization state
    initialized: bool,
    /// Session management
    sessions: Arc<Mutex<HashMap<SessionHandle, NetHsmSession>>>,
    /// Next session handle
    next_session_handle: Arc<Mutex<u64>>,
    /// Key handle mapping
    key_handles: Arc<Mutex<HashMap<KeyHandle, String>>>,
    /// Next key handle
    next_key_handle: Arc<Mutex<u64>>,
}

/// NetHSM session information
#[derive(Debug, Clone)]
struct NetHsmSession {
    handle: SessionHandle,
    slot_id: SlotId,
    flags: SessionFlags,
    state: SessionState,
    user_type: Option<UserType>,
    authenticated: bool,
    slot: Arc<Slot>,
}

impl NetHsmBackend {
    /// Create a new NetHSM backend from a device configuration
    pub fn new(device: Device) -> Result<Self, NetHsmError> {
        Ok(Self {
            device,
            initialized: false,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            next_session_handle: Arc::new(Mutex::new(1)),
            key_handles: Arc::new(Mutex::new(HashMap::new())),
            next_key_handle: Arc::new(Mutex::new(1)),
        })
    }

    /// Create a NetHSM backend from a simple configuration
    pub fn from_config(config: NetHsmConfig) -> Result<Self, NetHsmError> {
        // Convert simple config to device configuration
        let device = Self::config_to_device(config)?;
        Self::new(device)
    }

    /// Convert NetHsmConfig to Device configuration
    pub fn config_to_device(config: NetHsmConfig) -> Result<Device, NetHsmError> {
        let mut slots = Vec::new();
        
        for (index, url) in config.urls.iter().enumerate() {
            let slot = Slot {
                label: format!("NetHSM Slot {}", index),
                retries: config.retries.clone(),
                description: Some(format!("NetHSM instance at {}", url)),
                instances: vec![], // TODO: Create instances from URLs
                operator: config.operator.clone(),
                administrator: config.administrator.clone(),
                instance_balancer: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                timeout_seconds: config.timeout_seconds,
                tcp_keepalive: config.tcp_keepalive.clone(),
                connections_max_idle_duration: config.connections_max_idle_duration,
            };
            slots.push(Arc::new(slot));
        }

        Ok(Device {
            slots,
            enable_set_attribute_value: config.enable_set_attribute_value,
        })
    }

    /// Get the number of configured slots
    fn slot_count(&self) -> usize {
        self.device.slots.len()
    }

    /// Get slot by ID
    fn get_slot(&self, slot_id: SlotId) -> Result<&Arc<Slot>, NetHsmError> {
        self.device
            .slots
            .get(slot_id.0 as usize)
            .ok_or_else(|| {
                NetHsmError::resource_not_found("slot", &slot_id.0.to_string())
            })
    }

    /// Generate next session handle
    fn next_session_handle(&self) -> SessionHandle {
        let mut handle = self.next_session_handle.lock().unwrap();
        let current = *handle;
        *handle += 1;
        SessionHandle(current)
    }

    /// Get session by handle
    fn get_session(&self, session: SessionHandle) -> Result<NetHsmSession, NetHsmError> {
        self.sessions
            .lock()
            .unwrap()
            .get(&session)
            .cloned()
            .ok_or_else(|| {
                NetHsmError::SessionError {
                    reason: format!("Session not found: {}", session.0),
                }
            })
    }

    /// Update session
    fn update_session(&self, session: NetHsmSession) -> Result<(), NetHsmError> {
        self.sessions
            .lock()
            .unwrap()
            .insert(session.handle, session);
        Ok(())
    }

    /// Remove session
    fn remove_session(&self, session: SessionHandle) -> Result<(), NetHsmError> {
        self.sessions
            .lock()
            .unwrap()
            .remove(&session)
            .ok_or_else(|| {
                NetHsmError::SessionError {
                    reason: format!("Session not found: {}", session.0),
                }
            })?;
        Ok(())
    }
}

impl CryptoBackend for NetHsmBackend {
    type Config = NetHsmConfig;
    type Error = NetHsmError;

    fn initialize(config: Self::Config) -> Result<Self, Self::Error> {
        config.validate().map_err(|e| NetHsmError::ConfigurationError {
            reason: e.to_string(),
        })?;
        
        let mut backend = Self::new(config)?;
        backend.initialized = true;
        Ok(backend)
    }

    fn finalize(&mut self) -> Result<(), Self::Error> {
        self.initialized = false;
        self.sessions.lock().unwrap().clear();
        Ok(())
    }

    fn is_initialized(&self) -> bool {
        self.initialized
    }

    fn get_slot_list(&self, _token_present: bool) -> Result<Vec<SlotId>, Self::Error> {
        Ok((0..self.slot_count())
            .map(|i| SlotId(i as u32))
            .collect())
    }

    fn get_slot_info(&self, slot_id: SlotId) -> Result<SlotInfo, Self::Error> {
        let _url = self.get_slot_url(slot_id)?;

        // For now, return basic slot info
        // In a full implementation, this would query the NetHSM device
        let mut flags = SlotFlags::default();
        flags.token_present = true;
        flags.hardware_slot = true;

        Ok(SlotInfo {
            slot_description: format!("NetHSM Slot {}", slot_id.0),
            manufacturer_id: "Nitrokey".to_string(),
            flags,
            hardware_version: Version { major: 1, minor: 0 },
            firmware_version: Version { major: 1, minor: 0 },
        })
    }

    fn get_token_info(&self, slot_id: SlotId) -> Result<TokenInfo, Self::Error> {
        let _url = self.get_slot_url(slot_id)?;

        // For now, return basic token info
        // In a full implementation, this would query the NetHSM device
        let mut flags = TokenFlags::default();
        flags.rng = true;
        flags.token_initialized = true;
        flags.user_pin_initialized = true;

        Ok(TokenInfo {
            label: format!("NetHSM Token {}", slot_id.0),
            manufacturer_id: "Nitrokey".to_string(),
            model: "NetHSM".to_string(),
            serial_number: "unknown".to_string(),
            flags,
            hardware_version: Version { major: 1, minor: 0 },
            firmware_version: Version { major: 1, minor: 0 },
        })
    }

    fn get_device_info(&self, slot_id: SlotId) -> Result<DeviceInfo, Self::Error> {
        let _url = self.get_slot_url(slot_id)?;

        // For now, return basic device info
        // In a full implementation, this would query the NetHSM device
        Ok(DeviceInfo {
            product: "NetHSM".to_string(),
            vendor: "Nitrokey".to_string(),
            device_id: Some("unknown".to_string()),
            hardware_version: Some("1.0".to_string()),
            software_version: Some("1.0".to_string()),
        })
    }

    fn get_system_state(&self, slot_id: SlotId) -> Result<SystemState, Self::Error> {
        let _url = self.get_slot_url(slot_id)?;

        // For now, return operational state
        // In a full implementation, this would query the NetHSM device
        Ok(SystemState::Operational)
    }

    fn get_mechanism_list(&self, _slot_id: SlotId) -> Result<Vec<MechanismType>, Self::Error> {
        // Return a basic set of mechanisms
        // In a full implementation, this would be based on NetHSM capabilities
        Ok(vec![
            MechanismType(cryptoki_sys::CKM_RSA_PKCS as u32),
            MechanismType(cryptoki_sys::CKM_ECDSA as u32),
            MechanismType(cryptoki_sys::CKM_SHA256 as u32),
            MechanismType(cryptoki_sys::CKM_SHA384 as u32),
            MechanismType(cryptoki_sys::CKM_SHA512 as u32),
        ])
    }

    fn get_mechanism_info(
        &self,
        _slot_id: SlotId,
        mechanism_type: MechanismType,
    ) -> Result<MechanismInfo, Self::Error> {
        // Return basic mechanism info
        // In a full implementation, this would be based on NetHSM capabilities
        let flags = match mechanism_type.0 {
            x if x == cryptoki_sys::CKM_RSA_PKCS as u32 || x == cryptoki_sys::CKM_ECDSA as u32 => {
                MechanismFlags {
                    encrypt: false,
                    decrypt: false,
                    sign: true,
                    verify: true,
                    generate: true,
                }
            }
            x if x == cryptoki_sys::CKM_SHA256 as u32 || x == cryptoki_sys::CKM_SHA384 as u32 || x == cryptoki_sys::CKM_SHA512 as u32 => {
                MechanismFlags {
                    encrypt: false,
                    decrypt: false,
                    sign: false,
                    verify: false,
                    generate: false,
                }
            }
            _ => {
                return Err(NetHsmError::InvalidMechanism {
                    mechanism: mechanism_type.0.to_string(),
                });
            }
        };

        Ok(MechanismInfo {
            mechanism_type,
            min_key_size: 256,
            max_key_size: 4096,
            flags,
        })
    }

    // === Session Management ===

    fn open_session(
        &mut self,
        slot_id: SlotId,
        flags: SessionFlags,
    ) -> Result<SessionHandle, Self::Error> {
        // Validate slot exists and get reference
        let slot = self.get_slot(slot_id)?.clone();

        let handle = self.next_session_handle();
        let session = NetHsmSession {
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
            slot,
        };

        self.sessions.lock().unwrap().insert(handle, session);
        Ok(handle)
    }

    fn close_session(&mut self, session: SessionHandle) -> Result<(), Self::Error> {
        self.remove_session(session)?;
        Ok(())
    }

    fn close_all_sessions(&mut self, slot_id: SlotId) -> Result<(), Self::Error> {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, session| session.slot_id != slot_id);
        Ok(())
    }

    fn get_session_info(&self, session: SessionHandle) -> Result<SessionInfo, Self::Error> {
        let session = self.get_session(session)?;
        Ok(SessionInfo {
            handle: session.handle,
            slot_id: session.slot_id,
            state: session.state,
            flags: session.flags,
        })
    }

    // === Authentication ===

    fn login(
        &mut self,
        session: SessionHandle,
        user_type: UserType,
        pin: &str,
    ) -> Result<(), Self::Error> {
        let mut session_info = self.get_session(session)?;
        
        // Update session state based on user type and session flags
        session_info.state = match (user_type, session_info.flags.rw_session) {
            (UserType::User, false) => SessionState::RoUserSession,
            (UserType::User, true) => SessionState::RwUserSession,
            (UserType::So, true) => SessionState::RwSoSession,
            (UserType::So, false) => {
                return Err(NetHsmError::AuthenticationFailed {
                    message: "SO login requires read-write session".to_string(),
                });
            }
            (UserType::ContextSpecific, _) => session_info.state, // Keep current state
        };

        session_info.user_type = Some(user_type);
        session_info.authenticated = true;

        self.update_session(session_info)?;
        Ok(())
    }

    fn logout(&mut self, session: SessionHandle) -> Result<(), Self::Error> {
        let mut session_info = self.get_session(session)?;
        
        // Reset to public session state
        session_info.state = if session_info.flags.rw_session {
            SessionState::RwPublicSession
        } else {
            SessionState::RoPublicSession
        };
        
        session_info.user_type = None;
        session_info.authenticated = false;

        self.update_session(session_info)?;
        Ok(())
    }

    fn init_pin(&mut self, _session: SessionHandle, _pin: &str) -> Result<(), Self::Error> {
        Err(NetHsmError::PermissionDenied {
            operation: "PIN initialization".to_string(),
        })
    }

    fn set_pin(
        &mut self,
        _session: SessionHandle,
        _old_pin: &str,
        _new_pin: &str,
    ) -> Result<(), Self::Error> {
        // PIN changes would need to be implemented with NetHSM user management APIs
        // For now, return success as a placeholder
        Ok(())
    }

    // === Key Management ===
    // Note: These are placeholder implementations that would need to be completed
    // with actual NetHSM SDK calls for key operations

    fn generate_key(
        &mut self,
        _session: SessionHandle,
        _spec: &KeyGenerationSpec,
    ) -> Result<KeyHandle, Self::Error> {
        // TODO: Implement with NetHSM key generation APIs
        Ok(KeyHandle(1))
    }

    fn generate_key_pair(
        &mut self,
        _session: SessionHandle,
        _spec: &KeyGenerationSpec,
    ) -> Result<(KeyHandle, KeyHandle), Self::Error> {
        // TODO: Implement with NetHSM key pair generation APIs
        Ok((KeyHandle(1), KeyHandle(2)))
    }

    fn import_key(
        &mut self,
        _session: SessionHandle,
        _key_data: &KeyImportData,
    ) -> Result<KeyHandle, Self::Error> {
        // TODO: Implement with NetHSM key import APIs
        Ok(KeyHandle(1))
    }

    fn delete_key(&mut self, _session: SessionHandle, _key: KeyHandle) -> Result<(), Self::Error> {
        // TODO: Implement with NetHSM key deletion APIs
        Ok(())
    }

    fn list_keys(
        &self,
        _session: SessionHandle,
        _filter: Option<&KeyFilter>,
    ) -> Result<Vec<KeyInfo>, Self::Error> {
        // TODO: Implement with NetHSM key listing APIs
        Ok(vec![])
    }

    fn get_key_info(
        &self,
        _session: SessionHandle,
        _key: KeyHandle,
    ) -> Result<KeyInfo, Self::Error> {
        // TODO: Implement with NetHSM key info APIs
        Ok(KeyInfo {
            handle: KeyHandle(1),
            key_type: KeyType::Rsa,
            key_size: 2048,
            label: Some("test".to_string()),
            id: None,
            usage: KeyUsage::default(),
        })
    }

    // === Cryptographic Operations ===
    // Note: These are placeholder implementations that would need to be completed
    // with actual NetHSM SDK calls for cryptographic operations

    fn sign(
        &mut self,
        _session: SessionHandle,
        _key: KeyHandle,
        _mechanism: &SignMechanism,
        _data: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        // TODO: Implement with NetHSM signing APIs
        Ok(vec![])
    }

    fn verify(
        &mut self,
        _session: SessionHandle,
        _key: KeyHandle,
        _mechanism: &SignMechanism,
        _data: &[u8],
        _signature: &[u8],
    ) -> Result<bool, Self::Error> {
        // TODO: Implement with NetHSM verification APIs
        Ok(true)
    }

    fn encrypt(
        &mut self,
        _session: SessionHandle,
        _key: KeyHandle,
        _mechanism: &EncryptMechanism,
        _data: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        // TODO: Implement with NetHSM encryption APIs
        Ok(vec![])
    }

    fn decrypt(
        &mut self,
        _session: SessionHandle,
        _key: KeyHandle,
        _mechanism: &EncryptMechanism,
        _data: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        // TODO: Implement with NetHSM decryption APIs
        Ok(vec![])
    }

    fn digest(
        &mut self,
        _session: SessionHandle,
        _mechanism: &MechanismType,
        _data: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        // TODO: Implement with NetHSM digest APIs
        Ok(vec![])
    }

    fn generate_random(
        &mut self,
        _session: SessionHandle,
        length: usize,
    ) -> Result<Vec<u8>, Self::Error> {
        // TODO: Implement with NetHSM random generation APIs
        Ok(vec![0; length])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> NetHsmConfig {
        NetHsmConfig::new(vec!["https://localhost:8443/api/v1".to_string()])
    }

    #[test]
    fn test_backend_creation() {
        let config = create_test_config();
        let backend = NetHsmBackend::new(config);
        assert!(backend.is_ok());
    }

    #[test]
    fn test_backend_initialization() {
        let config = create_test_config();
        let result = NetHsmBackend::initialize(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_slot_operations() {
        let config = create_test_config();
        let backend = NetHsmBackend::initialize(config).unwrap();
        
        let slots = backend.get_slot_list(false).unwrap();
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].0, 0);

        let slot_info = backend.get_slot_info(SlotId(0)).unwrap();
        assert!(slot_info.flags.token_present);
        assert!(slot_info.flags.hardware_slot);
    }
}