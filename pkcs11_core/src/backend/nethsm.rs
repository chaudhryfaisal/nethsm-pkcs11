//! NetHSM backend implementation for the PKCS#11 abstraction layer.

use std::sync::Arc;

use nethsm_sdk_rs::{
    apis::default_api,
    models::{HealthStateData, InfoData, SystemState as NetHsmSystemState},
};

use crate::{
    backend::{
        login::{LoginCtx, UserMode},
        BackendError, CryptoBackend, DeviceInfo, SlotId, SlotInfo, SystemState, TokenInfo,
        MechanismType, MechanismInfo, SessionHandle, SessionFlags, SessionInfo, UserType,
        KeyGenerationSpec, KeyHandle, KeyImportData, KeyInfo, KeyFilter, SignMechanism,
        EncryptMechanism, BackendConfig,
    },
    config::device::Slot,
    defs::{DEFAULT_FIRMWARE_VERSION, DEFAULT_HARDWARE_VERSION, MECHANISM_LIST},
    utils::version_struct_from_str,
};

/// NetHSM backend configuration
#[derive(Debug, Clone)]
pub struct NetHsmBackendConfig {
    pub device: crate::config::device::Device,
}

impl crate::backend::BackendConfig for NetHsmBackendConfig {
    fn validate(&self) -> Result<(), BackendError> {
        if self.device.slots.is_empty() {
            return Err(BackendError::configuration_error("No slots configured"));
        }
        Ok(())
    }

    fn backend_type(&self) -> crate::backend::BackendType {
        crate::backend::BackendType::NetHsm
    }

    fn clone_config(&self) -> Box<dyn crate::backend::BackendConfig> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// NetHSM backend implementation
pub struct NetHsmBackend {
    device: crate::config::device::Device,
    initialized: bool,
}

impl NetHsmBackend {
    /// Create a new NetHSM backend
    pub fn new(config: NetHsmBackendConfig) -> Result<Self, BackendError> {
        Ok(Self {
            device: config.device,
            initialized: true,
        })
    }

    /// Get slot by ID
    fn get_slot(&self, slot_id: SlotId) -> Result<Arc<Slot>, BackendError> {
        let slot = self.device.slots
            .get(slot_id.0 as usize)
            .ok_or_else(|| BackendError::invalid_slot(slot_id.0))?;
        Ok(slot.clone())
    }
}

impl CryptoBackend for NetHsmBackend {
    type Config = NetHsmBackendConfig;
    type Error = BackendError;

    fn initialize(config: Self::Config) -> Result<Self, Self::Error> {
        config.validate()?;
        Self::new(config)
    }

    fn finalize(&mut self) -> Result<(), Self::Error> {
        self.initialized = false;
        Ok(())
    }

    fn is_initialized(&self) -> bool {
        self.initialized
    }

    fn get_slot_list(&self, _token_present: bool) -> Result<Vec<SlotId>, Self::Error> {
        Ok((0..self.device.slots.len())
            .map(|i| SlotId(i as u32))
            .collect())
    }

    fn get_slot_info(&self, slot_id: SlotId) -> Result<SlotInfo, Self::Error> {
        let slot = self.get_slot(slot_id)?;
        let login_ctx = LoginCtx::new(slot.clone(), false, false);

        let info = match login_ctx.try_(
            default_api::info_get,
            UserMode::Guest,
        ) {
            Ok(info) => info.entity,
            Err(_) => InfoData {
                product: "unknown".to_string(),
                vendor: "unknown".to_string(),
            }
        };

        let system_state = match login_ctx.try_(
            default_api::health_state_get,
            UserMode::Guest,
        ) {
            Ok(info) => info.entity,
            Err(_) => HealthStateData {
                state: NetHsmSystemState::Unprovisioned,
            }
        };

        let mut flags = crate::backend::SlotFlags::default();
        if system_state.state == NetHsmSystemState::Operational {
            flags.token_present = true;
        }

        Ok(SlotInfo {
            slot_description: info.product,
            manufacturer_id: info.vendor,
            flags,
            hardware_version: DEFAULT_HARDWARE_VERSION.into(),
            firmware_version: DEFAULT_FIRMWARE_VERSION.into(),
        })
    }

    fn get_token_info(&self, slot_id: SlotId) -> Result<TokenInfo, Self::Error> {
        let slot = self.get_slot(slot_id)?;
        let login_ctx = LoginCtx::new(slot.clone(), true, false);

        let info = login_ctx.try_(
            default_api::info_get,
            UserMode::Guest,
        ).map_err(|_| BackendError::communication_error("Failed to get device info"))?;

        let mut serial_number = "unknown".to_string();
        let mut hardware_version = DEFAULT_HARDWARE_VERSION.into();
        let mut firmware_version = DEFAULT_FIRMWARE_VERSION.into();

        // Try to fetch system info
        if login_ctx.can_run_mode(UserMode::Administrator) {
            if let Ok(system_info) = login_ctx.try_(default_api::system_info_get, UserMode::Administrator) {
                serial_number = system_info.entity.device_id;
                hardware_version = version_struct_from_str(system_info.entity.hardware_version).into();
                firmware_version = version_struct_from_str(system_info.entity.software_version).into();
            }
        }

        let mut flags = crate::backend::TokenFlags::default();
        flags.rng = true;
        flags.token_initialized = true;
        flags.user_pin_initialized = true;

        if !slot.is_connected() {
            flags.login_required = true;
        }

        Ok(TokenInfo {
            label: slot.label.clone(),
            manufacturer_id: info.entity.vendor,
            model: info.entity.product,
            serial_number,
            flags,
            hardware_version,
            firmware_version,
        })
    }

    fn get_device_info(&self, slot_id: SlotId) -> Result<DeviceInfo, Self::Error> {
        let slot = self.get_slot(slot_id)?;
        let login_ctx = LoginCtx::new(slot.clone(), false, false);

        let info = login_ctx.try_(
            default_api::info_get,
            UserMode::Guest,
        ).map_err(|_| BackendError::communication_error("Failed to get device info"))?;

        let mut device_info = DeviceInfo {
            product: info.entity.product,
            vendor: info.entity.vendor,
            device_id: None,
            hardware_version: None,
            software_version: None,
        };

        // Try to get system info if possible
        if login_ctx.can_run_mode(UserMode::Administrator) {
            if let Ok(system_info) = login_ctx.try_(default_api::system_info_get, UserMode::Administrator) {
                device_info.device_id = Some(system_info.entity.device_id);
                device_info.hardware_version = Some(system_info.entity.hardware_version);
                device_info.software_version = Some(system_info.entity.software_version);
            }
        }

        Ok(device_info)
    }

    fn get_system_state(&self, slot_id: SlotId) -> Result<SystemState, Self::Error> {
        let slot = self.get_slot(slot_id)?;
        let login_ctx = LoginCtx::new(slot.clone(), false, false);

        let system_state = match login_ctx.try_(
            default_api::health_state_get,
            UserMode::Guest,
        ) {
            Ok(info) => info.entity,
            Err(_) => return Ok(SystemState::Unknown),
        };

        Ok(match system_state.state {
            NetHsmSystemState::Unprovisioned => SystemState::Unprovisioned,
            NetHsmSystemState::Operational => SystemState::Operational,
            NetHsmSystemState::Locked => SystemState::Locked,
            _ => SystemState::Unknown,
        })
    }

    fn get_mechanism_list(&self, _slot_id: SlotId) -> Result<Vec<MechanismType>, Self::Error> {
        Ok(MECHANISM_LIST
            .iter()
            .map(|mechanism| MechanismType(mechanism.ck_type() as u32))
            .collect())
    }

    fn get_mechanism_info(
        &self,
        _slot_id: SlotId,
        mechanism_type: MechanismType,
    ) -> Result<MechanismInfo, Self::Error> {
        let mechanism = MECHANISM_LIST
            .iter()
            .find(|m| m.ck_type() as u32 == mechanism_type.0)
            .ok_or_else(|| BackendError::unsupported_mechanism(mechanism_type.0))?;

        let ck_info = mechanism.ck_info();
        Ok(MechanismInfo {
            mechanism_type,
            min_key_size: ck_info.ulMinKeySize as u32,
            max_key_size: ck_info.ulMaxKeySize as u32,
            flags: crate::backend::MechanismFlags {
                encrypt: (ck_info.flags & cryptoki_sys::CKF_ENCRYPT) != 0,
                decrypt: (ck_info.flags & cryptoki_sys::CKF_DECRYPT) != 0,
                sign: (ck_info.flags & cryptoki_sys::CKF_SIGN) != 0,
                verify: (ck_info.flags & cryptoki_sys::CKF_VERIFY) != 0,
                generate: (ck_info.flags & cryptoki_sys::CKF_GENERATE) != 0,
            },
        })
    }

    // Session management - for now, we'll use simple placeholder implementations
    fn open_session(
        &mut self,
        _slot_id: SlotId,
        _flags: SessionFlags,
    ) -> Result<SessionHandle, Self::Error> {
        // This would be implemented with actual session management
        Ok(SessionHandle(1))
    }

    fn close_session(&mut self, _session: SessionHandle) -> Result<(), Self::Error> {
        Ok(())
    }

    fn close_all_sessions(&mut self, _slot_id: SlotId) -> Result<(), Self::Error> {
        Ok(())
    }

    fn get_session_info(&self, _session: SessionHandle) -> Result<SessionInfo, Self::Error> {
        // Placeholder implementation
        Ok(SessionInfo {
            handle: SessionHandle(1),
            slot_id: SlotId(0),
            state: crate::backend::SessionState::RwPublicSession,
            flags: SessionFlags {
                rw_session: true,
                serial_session: true,
            },
        })
    }

    // Authentication - placeholder implementations
    fn login(
        &mut self,
        _session: SessionHandle,
        _user_type: UserType,
        _pin: &str,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn logout(&mut self, _session: SessionHandle) -> Result<(), Self::Error> {
        Ok(())
    }

    fn init_pin(&mut self, _session: SessionHandle, _pin: &str) -> Result<(), Self::Error> {
        Err(BackendError::unsupported_operation("PIN initialization not supported"))
    }

    fn set_pin(
        &mut self,
        _session: SessionHandle,
        _old_pin: &str,
        _new_pin: &str,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    // Key management - placeholder implementations
    fn generate_key(
        &mut self,
        _session: SessionHandle,
        _spec: &KeyGenerationSpec,
    ) -> Result<KeyHandle, Self::Error> {
        Ok(KeyHandle(1))
    }

    fn generate_key_pair(
        &mut self,
        _session: SessionHandle,
        _spec: &KeyGenerationSpec,
    ) -> Result<(KeyHandle, KeyHandle), Self::Error> {
        Ok((KeyHandle(1), KeyHandle(2)))
    }

    fn import_key(
        &mut self,
        _session: SessionHandle,
        _key_data: &KeyImportData,
    ) -> Result<KeyHandle, Self::Error> {
        Ok(KeyHandle(1))
    }

    fn delete_key(&mut self, _session: SessionHandle, _key: KeyHandle) -> Result<(), Self::Error> {
        Ok(())
    }

    fn list_keys(
        &self,
        _session: SessionHandle,
        _filter: Option<&KeyFilter>,
    ) -> Result<Vec<KeyInfo>, Self::Error> {
        Ok(vec![])
    }

    fn get_key_info(
        &self,
        _session: SessionHandle,
        _key: KeyHandle,
    ) -> Result<KeyInfo, Self::Error> {
        Ok(KeyInfo {
            handle: KeyHandle(1),
            key_type: crate::backend::KeyType::Rsa,
            key_size: 2048,
            label: Some("test".to_string()),
            id: None,
            usage: crate::backend::KeyUsage::default(),
        })
    }

    // Cryptographic operations - placeholder implementations
    fn sign(
        &mut self,
        _session: SessionHandle,
        _key: KeyHandle,
        _mechanism: &SignMechanism,
        _data: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
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
        Ok(true)
    }

    fn encrypt(
        &mut self,
        _session: SessionHandle,
        _key: KeyHandle,
        _mechanism: &EncryptMechanism,
        _data: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(vec![])
    }

    fn decrypt(
        &mut self,
        _session: SessionHandle,
        _key: KeyHandle,
        _mechanism: &EncryptMechanism,
        _data: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(vec![])
    }

    fn digest(
        &mut self,
        _session: SessionHandle,
        _mechanism: &MechanismType,
        _data: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(vec![])
    }

    fn generate_random(
        &mut self,
        _session: SessionHandle,
        length: usize,
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(vec![0; length])
    }
}