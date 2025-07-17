//! Tests for the backend registry system.
//!
//! This module tests the backend discovery, registration, and instantiation
//! functionality that enables the modular architecture.

use pkcs11_core::backend::{
    registry::*,
    types::*,
    error::BackendError,
    CryptoBackend, ErasedCryptoBackend,
};
use std::sync::{Arc, Mutex};

/// Mock backend for testing registry functionality
struct TestBackend {
    initialized: bool,
    config: TestBackendConfig,
}

#[derive(Debug, Clone)]
struct TestBackendConfig {
    name: String,
    fail_initialization: bool,
}

impl BackendConfig for TestBackendConfig {
    fn backend_type(&self) -> BackendType {
        BackendType::Custom("test".to_string())
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.name.is_empty() {
            return Err(ConfigError::InvalidValue {
                field: "name".to_string(),
                value: self.name.clone(),
                reason: "Name cannot be empty".to_string(),
            });
        }
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl CryptoBackend for TestBackend {
    type Config = TestBackendConfig;
    type Error = BackendError;

    fn initialize(config: Self::Config) -> Result<Self, Self::Error> {
        if config.fail_initialization {
            return Err(BackendError::initialization_error("Test initialization failure"));
        }
        
        Ok(Self {
            initialized: true,
            config,
        })
    }

    fn finalize(&mut self) -> Result<(), Self::Error> {
        self.initialized = false;
        Ok(())
    }

    fn is_initialized(&self) -> bool {
        self.initialized
    }

    fn get_slot_list(&self, _token_present: bool) -> Result<Vec<SlotId>, Self::Error> {
        Ok(vec![SlotId(0)])
    }

    fn get_slot_info(&self, _slot_id: SlotId) -> Result<SlotInfo, Self::Error> {
        Ok(SlotInfo {
            slot_description: "Test Slot".to_string(),
            manufacturer_id: "Test Manufacturer".to_string(),
            flags: SlotFlags::default(),
            hardware_version: Version { major: 1, minor: 0 },
            firmware_version: Version { major: 1, minor: 0 },
        })
    }

    fn get_token_info(&self, _slot_id: SlotId) -> Result<TokenInfo, Self::Error> {
        Ok(TokenInfo {
            label: "Test Token".to_string(),
            manufacturer_id: "Test Manufacturer".to_string(),
            model: "Test Model".to_string(),
            serial_number: "TEST001".to_string(),
            flags: TokenFlags::default(),
            hardware_version: Version { major: 1, minor: 0 },
            firmware_version: Version { major: 1, minor: 0 },
        })
    }

    fn get_device_info(&self, _slot_id: SlotId) -> Result<DeviceInfo, Self::Error> {
        Ok(DeviceInfo {
            product: "Test Device".to_string(),
            vendor: "Test Vendor".to_string(),
            device_id: Some("TEST001".to_string()),
            hardware_version: Some("1.0".to_string()),
            software_version: Some("1.0".to_string()),
        })
    }

    fn get_system_state(&self, _slot_id: SlotId) -> Result<SystemState, Self::Error> {
        Ok(SystemState::Operational)
    }

    fn get_mechanism_list(&self, _slot_id: SlotId) -> Result<Vec<MechanismType>, Self::Error> {
        Ok(vec![MechanismType(cryptoki_sys::CKM_RSA_PKCS as u32)])
    }

    fn get_mechanism_info(
        &self,
        _slot_id: SlotId,
        _mechanism_type: MechanismType,
    ) -> Result<MechanismInfo, Self::Error> {
        Ok(MechanismInfo {
            mechanism_type: MechanismType(cryptoki_sys::CKM_RSA_PKCS as u32),
            min_key_size: 1024,
            max_key_size: 4096,
            flags: MechanismFlags {
                encrypt: true,
                decrypt: true,
                sign: true,
                verify: true,
                generate: true,
            },
        })
    }

    fn open_session(
        &mut self,
        _slot_id: SlotId,
        _flags: SessionFlags,
    ) -> Result<SessionHandle, Self::Error> {
        Ok(SessionHandle(1))
    }

    fn close_session(&mut self, _session: SessionHandle) -> Result<(), Self::Error> {
        Ok(())
    }

    fn close_all_sessions(&mut self, _slot_id: SlotId) -> Result<(), Self::Error> {
        Ok(())
    }

    fn get_session_info(&self, session: SessionHandle) -> Result<SessionInfo, Self::Error> {
        Ok(SessionInfo {
            handle: session,
            slot_id: SlotId(0),
            state: SessionState::RwPublicSession,
            flags: SessionFlags {
                rw_session: true,
                serial_session: true,
            },
        })
    }

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
        Err(BackendError::not_supported("PIN initialization not supported"))
    }

    fn set_pin(
        &mut self,
        _session: SessionHandle,
        _old_pin: &str,
        _new_pin: &str,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

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
        Ok(KeyHandle(3))
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
        key: KeyHandle,
    ) -> Result<KeyInfo, Self::Error> {
        Ok(KeyInfo {
            handle: key,
            key_type: KeyType::Rsa,
            key_size: 2048,
            label: Some("test_key".to_string()),
            id: Some(vec![1, 2, 3, 4]),
            usage: KeyUsage::default(),
        })
    }

    fn sign(
        &mut self,
        _session: SessionHandle,
        _key: KeyHandle,
        _mechanism: &SignMechanism,
        _data: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(vec![0x42; 256]) // Mock signature
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
        data: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(data.to_vec()) // Mock encryption (identity)
    }

    fn decrypt(
        &mut self,
        _session: SessionHandle,
        _key: KeyHandle,
        _mechanism: &EncryptMechanism,
        data: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(data.to_vec()) // Mock decryption (identity)
    }

    fn digest(
        &mut self,
        _session: SessionHandle,
        _mechanism: &MechanismType,
        data: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(vec![0x42; 32]) // Mock digest
    }

    fn generate_random(
        &mut self,
        _session: SessionHandle,
        length: usize,
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(vec![0x42; length]) // Mock random data
    }
}

/// Test backend discovery implementation
struct TestBackendDiscovery {
    backend_type: BackendType,
    available: bool,
}

impl TestBackendDiscovery {
    fn new(backend_type: BackendType, available: bool) -> Self {
        Self {
            backend_type,
            available,
        }
    }
}

impl BackendDiscovery for TestBackendDiscovery {
    fn backend_type(&self) -> BackendType {
        self.backend_type.clone()
    }

    fn is_available(&self) -> bool {
        self.available
    }

    fn create_factory(&self) -> BackendFactory {
        let backend_type = self.backend_type.clone();
        Box::new(move |config| {
            let test_config = config
                .as_any()
                .downcast_ref::<TestBackendConfig>()
                .ok_or_else(|| BackendError::configuration_error("Invalid test configuration"))?;
            
            let backend = TestBackend::initialize(test_config.clone())?;
            Ok(Box::new(backend) as Box<dyn ErasedCryptoBackend>)
        })
    }

    fn metadata(&self) -> BackendMetadata {
        BackendMetadata {
            name: format!("Test Backend {:?}", self.backend_type),
            description: "Test backend for registry testing".to_string(),
            version: "1.0.0".to_string(),
            features: vec!["signing".to_string(), "encryption".to_string()],
            vendor: Some("Test Vendor".to_string()),
        }
    }
}

#[test]
fn test_backend_registry_creation() {
    let registry = BackendRegistry::new();
    assert_eq!(registry.registered_backends().len(), 0);
}

#[test]
fn test_backend_registration() {
    let mut registry = BackendRegistry::new();
    let backend_type = BackendType::Custom("test".to_string());
    
    registry.register(backend_type.clone(), |config| {
        let test_config = config
            .as_any()
            .downcast_ref::<TestBackendConfig>()
            .ok_or_else(|| BackendError::configuration_error("Invalid configuration"))?;
        
        let backend = TestBackend::initialize(test_config.clone())?;
        Ok(Box::new(backend) as Box<dyn ErasedCryptoBackend>)
    });
    
    assert_eq!(registry.registered_backends().len(), 1);
    assert!(registry.is_registered(&backend_type));
}

#[test]
fn test_backend_creation() {
    let mut registry = BackendRegistry::new();
    let backend_type = BackendType::Custom("test".to_string());
    
    registry.register(backend_type.clone(), |config| {
        let test_config = config
            .as_any()
            .downcast_ref::<TestBackendConfig>()
            .ok_or_else(|| BackendError::configuration_error("Invalid configuration"))?;
        
        let backend = TestBackend::initialize(test_config.clone())?;
        Ok(Box::new(backend) as Box<dyn ErasedCryptoBackend>)
    });
    
    let config = TestBackendConfig {
        name: "test_backend".to_string(),
        fail_initialization: false,
    };
    
    let backend = registry.create_backend(&config).unwrap();
    assert!(backend.is_initialized());
}

#[test]
fn test_backend_creation_failure() {
    let mut registry = BackendRegistry::new();
    let backend_type = BackendType::Custom("test".to_string());
    
    registry.register(backend_type.clone(), |config| {
        let test_config = config
            .as_any()
            .downcast_ref::<TestBackendConfig>()
            .ok_or_else(|| BackendError::configuration_error("Invalid configuration"))?;
        
        let backend = TestBackend::initialize(test_config.clone())?;
        Ok(Box::new(backend) as Box<dyn ErasedCryptoBackend>)
    });
    
    let config = TestBackendConfig {
        name: "test_backend".to_string(),
        fail_initialization: true,
    };
    
    let result = registry.create_backend(&config);
    assert!(result.is_err());
}

#[test]
fn test_unregistered_backend() {
    let registry = BackendRegistry::new();
    let backend_type = BackendType::Custom("nonexistent".to_string());
    
    assert!(!registry.is_registered(&backend_type));
    
    let config = TestBackendConfig {
        name: "test".to_string(),
        fail_initialization: false,
    };
    
    let result = registry.create_backend(&config);
    assert!(result.is_err());
}

#[test]
fn test_backend_discovery_manager() {
    let mut manager = BackendDiscoveryManager::new();
    
    // Add available and unavailable discoveries
    manager.add_discovery(TestBackendDiscovery::new(
        BackendType::Custom("available".to_string()),
        true,
    ));
    manager.add_discovery(TestBackendDiscovery::new(
        BackendType::Custom("unavailable".to_string()),
        false,
    ));
    
    // Discover and register backends
    let registered = manager.discover_and_register().unwrap();
    
    // Only the available backend should be registered
    assert_eq!(registered.len(), 1);
    assert_eq!(registered[0], BackendType::Custom("available".to_string()));
}

#[test]
fn test_backend_metadata() {
    let discovery = TestBackendDiscovery::new(
        BackendType::Custom("metadata_test".to_string()),
        true,
    );
    
    let metadata = discovery.metadata();
    assert!(metadata.name.contains("metadata_test"));
    assert_eq!(metadata.description, "Test backend for registry testing");
    assert_eq!(metadata.version, "1.0.0");
    assert!(metadata.features.contains(&"signing".to_string()));
    assert!(metadata.vendor.is_some());
}

#[test]
fn test_backend_config_validation() {
    let valid_config = TestBackendConfig {
        name: "valid_name".to_string(),
        fail_initialization: false,
    };
    assert!(valid_config.validate().is_ok());
    
    let invalid_config = TestBackendConfig {
        name: "".to_string(),
        fail_initialization: false,
    };
    assert!(invalid_config.validate().is_err());
}

#[test]
fn test_backend_types() {
    let nethsm_type = BackendType::NetHsm;
    let custom_type = BackendType::Custom("custom".to_string());
    
    assert_ne!(nethsm_type, custom_type);
    
    // Test Display implementation
    assert_eq!(format!("{}", nethsm_type), "NetHsm");
    assert_eq!(format!("{}", custom_type), "Custom(custom)");
}