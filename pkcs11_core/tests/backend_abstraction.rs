//! Tests for the backend abstraction layer.
//!
//! This module tests the core backend traits and type system that enables
//! the modular architecture.

use pkcs11_core::backend::{
    types::*,
    error::{BackendError, ConfigError},
    CryptoBackend, ErasedCryptoBackend, SyncBackendWrapper,
};

#[test]
fn test_backend_types() {
    // Test SlotId
    let slot1 = SlotId(0);
    let slot2 = SlotId(1);
    assert_ne!(slot1, slot2);
    assert_eq!(slot1.0, 0);

    // Test SessionHandle
    let session1 = SessionHandle(100);
    let session2 = SessionHandle(200);
    assert_ne!(session1, session2);
    assert_eq!(session1.0, 100);

    // Test KeyHandle
    let key1 = KeyHandle(1000);
    let key2 = KeyHandle(2000);
    assert_ne!(key1, key2);
    assert_eq!(key1.0, 1000);
}

#[test]
fn test_backend_type_enum() {
    let nethsm = BackendType::NetHsm;
    let custom = BackendType::Custom("test".to_string());
    
    assert_ne!(nethsm, custom);
    
    // Test Display trait
    assert_eq!(format!("{}", nethsm), "NetHsm");
    assert_eq!(format!("{}", custom), "Custom(test)");
    
    // Test Debug trait
    assert!(format!("{:?}", nethsm).contains("NetHsm"));
    assert!(format!("{:?}", custom).contains("Custom"));
}

#[test]
fn test_key_type_enum() {
    let rsa = KeyType::Rsa;
    let ec = KeyType::EllipticCurve;
    let aes = KeyType::Aes;
    
    assert_ne!(rsa, ec);
    assert_ne!(ec, aes);
    assert_ne!(rsa, aes);
    
    // Test that all variants are covered
    match rsa {
        KeyType::Rsa => {},
        KeyType::EllipticCurve => panic!("Wrong variant"),
        KeyType::Aes => panic!("Wrong variant"),
    }
}

#[test]
fn test_elliptic_curve_enum() {
    let p256 = EllipticCurve::P256;
    let p384 = EllipticCurve::P384;
    let p521 = EllipticCurve::P521;
    
    assert_ne!(p256, p384);
    assert_ne!(p384, p521);
    assert_ne!(p256, p521);
}

#[test]
fn test_session_state_enum() {
    let ro_public = SessionState::RoPublicSession;
    let rw_public = SessionState::RwPublicSession;
    let ro_user = SessionState::RoUserSession;
    let rw_user = SessionState::RwUserSession;
    let rw_so = SessionState::RwSoSession;
    
    // Test that all states are different
    let states = vec![ro_public, rw_public, ro_user, rw_user, rw_so];
    for (i, state1) in states.iter().enumerate() {
        for (j, state2) in states.iter().enumerate() {
            if i != j {
                assert_ne!(state1, state2);
            }
        }
    }
}

#[test]
fn test_system_state_enum() {
    let operational = SystemState::Operational;
    let maintenance = SystemState::Maintenance;
    let error = SystemState::Error;
    
    assert_ne!(operational, maintenance);
    assert_ne!(maintenance, error);
    assert_ne!(operational, error);
}

#[test]
fn test_user_type_enum() {
    let user = UserType::User;
    let so = UserType::So;
    let context_specific = UserType::ContextSpecific;
    
    assert_ne!(user, so);
    assert_ne!(so, context_specific);
    assert_ne!(user, context_specific);
}

#[test]
fn test_session_flags() {
    let flags1 = SessionFlags {
        rw_session: true,
        serial_session: true,
    };
    
    let flags2 = SessionFlags {
        rw_session: false,
        serial_session: true,
    };
    
    assert_ne!(flags1, flags2);
    assert!(flags1.rw_session);
    assert!(!flags2.rw_session);
    assert!(flags1.serial_session);
    assert!(flags2.serial_session);
}

#[test]
fn test_slot_flags() {
    let mut flags = SlotFlags::default();
    assert!(!flags.token_present);
    assert!(!flags.hardware_slot);
    
    flags.token_present = true;
    flags.hardware_slot = true;
    
    assert!(flags.token_present);
    assert!(flags.hardware_slot);
}

#[test]
fn test_token_flags() {
    let mut flags = TokenFlags::default();
    assert!(!flags.rng);
    assert!(!flags.token_initialized);
    assert!(!flags.user_pin_initialized);
    assert!(!flags.login_required);
    
    flags.rng = true;
    flags.token_initialized = true;
    flags.user_pin_initialized = true;
    flags.login_required = true;
    
    assert!(flags.rng);
    assert!(flags.token_initialized);
    assert!(flags.user_pin_initialized);
    assert!(flags.login_required);
}

#[test]
fn test_mechanism_flags() {
    let mut flags = MechanismFlags {
        encrypt: false,
        decrypt: false,
        sign: false,
        verify: false,
        generate: false,
    };
    
    assert!(!flags.encrypt);
    assert!(!flags.decrypt);
    assert!(!flags.sign);
    assert!(!flags.verify);
    assert!(!flags.generate);
    
    flags.encrypt = true;
    flags.sign = true;
    
    assert!(flags.encrypt);
    assert!(flags.sign);
    assert!(!flags.decrypt);
    assert!(!flags.verify);
    assert!(!flags.generate);
}

#[test]
fn test_key_usage() {
    let usage = KeyUsage {
        sign: true,
        verify: true,
        encrypt: false,
        decrypt: false,
        derive: false,
        extractable: false,
        sensitive: true,
    };
    
    assert!(usage.sign);
    assert!(usage.verify);
    assert!(!usage.encrypt);
    assert!(!usage.decrypt);
    assert!(!usage.derive);
    assert!(!usage.extractable);
    assert!(usage.sensitive);
}

#[test]
fn test_key_usage_default() {
    let usage = KeyUsage::default();
    
    // Check that default values are reasonable
    assert!(!usage.sign);
    assert!(!usage.verify);
    assert!(!usage.encrypt);
    assert!(!usage.decrypt);
    assert!(!usage.derive);
    assert!(!usage.extractable);
    assert!(!usage.sensitive);
}

#[test]
fn test_version() {
    let version1 = Version { major: 1, minor: 0 };
    let version2 = Version { major: 1, minor: 1 };
    let version3 = Version { major: 2, minor: 0 };
    
    assert_ne!(version1, version2);
    assert_ne!(version2, version3);
    assert_ne!(version1, version3);
    
    assert_eq!(version1.major, 1);
    assert_eq!(version1.minor, 0);
}

#[test]
fn test_slot_info() {
    let slot_info = SlotInfo {
        slot_description: "Test Slot".to_string(),
        manufacturer_id: "Test Manufacturer".to_string(),
        flags: SlotFlags {
            token_present: true,
            hardware_slot: false,
        },
        hardware_version: Version { major: 1, minor: 0 },
        firmware_version: Version { major: 1, minor: 1 },
    };
    
    assert_eq!(slot_info.slot_description, "Test Slot");
    assert_eq!(slot_info.manufacturer_id, "Test Manufacturer");
    assert!(slot_info.flags.token_present);
    assert!(!slot_info.flags.hardware_slot);
    assert_eq!(slot_info.hardware_version.major, 1);
    assert_eq!(slot_info.firmware_version.minor, 1);
}

#[test]
fn test_token_info() {
    let token_info = TokenInfo {
        label: "Test Token".to_string(),
        manufacturer_id: "Test Manufacturer".to_string(),
        model: "Test Model".to_string(),
        serial_number: "12345".to_string(),
        flags: TokenFlags {
            rng: true,
            token_initialized: true,
            user_pin_initialized: true,
            login_required: false,
        },
        hardware_version: Version { major: 2, minor: 0 },
        firmware_version: Version { major: 2, minor: 1 },
    };
    
    assert_eq!(token_info.label, "Test Token");
    assert_eq!(token_info.model, "Test Model");
    assert_eq!(token_info.serial_number, "12345");
    assert!(token_info.flags.rng);
    assert!(token_info.flags.token_initialized);
    assert!(!token_info.flags.login_required);
}

#[test]
fn test_device_info() {
    let device_info = DeviceInfo {
        product: "Test Device".to_string(),
        vendor: "Test Vendor".to_string(),
        device_id: Some("DEV001".to_string()),
        hardware_version: Some("1.0".to_string()),
        software_version: Some("2.0".to_string()),
    };
    
    assert_eq!(device_info.product, "Test Device");
    assert_eq!(device_info.vendor, "Test Vendor");
    assert_eq!(device_info.device_id, Some("DEV001".to_string()));
    assert_eq!(device_info.hardware_version, Some("1.0".to_string()));
    assert_eq!(device_info.software_version, Some("2.0".to_string()));
}

#[test]
fn test_session_info() {
    let session_info = SessionInfo {
        handle: SessionHandle(123),
        slot_id: SlotId(0),
        state: SessionState::RwUserSession,
        flags: SessionFlags {
            rw_session: true,
            serial_session: true,
        },
    };
    
    assert_eq!(session_info.handle.0, 123);
    assert_eq!(session_info.slot_id.0, 0);
    assert_eq!(session_info.state, SessionState::RwUserSession);
    assert!(session_info.flags.rw_session);
}

#[test]
fn test_mechanism_type() {
    let rsa_pkcs = MechanismType(cryptoki_sys::CKM_RSA_PKCS as u32);
    let ecdsa = MechanismType(cryptoki_sys::CKM_ECDSA as u32);
    
    assert_ne!(rsa_pkcs, ecdsa);
    assert_eq!(rsa_pkcs.0, cryptoki_sys::CKM_RSA_PKCS as u32);
    assert_eq!(ecdsa.0, cryptoki_sys::CKM_ECDSA as u32);
}

#[test]
fn test_mechanism_info() {
    let mechanism_info = MechanismInfo {
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
    };
    
    assert_eq!(mechanism_info.mechanism_type.0, cryptoki_sys::CKM_RSA_PKCS as u32);
    assert_eq!(mechanism_info.min_key_size, 1024);
    assert_eq!(mechanism_info.max_key_size, 4096);
    assert!(mechanism_info.flags.encrypt);
    assert!(mechanism_info.flags.sign);
}

#[test]
fn test_key_info() {
    let key_info = KeyInfo {
        handle: KeyHandle(456),
        key_type: KeyType::Rsa,
        key_size: 2048,
        label: Some("test_key".to_string()),
        id: Some(vec![1, 2, 3, 4]),
        usage: KeyUsage {
            sign: true,
            verify: false,
            encrypt: true,
            decrypt: true,
            derive: false,
            extractable: false,
            sensitive: true,
        },
    };
    
    assert_eq!(key_info.handle.0, 456);
    assert_eq!(key_info.key_type, KeyType::Rsa);
    assert_eq!(key_info.key_size, 2048);
    assert_eq!(key_info.label, Some("test_key".to_string()));
    assert_eq!(key_info.id, Some(vec![1, 2, 3, 4]));
    assert!(key_info.usage.sign);
    assert!(!key_info.usage.verify);
    assert!(key_info.usage.encrypt);
}

#[test]
fn test_key_generation_spec() {
    let spec = KeyGenerationSpec {
        key_type: KeyType::Rsa,
        key_size: 2048,
        label: Some("generated_key".to_string()),
        id: Some(vec![5, 6, 7, 8]),
        usage: KeyUsage {
            sign: true,
            verify: true,
            encrypt: false,
            decrypt: false,
            derive: false,
            extractable: false,
            sensitive: true,
        },
        mechanism: MechanismType(cryptoki_sys::CKM_RSA_PKCS_KEY_PAIR_GEN as u32),
        parameters: None,
    };
    
    assert_eq!(spec.key_type, KeyType::Rsa);
    assert_eq!(spec.key_size, 2048);
    assert_eq!(spec.label, Some("generated_key".to_string()));
    assert!(spec.usage.sign);
    assert!(spec.usage.verify);
    assert!(!spec.usage.encrypt);
    assert!(spec.parameters.is_none());
}

#[test]
fn test_key_generation_spec_with_parameters() {
    let spec = KeyGenerationSpec {
        key_type: KeyType::EllipticCurve,
        key_size: 256,
        label: Some("ec_key".to_string()),
        id: None,
        usage: KeyUsage::default(),
        mechanism: MechanismType(cryptoki_sys::CKM_EC_KEY_PAIR_GEN as u32),
        parameters: Some(KeyParameters::EllipticCurve {
            curve: EllipticCurve::P256,
        }),
    };
    
    assert_eq!(spec.key_type, KeyType::EllipticCurve);
    assert_eq!(spec.key_size, 256);
    assert!(spec.parameters.is_some());
    
    if let Some(KeyParameters::EllipticCurve { curve }) = spec.parameters {
        assert_eq!(curve, EllipticCurve::P256);
    } else {
        panic!("Expected EllipticCurve parameters");
    }
}

#[test]
fn test_key_filter() {
    let filter = KeyFilter {
        key_type: Some(KeyType::Rsa),
        label: Some("test_filter".to_string()),
        id: Some(vec![9, 10, 11, 12]),
        usage: Some(KeyUsage {
            sign: true,
            verify: false,
            encrypt: false,
            decrypt: false,
            derive: false,
            extractable: false,
            sensitive: false,
        }),
    };
    
    assert_eq!(filter.key_type, Some(KeyType::Rsa));
    assert_eq!(filter.label, Some("test_filter".to_string()));
    assert_eq!(filter.id, Some(vec![9, 10, 11, 12]));
    assert!(filter.usage.is_some());
    
    if let Some(usage) = filter.usage {
        assert!(usage.sign);
        assert!(!usage.verify);
    }
}

#[test]
fn test_sign_mechanism() {
    let mechanism = SignMechanism {
        mechanism_type: MechanismType(cryptoki_sys::CKM_RSA_PKCS as u32),
        parameters: None,
    };
    
    assert_eq!(mechanism.mechanism_type.0, cryptoki_sys::CKM_RSA_PKCS as u32);
    assert!(mechanism.parameters.is_none());
}

#[test]
fn test_sign_mechanism_with_parameters() {
    let mechanism = SignMechanism {
        mechanism_type: MechanismType(cryptoki_sys::CKM_RSA_PKCS_PSS as u32),
        parameters: Some(SignParameters::RsaPss {
            hash_algorithm: MechanismType(cryptoki_sys::CKM_SHA256 as u32),
            mgf: MechanismType(cryptoki_sys::CKG_MGF1_SHA256 as u32),
            salt_length: 32,
        }),
    };
    
    assert_eq!(mechanism.mechanism_type.0, cryptoki_sys::CKM_RSA_PKCS_PSS as u32);
    assert!(mechanism.parameters.is_some());
    
    if let Some(SignParameters::RsaPss { hash_algorithm, mgf, salt_length }) = mechanism.parameters {
        assert_eq!(hash_algorithm.0, cryptoki_sys::CKM_SHA256 as u32);
        assert_eq!(mgf.0, cryptoki_sys::CKG_MGF1_SHA256 as u32);
        assert_eq!(salt_length, 32);
    } else {
        panic!("Expected RsaPss parameters");
    }
}

#[test]
fn test_encrypt_mechanism() {
    let mechanism = EncryptMechanism {
        mechanism_type: MechanismType(cryptoki_sys::CKM_AES_CBC as u32),
        parameters: Some(EncryptParameters::AesCbc {
            iv: vec![0; 16],
        }),
    };
    
    assert_eq!(mechanism.mechanism_type.0, cryptoki_sys::CKM_AES_CBC as u32);
    assert!(mechanism.parameters.is_some());
    
    if let Some(EncryptParameters::AesCbc { iv }) = mechanism.parameters {
        assert_eq!(iv.len(), 16);
        assert_eq!(iv, vec![0; 16]);
    } else {
        panic!("Expected AesCbc parameters");
    }
}

#[test]
fn test_backend_error_types() {
    let config_error = BackendError::configuration_error("Test config error");
    let init_error = BackendError::initialization_error("Test init error");
    let not_supported = BackendError::not_supported("Test not supported");
    let internal_error = BackendError::internal_error("Test internal error");
    
    // Test that errors can be formatted
    assert!(format!("{}", config_error).contains("Test config error"));
    assert!(format!("{}", init_error).contains("Test init error"));
    assert!(format!("{}", not_supported).contains("Test not supported"));
    assert!(format!("{}", internal_error).contains("Test internal error"));
    
    // Test Debug formatting
    assert!(format!("{:?}", config_error).len() > 0);
    assert!(format!("{:?}", init_error).len() > 0);
}

#[test]
fn test_config_error_types() {
    let missing_field = ConfigError::MissingField {
        field: "test_field".to_string(),
    };
    
    let invalid_value = ConfigError::InvalidValue {
        field: "test_field".to_string(),
        value: "invalid".to_string(),
        reason: "Test reason".to_string(),
    };
    
    let validation_failed = ConfigError::ValidationFailed {
        message: "Test validation".to_string(),
    };
    
    // Test that errors can be formatted
    assert!(format!("{}", missing_field).contains("test_field"));
    assert!(format!("{}", invalid_value).contains("invalid"));
    assert!(format!("{}", validation_failed).contains("Test validation"));
    
    // Test Debug formatting
    assert!(format!("{:?}", missing_field).len() > 0);
    assert!(format!("{:?}", invalid_value).len() > 0);
    assert!(format!("{:?}", validation_failed).len() > 0);
}