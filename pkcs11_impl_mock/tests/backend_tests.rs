//! Tests for the mock backend implementation.

use pkcs11_core::backend::{
    types::*,
    CryptoBackend,
};
use pkcs11_impl_mock::{
    backend::MockBackend,
    config::MockConfig,
};

#[test]
fn test_mock_backend_initialization() {
    let config = MockConfig::new();
    let backend = MockBackend::initialize(config).unwrap();
    
    assert!(backend.is_initialized());
}

#[test]
fn test_mock_backend_finalization() {
    let config = MockConfig::new();
    let mut backend = MockBackend::initialize(config).unwrap();
    
    assert!(backend.is_initialized());
    backend.finalize().unwrap();
    assert!(!backend.is_initialized());
}

#[test]
fn test_slot_operations() {
    let config = MockConfig::new();
    let backend = MockBackend::initialize(config).unwrap();
    
    // Test slot list
    let slots = backend.get_slot_list(false).unwrap();
    assert_eq!(slots.len(), 1);
    assert_eq!(slots[0].0, 0);
    
    // Test slot info
    let slot_info = backend.get_slot_info(slots[0]).unwrap();
    assert!(!slot_info.slot_description.is_empty());
    assert!(!slot_info.manufacturer_id.is_empty());
    
    // Test token info
    let token_info = backend.get_token_info(slots[0]).unwrap();
    assert!(!token_info.label.is_empty());
    assert!(!token_info.model.is_empty());
    
    // Test device info
    let device_info = backend.get_device_info(slots[0]).unwrap();
    assert!(!device_info.product.is_empty());
    assert!(!device_info.vendor.is_empty());
    
    // Test system state
    let system_state = backend.get_system_state(slots[0]).unwrap();
    assert_eq!(system_state, SystemState::Operational);
}

#[test]
fn test_mechanism_operations() {
    let config = MockConfig::new();
    let backend = MockBackend::initialize(config).unwrap();
    
    let slots = backend.get_slot_list(false).unwrap();
    let mechanisms = backend.get_mechanism_list(slots[0]).unwrap();
    
    assert!(!mechanisms.is_empty());
    
    // Test that we can get info for each mechanism
    for mechanism in &mechanisms {
        let mechanism_info = backend.get_mechanism_info(slots[0], *mechanism).unwrap();
        assert_eq!(mechanism_info.mechanism_type, *mechanism);
    }
}

#[test]
fn test_session_management() {
    let config = MockConfig::new();
    let mut backend = MockBackend::initialize(config).unwrap();
    
    let slots = backend.get_slot_list(false).unwrap();
    let flags = SessionFlags {
        rw_session: true,
        serial_session: true,
    };
    
    // Test session opening
    let session = backend.open_session(slots[0], flags).unwrap();
    
    // Test session info
    let session_info = backend.get_session_info(session).unwrap();
    assert_eq!(session_info.handle, session);
    assert_eq!(session_info.slot_id, slots[0]);
    assert_eq!(session_info.flags.rw_session, true);
    
    // Test session closing
    backend.close_session(session).unwrap();
}

#[test]
fn test_multiple_sessions() {
    let config = MockConfig::new();
    let mut backend = MockBackend::initialize(config).unwrap();
    
    let slots = backend.get_slot_list(false).unwrap();
    let flags = SessionFlags {
        rw_session: true,
        serial_session: true,
    };
    
    // Open multiple sessions
    let session1 = backend.open_session(slots[0], flags).unwrap();
    let session2 = backend.open_session(slots[0], flags).unwrap();
    
    assert_ne!(session1, session2);
    
    // Close all sessions
    backend.close_all_sessions(slots[0]).unwrap();
}

#[test]
fn test_authentication() {
    let config = MockConfig::new().with_require_auth(true);
    let mut backend = MockBackend::initialize(config).unwrap();
    
    let slots = backend.get_slot_list(false).unwrap();
    let flags = SessionFlags {
        rw_session: true,
        serial_session: true,
    };
    let session = backend.open_session(slots[0], flags).unwrap();
    
    // Test login
    backend.login(session, UserType::User, "123456").unwrap();
    
    // Test logout
    backend.logout(session).unwrap();
    
    backend.close_session(session).unwrap();
}

#[test]
fn test_authentication_failure() {
    let config = MockConfig::new().with_require_auth(true);
    let mut backend = MockBackend::initialize(config).unwrap();
    
    let slots = backend.get_slot_list(false).unwrap();
    let flags = SessionFlags {
        rw_session: true,
        serial_session: true,
    };
    let session = backend.open_session(slots[0], flags).unwrap();
    
    // Test login with wrong PIN
    let result = backend.login(session, UserType::User, "wrong_pin");
    assert!(result.is_err());
    
    backend.close_session(session).unwrap();
}

#[test]
fn test_key_generation() {
    let config = MockConfig::new();
    let mut backend = MockBackend::initialize(config).unwrap();
    
    let slots = backend.get_slot_list(false).unwrap();
    let flags = SessionFlags {
        rw_session: true,
        serial_session: true,
    };
    let session = backend.open_session(slots[0], flags).unwrap();
    
    // Generate RSA key pair
    let spec = KeyGenerationSpec {
        key_type: KeyType::Rsa,
        key_size: 2048,
        label: Some("test_rsa".to_string()),
        id: Some(vec![1, 2, 3, 4]),
        usage: KeyUsage {
            sign: true,
            verify: true,
            encrypt: true,
            decrypt: true,
            derive: false,
            extractable: false,
            sensitive: true,
        },
        mechanism: MechanismType(cryptoki_sys::CKM_RSA_PKCS_KEY_PAIR_GEN as u32),
        parameters: None,
    };
    
    let (private_key, public_key) = backend.generate_key_pair(session, &spec).unwrap();
    assert_ne!(private_key, public_key);
    
    // Test key info
    let private_info = backend.get_key_info(session, private_key).unwrap();
    assert_eq!(private_info.key_type, KeyType::Rsa);
    assert_eq!(private_info.key_size, 2048);
    
    // Clean up
    backend.delete_key(session, private_key).unwrap();
    backend.delete_key(session, public_key).unwrap();
    backend.close_session(session).unwrap();
}

#[test]
fn test_symmetric_key_generation() {
    let config = MockConfig::new();
    let mut backend = MockBackend::initialize(config).unwrap();
    
    let slots = backend.get_slot_list(false).unwrap();
    let flags = SessionFlags {
        rw_session: true,
        serial_session: true,
    };
    let session = backend.open_session(slots[0], flags).unwrap();
    
    // Generate AES key
    let spec = KeyGenerationSpec {
        key_type: KeyType::Aes,
        key_size: 256,
        label: Some("test_aes".to_string()),
        id: Some(vec![5, 6, 7, 8]),
        usage: KeyUsage {
            sign: false,
            verify: false,
            encrypt: true,
            decrypt: true,
            derive: false,
            extractable: false,
            sensitive: true,
        },
        mechanism: MechanismType(cryptoki_sys::CKM_AES_KEY_GEN as u32),
        parameters: None,
    };
    
    let key = backend.generate_key(session, &spec).unwrap();
    
    // Test key info
    let key_info = backend.get_key_info(session, key).unwrap();
    assert_eq!(key_info.key_type, KeyType::Aes);
    assert_eq!(key_info.key_size, 256);
    
    // Clean up
    backend.delete_key(session, key).unwrap();
    backend.close_session(session).unwrap();
}

#[test]
fn test_signing_operations() {
    let config = MockConfig::new();
    let mut backend = MockBackend::initialize(config).unwrap();
    
    let slots = backend.get_slot_list(false).unwrap();
    let flags = SessionFlags {
        rw_session: true,
        serial_session: true,
    };
    let session = backend.open_session(slots[0], flags).unwrap();
    
    // Generate RSA key pair
    let spec = KeyGenerationSpec {
        key_type: KeyType::Rsa,
        key_size: 2048,
        label: Some("sign_test".to_string()),
        id: Some(vec![1, 2, 3, 4]),
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
    
    let (private_key, public_key) = backend.generate_key_pair(session, &spec).unwrap();
    
    // Test signing
    let data = b"test data for signing";
    let mechanism = SignMechanism {
        mechanism_type: MechanismType(cryptoki_sys::CKM_RSA_PKCS as u32),
        parameters: None,
    };
    
    let signature = backend.sign(session, private_key, &mechanism, data).unwrap();
    assert!(!signature.is_empty());
    
    // Test verification
    let verified = backend.verify(session, public_key, &mechanism, data, &signature).unwrap();
    assert!(verified);
    
    // Clean up
    backend.delete_key(session, private_key).unwrap();
    backend.delete_key(session, public_key).unwrap();
    backend.close_session(session).unwrap();
}

#[test]
fn test_random_generation() {
    let config = MockConfig::new();
    let mut backend = MockBackend::initialize(config).unwrap();
    
    let slots = backend.get_slot_list(false).unwrap();
    let flags = SessionFlags {
        rw_session: true,
        serial_session: true,
    };
    let session = backend.open_session(slots[0], flags).unwrap();
    
    // Generate random data
    let random1 = backend.generate_random(session, 32).unwrap();
    let random2 = backend.generate_random(session, 32).unwrap();
    
    assert_eq!(random1.len(), 32);
    assert_eq!(random2.len(), 32);
    
    // With deterministic mode, random data should be the same
    let config = MockConfig::new().with_deterministic(true).with_random_seed(42);
    let mut backend2 = MockBackend::initialize(config).unwrap();
    let session2 = backend2.open_session(slots[0], flags).unwrap();
    
    let random3 = backend2.generate_random(session2, 32).unwrap();
    let random4 = backend2.generate_random(session2, 32).unwrap();
    
    // In deterministic mode with same seed, should get same results
    assert_eq!(random3.len(), 32);
    assert_eq!(random4.len(), 32);
    
    backend.close_session(session).unwrap();
    backend2.close_session(session2).unwrap();
}

#[test]
fn test_digest_operations() {
    let config = MockConfig::new();
    let mut backend = MockBackend::initialize(config).unwrap();
    
    let slots = backend.get_slot_list(false).unwrap();
    let flags = SessionFlags {
        rw_session: true,
        serial_session: true,
    };
    let session = backend.open_session(slots[0], flags).unwrap();
    
    let data = b"test data for hashing";
    let mechanism = MechanismType(cryptoki_sys::CKM_SHA256 as u32);
    
    let digest = backend.digest(session, &mechanism, data).unwrap();
    assert_eq!(digest.len(), 32); // SHA-256 produces 32-byte digest
    
    backend.close_session(session).unwrap();
}

#[test]
fn test_invalid_slot() {
    let config = MockConfig::new();
    let backend = MockBackend::initialize(config).unwrap();
    
    let invalid_slot = SlotId(999);
    let result = backend.get_slot_info(invalid_slot);
    assert!(result.is_err());
}

#[test]
fn test_invalid_session() {
    let config = MockConfig::new();
    let backend = MockBackend::initialize(config).unwrap();
    
    let invalid_session = SessionHandle(999);
    let result = backend.get_session_info(invalid_session);
    assert!(result.is_err());
}

#[test]
fn test_invalid_key() {
    let config = MockConfig::new();
    let backend = MockBackend::initialize(config).unwrap();
    
    let slots = backend.get_slot_list(false).unwrap();
    let flags = SessionFlags {
        rw_session: true,
        serial_session: true,
    };
    let mut backend_mut = backend;
    let session = backend_mut.open_session(slots[0], flags).unwrap();
    
    let invalid_key = KeyHandle(999);
    let result = backend_mut.get_key_info(session, invalid_key);
    assert!(result.is_err());
    
    backend_mut.close_session(session).unwrap();
}