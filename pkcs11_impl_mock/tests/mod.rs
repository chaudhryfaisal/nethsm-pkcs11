//! Tests for the mock PKCS#11 implementation.
//!
//! This module contains comprehensive tests for the mock backend implementation,
//! validating its functionality and ensuring it provides a reliable testing platform.

mod backend_tests;
mod config_tests;
mod crypto_tests;
mod storage_tests;
mod error_injection_tests;
mod integration_tests;

// Re-export common test utilities
pub use tests_common::*;

// Test configuration helpers
use pkcs11_impl_mock::config::{MockConfig, MechanismConfig};
use std::collections::HashMap;

/// Create a basic test configuration
pub fn create_test_config() -> MockConfig {
    let mut mechanisms = HashMap::new();
    
    mechanisms.insert("CKM_RSA_PKCS".to_string(), MechanismConfig {
        enabled: true,
        supports_encryption: true,
        supports_decryption: true,
        supports_signing: true,
        supports_verification: true,
        supports_key_generation: true,
        min_key_size: Some(1024),
        max_key_size: Some(4096),
    });
    
    mechanisms.insert("CKM_ECDSA".to_string(), MechanismConfig {
        enabled: true,
        supports_encryption: false,
        supports_decryption: false,
        supports_signing: true,
        supports_verification: true,
        supports_key_generation: true,
        min_key_size: Some(256),
        max_key_size: Some(521),
    });
    
    mechanisms.insert("CKM_AES_CBC".to_string(), MechanismConfig {
        enabled: true,
        supports_encryption: true,
        supports_decryption: true,
        supports_signing: false,
        supports_verification: false,
        supports_key_generation: true,
        min_key_size: Some(128),
        max_key_size: Some(256),
    });

    MockConfig {
        token_label: "Mock Test Token".to_string(),
        manufacturer_id: "Test Manufacturer".to_string(),
        model: "Mock HSM".to_string(),
        serial_number: "TEST001".to_string(),
        firmware_version: "1.0.0".to_string(),
        max_sessions: 100,
        max_objects: 1000,
        require_auth: false,
        default_pin: "123456".to_string(),
        deterministic: true,
        random_seed: Some(42),
        mechanisms,
        operation_delays: HashMap::new(),
        error_injection: None,
    }
}

/// Create a test configuration with authentication required
pub fn create_auth_test_config() -> MockConfig {
    let mut config = create_test_config();
    config.require_auth = true;
    config
}

/// Create a test configuration with minimal mechanisms
pub fn create_minimal_test_config() -> MockConfig {
    let mut mechanisms = HashMap::new();
    
    mechanisms.insert("CKM_RSA_PKCS".to_string(), MechanismConfig {
        enabled: true,
        supports_encryption: true,
        supports_decryption: true,
        supports_signing: true,
        supports_verification: true,
        supports_key_generation: true,
        min_key_size: Some(2048),
        max_key_size: Some(2048),
    });

    MockConfig {
        token_label: "Minimal Mock Token".to_string(),
        manufacturer_id: "Test".to_string(),
        model: "Minimal".to_string(),
        serial_number: "MIN001".to_string(),
        firmware_version: "1.0".to_string(),
        max_sessions: 10,
        max_objects: 100,
        require_auth: false,
        default_pin: "123456".to_string(),
        deterministic: true,
        random_seed: Some(42),
        mechanisms,
        operation_delays: HashMap::new(),
        error_injection: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_test_config() {
        let config = create_test_config();
        assert_eq!(config.token_label, "Mock Test Token");
        assert!(!config.require_auth);
        assert!(config.deterministic);
        assert!(config.mechanisms.contains_key("CKM_RSA_PKCS"));
        assert!(config.mechanisms.contains_key("CKM_ECDSA"));
        assert!(config.mechanisms.contains_key("CKM_AES_CBC"));
    }

    #[test]
    fn test_create_auth_test_config() {
        let config = create_auth_test_config();
        assert!(config.require_auth);
        assert_eq!(config.default_pin, "123456");
    }

    #[test]
    fn test_create_minimal_test_config() {
        let config = create_minimal_test_config();
        assert_eq!(config.mechanisms.len(), 1);
        assert!(config.mechanisms.contains_key("CKM_RSA_PKCS"));
        assert!(!config.mechanisms.contains_key("CKM_ECDSA"));
    }
}