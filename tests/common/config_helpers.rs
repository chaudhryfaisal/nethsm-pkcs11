//! Configuration helpers for PKCS#11 testing.
//!
//! This module provides utilities for creating and managing test configurations
//! for different backend implementations and test scenarios.

use pkcs11_core::backend::types::*;
use pkcs11_impl_mock::config::{MockConfig, MechanismConfig, ErrorInjectionConfig};
use pkcs11_impl_nethsm_sdk::config::NetHsmConfig;
use std::collections::HashMap;
use tempfile::NamedTempFile;
use std::io::Write;

/// Create a default mock configuration for testing
pub fn create_mock_config() -> MockConfig {
    let mut mechanisms = HashMap::new();
    
    // Enable common mechanisms
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
    
    mechanisms.insert("CKM_RSA_PKCS_PSS".to_string(), MechanismConfig {
        enabled: true,
        supports_encryption: false,
        supports_decryption: false,
        supports_signing: true,
        supports_verification: true,
        supports_key_generation: false,
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
    
    mechanisms.insert("CKM_SHA256".to_string(), MechanismConfig {
        enabled: true,
        supports_encryption: false,
        supports_decryption: false,
        supports_signing: false,
        supports_verification: false,
        supports_key_generation: false,
        min_key_size: None,
        max_key_size: None,
    });
    
    mechanisms.insert("CKM_SHA384".to_string(), MechanismConfig {
        enabled: true,
        supports_encryption: false,
        supports_decryption: false,
        supports_signing: false,
        supports_verification: false,
        supports_key_generation: false,
        min_key_size: None,
        max_key_size: None,
    });
    
    mechanisms.insert("CKM_SHA512".to_string(), MechanismConfig {
        enabled: true,
        supports_encryption: false,
        supports_decryption: false,
        supports_signing: false,
        supports_verification: false,
        supports_key_generation: false,
        min_key_size: None,
        max_key_size: None,
    });

    MockConfig {
        token_label: "Mock PKCS#11 Token".to_string(),
        manufacturer_id: "Test Manufacturer".to_string(),
        model: "Mock HSM v1.0".to_string(),
        serial_number: "123456789".to_string(),
        firmware_version: "1.0.0".to_string(),
        max_sessions: 100,
        max_objects: 1000,
        require_auth: false, // Disabled for easier testing
        default_pin: "123456".to_string(),
        deterministic: true,
        random_seed: Some(42),
        mechanisms,
        operation_delays: HashMap::new(),
        error_injection: None,
    }
}

/// Create a mock configuration with authentication required
pub fn create_mock_config_with_auth() -> MockConfig {
    let mut config = create_mock_config();
    config.require_auth = true;
    config
}

/// Create a mock configuration with error injection
pub fn create_mock_config_with_errors() -> MockConfig {
    let mut config = create_mock_config();
    
    config.error_injection = Some(ErrorInjectionConfig {
        enabled: true,
        operations: vec!["sign".to_string(), "encrypt".to_string()],
        trigger_count: 5,
        error_type: "NetworkError".to_string(),
        error_message: "Simulated network failure".to_string(),
    });
    
    config
}

/// Create a mock configuration with operation delays
pub fn create_mock_config_with_delays() -> MockConfig {
    let mut config = create_mock_config();
    
    config.operation_delays.insert("sign".to_string(), 100); // 100ms delay
    config.operation_delays.insert("generate_key_pair".to_string(), 500); // 500ms delay
    config.operation_delays.insert("encrypt".to_string(), 50); // 50ms delay
    
    config
}

/// Create a minimal mock configuration for quick tests
pub fn create_minimal_mock_config() -> MockConfig {
    let mut mechanisms = HashMap::new();
    
    // Only enable RSA PKCS for minimal testing
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
    
    mechanisms.insert("CKM_SHA256".to_string(), MechanismConfig {
        enabled: true,
        supports_encryption: false,
        supports_decryption: false,
        supports_signing: false,
        supports_verification: false,
        supports_key_generation: false,
        min_key_size: None,
        max_key_size: None,
    });

    MockConfig {
        token_label: "Minimal Mock Token".to_string(),
        manufacturer_id: "Test".to_string(),
        model: "Minimal".to_string(),
        serial_number: "000001".to_string(),
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

/// Create a NetHSM configuration for testing
pub fn create_nethsm_config(urls: Vec<String>) -> NetHsmConfig {
    NetHsmConfig::new(urls)
}

/// Create a NetHSM configuration for local testing
pub fn create_local_nethsm_config() -> NetHsmConfig {
    create_nethsm_config(vec!["https://localhost:8443/api/v1".to_string()])
}

/// Create a NetHSM configuration with multiple instances
pub fn create_multi_instance_nethsm_config() -> NetHsmConfig {
    create_nethsm_config(vec![
        "https://localhost:8443/api/v1".to_string(),
        "https://localhost:8444/api/v1".to_string(),
        "https://localhost:8445/api/v1".to_string(),
    ])
}

/// Configuration builder for creating custom test configurations
pub struct TestConfigBuilder {
    mock_config: Option<MockConfig>,
    nethsm_config: Option<NetHsmConfig>,
}

impl TestConfigBuilder {
    pub fn new() -> Self {
        Self {
            mock_config: None,
            nethsm_config: None,
        }
    }

    pub fn with_mock(mut self, config: MockConfig) -> Self {
        self.mock_config = Some(config);
        self
    }

    pub fn with_nethsm(mut self, config: NetHsmConfig) -> Self {
        self.nethsm_config = Some(config);
        self
    }

    pub fn with_default_mock(self) -> Self {
        self.with_mock(create_mock_config())
    }

    pub fn with_default_nethsm(self) -> Self {
        self.with_nethsm(create_local_nethsm_config())
    }

    pub fn build_mock(self) -> Option<MockConfig> {
        self.mock_config
    }

    pub fn build_nethsm(self) -> Option<NetHsmConfig> {
        self.nethsm_config
    }
}

/// Create a temporary configuration file for testing
pub fn create_temp_config_file(content: &str) -> Result<NamedTempFile, std::io::Error> {
    let mut temp_file = NamedTempFile::new()?;
    temp_file.write_all(content.as_bytes())?;
    temp_file.flush()?;
    Ok(temp_file)
}

/// Create a YAML configuration for mock backend testing
pub fn create_mock_yaml_config() -> String {
    r#"
slots:
  - label: "Mock Test Slot"
    description: "Mock PKCS#11 slot for testing"
    backend_type: "mock"
    backend_config:
      token_label: "Mock Test Token"
      manufacturer_id: "Test Manufacturer"
      model: "Mock HSM"
      serial_number: "TEST001"
      require_auth: false
      default_pin: "123456"
      deterministic: true
      random_seed: 42
      max_sessions: 100
      max_objects: 1000
      mechanisms:
        CKM_RSA_PKCS:
          enabled: true
          supports_signing: true
          supports_verification: true
          supports_encryption: true
          supports_decryption: true
          supports_key_generation: true
          min_key_size: 1024
          max_key_size: 4096
        CKM_ECDSA:
          enabled: true
          supports_signing: true
          supports_verification: true
          supports_key_generation: true
          min_key_size: 256
          max_key_size: 521
        CKM_AES_CBC:
          enabled: true
          supports_encryption: true
          supports_decryption: true
          supports_key_generation: true
          min_key_size: 128
          max_key_size: 256
        CKM_SHA256:
          enabled: true
        CKM_SHA384:
          enabled: true
        CKM_SHA512:
          enabled: true

logging:
  level: "debug"
  format: "json"
"#.to_string()
}

/// Create a YAML configuration for NetHSM backend testing
pub fn create_nethsm_yaml_config() -> String {
    r#"
slots:
  - label: "NetHSM Test Slot"
    description: "NetHSM slot for testing"
    backend_type: "nethsm"
    backend_config:
      urls:
        - "https://localhost:8443/api/v1"
      timeout_seconds: 30
      retries: 3
      danger_insecure_cert: true
    operator:
      username: "operator"
      password: "opPassphrase"
    administrator:
      username: "admin"
      password: "Administrator"

logging:
  level: "info"
  format: "text"
"#.to_string()
}

/// Create a YAML configuration with multiple backends
pub fn create_multi_backend_yaml_config() -> String {
    r#"
slots:
  - label: "Mock Slot"
    description: "Mock backend for testing"
    backend_type: "mock"
    backend_config:
      token_label: "Mock Token"
      require_auth: false
      deterministic: true
      
  - label: "NetHSM Slot"
    description: "NetHSM backend for testing"
    backend_type: "nethsm"
    backend_config:
      urls:
        - "https://localhost:8443/api/v1"
      danger_insecure_cert: true
    operator:
      username: "operator"
      password: "opPassphrase"

logging:
  level: "debug"
"#.to_string()
}

/// Test configuration presets
pub struct ConfigPresets;

impl ConfigPresets {
    /// Get a configuration preset by name
    pub fn get(name: &str) -> Option<String> {
        match name {
            "mock_basic" => Some(create_mock_yaml_config()),
            "nethsm_basic" => Some(create_nethsm_yaml_config()),
            "multi_backend" => Some(create_multi_backend_yaml_config()),
            _ => None,
        }
    }

    /// List all available presets
    pub fn list() -> Vec<&'static str> {
        vec!["mock_basic", "nethsm_basic", "multi_backend"]
    }
}

/// Environment setup helpers
pub struct TestEnvironment;

impl TestEnvironment {
    /// Set up environment variables for testing
    pub fn setup() {
        std::env::set_var("RUST_LOG", "debug");
        std::env::set_var("PKCS11_TEST_MODE", "1");
    }

    /// Clean up environment after testing
    pub fn cleanup() {
        std::env::remove_var("PKCS11_TEST_MODE");
    }

    /// Check if we're running in CI environment
    pub fn is_ci() -> bool {
        std::env::var("CI").is_ok() || std::env::var("GITHUB_ACTIONS").is_ok()
    }

    /// Check if NetHSM tests should be skipped
    pub fn should_skip_nethsm_tests() -> bool {
        std::env::var("SKIP_NETHSM_TESTS").is_ok() || 
        (Self::is_ci() && std::env::var("ENABLE_NETHSM_TESTS").is_err())
    }

    /// Get test timeout based on environment
    pub fn get_test_timeout() -> std::time::Duration {
        if Self::is_ci() {
            std::time::Duration::from_secs(300) // 5 minutes in CI
        } else {
            std::time::Duration::from_secs(60) // 1 minute locally
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_mock_config() {
        let config = create_mock_config();
        assert_eq!(config.token_label, "Mock PKCS#11 Token");
        assert!(!config.require_auth);
        assert!(config.deterministic);
        assert!(config.mechanisms.contains_key("CKM_RSA_PKCS"));
        assert!(config.mechanisms.contains_key("CKM_ECDSA"));
    }

    #[test]
    fn test_create_mock_config_with_auth() {
        let config = create_mock_config_with_auth();
        assert!(config.require_auth);
        assert_eq!(config.default_pin, "123456");
    }

    #[test]
    fn test_create_minimal_mock_config() {
        let config = create_minimal_mock_config();
        assert_eq!(config.mechanisms.len(), 2); // Only RSA and SHA256
        assert!(config.mechanisms.contains_key("CKM_RSA_PKCS"));
        assert!(config.mechanisms.contains_key("CKM_SHA256"));
        assert!(!config.mechanisms.contains_key("CKM_ECDSA"));
    }

    #[test]
    fn test_create_nethsm_config() {
        let urls = vec!["https://test.example.com/api/v1".to_string()];
        let config = create_nethsm_config(urls.clone());
        assert_eq!(config.urls(), &urls);
    }

    #[test]
    fn test_config_builder() {
        let builder = TestConfigBuilder::new()
            .with_default_mock()
            .with_default_nethsm();
            
        let mock_config = builder.build_mock();
        assert!(mock_config.is_some());
        
        let builder = TestConfigBuilder::new().with_default_nethsm();
        let nethsm_config = builder.build_nethsm();
        assert!(nethsm_config.is_some());
    }

    #[test]
    fn test_yaml_config_generation() {
        let mock_yaml = create_mock_yaml_config();
        assert!(mock_yaml.contains("Mock Test Slot"));
        assert!(mock_yaml.contains("CKM_RSA_PKCS"));
        
        let nethsm_yaml = create_nethsm_yaml_config();
        assert!(nethsm_yaml.contains("NetHSM Test Slot"));
        assert!(nethsm_yaml.contains("localhost:8443"));
        
        let multi_yaml = create_multi_backend_yaml_config();
        assert!(multi_yaml.contains("Mock Slot"));
        assert!(multi_yaml.contains("NetHSM Slot"));
    }

    #[test]
    fn test_config_presets() {
        let presets = ConfigPresets::list();
        assert!(presets.contains(&"mock_basic"));
        assert!(presets.contains(&"nethsm_basic"));
        assert!(presets.contains(&"multi_backend"));
        
        let mock_config = ConfigPresets::get("mock_basic");
        assert!(mock_config.is_some());
        
        let invalid_config = ConfigPresets::get("invalid");
        assert!(invalid_config.is_none());
    }

    #[test]
    fn test_temp_config_file() {
        let content = "test: value\n";
        let temp_file = create_temp_config_file(content).unwrap();
        
        let file_content = std::fs::read_to_string(temp_file.path()).unwrap();
        assert_eq!(file_content, content);
    }

    #[test]
    fn test_environment_helpers() {
        TestEnvironment::setup();
        assert_eq!(std::env::var("RUST_LOG").unwrap(), "debug");
        assert_eq!(std::env::var("PKCS11_TEST_MODE").unwrap(), "1");
        
        TestEnvironment::cleanup();
        assert!(std::env::var("PKCS11_TEST_MODE").is_err());
    }
}