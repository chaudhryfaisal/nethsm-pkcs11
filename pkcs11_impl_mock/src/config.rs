//! Configuration support for the mock PKCS#11 implementation.

use crate::error::{ErrorInjectionConfig, MockError, MockResult};
use pkcs11_core::backend::{error::BackendError, types::{BackendConfig, BackendType}};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Mock-specific configuration structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockConfig {
    /// Whether to use deterministic behavior for testing
    pub deterministic: bool,
    
    /// Seed for deterministic random number generation
    pub random_seed: Option<u64>,
    
    /// Maximum number of sessions to allow
    pub max_sessions: u32,
    
    /// Maximum number of objects to store
    pub max_objects: u32,
    
    /// Default PIN for authentication
    pub default_pin: String,
    
    /// Whether to require authentication for operations
    pub require_auth: bool,
    
    /// Simulated token label
    pub token_label: String,
    
    /// Simulated manufacturer ID
    pub manufacturer_id: String,
    
    /// Simulated model
    pub model: String,
    
    /// Simulated serial number
    pub serial_number: String,
    
    /// Simulated firmware version
    pub firmware_version: String,
    
    /// Supported mechanisms and their configurations
    pub mechanisms: HashMap<String, MechanismConfig>,
    
    /// Error injection configuration for testing
    pub error_injection: Option<ErrorInjectionConfig>,
    
    /// Whether to log all operations for debugging
    pub verbose_logging: bool,
    
    /// Simulated operation delays in milliseconds
    pub operation_delays: HashMap<String, u64>,
}

/// Configuration for individual cryptographic mechanisms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MechanismConfig {
    /// Whether the mechanism is enabled
    pub enabled: bool,
    
    /// Minimum key size for the mechanism
    pub min_key_size: Option<u32>,
    
    /// Maximum key size for the mechanism
    pub max_key_size: Option<u32>,
    
    /// Default key size for the mechanism
    pub default_key_size: Option<u32>,
    
    /// Whether the mechanism supports encryption
    pub supports_encryption: bool,
    
    /// Whether the mechanism supports decryption
    pub supports_decryption: bool,
    
    /// Whether the mechanism supports signing
    pub supports_signing: bool,
    
    /// Whether the mechanism supports verification
    pub supports_verification: bool,
    
    /// Whether the mechanism supports key generation
    pub supports_key_generation: bool,
    
    /// Whether the mechanism supports key derivation
    pub supports_key_derivation: bool,
}

impl Default for MockConfig {
    fn default() -> Self {
        let mut mechanisms = HashMap::new();
        
        // RSA mechanisms
        mechanisms.insert("CKM_RSA_PKCS".to_string(), MechanismConfig {
            enabled: true,
            min_key_size: Some(1024),
            max_key_size: Some(4096),
            default_key_size: Some(2048),
            supports_encryption: true,
            supports_decryption: true,
            supports_signing: true,
            supports_verification: true,
            supports_key_generation: true,
            supports_key_derivation: false,
        });
        
        mechanisms.insert("CKM_RSA_PKCS_PSS".to_string(), MechanismConfig {
            enabled: true,
            min_key_size: Some(1024),
            max_key_size: Some(4096),
            default_key_size: Some(2048),
            supports_encryption: false,
            supports_decryption: false,
            supports_signing: true,
            supports_verification: true,
            supports_key_generation: true,
            supports_key_derivation: false,
        });
        
        // ECDSA mechanisms
        mechanisms.insert("CKM_ECDSA".to_string(), MechanismConfig {
            enabled: true,
            min_key_size: Some(256),
            max_key_size: Some(521),
            default_key_size: Some(256),
            supports_encryption: false,
            supports_decryption: false,
            supports_signing: true,
            supports_verification: true,
            supports_key_generation: true,
            supports_key_derivation: false,
        });
        
        // AES mechanisms
        mechanisms.insert("CKM_AES_CBC".to_string(), MechanismConfig {
            enabled: true,
            min_key_size: Some(128),
            max_key_size: Some(256),
            default_key_size: Some(256),
            supports_encryption: true,
            supports_decryption: true,
            supports_signing: false,
            supports_verification: false,
            supports_key_generation: true,
            supports_key_derivation: false,
        });
        
        // Hash mechanisms
        mechanisms.insert("CKM_SHA256".to_string(), MechanismConfig {
            enabled: true,
            min_key_size: None,
            max_key_size: None,
            default_key_size: None,
            supports_encryption: false,
            supports_decryption: false,
            supports_signing: false,
            supports_verification: false,
            supports_key_generation: false,
            supports_key_derivation: false,
        });
        
        Self {
            deterministic: true,
            random_seed: Some(42),
            max_sessions: 100,
            max_objects: 1000,
            default_pin: "123456".to_string(),
            require_auth: false,
            token_label: "Mock Token".to_string(),
            manufacturer_id: "Mock Manufacturer".to_string(),
            model: "Mock Model".to_string(),
            serial_number: "MOCK001".to_string(),
            firmware_version: "1.0.0".to_string(),
            mechanisms,
            error_injection: None,
            verbose_logging: false,
            operation_delays: HashMap::new(),
        }
    }
}

impl MockConfig {
    /// Create a new mock configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Set whether to use deterministic behavior.
    pub fn with_deterministic(mut self, deterministic: bool) -> Self {
        self.deterministic = deterministic;
        self
    }
    
    /// Set the random seed for deterministic behavior.
    pub fn with_random_seed(mut self, seed: u64) -> Self {
        self.random_seed = Some(seed);
        self
    }
    
    /// Set the maximum number of sessions.
    pub fn with_max_sessions(mut self, max_sessions: u32) -> Self {
        self.max_sessions = max_sessions;
        self
    }
    
    /// Set the maximum number of objects.
    pub fn with_max_objects(mut self, max_objects: u32) -> Self {
        self.max_objects = max_objects;
        self
    }
    
    /// Set the default PIN.
    pub fn with_default_pin(mut self, pin: &str) -> Self {
        self.default_pin = pin.to_string();
        self
    }
    
    /// Set whether authentication is required.
    pub fn with_require_auth(mut self, require_auth: bool) -> Self {
        self.require_auth = require_auth;
        self
    }
    
    /// Set the token label.
    pub fn with_token_label(mut self, label: &str) -> Self {
        self.token_label = label.to_string();
        self
    }
    
    /// Set error injection configuration.
    pub fn with_error_injection(mut self, config: ErrorInjectionConfig) -> Self {
        self.error_injection = Some(config);
        self
    }
    
    /// Enable verbose logging.
    pub fn with_verbose_logging(mut self, verbose: bool) -> Self {
        self.verbose_logging = verbose;
        self
    }
    
    /// Add an operation delay.
    pub fn with_operation_delay(mut self, operation: &str, delay_ms: u64) -> Self {
        self.operation_delays.insert(operation.to_string(), delay_ms);
        self
    }
    
    /// Get the delay for an operation.
    pub fn get_operation_delay(&self, operation: &str) -> Option<u64> {
        self.operation_delays.get(operation).copied()
    }
    
    /// Check if a mechanism is supported.
    pub fn is_mechanism_supported(&self, mechanism: &str) -> bool {
        self.mechanisms.get(mechanism)
            .map(|config| config.enabled)
            .unwrap_or(false)
    }
    
    /// Get mechanism configuration.
    pub fn get_mechanism_config(&self, mechanism: &str) -> Option<&MechanismConfig> {
        self.mechanisms.get(mechanism)
    }
}

impl BackendConfig for MockConfig {
    fn validate(&self) -> Result<(), BackendError> {
        if self.max_sessions == 0 {
            return Err(BackendError::configuration_error(
                "max_sessions must be greater than 0".to_string()
            ));
        }
        
        if self.max_objects == 0 {
            return Err(BackendError::configuration_error(
                "max_objects must be greater than 0".to_string()
            ));
        }
        
        if self.default_pin.is_empty() {
            return Err(BackendError::configuration_error(
                "default_pin cannot be empty".to_string()
            ));
        }
        
        if self.token_label.is_empty() {
            return Err(BackendError::configuration_error(
                "token_label cannot be empty".to_string()
            ));
        }
        
        // Validate mechanism configurations
        for (name, config) in &self.mechanisms {
            if let (Some(min), Some(max)) = (config.min_key_size, config.max_key_size) {
                if min > max {
                    return Err(BackendError::configuration_error(
                        format!("Invalid key size range for mechanism {}: min {} > max {}", 
                               name, min, max)
                    ));
                }
            }
        }
        
        Ok(())
    }
    
    fn backend_type(&self) -> BackendType {
        BackendType::Mock
    }
    
    fn clone_config(&self) -> Box<dyn BackendConfig> {
        Box::new(self.clone())
    }
    
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl Default for MechanismConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_key_size: None,
            max_key_size: None,
            default_key_size: None,
            supports_encryption: false,
            supports_decryption: false,
            supports_signing: false,
            supports_verification: false,
            supports_key_generation: false,
            supports_key_derivation: false,
        }
    }
}

impl MechanismConfig {
    /// Create a new mechanism configuration.
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Enable the mechanism.
    pub fn enabled(mut self) -> Self {
        self.enabled = true;
        self
    }
    
    /// Disable the mechanism.
    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }
    
    /// Set key size range.
    pub fn with_key_size_range(mut self, min: u32, max: u32) -> Self {
        self.min_key_size = Some(min);
        self.max_key_size = Some(max);
        self
    }
    
    /// Set default key size.
    pub fn with_default_key_size(mut self, size: u32) -> Self {
        self.default_key_size = Some(size);
        self
    }
    
    /// Enable encryption support.
    pub fn with_encryption(mut self) -> Self {
        self.supports_encryption = true;
        self.supports_decryption = true;
        self
    }
    
    /// Enable signing support.
    pub fn with_signing(mut self) -> Self {
        self.supports_signing = true;
        self.supports_verification = true;
        self
    }
    
    /// Enable key generation support.
    pub fn with_key_generation(mut self) -> Self {
        self.supports_key_generation = true;
        self
    }
    
    /// Enable key derivation support.
    pub fn with_key_derivation(mut self) -> Self {
        self.supports_key_derivation = true;
        self
    }
}