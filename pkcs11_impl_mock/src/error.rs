//! Error handling for the mock PKCS#11 implementation.

use pkcs11_core::backend::error::BackendError;
use thiserror::Error;

/// Mock-specific error types that can be converted to backend errors.
#[derive(Error, Debug, Clone)]
pub enum MockError {
    #[error("Mock configuration error: {0}")]
    Configuration(String),
    
    #[error("Mock storage error: {0}")]
    Storage(String),
    
    #[error("Mock cryptographic operation failed: {0}")]
    Crypto(String),
    
    #[error("Mock session error: {0}")]
    Session(String),
    
    #[error("Mock object not found: {0}")]
    ObjectNotFound(String),
    
    #[error("Mock key generation failed: {0}")]
    KeyGeneration(String),
    
    #[error("Mock signature operation failed: {0}")]
    Signature(String),
    
    #[error("Mock encryption operation failed: {0}")]
    Encryption(String),
    
    #[error("Mock decryption operation failed: {0}")]
    Decryption(String),
    
    #[error("Mock digest operation failed: {0}")]
    Digest(String),
    
    #[error("Mock random number generation failed: {0}")]
    Random(String),
    
    #[error("Mock authentication failed: {0}")]
    Authentication(String),
    
    #[error("Mock operation not supported: {0}")]
    NotSupported(String),
    
    #[error("Mock internal error: {0}")]
    Internal(String),
    
    /// Injected error for testing error handling paths
    #[error("Injected error for testing: {0}")]
    Injected(String),
}

impl From<MockError> for BackendError {
    fn from(error: MockError) -> Self {
        match error {
            MockError::Configuration(msg) => BackendError::configuration_error(msg),
            MockError::Storage(msg) => BackendError::internal_error(format!("Storage: {}", msg)),
            MockError::Crypto(msg) => BackendError::internal_error(format!("Crypto: {}", msg)),
            MockError::Session(msg) => BackendError::internal_error(format!("Session: {}", msg)),
            MockError::ObjectNotFound(msg) => BackendError::key_not_found(msg),
            MockError::KeyGeneration(msg) => BackendError::internal_error(format!("Key generation: {}", msg)),
            MockError::Signature(msg) => BackendError::internal_error(format!("Signature: {}", msg)),
            MockError::Encryption(msg) => BackendError::internal_error(format!("Encryption: {}", msg)),
            MockError::Decryption(msg) => BackendError::internal_error(format!("Decryption: {}", msg)),
            MockError::Digest(msg) => BackendError::internal_error(format!("Digest: {}", msg)),
            MockError::Random(msg) => BackendError::internal_error(format!("Random: {}", msg)),
            MockError::Authentication(msg) => BackendError::authentication_failed(msg),
            MockError::NotSupported(msg) => BackendError::unsupported_operation(msg),
            MockError::Internal(msg) => BackendError::internal_error(msg),
            MockError::Injected(msg) => BackendError::internal_error(format!("Injected: {}", msg)),
        }
    }
}

/// Configuration for error injection in testing scenarios.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ErrorInjectionConfig {
    /// Probability of injecting errors (0.0 = never, 1.0 = always)
    pub error_probability: f64,
    
    /// Specific operations to inject errors for
    pub inject_on_operations: Vec<String>,
    
    /// Error message to inject
    pub error_message: String,
    
    /// Whether to inject errors deterministically based on operation count
    pub deterministic: bool,
    
    /// Operation count threshold for deterministic injection
    pub operation_threshold: u32,
}

impl ErrorInjectionConfig {
    /// Create a new error injection configuration.
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Set the error probability.
    pub fn with_probability(mut self, probability: f64) -> Self {
        self.error_probability = probability.clamp(0.0, 1.0);
        self
    }
    
    /// Add an operation to inject errors for.
    pub fn inject_on(mut self, operation: &str) -> Self {
        self.inject_on_operations.push(operation.to_string());
        self
    }
    
    /// Set the error message to inject.
    pub fn with_message(mut self, message: &str) -> Self {
        self.error_message = message.to_string();
        self
    }
    
    /// Enable deterministic error injection.
    pub fn deterministic(mut self, threshold: u32) -> Self {
        self.deterministic = true;
        self.operation_threshold = threshold;
        self
    }
    
    /// Check if an error should be injected for the given operation.
    pub fn should_inject(&self, operation: &str, operation_count: u32) -> bool {
        if self.inject_on_operations.is_empty() || 
           self.inject_on_operations.contains(&operation.to_string()) {
            if self.deterministic {
                operation_count >= self.operation_threshold
            } else {
                rand::random::<f64>() < self.error_probability
            }
        } else {
            false
        }
    }
    
    /// Create an injected error.
    pub fn create_error(&self) -> MockError {
        MockError::Injected(
            if self.error_message.is_empty() {
                "Test error injection".to_string()
            } else {
                self.error_message.clone()
            }
        )
    }
}

/// Result type for mock operations.
pub type MockResult<T> = Result<T, MockError>;