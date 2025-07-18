//! Mock implementation for PKCS#11
//!
//! This crate provides a comprehensive mock implementation of the PKCS#11 interface
//! for testing and development purposes. It simulates HSM behavior without requiring
//! actual hardware, providing deterministic and configurable mock operations.
//!
//! # Features
//!
//! - **Complete PKCS#11 Implementation**: Implements all standard PKCS#11 operations
//! - **Deterministic Behavior**: Configurable deterministic mode for reproducible testing
//! - **Error Injection**: Configurable error injection for testing error handling paths
//! - **In-Memory Storage**: Fast in-memory storage for keys, certificates, and sessions
//! - **Mock Cryptography**: Realistic mock cryptographic operations with predictable outputs
//! - **Configurable Mechanisms**: Support for RSA, ECDSA, AES, and hash mechanisms
//! - **Session Management**: Complete session lifecycle management with authentication
//! - **Self-Contained**: Completely independent of NetHSM or other backend implementations
//!
//! # Usage
//!
//! This crate can be used as a drop-in replacement for any PKCS#11 provider in testing
//! environments. It exports the standard PKCS#11 C API functions and can be loaded by
//! any PKCS#11-compatible application.
//!
//! ## Basic Usage
//!
//! ```rust
//! use pkcs11_impl_mock::{MockBackend, MockConfig};
//! use pkcs11_core::backend::CryptoBackend;
//!
//! // Create a mock configuration
//! let config = MockConfig::default()
//!     .with_deterministic(true)
//!     .with_max_sessions(10);
//!
//! // Initialize the mock backend
//! let backend = MockBackend::initialize(config).unwrap();
//! ```
//!
//! ## Dynamic Registration
//!
//! The mock provider can be dynamically registered with the core backend registry:
//!
//! ```rust
//! use pkcs11_impl_mock::{MockBackend, MockConfig};
//! use pkcs11_core::backend::registry::BackendRegistry;
//!
//! // Register the mock backend
//! let config = MockConfig::default();
//! BackendRegistry::register_backend("mock", Box::new(config));
//! ```
//!
//! # Security Notice
//!
//! **WARNING**: This is a mock implementation intended for testing and development only.
//! It does not provide real cryptographic security and should never be used in production
//! environments where actual security is required.

pub mod backend;
pub mod config;
pub mod crypto;
pub mod error;
pub mod storage;

// Re-export main types for convenience
pub use backend::MockBackend;
pub use config::MockConfig;
pub use error::{MockError, MockResult};

// Re-export core functionality for convenience
pub use pkcs11_core::backend::{CryptoBackend, BackendConfig, BackendType};

use lazy_static::lazy_static;
use std::sync::{Arc, Mutex};
use pkcs11_core::backend::SyncBackendWrapper;

// Global backend instance for C API compatibility
lazy_static! {
    static ref MOCK_BACKEND: Arc<Mutex<Option<SyncBackendWrapper>>> = Arc::new(Mutex::new(None));
}

/// Initialize the mock PKCS#11 provider with the given configuration.
///
/// This function creates a new mock backend instance and stores it globally
/// for use by the PKCS#11 C API functions.
pub fn initialize_mock_provider(config: MockConfig) -> MockResult<()> {
    let backend = MockBackend::initialize(config)?;
    let wrapper = SyncBackendWrapper::new(Box::new(backend));
    let mut global_backend = MOCK_BACKEND.lock().unwrap();
    *global_backend = Some(wrapper);
    Ok(())
}

/// Initialize the mock PKCS#11 provider with default configuration.
pub fn initialize_mock_provider_default() -> MockResult<()> {
    initialize_mock_provider(MockConfig::default())
}

/// Get the global backend instance.
///
/// This function is used internally by the PKCS#11 C API functions to access
/// the mock backend instance.
pub fn get_backend() -> Option<Arc<Mutex<Option<SyncBackendWrapper>>>> {
    let backend = MOCK_BACKEND.lock().unwrap();
    if backend.is_some() {
        Some(MOCK_BACKEND.clone())
    } else {
        None
    }
}

/// Finalize the mock provider and clean up resources.
pub fn finalize_mock_provider() -> MockResult<()> {
    let mut global_backend = MOCK_BACKEND.lock().unwrap();
    if let Some(mut backend) = global_backend.take() {
        backend.finalize().map_err(|e| MockError::Internal(e.to_string()))?;
    }
    Ok(())
}

/// Create a new mock backend factory function for dynamic registration.
///
/// This function can be used to register the mock backend with the core
/// backend registry system.
pub fn create_mock_backend(config: Box<dyn BackendConfig>) -> Result<Box<dyn pkcs11_core::backend::ErasedCryptoBackend + Send + Sync>, Box<dyn std::error::Error + Send + Sync>> {
    let mock_config = config.as_any()
        .downcast_ref::<MockConfig>()
        .ok_or("Invalid configuration type for mock backend")?;
    
    let backend = MockBackend::initialize(mock_config.clone())
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
    
    Ok(Box::new(backend))
}

// PKCS#11 C API exports
// These functions provide the standard PKCS#11 interface that can be loaded by any
// PKCS#11-compatible application.

// All PKCS#11 C API functions are provided by pkcs11_core
pub use pkcs11_core::api::*;

#[cfg(test)]
mod tests {
    use super::*;
    use pkcs11_core::backend::types::*;

    #[test]
    fn test_mock_backend_creation() {
        let config = MockConfig::default();
        let backend = MockBackend::initialize(config).unwrap();
        assert!(backend.is_initialized());
    }

    #[test]
    fn test_mock_config_validation() {
        let config = MockConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_backend_type() {
        let config = MockConfig::default();
        assert_eq!(config.backend_type(), BackendType::Mock);
    }

    #[test]
    fn test_provider_initialization() {
        let config = MockConfig::default();
        assert!(initialize_mock_provider(config).is_ok());
        assert!(finalize_mock_provider().is_ok());
    }
}