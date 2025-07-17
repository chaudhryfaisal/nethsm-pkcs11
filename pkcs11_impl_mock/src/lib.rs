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
//!
//! # Usage
//!
//! This crate can be used as a drop-in replacement for any PKCS#11 provider in testing
//! environments. It exports the standard PKCS#11 C API functions and can be loaded by
//! any PKCS#11-compatible application.
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

// Re-export core functionality (excluding API functions to avoid conflicts)
pub use pkcs11_core::{
    data,
    utils,
};

// Re-export main types for convenience
pub use backend::MockBackend;
use pkcs11_core::backend::CryptoBackend;
pub use config::MockConfig;
pub use error::{MockError, MockResult};

use lazy_static::lazy_static;
use std::sync::{Arc, Mutex};
use pkcs11_core::backend::SyncBackendWrapper;

// Global backend instance
lazy_static! {
    static ref MOCK_BACKEND: Arc<Mutex<Option<SyncBackendWrapper>>> = Arc::new(Mutex::new(None));
}

/// Initialize the mock PKCS#11 provider with the given configuration.
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

/// Get the backend instance.
fn get_backend() -> Option<Arc<Mutex<Option<SyncBackendWrapper>>>> {
    let backend = MOCK_BACKEND.lock().unwrap();
    if backend.is_some() {
        // Return a reference to the existing backend instead of cloning
        Some(MOCK_BACKEND.clone())
    } else {
        None
    }
}

// PKCS#11 C API exports
// These functions provide the standard PKCS#11 interface that can be loaded by any
// PKCS#11-compatible application.

// Mock-specific initialization logic will be handled through the backend registry
// All PKCS#11 C API functions are provided by pkcs11_core
pub use pkcs11_core::api::*;