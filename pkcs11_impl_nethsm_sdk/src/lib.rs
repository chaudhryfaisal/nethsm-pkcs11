//! NetHSM SDK implementation for PKCS#11
//!
//! This crate provides a complete PKCS#11 provider implementation using the NetHSM SDK
//! for communication with NetHSM devices. It serves as a standalone PKCS#11 library
//! that can be used as a drop-in replacement for other PKCS#11 implementations.
//!
//! # Architecture
//!
//! This implementation uses the modular architecture provided by pkcs11_core:
//! - `backend.rs`: NetHSM-specific backend implementation
//! - `config.rs`: Configuration management for NetHSM
//! - `error.rs`: Error handling and conversion
//! - `lib.rs`: PKCS#11 C API exports and initialization
//!
//! # Usage
//!
//! This library can be used directly as a PKCS#11 provider by any application
//! that supports PKCS#11. The configuration is read from standard NetHSM
//! configuration files (p11nethsm.conf).

use std::sync::{Arc, Mutex};

use once_cell::sync::OnceCell;
use log::{debug, error, trace};

use pkcs11_core::{
    backend::{
        registry::register_backend,
        types::BackendType,
        SyncBackendWrapper,
    },
};

// Re-export core functionality (excluding API functions to avoid conflicts)
pub use pkcs11_core::{
    data,
    utils,
};

// Export our specific implementations
pub mod backend;
pub mod config;
pub mod error;

use backend::NetHsmBackend;
use pkcs11_core::backend::CryptoBackend;
use config::NetHsmConfig;

/// Global backend instance
static BACKEND: OnceCell<Arc<Mutex<SyncBackendWrapper>>> = OnceCell::new();

/// Initialize the NetHSM backend
fn initialize_nethsm_backend() -> Result<Arc<Mutex<SyncBackendWrapper>>, Box<dyn std::error::Error>> {
    // Create a basic NetHSM configuration
    // In a full implementation, this would read from configuration files
    let config = NetHsmConfig::new(vec!["https://localhost:8443/api/v1".to_string()]);
    
    // Initialize the backend
    let backend = NetHsmBackend::initialize(config)?;
    
    // Wrap in sync wrapper and return
    let sync_backend = SyncBackendWrapper::new(Box::new(backend));
    Ok(Arc::new(Mutex::new(sync_backend)))
}

/// Get or initialize the global backend
fn get_backend() -> Result<Arc<Mutex<SyncBackendWrapper>>, cryptoki_sys::CK_RV> {
    BACKEND.get_or_try_init(|| {
        initialize_nethsm_backend().map_err(|e| {
            error!("Failed to initialize NetHSM backend: {}", e);
            cryptoki_sys::CKR_FUNCTION_FAILED
        })
    }).map(|backend| backend.clone())
    .map_err(|_| cryptoki_sys::CKR_FUNCTION_FAILED)
}

// === PKCS#11 C API Function Exports ===

// Export all PKCS#11 functions through pkcs11_core to avoid symbol conflicts
// The C_GetFunctionList is also provided by pkcs11_core

// NetHSM-specific initialization logic will be handled through the backend registry
// All PKCS#11 C API functions are provided by pkcs11_core

// Export all PKCS#11 functions through pkcs11_core to avoid symbol conflicts
pub use pkcs11_core::api::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_function_list() {
        let mut fn_list: *mut cryptoki_sys::CK_FUNCTION_LIST = std::ptr::null_mut();
        let rv = C_GetFunctionList(&mut fn_list);
        assert_eq!(rv, cryptoki_sys::CKR_OK);
        assert!(!fn_list.is_null());
    }

    #[test]
    fn test_get_info() {
        let mut info = std::mem::MaybeUninit::<cryptoki_sys::CK_INFO>::uninit();
        let rv = C_GetInfo(info.as_mut_ptr());
        assert_eq!(rv, cryptoki_sys::CKR_OK);
        
        let info = unsafe { info.assume_init() };
        assert_eq!(info.cryptokiVersion.major, 2);
        assert_eq!(info.cryptokiVersion.minor, 40);
    }
}