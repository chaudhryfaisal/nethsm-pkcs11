//! Backend abstraction layer for PKCS#11 implementations.
//!
//! This module provides a unified interface for different cryptographic backends,
//! allowing the PKCS#11 implementation to work with various HSM types and
//! cryptographic providers.

use std::sync::{Arc, Mutex, PoisonError};

// Re-export existing modules for backward compatibility
pub mod db;
pub mod decrypt;
pub mod encrypt;
pub mod events;
pub mod key;
pub mod login;
pub mod mechanism;
pub mod object;
pub mod session;
pub mod sign;
pub mod slot;

// New abstraction layer modules
pub mod error;
pub mod types;
pub mod registry;
pub mod nethsm;

pub use error::{BackendError, BackendResult, ConfigError};
pub use types::*;

// Re-export existing types for backward compatibility
use self::{
    db::object::ObjectKind,
    login::{LoginError, UserMode},
    mechanism::{MechMode, Mechanism},
};
use cryptoki_sys::{
    CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_VALUE_INVALID, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_INVALID,
    CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_REMOVED, CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_KEY_HANDLE_INVALID, CKR_MECHANISM_INVALID, CKR_OPERATION_ACTIVE,
    CKR_OPERATION_NOT_INITIALIZED, CKR_TOKEN_NOT_PRESENT, CKR_USER_NOT_LOGGED_IN,
    CK_ATTRIBUTE_TYPE, CK_OBJECT_HANDLE, CK_RV, CK_ATTRIBUTE, CK_ULONG,
};
use log::error;

#[cfg(feature = "nethsm-backend")]
use nethsm_sdk_rs::apis;

/// Main trait for cryptographic backend implementations.
///
/// This trait defines the interface that all backend implementations must provide.
/// It covers the full lifecycle of cryptographic operations including authentication,
/// key management, and cryptographic operations.
pub trait CryptoBackend: Send + Sync {
    /// Backend-specific configuration type
    type Config: BackendConfig;

    /// Backend-specific error type that can be converted to BackendError
    type Error: Into<BackendError> + Send + Sync;

    // === Lifecycle Management ===

    /// Initialize the backend with the given configuration
    fn initialize(config: Self::Config) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Finalize the backend and clean up resources
    fn finalize(&mut self) -> Result<(), Self::Error>;

    /// Check if the backend is initialized and ready for operations
    fn is_initialized(&self) -> bool;

    // === Slot and Token Management ===

    /// Get the list of available slots
    fn get_slot_list(&self, token_present: bool) -> Result<Vec<SlotId>, Self::Error>;

    /// Get information about a specific slot
    fn get_slot_info(&self, slot_id: SlotId) -> Result<SlotInfo, Self::Error>;

    /// Get information about the token in a specific slot
    fn get_token_info(&self, slot_id: SlotId) -> Result<TokenInfo, Self::Error>;

    /// Get device information for a slot
    fn get_device_info(&self, slot_id: SlotId) -> Result<DeviceInfo, Self::Error>;

    /// Get system state for a slot
    fn get_system_state(&self, slot_id: SlotId) -> Result<SystemState, Self::Error>;

    /// Get the list of supported mechanisms for a slot
    fn get_mechanism_list(&self, slot_id: SlotId) -> Result<Vec<MechanismType>, Self::Error>;

    /// Get information about a specific mechanism
    fn get_mechanism_info(
        &self,
        slot_id: SlotId,
        mechanism_type: MechanismType,
    ) -> Result<MechanismInfo, Self::Error>;

    // === Session Management ===

    /// Open a new session
    fn open_session(
        &mut self,
        slot_id: SlotId,
        flags: SessionFlags,
    ) -> Result<SessionHandle, Self::Error>;

    /// Close a session
    fn close_session(&mut self, session: SessionHandle) -> Result<(), Self::Error>;

    /// Close all sessions for a slot
    fn close_all_sessions(&mut self, slot_id: SlotId) -> Result<(), Self::Error>;

    /// Get session information
    fn get_session_info(&self, session: SessionHandle) -> Result<SessionInfo, Self::Error>;

    // === Authentication ===

    /// Authenticate a user and create a backend session
    fn login(
        &mut self,
        session: SessionHandle,
        user_type: UserType,
        pin: &str,
    ) -> Result<(), Self::Error>;

    /// Log out a user
    fn logout(&mut self, session: SessionHandle) -> Result<(), Self::Error>;

    /// Initialize the user PIN
    fn init_pin(&mut self, session: SessionHandle, pin: &str) -> Result<(), Self::Error>;

    /// Set/change the user PIN
    fn set_pin(
        &mut self,
        session: SessionHandle,
        old_pin: &str,
        new_pin: &str,
    ) -> Result<(), Self::Error>;

    // === Key Management ===

    /// Generate a new key
    fn generate_key(
        &mut self,
        session: SessionHandle,
        spec: &KeyGenerationSpec,
    ) -> Result<KeyHandle, Self::Error>;

    /// Generate a key pair
    fn generate_key_pair(
        &mut self,
        session: SessionHandle,
        spec: &KeyGenerationSpec,
    ) -> Result<(KeyHandle, KeyHandle), Self::Error>;

    /// Import a key
    fn import_key(
        &mut self,
        session: SessionHandle,
        key_data: &KeyImportData,
    ) -> Result<KeyHandle, Self::Error>;

    /// Delete a key
    fn delete_key(&mut self, session: SessionHandle, key: KeyHandle) -> Result<(), Self::Error>;

    /// List keys matching the given filter
    fn list_keys(
        &self,
        session: SessionHandle,
        filter: Option<&KeyFilter>,
    ) -> Result<Vec<KeyInfo>, Self::Error>;

    /// Get information about a specific key
    fn get_key_info(
        &self,
        session: SessionHandle,
        key: KeyHandle,
    ) -> Result<KeyInfo, Self::Error>;

    // === Cryptographic Operations ===

    /// Sign data with a key
    fn sign(
        &mut self,
        session: SessionHandle,
        key: KeyHandle,
        mechanism: &SignMechanism,
        data: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;

    /// Verify a signature
    fn verify(
        &mut self,
        session: SessionHandle,
        key: KeyHandle,
        mechanism: &SignMechanism,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, Self::Error>;

    /// Encrypt data
    fn encrypt(
        &mut self,
        session: SessionHandle,
        key: KeyHandle,
        mechanism: &EncryptMechanism,
        data: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;

    /// Decrypt data
    fn decrypt(
        &mut self,
        session: SessionHandle,
        key: KeyHandle,
        mechanism: &EncryptMechanism,
        data: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;

    /// Compute a digest
    fn digest(
        &mut self,
        session: SessionHandle,
        mechanism: &MechanismType,
        data: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;

    /// Generate random data
    fn generate_random(
        &mut self,
        session: SessionHandle,
        length: usize,
    ) -> Result<Vec<u8>, Self::Error>;
}

/// Thread-safe wrapper for backend implementations
pub struct ThreadSafeBackend<T: CryptoBackend> {
    backend: Arc<Mutex<T>>,
}

impl<T: CryptoBackend> ThreadSafeBackend<T> {
    /// Create a new thread-safe wrapper
    pub fn new(backend: T) -> Self {
        Self {
            backend: Arc::new(Mutex::new(backend)),
        }
    }

    /// Execute a closure with mutable access to the backend
    pub fn with_backend<F, R>(&self, f: F) -> Result<R, BackendError>
    where
        F: FnOnce(&mut T) -> Result<R, T::Error>,
    {
        let mut backend = self.backend.lock().map_err(|_| {
            BackendError::internal_error("Failed to acquire backend lock")
        })?;
        f(&mut *backend).map_err(Into::into)
    }

    /// Execute a closure with read-only access to the backend
    pub fn with_backend_ref<F, R>(&self, f: F) -> Result<R, BackendError>
    where
        F: FnOnce(&T) -> Result<R, T::Error>,
    {
        let backend = self.backend.lock().map_err(|_| {
            BackendError::internal_error("Failed to acquire backend lock")
        })?;
        f(&*backend).map_err(Into::into)
    }
}

/// Trait object for type-erased backend
pub trait ErasedCryptoBackend: Send + Sync {
    /// Check if the backend is initialized and ready for operations
    fn is_initialized(&self) -> bool;

    /// Finalize the backend and clean up resources
    fn finalize(&mut self) -> Result<(), BackendError>;

    // === Slot and Token Management ===

    /// Get the list of available slots
    fn get_slot_list(&self, token_present: bool) -> Result<Vec<SlotId>, BackendError>;

    /// Get information about a specific slot
    fn get_slot_info(&self, slot_id: SlotId) -> Result<SlotInfo, BackendError>;

    /// Get information about the token in a specific slot
    fn get_token_info(&self, slot_id: SlotId) -> Result<TokenInfo, BackendError>;

    /// Get device information for a slot
    fn get_device_info(&self, slot_id: SlotId) -> Result<DeviceInfo, BackendError>;

    /// Get system state for a slot
    fn get_system_state(&self, slot_id: SlotId) -> Result<SystemState, BackendError>;

    /// Get the list of supported mechanisms for a slot
    fn get_mechanism_list(&self, slot_id: SlotId) -> Result<Vec<MechanismType>, BackendError>;

    /// Get information about a specific mechanism
    fn get_mechanism_info(
        &self,
        slot_id: SlotId,
        mechanism_type: MechanismType,
    ) -> Result<MechanismInfo, BackendError>;

    // === Session Management ===

    /// Open a new session
    fn open_session(
        &mut self,
        slot_id: SlotId,
        flags: SessionFlags,
    ) -> Result<SessionHandle, BackendError>;

    /// Close a session
    fn close_session(&mut self, session: SessionHandle) -> Result<(), BackendError>;

    /// Close all sessions for a slot
    fn close_all_sessions(&mut self, slot_id: SlotId) -> Result<(), BackendError>;

    /// Get session information
    fn get_session_info(&self, session: SessionHandle) -> Result<SessionInfo, BackendError>;

    // === Authentication ===

    /// Authenticate a user and create a backend session
    fn login(
        &mut self,
        session: SessionHandle,
        user_type: UserType,
        pin: &str,
    ) -> Result<(), BackendError>;

    /// Log out a user
    fn logout(&mut self, session: SessionHandle) -> Result<(), BackendError>;

    /// Initialize the user PIN
    fn init_pin(&mut self, session: SessionHandle, pin: &str) -> Result<(), BackendError>;

    /// Set/change the user PIN
    fn set_pin(
        &mut self,
        session: SessionHandle,
        old_pin: &str,
        new_pin: &str,
    ) -> Result<(), BackendError>;

    // === Key Management ===

    /// Generate a new key
    fn generate_key(
        &mut self,
        session: SessionHandle,
        spec: &KeyGenerationSpec,
    ) -> Result<KeyHandle, BackendError>;

    /// Generate a key pair
    fn generate_key_pair(
        &mut self,
        session: SessionHandle,
        spec: &KeyGenerationSpec,
    ) -> Result<(KeyHandle, KeyHandle), BackendError>;

    /// Import a key
    fn import_key(
        &mut self,
        session: SessionHandle,
        key_data: &KeyImportData,
    ) -> Result<KeyHandle, BackendError>;

    /// Delete a key
    fn delete_key(&mut self, session: SessionHandle, key: KeyHandle) -> Result<(), BackendError>;

    /// List keys matching the given filter
    fn list_keys(
        &self,
        session: SessionHandle,
        filter: Option<&KeyFilter>,
    ) -> Result<Vec<KeyInfo>, BackendError>;

    /// Get information about a specific key
    fn get_key_info(
        &self,
        session: SessionHandle,
        key: KeyHandle,
    ) -> Result<KeyInfo, BackendError>;

    // === Cryptographic Operations ===

    /// Sign data with a key
    fn sign(
        &mut self,
        session: SessionHandle,
        key: KeyHandle,
        mechanism: &SignMechanism,
        data: &[u8],
    ) -> Result<Vec<u8>, BackendError>;

    /// Verify a signature
    fn verify(
        &mut self,
        session: SessionHandle,
        key: KeyHandle,
        mechanism: &SignMechanism,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, BackendError>;

    /// Encrypt data
    fn encrypt(
        &mut self,
        session: SessionHandle,
        key: KeyHandle,
        mechanism: &EncryptMechanism,
        data: &[u8],
    ) -> Result<Vec<u8>, BackendError>;

    /// Decrypt data
    fn decrypt(
        &mut self,
        session: SessionHandle,
        key: KeyHandle,
        mechanism: &EncryptMechanism,
        data: &[u8],
    ) -> Result<Vec<u8>, BackendError>;

    /// Compute a digest
    fn digest(
        &mut self,
        session: SessionHandle,
        mechanism: &MechanismType,
        data: &[u8],
    ) -> Result<Vec<u8>, BackendError>;

    /// Generate random data
    fn generate_random(
        &mut self,
        session: SessionHandle,
        length: usize,
    ) -> Result<Vec<u8>, BackendError>;
}

/// Implement ErasedCryptoBackend for any CryptoBackend
impl<T: CryptoBackend> ErasedCryptoBackend for T
where
    T::Error: Into<BackendError>,
{
    fn is_initialized(&self) -> bool {
        CryptoBackend::is_initialized(self)
    }

    fn finalize(&mut self) -> Result<(), BackendError> {
        CryptoBackend::finalize(self).map_err(Into::into)
    }

    fn get_slot_list(&self, token_present: bool) -> Result<Vec<SlotId>, BackendError> {
        CryptoBackend::get_slot_list(self, token_present).map_err(Into::into)
    }

    fn get_slot_info(&self, slot_id: SlotId) -> Result<SlotInfo, BackendError> {
        CryptoBackend::get_slot_info(self, slot_id).map_err(Into::into)
    }

    fn get_token_info(&self, slot_id: SlotId) -> Result<TokenInfo, BackendError> {
        CryptoBackend::get_token_info(self, slot_id).map_err(Into::into)
    }

    fn get_device_info(&self, slot_id: SlotId) -> Result<DeviceInfo, BackendError> {
        CryptoBackend::get_device_info(self, slot_id).map_err(Into::into)
    }

    fn get_system_state(&self, slot_id: SlotId) -> Result<SystemState, BackendError> {
        CryptoBackend::get_system_state(self, slot_id).map_err(Into::into)
    }

    fn get_mechanism_list(&self, slot_id: SlotId) -> Result<Vec<MechanismType>, BackendError> {
        CryptoBackend::get_mechanism_list(self, slot_id).map_err(Into::into)
    }

    fn get_mechanism_info(
        &self,
        slot_id: SlotId,
        mechanism_type: MechanismType,
    ) -> Result<MechanismInfo, BackendError> {
        CryptoBackend::get_mechanism_info(self, slot_id, mechanism_type).map_err(Into::into)
    }

    fn open_session(
        &mut self,
        slot_id: SlotId,
        flags: SessionFlags,
    ) -> Result<SessionHandle, BackendError> {
        CryptoBackend::open_session(self, slot_id, flags).map_err(Into::into)
    }

    fn close_session(&mut self, session: SessionHandle) -> Result<(), BackendError> {
        CryptoBackend::close_session(self, session).map_err(Into::into)
    }

    fn close_all_sessions(&mut self, slot_id: SlotId) -> Result<(), BackendError> {
        CryptoBackend::close_all_sessions(self, slot_id).map_err(Into::into)
    }

    fn get_session_info(&self, session: SessionHandle) -> Result<SessionInfo, BackendError> {
        CryptoBackend::get_session_info(self, session).map_err(Into::into)
    }

    fn login(
        &mut self,
        session: SessionHandle,
        user_type: UserType,
        pin: &str,
    ) -> Result<(), BackendError> {
        CryptoBackend::login(self, session, user_type, pin).map_err(Into::into)
    }

    fn logout(&mut self, session: SessionHandle) -> Result<(), BackendError> {
        CryptoBackend::logout(self, session).map_err(Into::into)
    }

    fn init_pin(&mut self, session: SessionHandle, pin: &str) -> Result<(), BackendError> {
        CryptoBackend::init_pin(self, session, pin).map_err(Into::into)
    }

    fn set_pin(
        &mut self,
        session: SessionHandle,
        old_pin: &str,
        new_pin: &str,
    ) -> Result<(), BackendError> {
        CryptoBackend::set_pin(self, session, old_pin, new_pin).map_err(Into::into)
    }

    fn generate_key(
        &mut self,
        session: SessionHandle,
        spec: &KeyGenerationSpec,
    ) -> Result<KeyHandle, BackendError> {
        CryptoBackend::generate_key(self, session, spec).map_err(Into::into)
    }

    fn generate_key_pair(
        &mut self,
        session: SessionHandle,
        spec: &KeyGenerationSpec,
    ) -> Result<(KeyHandle, KeyHandle), BackendError> {
        CryptoBackend::generate_key_pair(self, session, spec).map_err(Into::into)
    }

    fn import_key(
        &mut self,
        session: SessionHandle,
        key_data: &KeyImportData,
    ) -> Result<KeyHandle, BackendError> {
        CryptoBackend::import_key(self, session, key_data).map_err(Into::into)
    }

    fn delete_key(&mut self, session: SessionHandle, key: KeyHandle) -> Result<(), BackendError> {
        CryptoBackend::delete_key(self, session, key).map_err(Into::into)
    }

    fn list_keys(
        &self,
        session: SessionHandle,
        filter: Option<&KeyFilter>,
    ) -> Result<Vec<KeyInfo>, BackendError> {
        CryptoBackend::list_keys(self, session, filter).map_err(Into::into)
    }

    fn get_key_info(
        &self,
        session: SessionHandle,
        key: KeyHandle,
    ) -> Result<KeyInfo, BackendError> {
        CryptoBackend::get_key_info(self, session, key).map_err(Into::into)
    }

    fn sign(
        &mut self,
        session: SessionHandle,
        key: KeyHandle,
        mechanism: &SignMechanism,
        data: &[u8],
    ) -> Result<Vec<u8>, BackendError> {
        CryptoBackend::sign(self, session, key, mechanism, data).map_err(Into::into)
    }

    fn verify(
        &mut self,
        session: SessionHandle,
        key: KeyHandle,
        mechanism: &SignMechanism,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, BackendError> {
        CryptoBackend::verify(self, session, key, mechanism, data, signature).map_err(Into::into)
    }

    fn encrypt(
        &mut self,
        session: SessionHandle,
        key: KeyHandle,
        mechanism: &EncryptMechanism,
        data: &[u8],
    ) -> Result<Vec<u8>, BackendError> {
        CryptoBackend::encrypt(self, session, key, mechanism, data).map_err(Into::into)
    }

    fn decrypt(
        &mut self,
        session: SessionHandle,
        key: KeyHandle,
        mechanism: &EncryptMechanism,
        data: &[u8],
    ) -> Result<Vec<u8>, BackendError> {
        CryptoBackend::decrypt(self, session, key, mechanism, data).map_err(Into::into)
    }

    fn digest(
        &mut self,
        session: SessionHandle,
        mechanism: &MechanismType,
        data: &[u8],
    ) -> Result<Vec<u8>, BackendError> {
        CryptoBackend::digest(self, session, mechanism, data).map_err(Into::into)
    }

    fn generate_random(
        &mut self,
        session: SessionHandle,
        length: usize,
    ) -> Result<Vec<u8>, BackendError> {
        CryptoBackend::generate_random(self, session, length).map_err(Into::into)
    }
}

/// Synchronous wrapper for CryptoBackend trait
///
/// This wrapper provides a synchronous interface to the async CryptoBackend trait,
/// which is necessary for the PKCS#11 C API compatibility.
pub struct SyncBackendWrapper {
    backend: Box<dyn ErasedCryptoBackend + Send + Sync>,
}

impl SyncBackendWrapper {
    /// Create a new synchronous wrapper
    pub fn new(backend: Box<dyn ErasedCryptoBackend + Send + Sync>) -> Self {
        Self { backend }
    }

    // === Lifecycle Management ===

    /// Check if the backend is initialized and ready for operations
    pub fn is_initialized(&self) -> bool {
        self.backend.is_initialized()
    }

    /// Finalize the backend and clean up resources
    pub fn finalize(&mut self) -> Result<(), BackendError> {
        self.backend.finalize()
    }

    // === Slot and Token Management ===

    /// Get the list of available slots
    pub fn get_slot_list(&self, token_present: bool) -> Result<Vec<SlotId>, BackendError> {
        self.backend.get_slot_list(token_present)
    }

    /// Get information about a specific slot
    pub fn get_slot_info(&self, slot_id: SlotId) -> Result<SlotInfo, BackendError> {
        self.backend.get_slot_info(slot_id)
    }

    /// Get information about the token in a specific slot
    pub fn get_token_info(&self, slot_id: SlotId) -> Result<TokenInfo, BackendError> {
        self.backend.get_token_info(slot_id)
    }

    /// Get device information for a slot
    pub fn get_device_info(&self, slot_id: SlotId) -> Result<DeviceInfo, BackendError> {
        self.backend.get_device_info(slot_id)
    }

    /// Get system state for a slot
    pub fn get_system_state(&self, slot_id: SlotId) -> Result<SystemState, BackendError> {
        self.backend.get_system_state(slot_id)
    }

    /// Get the list of supported mechanisms for a slot
    pub fn get_mechanism_list(&self, slot_id: SlotId) -> Result<Vec<MechanismType>, BackendError> {
        self.backend.get_mechanism_list(slot_id)
    }

    /// Get information about a specific mechanism
    pub fn get_mechanism_info(
        &self,
        slot_id: SlotId,
        mechanism_type: MechanismType,
    ) -> Result<MechanismInfo, BackendError> {
        self.backend.get_mechanism_info(slot_id, mechanism_type)
    }

    // === Session Management ===

    /// Open a new session
    pub fn open_session(
        &mut self,
        slot_id: SlotId,
        flags: SessionFlags,
    ) -> Result<SessionHandle, BackendError> {
        self.backend.open_session(slot_id, flags)
    }

    /// Close a session
    pub fn close_session(&mut self, session: SessionHandle) -> Result<(), BackendError> {
        self.backend.close_session(session)
    }

    /// Close all sessions for a slot
    pub fn close_all_sessions(&mut self, slot_id: SlotId) -> Result<(), BackendError> {
        self.backend.close_all_sessions(slot_id)
    }

    /// Get session information
    pub fn get_session_info(&self, session: SessionHandle) -> Result<SessionInfo, BackendError> {
        self.backend.get_session_info(session)
    }

    // === Authentication ===

    /// Authenticate a user and create a backend session
    pub fn login(
        &mut self,
        session: SessionHandle,
        user_type: UserType,
        pin: &str,
    ) -> Result<(), BackendError> {
        self.backend.login(session, user_type, pin)
    }

    /// Log out a user
    pub fn logout(&mut self, session: SessionHandle) -> Result<(), BackendError> {
        self.backend.logout(session)
    }

    /// Initialize the user PIN
    pub fn init_pin(&mut self, session: SessionHandle, pin: &str) -> Result<(), BackendError> {
        self.backend.init_pin(session, pin)
    }

    /// Set/change the user PIN
    pub fn set_pin(
        &mut self,
        session: SessionHandle,
        old_pin: &str,
        new_pin: &str,
    ) -> Result<(), BackendError> {
        self.backend.set_pin(session, old_pin, new_pin)
    }

    // === Key Management ===

    /// Generate a new key
    pub fn generate_key(
        &mut self,
        session: SessionHandle,
        spec: &KeyGenerationSpec,
    ) -> Result<KeyHandle, BackendError> {
        self.backend.generate_key(session, spec)
    }

    /// Generate a key pair
    pub fn generate_key_pair(
        &mut self,
        session: SessionHandle,
        spec: &KeyGenerationSpec,
    ) -> Result<(KeyHandle, KeyHandle), BackendError> {
        self.backend.generate_key_pair(session, spec)
    }

    /// Import a key
    pub fn import_key(
        &mut self,
        session: SessionHandle,
        key_data: &KeyImportData,
    ) -> Result<KeyHandle, BackendError> {
        self.backend.import_key(session, key_data)
    }

    /// Delete a key
    pub fn delete_key(&mut self, session: SessionHandle, key: KeyHandle) -> Result<(), BackendError> {
        self.backend.delete_key(session, key)
    }

    /// List keys matching the given filter
    pub fn list_keys(
        &self,
        session: SessionHandle,
        filter: Option<&KeyFilter>,
    ) -> Result<Vec<KeyInfo>, BackendError> {
        self.backend.list_keys(session, filter)
    }

    /// Get information about a specific key
    pub fn get_key_info(
        &self,
        session: SessionHandle,
        key: KeyHandle,
    ) -> Result<KeyInfo, BackendError> {
        self.backend.get_key_info(session, key)
    }

    // === Cryptographic Operations ===

    /// Sign data with a key
    pub fn sign(
        &mut self,
        session: SessionHandle,
        key: KeyHandle,
        mechanism: &SignMechanism,
        data: &[u8],
    ) -> Result<Vec<u8>, BackendError> {
        self.backend.sign(session, key, mechanism, data)
    }

    /// Verify a signature
    pub fn verify(
        &mut self,
        session: SessionHandle,
        key: KeyHandle,
        mechanism: &SignMechanism,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, BackendError> {
        self.backend.verify(session, key, mechanism, data, signature)
    }

    /// Encrypt data
    pub fn encrypt(
        &mut self,
        session: SessionHandle,
        key: KeyHandle,
        mechanism: &EncryptMechanism,
        data: &[u8],
    ) -> Result<Vec<u8>, BackendError> {
        self.backend.encrypt(session, key, mechanism, data)
    }

    /// Decrypt data
    pub fn decrypt(
        &mut self,
        session: SessionHandle,
        key: KeyHandle,
        mechanism: &EncryptMechanism,
        data: &[u8],
    ) -> Result<Vec<u8>, BackendError> {
        self.backend.decrypt(session, key, mechanism, data)
    }

    /// Compute a digest
    pub fn digest(
        &mut self,
        session: SessionHandle,
        mechanism: &MechanismType,
        data: &[u8],
    ) -> Result<Vec<u8>, BackendError> {
        self.backend.digest(session, mechanism, data)
    }

    /// Generate random data
    pub fn generate_random(
        &mut self,
        session: SessionHandle,
        length: usize,
    ) -> Result<Vec<u8>, BackendError> {
        self.backend.generate_random(session, length)
    }
}

// === Legacy Error Types for Backward Compatibility ===

#[cfg(feature = "nethsm-backend")]
#[derive(Debug, Clone)]
pub struct ResponseContent {
    pub status: u16,
    pub content: String,
}

#[cfg(feature = "nethsm-backend")]
#[derive(Debug)]
pub enum ApiError {
    Ureq(String),
    Serde(serde_json::Error),
    Io(std::io::Error),
    ResponseError(ResponseContent),
    InstanceRemoved,
    NoInstance,
    StringParse(std::string::FromUtf8Error),
}

#[cfg(feature = "nethsm-backend")]
impl<T> From<apis::Error<T>> for ApiError {
    fn from(err: apis::Error<T>) -> Self {
        match err {
            apis::Error::Ureq(e) => ApiError::Ureq(e.to_string()),
            apis::Error::Serde(e) => ApiError::Serde(e),
            apis::Error::Io(e) => ApiError::Io(e),
            apis::Error::ResponseError(resp) => ApiError::ResponseError(ResponseContent {
                status: resp.status,
                content: String::from_utf8(resp.content).unwrap_or_else(|e| {
                    error!(
                        "Unable to parse response content into string: {:?}",
                        e.as_bytes()
                    );
                    String::default()
                }),
            }),
            apis::Error::StringParse(e) => ApiError::StringParse(e),
            apis::Error::Multipart { field: _, error } => ApiError::Io(error),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Der(der::Error),
    Pem(pem_rfc7468::Error),
    NotLoggedIn(UserMode),
    InvalidObjectHandle(CK_OBJECT_HANDLE),
    InvalidMechanism((String, ObjectKind), Mechanism),
    InvalidAttribute(CK_ATTRIBUTE_TYPE),
    MissingAttribute(CK_ATTRIBUTE_TYPE),
    ObjectClassNotSupported,
    InvalidMechanismMode(MechMode, Mechanism),
    #[cfg(feature = "nethsm-backend")]
    Api(ApiError),
    Base64(base64ct::Error),
    StringParse(std::string::FromUtf8Error),
    Login(LoginError),
    OperationNotInitialized,
    LibraryNotInitialized,
    OperationActive,
    KeyField(String),
    DbLock,
    InvalidDataLength,
    InvalidData,
    InvalidEncryptedDataLength,
}

#[cfg(feature = "nethsm-backend")]
impl From<ApiError> for Error {
    fn from(err: ApiError) -> Self {
        Error::Api(err)
    }
}

impl<T> From<PoisonError<T>> for Error {
    fn from(_: PoisonError<T>) -> Self {
        Error::DbLock
    }
}

#[cfg(feature = "nethsm-backend")]
impl<T> From<apis::Error<T>> for Error {
    fn from(err: apis::Error<T>) -> Self {
        Error::Api(err.into())
    }
}

impl From<base64ct::Error> for Error {
    fn from(err: base64ct::Error) -> Self {
        Error::Base64(err)
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(err: std::string::FromUtf8Error) -> Self {
        Error::StringParse(err)
    }
}

impl From<Error> for CK_RV {
    fn from(err: Error) -> Self {
        error!("{err}");
        match err {
            Error::Der(_) => CKR_DEVICE_ERROR,
            Error::Pem(_) => CKR_DEVICE_ERROR,
            Error::InvalidEncryptedDataLength => CKR_ENCRYPTED_DATA_LEN_RANGE,
            Error::InvalidData => CKR_DATA_INVALID,
            Error::InvalidDataLength => CKR_DATA_LEN_RANGE,
            Error::InvalidObjectHandle(_) => CKR_KEY_HANDLE_INVALID,
            Error::OperationNotInitialized => CKR_OPERATION_NOT_INITIALIZED,
            Error::LibraryNotInitialized => CKR_CRYPTOKI_NOT_INITIALIZED,
            Error::DbLock => CKR_DEVICE_ERROR,
            Error::KeyField(_) => CKR_DEVICE_ERROR,
            Error::OperationActive => CKR_OPERATION_ACTIVE,
            Error::Login(e) => e.into(),
            Error::InvalidAttribute(_) => CKR_ATTRIBUTE_VALUE_INVALID,
            Error::ObjectClassNotSupported => CKR_ATTRIBUTE_VALUE_INVALID,
            Error::MissingAttribute(_) => CKR_ARGUMENTS_BAD,
            Error::NotLoggedIn(_) => CKR_USER_NOT_LOGGED_IN,
            Error::InvalidMechanism(_, _) => CKR_MECHANISM_INVALID,
            Error::InvalidMechanismMode(_, _) => CKR_MECHANISM_INVALID,
            Error::Base64(_) | Error::StringParse(_) => CKR_DEVICE_ERROR,
            #[cfg(feature = "nethsm-backend")]
            Error::Api(err) => match err {
                ApiError::NoInstance => CKR_TOKEN_NOT_PRESENT,
                ApiError::Ureq(_) => CKR_DEVICE_ERROR,
                ApiError::Io(_) => CKR_DEVICE_ERROR,
                ApiError::Serde(_) => CKR_DEVICE_ERROR,
                ApiError::ResponseError(resp) => match resp.status {
                    404 => CKR_KEY_HANDLE_INVALID,
                    401 | 403 => CKR_USER_NOT_LOGGED_IN,
                    412 => CKR_TOKEN_NOT_PRESENT,
                    _ => CKR_DEVICE_ERROR,
                },
                ApiError::StringParse(_) => CKR_DEVICE_ERROR,
                ApiError::InstanceRemoved => CKR_DEVICE_REMOVED,
            },
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let msg = match self {
            Error::Der(err) => format!("DER error: {err:?}"),
            Error::Pem(err) => format!("PEM error: {err:?}"),
            Error::InvalidEncryptedDataLength => "Invalid encrypted data length".to_string(),
            Error::InvalidData => "Invalid input data".to_string(),
            Error::InvalidDataLength => "Invalid input data length".to_string(),
            Error::InvalidObjectHandle(handle) => {
                format!("Object handle does not exist: {handle}")
            }
            Error::OperationNotInitialized => "Operation not initialized".to_string(),
            Error::LibraryNotInitialized => "Library not initialized".to_string(),
            Error::DbLock => "Internal mutex lock error".to_string(),
            Error::KeyField(field) => {
                format!("Key field {field} received from the NetHSM is not valid")
            }
            Error::OperationActive => "An operation is already active for this session".to_string(),
            Error::Login(err) => err.to_string(),
            Error::NotLoggedIn(mode) => {
                format!("The module needs to be logged in as {mode:?}, check the configuration")
            }
            Error::InvalidMechanism(obj, mech) => {
                format!(
                    "The mechanism {:?} not supported for {:?} {}",
                    mech, obj.1, obj.0
                )
            }
            Error::InvalidAttribute(attr) => format!("Invalid attribute: {attr:?}"),
            Error::MissingAttribute(attr) => format!("Missing attribute: {attr:?}"),
            Error::ObjectClassNotSupported => "Object class not supported".to_string(),
            Error::InvalidMechanismMode(mode, mechanism) => {
                format!("Unable to use mechanim {mechanism:?} for {mode:?}")
            }
            #[cfg(feature = "nethsm-backend")]
            Error::Api(err) => match err {
                ApiError::NoInstance => "No valid instance in the slot".to_string(),
                ApiError::Ureq(err) => format!("Request error : {err}"),
                ApiError::Serde(err) => format!("Serde error: {err:?}"),
                ApiError::Io(err) => format!("IO error: {err:?}"),
                ApiError::ResponseError(resp) => match resp.status {
                    404 => "Key not found".to_string(),
                    401 | 403 => "Invalid credentials".to_string(),
                    412 => "The NetHSM is not set up properly".to_string(),
                    _ => format!("Api error: {resp:?}"),
                },
                ApiError::StringParse(err) => format!("String parse error: {err:?}"),
                ApiError::InstanceRemoved => "Failed to connect to instance".to_string(),
            },
            Error::Base64(err) => format!("Base64 Decode error: {err:?}"),
            Error::StringParse(err) => format!("String parse error: {err:?}"),
        };
        write!(f, "{msg}")
    }
}
