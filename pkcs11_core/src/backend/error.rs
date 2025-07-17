//! Unified error handling for the backend abstraction layer.
//!
//! This module provides a comprehensive error type system that can be converted
//! to PKCS#11 error codes while maintaining detailed error information for debugging.

use cryptoki_sys::CK_RV;
use std::fmt;
use thiserror::Error;

/// Unified backend error type
#[derive(Debug, Error)]
pub enum BackendError {
    /// Authentication failed
    #[error("Authentication failed: {message}")]
    AuthenticationFailed { message: String },

    /// Key not found
    #[error("Key not found: {key_id}")]
    KeyNotFound { key_id: String },

    /// Certificate not found
    #[error("Certificate not found: {cert_id}")]
    CertificateNotFound { cert_id: String },

    /// Mechanism not supported
    #[error("Mechanism not supported: {mechanism}")]
    MechanismNotSupported { mechanism: String },

    /// Invalid key specification
    #[error("Invalid key specification: {reason}")]
    InvalidKeySpec { reason: String },

    /// Invalid key material
    #[error("Invalid key material: {reason}")]
    InvalidKeyMaterial { reason: String },

    /// Cryptographic operation failed
    #[error("Cryptographic operation failed: {operation} - {reason}")]
    CryptoOperationFailed { operation: String, reason: String },

    /// Backend configuration error
    #[error("Backend configuration error: {reason}")]
    ConfigurationError { reason: String },

    /// Network error
    #[error("Network error: {reason}")]
    NetworkError { reason: String },

    /// Permission denied
    #[error("Permission denied: {reason}")]
    PermissionDenied { reason: String },

    /// Backend not initialized
    #[error("Backend not initialized")]
    NotInitialized,

    /// Session invalid or expired
    #[error("Session invalid or expired: {session_id}")]
    InvalidSession { session_id: String },

    /// Slot not found
    #[error("Slot not found: {slot_id}")]
    SlotNotFound { slot_id: u32 },

    /// Token not present
    #[error("Token not present in slot: {slot_id}")]
    TokenNotPresent { slot_id: u32 },

    /// User already logged in
    #[error("User already logged in")]
    UserAlreadyLoggedIn,

    /// User not logged in
    #[error("User not logged in")]
    UserNotLoggedIn,

    /// PIN incorrect
    #[error("PIN incorrect")]
    PinIncorrect,

    /// PIN locked
    #[error("PIN locked")]
    PinLocked,

    /// Object handle invalid
    #[error("Object handle invalid: {handle}")]
    ObjectHandleInvalid { handle: u64 },

    /// Attribute type invalid
    #[error("Attribute type invalid: {attr_type}")]
    AttributeTypeInvalid { attr_type: u32 },

    /// Attribute value invalid
    #[error("Attribute value invalid: {attr_type}")]
    AttributeValueInvalid { attr_type: u32 },

    /// Data length range error
    #[error("Data length range error: expected {expected}, got {actual}")]
    DataLengthRange { expected: String, actual: usize },

    /// Buffer too small
    #[error("Buffer too small: need {needed}, have {available}")]
    BufferTooSmall { needed: usize, available: usize },

    /// Operation not supported
    #[error("Operation not supported: {operation}")]
    OperationNotSupported { operation: String },

    /// Internal backend error
    #[error("Internal backend error: {reason}")]
    InternalError { reason: String },
}

impl BackendError {
    /// Create an authentication failed error
    pub fn authentication_failed<S: Into<String>>(message: S) -> Self {
        Self::AuthenticationFailed {
            message: message.into(),
        }
    }

    /// Create a key not found error
    pub fn key_not_found<S: Into<String>>(key_id: S) -> Self {
        Self::KeyNotFound {
            key_id: key_id.into(),
        }
    }

    /// Create a configuration error
    pub fn configuration_error<S: Into<String>>(reason: S) -> Self {
        Self::ConfigurationError {
            reason: reason.into(),
        }
    }

    /// Create an internal error
    pub fn internal_error<S: Into<String>>(reason: S) -> Self {
        Self::InternalError {
            reason: reason.into(),
        }
    }

    /// Create a communication error
    pub fn communication_error<S: Into<String>>(message: S) -> Self {
        Self::NetworkError {
            reason: message.into(),
        }
    }

    /// Create an invalid slot error
    pub fn invalid_slot(slot_id: u32) -> Self {
        Self::SlotNotFound { slot_id }
    }

    /// Create an unsupported mechanism error
    pub fn unsupported_mechanism(mechanism: u32) -> Self {
        Self::MechanismNotSupported {
            mechanism: mechanism.to_string(),
        }
    }

    /// Create an unsupported operation error
    pub fn unsupported_operation<S: Into<String>>(operation: S) -> Self {
        Self::OperationNotSupported {
            operation: operation.into(),
        }
    }

    /// Create an initialization error
    pub fn initialization_error<S: Into<String>>(message: S) -> Self {
        Self::InternalError {
            reason: format!("Initialization error: {}", message.into()),
        }
    }

    /// Create a not supported error
    pub fn not_supported<S: Into<String>>(message: S) -> Self {
        Self::OperationNotSupported {
            operation: message.into(),
        }
    }
}

/// Conversion to PKCS#11 error codes
impl From<BackendError> for CK_RV {
    fn from(err: BackendError) -> Self {
        use cryptoki_sys::*;
        match err {
            BackendError::AuthenticationFailed { .. } => CKR_USER_NOT_LOGGED_IN,
            BackendError::KeyNotFound { .. } => CKR_KEY_HANDLE_INVALID,
            BackendError::CertificateNotFound { .. } => CKR_OBJECT_HANDLE_INVALID,
            BackendError::MechanismNotSupported { .. } => CKR_MECHANISM_INVALID,
            BackendError::InvalidKeySpec { .. } => CKR_ATTRIBUTE_VALUE_INVALID,
            BackendError::InvalidKeyMaterial { .. } => CKR_ATTRIBUTE_VALUE_INVALID,
            BackendError::CryptoOperationFailed { .. } => CKR_FUNCTION_FAILED,
            BackendError::ConfigurationError { .. } => CKR_GENERAL_ERROR,
            BackendError::NetworkError { .. } => CKR_DEVICE_ERROR,
            BackendError::PermissionDenied { .. } => CKR_USER_NOT_LOGGED_IN,
            BackendError::NotInitialized => CKR_CRYPTOKI_NOT_INITIALIZED,
            BackendError::InvalidSession { .. } => CKR_SESSION_HANDLE_INVALID,
            BackendError::SlotNotFound { .. } => CKR_SLOT_ID_INVALID,
            BackendError::TokenNotPresent { .. } => CKR_TOKEN_NOT_PRESENT,
            BackendError::UserAlreadyLoggedIn => CKR_USER_ALREADY_LOGGED_IN,
            BackendError::UserNotLoggedIn => CKR_USER_NOT_LOGGED_IN,
            BackendError::PinIncorrect => CKR_PIN_INCORRECT,
            BackendError::PinLocked => CKR_PIN_LOCKED,
            BackendError::ObjectHandleInvalid { .. } => CKR_OBJECT_HANDLE_INVALID,
            BackendError::AttributeTypeInvalid { .. } => CKR_ATTRIBUTE_TYPE_INVALID,
            BackendError::AttributeValueInvalid { .. } => CKR_ATTRIBUTE_VALUE_INVALID,
            BackendError::DataLengthRange { .. } => CKR_DATA_LEN_RANGE,
            BackendError::BufferTooSmall { .. } => CKR_BUFFER_TOO_SMALL,
            BackendError::OperationNotSupported { .. } => CKR_FUNCTION_NOT_SUPPORTED,
            BackendError::InternalError { .. } => CKR_GENERAL_ERROR,
        }
    }
}

/// Result type for backend operations
pub type BackendResult<T> = Result<T, BackendError>;

/// Configuration error type
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Missing required field
    #[error("Missing required field: {0}")]
    MissingField(String),

    /// Invalid value
    #[error("Invalid value for {field}: {value}")]
    InvalidValue { field: String, value: String },

    /// Validation failed
    #[error("Validation failed: {message}")]
    ValidationFailed { message: String },
}

impl From<ConfigError> for BackendError {
    fn from(err: ConfigError) -> Self {
        BackendError::ConfigurationError {
            reason: err.to_string(),
        }
    }
}