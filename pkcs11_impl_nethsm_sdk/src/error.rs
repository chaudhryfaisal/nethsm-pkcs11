//! NetHSM-specific error handling and conversion to backend errors.
//!
//! This module provides error types that are specific to NetHSM operations
//! and converts them to the unified backend error types used by pkcs11_core.

use pkcs11_core::backend::error::BackendError;
use thiserror::Error;

/// NetHSM-specific error types
#[derive(Debug, Error)]
pub enum NetHsmError {
    /// NetHSM SDK API error
    #[error("NetHSM API error: {0}")]
    ApiError(#[from] nethsm_sdk_rs::apis::Error<serde_json::Value>),

    /// Authentication failed
    #[error("Authentication failed: {message}")]
    AuthenticationFailed { message: String },

    /// Key operation failed
    #[error("Key operation failed: {operation} - {reason}")]
    KeyOperationFailed { operation: String, reason: String },

    /// Certificate operation failed
    #[error("Certificate operation failed: {operation} - {reason}")]
    CertificateOperationFailed { operation: String, reason: String },

    /// Cryptographic operation failed
    #[error("Cryptographic operation failed: {operation} - {reason}")]
    CryptoOperationFailed { operation: String, reason: String },

    /// Configuration error
    #[error("Configuration error: {reason}")]
    ConfigurationError { reason: String },

    /// Network communication error
    #[error("Network communication error: {reason}")]
    NetworkError { reason: String },

    /// Invalid data format
    #[error("Invalid data format: {reason}")]
    InvalidDataFormat { reason: String },

    /// Device not ready
    #[error("Device not ready: {reason}")]
    DeviceNotReady { reason: String },

    /// Permission denied
    #[error("Permission denied: {operation}")]
    PermissionDenied { operation: String },

    /// Resource not found
    #[error("Resource not found: {resource_type} - {resource_id}")]
    ResourceNotFound {
        resource_type: String,
        resource_id: String,
    },

    /// Invalid mechanism
    #[error("Invalid mechanism: {mechanism}")]
    InvalidMechanism { mechanism: String },

    /// Unsupported mechanism
    #[error("Unsupported mechanism: {0}")]
    UnsupportedMechanism(String),

    /// Session error
    #[error("Session error: {reason}")]
    SessionError { reason: String },

    /// Internal error
    #[error("Internal NetHSM error: {reason}")]
    InternalError { reason: String },
}

impl NetHsmError {
    /// Create an authentication failed error
    pub fn authentication_failed<S: Into<String>>(message: S) -> Self {
        Self::AuthenticationFailed {
            message: message.into(),
        }
    }

    /// Create a key operation failed error
    pub fn key_operation_failed<S: Into<String>>(operation: S, reason: S) -> Self {
        Self::KeyOperationFailed {
            operation: operation.into(),
            reason: reason.into(),
        }
    }

    /// Create a configuration error
    pub fn configuration_error<S: Into<String>>(reason: S) -> Self {
        Self::ConfigurationError {
            reason: reason.into(),
        }
    }

    /// Create a network error
    pub fn network_error<S: Into<String>>(reason: S) -> Self {
        Self::NetworkError {
            reason: reason.into(),
        }
    }

    /// Create a resource not found error
    pub fn resource_not_found<S: Into<String>>(resource_type: S, resource_id: S) -> Self {
        Self::ResourceNotFound {
            resource_type: resource_type.into(),
            resource_id: resource_id.into(),
        }
    }

    /// Create an internal error
    pub fn internal_error<S: Into<String>>(reason: S) -> Self {
        Self::InternalError {
            reason: reason.into(),
        }
    }
}

/// Convert NetHSM errors to backend errors
impl From<NetHsmError> for BackendError {
    fn from(err: NetHsmError) -> Self {
        match err {
            NetHsmError::ApiError(api_err) => {
                // Convert specific API errors to appropriate backend errors
                match api_err {
                    nethsm_sdk_rs::apis::Error::ResponseError(resp) => {
                        match resp.status {
                            401 | 403 => BackendError::AuthenticationFailed {
                                message: "Invalid credentials".to_string(),
                            },
                            404 => BackendError::KeyNotFound {
                                key_id: "unknown".to_string(),
                            },
                            412 => BackendError::TokenNotPresent { slot_id: 0 },
                            _ => BackendError::NetworkError {
                                reason: format!("HTTP {}: {}", resp.status, 
                                    String::from_utf8_lossy(&resp.content)),
                            },
                        }
                    }
                    nethsm_sdk_rs::apis::Error::Ureq(ureq_err) => BackendError::NetworkError {
                        reason: ureq_err.to_string(),
                    },
                    nethsm_sdk_rs::apis::Error::Io(io_err) => BackendError::NetworkError {
                        reason: io_err.to_string(),
                    },
                    nethsm_sdk_rs::apis::Error::Serde(serde_err) => BackendError::InternalError {
                        reason: format!("Serialization error: {}", serde_err),
                    },
                    _ => BackendError::InternalError {
                        reason: format!("NetHSM API error: {}", api_err),
                    },
                }
            }
            NetHsmError::AuthenticationFailed { message } => {
                BackendError::AuthenticationFailed { message }
            }
            NetHsmError::KeyOperationFailed { operation, reason } => {
                BackendError::CryptoOperationFailed { operation, reason }
            }
            NetHsmError::CertificateOperationFailed { operation, reason } => {
                BackendError::CryptoOperationFailed { operation, reason }
            }
            NetHsmError::CryptoOperationFailed { operation, reason } => {
                BackendError::CryptoOperationFailed { operation, reason }
            }
            NetHsmError::ConfigurationError { reason } => {
                BackendError::ConfigurationError { reason }
            }
            NetHsmError::NetworkError { reason } => BackendError::NetworkError { reason },
            NetHsmError::InvalidDataFormat { reason } => BackendError::InvalidKeyMaterial { reason },
            NetHsmError::DeviceNotReady { reason } => BackendError::TokenNotPresent { slot_id: 0 },
            NetHsmError::PermissionDenied { operation } => BackendError::PermissionDenied {
                reason: format!("Operation not permitted: {}", operation),
            },
            NetHsmError::ResourceNotFound {
                resource_type,
                resource_id,
            } => {
                if resource_type == "key" {
                    BackendError::KeyNotFound { key_id: resource_id }
                } else if resource_type == "certificate" {
                    BackendError::CertificateNotFound { cert_id: resource_id }
                } else {
                    BackendError::InternalError {
                        reason: format!("{} not found: {}", resource_type, resource_id),
                    }
                }
            }
            NetHsmError::InvalidMechanism { mechanism } => {
                BackendError::MechanismNotSupported { mechanism }
            }
            NetHsmError::UnsupportedMechanism(mechanism) => {
                BackendError::MechanismNotSupported { mechanism }
            }
            NetHsmError::SessionError { reason } => BackendError::InvalidSession {
                session_id: reason,
            },
            NetHsmError::InternalError { reason } => BackendError::InternalError { reason },
        }
    }
}

/// Result type for NetHSM operations
pub type NetHsmResult<T> = Result<T, NetHsmError>;

/// Helper function to convert API errors with context
pub fn convert_api_error<T>(
    result: Result<T, nethsm_sdk_rs::apis::Error<serde_json::Value>>,
    operation: &str,
) -> NetHsmResult<T> {
    result.map_err(|err| {
        log::error!("NetHSM API error in {}: {:?}", operation, err);
        NetHsmError::ApiError(err)
    })
}

/// Generic helper function to convert any NetHSM API error to our error type
pub fn convert_nethsm_result<T, E>(
    result: Result<nethsm_sdk_rs::apis::ResponseContent<T>, nethsm_sdk_rs::apis::Error<E>>,
    operation: &str,
) -> NetHsmResult<nethsm_sdk_rs::apis::ResponseContent<T>>
where
    E: std::fmt::Debug,
{
    result.map_err(|err| {
        log::error!("NetHSM API error in {}: {:?}", operation, err);
        // Create a simplified error for now
        NetHsmError::InternalError {
            reason: format!("NetHSM API error in {}: {:?}", operation, err),
        }
    })
}

/// Helper function to create a key operation error
pub fn key_operation_error<S: Into<String>>(operation: S, reason: S) -> NetHsmError {
    NetHsmError::key_operation_failed(operation, reason)
}

/// Helper function to create a crypto operation error
pub fn crypto_operation_error<S: Into<String>>(operation: S, reason: S) -> NetHsmError {
    NetHsmError::CryptoOperationFailed {
        operation: operation.into(),
        reason: reason.into(),
    }
}