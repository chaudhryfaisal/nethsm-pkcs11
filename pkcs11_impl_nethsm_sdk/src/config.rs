//! NetHSM-specific configuration structures and implementation.
//!
//! This module provides configuration types that are specific to NetHSM
//! and implements the BackendConfig trait from pkcs11_core.

use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use pkcs11_core::{
    backend::{
        error::BackendError,
        types::{BackendConfig, BackendType},
    },
};
use serde::{Deserialize, Serialize};

use crate::network::{TcpConnector, RustlsConnector};

/// NetHSM backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetHsmConfig {
    /// NetHSM instance URLs
    pub urls: Vec<String>,
    /// Enable set attribute value operations
    pub enable_set_attribute_value: bool,
    /// Connection timeout in seconds
    pub timeout_seconds: Option<u64>,
    /// Maximum idle connections
    pub max_idle_connections: Option<usize>,
    /// Allow insecure certificates (for testing)
    pub danger_insecure_cert: bool,
    /// SHA256 fingerprints for certificate validation
    pub sha256_fingerprints: Vec<String>,
    /// Retry configuration
    pub retries: Option<RetryConfig>,
    /// TCP keepalive configuration
    pub tcp_keepalive: Option<TcpKeepaliveConfig>,
    /// Maximum idle duration for connections
    pub connections_max_idle_duration: Option<u64>,
    /// User configurations
    pub operator: Option<UserConfig>,
    pub administrator: Option<UserConfig>,
}

/// Retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Number of retries
    pub count: u32,
    /// Delay between retries in seconds
    pub delay_seconds: u64,
}

/// TCP keepalive configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpKeepaliveConfig {
    /// Keepalive time in seconds
    pub time_seconds: u64,
    /// Keepalive interval in seconds
    pub interval_seconds: u64,
    /// Number of keepalive retries
    pub retries: u32,
}

/// User configuration for authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfig {
    /// Username
    pub username: String,
    /// Password (optional, can be set at runtime)
    pub password: Option<String>,
}

/// NetHSM instance data for connection management
#[derive(Debug, Clone)]
pub struct InstanceData {
    pub agent: Arc<ArcSwap<ureq::Agent>>,
    pub agent_config: ureq::config::Config,
    pub tcp_connector: TcpConnector,
    pub rustls_connector: RustlsConnector,
    config: nethsm_sdk_rs::apis::configuration::Configuration,
    pub state: Arc<std::sync::RwLock<InstanceState>>,
}

impl InstanceData {
    /// Get the NetHSM SDK configuration
    pub fn config(&self) -> &nethsm_sdk_rs::apis::configuration::Configuration {
        &self.config
    }
}

/// Instance state for connection management
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum InstanceState {
    #[default]
    Working,
    Failed {
        retry_count: u8,
        last_retry_at: std::time::Instant,
    },
}

/// NetHSM slot configuration
#[derive(Debug, Clone)]
pub struct Slot {
    pub label: String,
    pub retries: Option<RetryConfig>,
    pub description: Option<String>,
    pub instances: Vec<InstanceData>,
    pub operator: Option<UserConfig>,
    pub administrator: Option<UserConfig>,
    pub instance_balancer: Arc<std::sync::atomic::AtomicUsize>,
    pub timeout_seconds: Option<u64>,
    pub tcp_keepalive: Option<TcpKeepaliveConfig>,
    pub connections_max_idle_duration: Option<u64>,
}

/// Device configuration containing all slots
#[derive(Debug, Clone)]
pub struct Device {
    pub slots: Vec<Arc<Slot>>,
    pub enable_set_attribute_value: bool,
}

impl NetHsmConfig {
    /// Create a new NetHSM configuration
    pub fn new(urls: Vec<String>) -> Self {
        Self {
            urls,
            enable_set_attribute_value: false,
            timeout_seconds: None,
            max_idle_connections: None,
            danger_insecure_cert: false,
            sha256_fingerprints: Vec::new(),
            retries: None,
            tcp_keepalive: None,
            connections_max_idle_duration: None,
            operator: None,
            administrator: None,
        }
    }

    /// Create a new NetHSM configuration with custom settings
    pub fn with_settings(
        urls: Vec<String>,
        enable_set_attribute_value: bool,
        timeout_seconds: Option<u64>,
        max_idle_connections: Option<usize>,
        danger_insecure_cert: bool,
    ) -> Self {
        Self {
            urls,
            enable_set_attribute_value,
            timeout_seconds,
            max_idle_connections,
            danger_insecure_cert,
            sha256_fingerprints: Vec::new(),
            retries: None,
            tcp_keepalive: None,
            connections_max_idle_duration: None,
            operator: None,
            administrator: None,
        }
    }

    /// Get the NetHSM URLs
    pub fn urls(&self) -> &[String] {
        &self.urls
    }

    /// Check if set attribute value is enabled
    pub fn is_set_attribute_value_enabled(&self) -> bool {
        self.enable_set_attribute_value
    }

    /// Get timeout in seconds
    pub fn timeout_seconds(&self) -> Option<u64> {
        self.timeout_seconds
    }

    /// Get maximum idle connections
    pub fn max_idle_connections(&self) -> Option<usize> {
        self.max_idle_connections
    }

    /// Check if insecure certificates are allowed
    pub fn is_insecure_cert_allowed(&self) -> bool {
        self.danger_insecure_cert
    }
}

impl BackendConfig for NetHsmConfig {
    fn validate(&self) -> Result<(), BackendError> {
        // Validate that we have at least one URL
        if self.urls.is_empty() {
            return Err(BackendError::configuration_error("No NetHSM URLs configured"));
        }

        // Validate each URL
        for (index, url) in self.urls.iter().enumerate() {
            // Check URL is not empty
            if url.trim().is_empty() {
                return Err(BackendError::configuration_error(format!(
                    "URL {} is empty",
                    index
                )));
            }

            // Validate URL format (basic check)
            if !url.starts_with("http://") && !url.starts_with("https://") {
                return Err(BackendError::configuration_error(format!(
                    "URL {} has invalid format: {}",
                    index, url
                )));
            }
        }

        // Validate timeout if specified
        if let Some(timeout) = self.timeout_seconds {
            if timeout == 0 {
                return Err(BackendError::configuration_error(
                    "Timeout cannot be zero",
                ));
            }
        }

        // Validate max idle connections if specified
        if let Some(max_idle) = self.max_idle_connections {
            if max_idle == 0 {
                return Err(BackendError::configuration_error(
                    "Max idle connections cannot be zero",
                ));
            }
        }

        Ok(())
    }

    fn backend_type(&self) -> BackendType {
        BackendType::NetHsm
    }

    fn clone_config(&self) -> Box<dyn BackendConfig> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Builder for NetHSM configuration
pub struct NetHsmConfigBuilder {
    urls: Vec<String>,
    enable_set_attribute_value: bool,
    timeout_seconds: Option<u64>,
    max_idle_connections: Option<usize>,
    danger_insecure_cert: bool,
}

impl NetHsmConfigBuilder {
    /// Create a new configuration builder
    pub fn new() -> Self {
        Self {
            urls: Vec::new(),
            enable_set_attribute_value: false,
            timeout_seconds: None,
            max_idle_connections: None,
            danger_insecure_cert: false,
        }
    }

    /// Add a NetHSM URL
    pub fn add_url<S: Into<String>>(mut self, url: S) -> Self {
        self.urls.push(url.into());
        self
    }

    /// Set multiple URLs
    pub fn urls(mut self, urls: Vec<String>) -> Self {
        self.urls = urls;
        self
    }

    /// Enable set attribute value operations
    pub fn enable_set_attribute_value(mut self, enable: bool) -> Self {
        self.enable_set_attribute_value = enable;
        self
    }

    /// Set timeout in seconds
    pub fn timeout_seconds(mut self, timeout: u64) -> Self {
        self.timeout_seconds = Some(timeout);
        self
    }

    /// Set maximum idle connections
    pub fn max_idle_connections(mut self, max_idle: usize) -> Self {
        self.max_idle_connections = Some(max_idle);
        self
    }

    /// Allow insecure certificates (for testing)
    pub fn danger_insecure_cert(mut self, allow: bool) -> Self {
        self.danger_insecure_cert = allow;
        self
    }

    /// Build the configuration
    pub fn build(self) -> Result<NetHsmConfig, BackendError> {
        let config = NetHsmConfig::with_settings(
            self.urls,
            self.enable_set_attribute_value,
            self.timeout_seconds,
            self.max_idle_connections,
            self.danger_insecure_cert,
        );
        config.validate()?;
        Ok(config)
    }
}

impl Default for NetHsmConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper function to create a NetHSM configuration from URLs
pub fn create_nethsm_config(urls: Vec<String>) -> Result<NetHsmConfig, BackendError> {
    let config = NetHsmConfig::new(urls);
    config.validate()?;
    Ok(config)
}

/// Helper function to create a NetHSM configuration with custom settings
pub fn create_nethsm_config_with_settings(
    urls: Vec<String>,
    enable_set_attribute_value: bool,
    timeout_seconds: Option<u64>,
    max_idle_connections: Option<usize>,
    danger_insecure_cert: bool,
) -> Result<NetHsmConfig, BackendError> {
    let config = NetHsmConfig::with_settings(
        urls,
        enable_set_attribute_value,
        timeout_seconds,
        max_idle_connections,
        danger_insecure_cert,
    );
    config.validate()?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nethsm_config_creation() {
        let urls = vec!["https://localhost:8443/api/v1".to_string()];
        let config = NetHsmConfig::new(urls);
        assert_eq!(config.backend_type(), BackendType::NetHsm);
        assert!(!config.is_set_attribute_value_enabled());
        assert_eq!(config.urls().len(), 1);
    }

    #[test]
    fn test_nethsm_config_builder() {
        let config = NetHsmConfigBuilder::new()
            .add_url("https://localhost:8443/api/v1")
            .enable_set_attribute_value(true)
            .timeout_seconds(30)
            .max_idle_connections(10)
            .danger_insecure_cert(true)
            .build()
            .unwrap();

        assert!(config.is_set_attribute_value_enabled());
        assert_eq!(config.timeout_seconds(), Some(30));
        assert_eq!(config.max_idle_connections(), Some(10));
        assert!(config.is_insecure_cert_allowed());
    }

    #[test]
    fn test_config_validation_empty_urls() {
        let config = NetHsmConfig::new(vec![]);
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_invalid_url() {
        let config = NetHsmConfig::new(vec!["invalid-url".to_string()]);
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_valid_url() {
        let config = NetHsmConfig::new(vec!["https://localhost:8443/api/v1".to_string()]);
        assert!(config.validate().is_ok());
    }
}