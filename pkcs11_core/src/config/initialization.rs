use std::{
    path::PathBuf,
    sync::{Arc, Condvar, Mutex},
    thread::available_parallelism,
    time::Duration,
};

use crate::{
    backend::{registry::{create_backend}, BackendConfig, SyncBackendWrapper},
    data::BACKEND,
};

use super::{
    config_file::{config_files, ConfigError},
};
use log::{error, info};

const DEFAULT_USER_AGENT: &str = concat!("pkcs11-rs/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, thiserror::Error)]
pub enum InitializationError {
    #[error("Failed to load config")]
    Config(crate::config::config_file::ConfigError),
    #[error("Failed to load certificates")]
    NoCerts,
    #[error("No operator or administrator for slot: {0}")]
    NoUser(String),
    #[error("No instance given for a slot")]
    NoInstance,
    #[error("Backend initialization failed: {0}")]
    Backend(crate::backend::BackendError),
}


pub fn initialize_with_configs(
    configs: Result<Vec<(Vec<u8>, PathBuf)>, ConfigError>,
) -> Result<(), InitializationError> {
    // Use a closure called immediately so that `?` can be used
    let config_res = (|| {
        let configs_files = configs.map_err(InitializationError::Config)?;

        let config = crate::config::config_file::merge_configurations(
            configs_files.iter().map(|(data, _)| &**data),
        )
        .map_err(InitializationError::Config)?;
        let file_paths: Vec<PathBuf> = configs_files.into_iter().map(|(_, path)| path).collect();
        Ok((config, file_paths))
    })();

    crate::config::logging::configure_logger(&config_res);
    let (config, _) = config_res?;

    info!("Loaded configuration with {} slots", config.slots.len());

    // Initialize built-in backends (now handled by individual backend crates)
    crate::backend::registry::initialize_builtin_backends()
        .map_err(InitializationError::Backend)?;

    // Backend initialization is now handled by specific backend implementations
    // The core library no longer directly creates backend instances
    info!("Core initialization complete. Backend registration handled by implementation crates.");

    Ok(())
}

pub fn initialize() -> Result<(), InitializationError> {
    initialize_with_configs(config_files())
}

// NetHSM-specific TLS and slot configuration moved to pkcs11_impl_nethsm_sdk

#[cfg(test)]
mod tests {
    use super::*;

    use config_file::CertificateFormat;

    /// Test various good and bad configs for panics
    #[test]
    fn test_config_loading() {
        let config_content = r#"
slots:
  - label: LocalHSM
    description: Local HSM (docker)
    operator:
      username: "operator"
      password: "opPassphrase"
    administrator:
      username: "admin"
      password: "Administrator"
    instances:
      - url: "https://localhost:8443/api/v1"
        danger_insecure_cert: true  
        sha256_fingerprints: 
          - "31:92:8E:A4:5E:16:5C:A7:33:44:E8:E9:8E:64:C4:AE:7B:2A:57:E5:77:43:49:F3:69:C9:8F:C4:2F:3A:3B:6E"
    certificate_format: DER
    retries: 
      count: 10
      delay_seconds: 1
    timeout_seconds: 10
            "#;
        let config_path = "/path/to/config.conf";
        let configs = vec![(config_content.into(), config_path.into())];

        let device = initialize_with_configs(Ok(configs)).unwrap();
        assert_eq!(device.slots[0].certificate_format, CertificateFormat::Der);

        let config_bad_fingerprint_content = r#"
slots:
  - label: LocalHSM
    description: Local HSM (docker)
    operator:
      username: "operator"
      password: "opPassphrase"
    administrator:
      username: "admin"
      password: "Administrator"
    instances:
      - url: "https://localhost:8443/api/v1"
        danger_insecure_cert: true  
        sha256_fingerprints: 
          - "31:92:8E:A4:5Eeeeee:16:5C:A7:33:44:E8:E9:8E:64:C4:AE:7B:2A:57:E5:77:43:49:F3:69:C9:8F:C4:2F:3A:3B:6E"
    retries: 
      count: 10
      delay_seconds: 1
    timeout_seconds: 10
            "#;
        let configs_bad_fingerprint =
            vec![(config_bad_fingerprint_content.into(), config_path.into())];
        assert!(initialize_with_configs(Ok(configs_bad_fingerprint)).is_err());
        let config_bad_yml_content = r#"
dict:
bad_yml
            "#;
        let configs_bad_yml = vec![(config_bad_yml_content.into(), config_path.into())];
        assert!(initialize_with_configs(Ok(configs_bad_yml)).is_err());
    }
}
