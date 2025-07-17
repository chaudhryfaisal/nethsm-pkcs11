//! Backend registry for dynamic backend management.
//!
//! This module provides a registry system for discovering, registering, and
//! instantiating different cryptographic backends at runtime.

use super::{BackendConfig, BackendError, BackendResult, BackendType, ErasedCryptoBackend};
use super::nethsm::{NetHsmBackend, NetHsmBackendConfig};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

/// Type alias for backend factory functions
pub type BackendFactory = Box<
    dyn Fn(&dyn BackendConfig) -> BackendResult<Box<dyn ErasedCryptoBackend>>
        + Send
        + Sync,
>;

/// Backend registry for managing available backends
pub struct BackendRegistry {
    factories: HashMap<BackendType, BackendFactory>,
}

impl BackendRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            factories: HashMap::new(),
        }
    }

    /// Register a backend factory
    pub fn register<F>(&mut self, backend_type: BackendType, factory: F)
    where
        F: Fn(&dyn BackendConfig) -> BackendResult<Box<dyn ErasedCryptoBackend>>
            + Send
            + Sync
            + 'static,
    {
        self.factories.insert(backend_type, Box::new(factory));
    }

    /// Create a backend instance
    pub fn create_backend(
        &self,
        config: &dyn BackendConfig,
    ) -> BackendResult<Box<dyn ErasedCryptoBackend>> {
        let backend_type = config.backend_type();
        let factory = self
            .factories
            .get(&backend_type)
            .ok_or_else(|| {
                BackendError::configuration_error(format!(
                    "No factory registered for backend type: {}",
                    backend_type
                ))
            })?;

        factory(config)
    }

    /// Get list of registered backend types
    pub fn registered_backends(&self) -> Vec<BackendType> {
        self.factories.keys().cloned().collect()
    }

    /// Check if a backend type is registered
    pub fn is_registered(&self, backend_type: &BackendType) -> bool {
        self.factories.contains_key(backend_type)
    }
}

impl Default for BackendRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Global backend registry instance
static GLOBAL_REGISTRY: OnceLock<Arc<Mutex<BackendRegistry>>> = OnceLock::new();

/// Get the global backend registry
pub fn global_registry() -> &'static Arc<Mutex<BackendRegistry>> {
    GLOBAL_REGISTRY.get_or_init(|| Arc::new(Mutex::new(BackendRegistry::new())))
}

/// Register a backend factory globally
pub fn register_backend<F>(backend_type: BackendType, factory: F) -> BackendResult<()>
where
    F: Fn(&dyn BackendConfig) -> BackendResult<Box<dyn ErasedCryptoBackend>>
        + Send
        + Sync
        + 'static,
{
    let registry = global_registry();
    let mut registry = registry.lock().map_err(|_| {
        BackendError::internal_error("Failed to acquire registry lock")
    })?;
    
    registry.register(backend_type, factory);
    Ok(())
}

/// Create a backend instance using the global registry
pub fn create_backend(
    config: &dyn BackendConfig,
) -> BackendResult<Box<dyn ErasedCryptoBackend>> {
    let registry = global_registry();
    let registry = registry.lock().map_err(|_| {
        BackendError::internal_error("Failed to acquire registry lock")
    })?;
    
    registry.create_backend(config)
}

/// Get list of registered backend types from the global registry
pub fn registered_backends() -> BackendResult<Vec<BackendType>> {
    let registry = global_registry();
    let registry = registry.lock().map_err(|_| {
        BackendError::internal_error("Failed to acquire registry lock")
    })?;
    
    Ok(registry.registered_backends())
}

/// Check if a backend type is registered in the global registry
pub fn is_backend_registered(backend_type: &BackendType) -> BackendResult<bool> {
    let registry = global_registry();
    let registry = registry.lock().map_err(|_| {
        BackendError::internal_error("Failed to acquire registry lock")
    })?;
    
    Ok(registry.is_registered(backend_type))
}

/// Backend discovery trait for automatic backend registration
pub trait BackendDiscovery {
    /// Get the backend type this discovery handles
    fn backend_type(&self) -> BackendType;
    
    /// Check if the backend is available on this system
    fn is_available(&self) -> bool;
    
    /// Create a factory function for this backend
    fn create_factory(&self) -> BackendFactory;
    
    /// Get backend metadata
    fn metadata(&self) -> BackendMetadata;
}

/// Metadata about a backend
#[derive(Debug, Clone)]
pub struct BackendMetadata {
    /// Backend name
    pub name: String,
    /// Backend description
    pub description: String,
    /// Backend version
    pub version: String,
    /// Supported features
    pub features: Vec<String>,
    /// Vendor information
    pub vendor: Option<String>,
}

/// Backend discovery manager
pub struct BackendDiscoveryManager {
    discoveries: Vec<Box<dyn BackendDiscovery + Send + Sync>>,
}

impl BackendDiscoveryManager {
    /// Create a new discovery manager
    pub fn new() -> Self {
        Self {
            discoveries: Vec::new(),
        }
    }

    /// Add a backend discovery
    pub fn add_discovery<D>(&mut self, discovery: D)
    where
        D: BackendDiscovery + Send + Sync + 'static,
    {
        self.discoveries.push(Box::new(discovery));
    }

    /// Discover and register all available backends
    pub fn discover_and_register(&self) -> BackendResult<Vec<BackendType>> {
        let mut registered = Vec::new();
        
        for discovery in &self.discoveries {
            if discovery.is_available() {
                let backend_type = discovery.backend_type();
                let factory = discovery.create_factory();
                
                register_backend(backend_type, move |config| factory(config))?;
                registered.push(backend_type);
            }
        }
        
        Ok(registered)
    }

    /// Get metadata for all discoveries
    pub fn get_all_metadata(&self) -> Vec<(BackendType, BackendMetadata)> {
        self.discoveries
            .iter()
            .map(|d| (d.backend_type(), d.metadata()))
            .collect()
    }
}

impl Default for BackendDiscoveryManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Initialize the backend system with automatic discovery
pub fn initialize_backends() -> BackendResult<Vec<BackendType>> {
    let discovery_manager = BackendDiscoveryManager::new();
    discovery_manager.discover_and_register()
}

/// Initialize built-in backends
pub fn initialize_builtin_backends() -> BackendResult<()> {
    // Register NetHSM backend
    register_backend(BackendType::NetHsm, |config| {
        let nethsm_config = config
            .as_any()
            .downcast_ref::<NetHsmBackendConfig>()
            .ok_or_else(|| BackendError::configuration_error("Invalid NetHSM configuration"))?;
        
        let backend = NetHsmBackend::new(nethsm_config.clone())?;
        Ok(Box::new(backend) as Box<dyn ErasedCryptoBackend>)
    })?;
    
    Ok(())
}