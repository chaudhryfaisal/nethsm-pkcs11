pub mod api;

pub mod data;

pub mod utils;

pub mod backend;
mod config;
mod defs;
mod ureq;

#[cfg(panic = "abort")]
mod unwind_stubs;

#[macro_use]
extern crate std;

// Re-export key backend types for external use
pub use backend::{
    error::{BackendError, BackendResult, ConfigError},
    registry::{
        create_backend, global_registry, initialize_backends, is_backend_registered,
        register_backend, registered_backends, BackendDiscovery, BackendDiscoveryManager,
        BackendMetadata, BackendRegistry,
    },
    types::*,
    CryptoBackend, SyncBackendWrapper, ThreadSafeBackend,
};
