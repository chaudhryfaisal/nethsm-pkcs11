//! Common test utilities and helpers for the PKCS#11 testing framework.
//!
//! This module provides shared functionality for testing the modular PKCS#11 architecture,
//! including mock servers, test data generation, and common test scenarios.

pub mod mock_server;
pub mod test_data;
pub mod test_scenarios;
pub mod backend_testing;
pub mod config_helpers;

use std::sync::Once;
use env_logger;

static INIT: Once = Once::new();

/// Initialize logging for tests
pub fn init_test_logging() {
    INIT.call_once(|| {
        env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .is_test(true)
            .try_init()
            .ok();
    });
}

/// Test result type for convenience
pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Common test configuration
#[derive(Debug, Clone)]
pub struct TestConfig {
    pub timeout_seconds: u64,
    pub max_retries: u32,
    pub enable_logging: bool,
    pub deterministic: bool,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: 30,
            max_retries: 3,
            enable_logging: true,
            deterministic: true,
        }
    }
}

/// Test context for managing test lifecycle
pub struct TestContext {
    pub config: TestConfig,
    cleanup_handlers: Vec<Box<dyn FnOnce() + Send>>,
}

impl TestContext {
    pub fn new(config: TestConfig) -> Self {
        if config.enable_logging {
            init_test_logging();
        }
        
        Self {
            config,
            cleanup_handlers: Vec::new(),
        }
    }

    /// Add a cleanup handler to be called when the test context is dropped
    pub fn add_cleanup<F>(&mut self, handler: F)
    where
        F: FnOnce() + Send + 'static,
    {
        self.cleanup_handlers.push(Box::new(handler));
    }

    /// Run a test with timeout
    pub fn with_timeout<F, T>(&self, test_fn: F) -> TestResult<T>
    where
        F: FnOnce() -> TestResult<T> + Send + 'static,
        T: Send + 'static,
    {
        use std::time::Duration;
        use std::thread;
        
        let timeout = Duration::from_secs(self.config.timeout_seconds);
        let (tx, rx) = std::sync::mpsc::channel();
        
        let handle = thread::spawn(move || {
            let result = test_fn();
            tx.send(result).ok();
        });
        
        match rx.recv_timeout(timeout) {
            Ok(result) => result,
            Err(_) => {
                // Try to join the thread, but don't wait forever
                let _ = handle.join();
                Err("Test timed out".into())
            }
        }
    }
}

impl Drop for TestContext {
    fn drop(&mut self) {
        // Run cleanup handlers in reverse order
        for handler in self.cleanup_handlers.drain(..).rev() {
            handler();
        }
    }
}

/// Macro for creating test cases with common setup
#[macro_export]
macro_rules! test_case {
    ($name:ident, $test_fn:expr) => {
        #[test]
        fn $name() {
            let config = $crate::common::TestConfig::default();
            let mut ctx = $crate::common::TestContext::new(config);
            
            let result = ctx.with_timeout(|| $test_fn(&mut ctx));
            
            if let Err(e) = result {
                panic!("Test failed: {}", e);
            }
        }
    };
    
    ($name:ident, $config:expr, $test_fn:expr) => {
        #[test]
        fn $name() {
            let mut ctx = $crate::common::TestContext::new($config);
            
            let result = ctx.with_timeout(|| $test_fn(&mut ctx));
            
            if let Err(e) = result {
                panic!("Test failed: {}", e);
            }
        }
    };
}

/// Assertion helpers for PKCS#11 testing
pub mod assertions {
    use pkcs11_core::backend::types::*;
    
    /// Assert that two key infos are equivalent
    pub fn assert_key_info_eq(actual: &KeyInfo, expected: &KeyInfo) {
        assert_eq!(actual.key_type, expected.key_type, "Key types don't match");
        assert_eq!(actual.key_size, expected.key_size, "Key sizes don't match");
        assert_eq!(actual.label, expected.label, "Key labels don't match");
        assert_eq!(actual.id, expected.id, "Key IDs don't match");
        assert_eq!(actual.usage.sign, expected.usage.sign, "Sign usage doesn't match");
        assert_eq!(actual.usage.verify, expected.usage.verify, "Verify usage doesn't match");
        assert_eq!(actual.usage.encrypt, expected.usage.encrypt, "Encrypt usage doesn't match");
        assert_eq!(actual.usage.decrypt, expected.usage.decrypt, "Decrypt usage doesn't match");
    }
    
    /// Assert that a session is in the expected state
    pub fn assert_session_state(session_info: &SessionInfo, expected_state: SessionState) {
        assert_eq!(session_info.state, expected_state, "Session state doesn't match");
    }
    
    /// Assert that a mechanism is supported
    pub fn assert_mechanism_supported(mechanisms: &[MechanismType], mechanism: MechanismType) {
        assert!(
            mechanisms.contains(&mechanism),
            "Mechanism {:?} not found in supported mechanisms",
            mechanism
        );
    }
}