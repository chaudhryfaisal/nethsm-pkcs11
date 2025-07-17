//! Backend testing utilities for validating CryptoBackend implementations.
//!
//! This module provides a comprehensive test suite that can be used to validate
//! any implementation of the CryptoBackend trait, ensuring consistency and
//! correctness across different backend implementations.

use pkcs11_core::backend::{
    types::*,
    error::BackendError,
    CryptoBackend, ErasedCryptoBackend,
};
use crate::common::{TestResult, test_data};
use std::sync::Arc;

/// Comprehensive backend test suite
pub struct BackendTestSuite<T: CryptoBackend> {
    backend: T,
    test_config: BackendTestConfig,
}

/// Configuration for backend testing
#[derive(Debug, Clone)]
pub struct BackendTestConfig {
    pub test_key_generation: bool,
    pub test_cryptographic_operations: bool,
    pub test_session_management: bool,
    pub test_authentication: bool,
    pub test_error_conditions: bool,
    pub test_performance: bool,
    pub max_test_duration_seconds: u64,
}

impl Default for BackendTestConfig {
    fn default() -> Self {
        Self {
            test_key_generation: true,
            test_cryptographic_operations: true,
            test_session_management: true,
            test_authentication: true,
            test_error_conditions: true,
            test_performance: false, // Disabled by default for faster tests
            max_test_duration_seconds: 300, // 5 minutes
        }
    }
}

impl<T: CryptoBackend> BackendTestSuite<T> {
    /// Create a new test suite for the given backend
    pub fn new(backend: T, config: BackendTestConfig) -> Self {
        Self {
            backend,
            test_config: config,
        }
    }

    /// Run all enabled tests
    pub fn run_all_tests(&mut self) -> TestResult<BackendTestResults> {
        let mut results = BackendTestResults::new();

        if self.test_config.test_session_management {
            results.session_management = Some(self.test_session_management()?);
        }

        if self.test_config.test_authentication {
            results.authentication = Some(self.test_authentication()?);
        }

        if self.test_config.test_key_generation {
            results.key_generation = Some(self.test_key_generation()?);
        }

        if self.test_config.test_cryptographic_operations {
            results.cryptographic_operations = Some(self.test_cryptographic_operations()?);
        }

        if self.test_config.test_error_conditions {
            results.error_conditions = Some(self.test_error_conditions()?);
        }

        if self.test_config.test_performance {
            results.performance = Some(self.test_performance()?);
        }

        Ok(results)
    }

    /// Test session management functionality
    pub fn test_session_management(&mut self) -> TestResult<TestCategoryResult> {
        let mut result = TestCategoryResult::new("Session Management");

        // Test slot enumeration
        result.add_test("get_slot_list", || {
            let slots = self.backend.get_slot_list(false)?;
            assert!(!slots.is_empty(), "No slots available");
            Ok(())
        })?;

        // Test slot info
        result.add_test("get_slot_info", || {
            let slots = self.backend.get_slot_list(false)?;
            let slot_info = self.backend.get_slot_info(slots[0])?;
            assert!(!slot_info.slot_description.is_empty(), "Slot description is empty");
            Ok(())
        })?;

        // Test token info
        result.add_test("get_token_info", || {
            let slots = self.backend.get_slot_list(false)?;
            let token_info = self.backend.get_token_info(slots[0])?;
            assert!(!token_info.label.is_empty(), "Token label is empty");
            Ok(())
        })?;

        // Test session opening and closing
        result.add_test("session_lifecycle", || {
            let slots = self.backend.get_slot_list(false)?;
            let flags = test_data::session_flags(true, true);
            
            let session = self.backend.open_session(slots[0], flags)?;
            let session_info = self.backend.get_session_info(session)?;
            
            assert_eq!(session_info.handle, session, "Session handle mismatch");
            assert_eq!(session_info.slot_id, slots[0], "Slot ID mismatch");
            
            self.backend.close_session(session)?;
            Ok(())
        })?;

        // Test multiple sessions
        result.add_test("multiple_sessions", || {
            let slots = self.backend.get_slot_list(false)?;
            let flags = test_data::session_flags(true, true);
            
            let session1 = self.backend.open_session(slots[0], flags)?;
            let session2 = self.backend.open_session(slots[0], flags)?;
            
            assert_ne!(session1, session2, "Session handles should be unique");
            
            self.backend.close_session(session1)?;
            self.backend.close_session(session2)?;
            Ok(())
        })?;

        // Test close all sessions
        result.add_test("close_all_sessions", || {
            let slots = self.backend.get_slot_list(false)?;
            let flags = test_data::session_flags(true, true);
            
            let _session1 = self.backend.open_session(slots[0], flags)?;
            let _session2 = self.backend.open_session(slots[0], flags)?;
            
            self.backend.close_all_sessions(slots[0])?;
            Ok(())
        })?;

        Ok(result)
    }

    /// Test authentication functionality
    pub fn test_authentication(&mut self) -> TestResult<TestCategoryResult> {
        let mut result = TestCategoryResult::new("Authentication");

        // Test user login/logout
        result.add_test("user_login_logout", || {
            let slots = self.backend.get_slot_list(false)?;
            let flags = test_data::session_flags(true, true);
            let session = self.backend.open_session(slots[0], flags)?;

            // Test login
            self.backend.login(session, UserType::User, "test_pin")?;
            
            let session_info = self.backend.get_session_info(session)?;
            assert!(matches!(session_info.state, SessionState::RwUserSession), 
                   "Session should be in user state after login");

            // Test logout
            self.backend.logout(session)?;
            
            let session_info = self.backend.get_session_info(session)?;
            assert!(matches!(session_info.state, SessionState::RwPublicSession), 
                   "Session should be in public state after logout");

            self.backend.close_session(session)?;
            Ok(())
        })?;

        // Test SO login (if supported)
        result.add_test("so_login", || {
            let slots = self.backend.get_slot_list(false)?;
            let flags = test_data::session_flags(true, true);
            let session = self.backend.open_session(slots[0], flags)?;

            match self.backend.login(session, UserType::So, "so_pin") {
                Ok(_) => {
                    let session_info = self.backend.get_session_info(session)?;
                    assert!(matches!(session_info.state, SessionState::RwSoSession), 
                           "Session should be in SO state after SO login");
                    self.backend.logout(session)?;
                }
                Err(_) => {
                    // SO login might not be supported, which is acceptable
                }
            }

            self.backend.close_session(session)?;
            Ok(())
        })?;

        Ok(result)
    }

    /// Test key generation functionality
    pub fn test_key_generation(&mut self) -> TestResult<TestCategoryResult> {
        let mut result = TestCategoryResult::new("Key Generation");

        // Test RSA key pair generation
        result.add_test("rsa_key_pair_generation", || {
            let slots = self.backend.get_slot_list(false)?;
            let flags = test_data::session_flags(true, true);
            let session = self.backend.open_session(slots[0], flags)?;

            // Login if required
            let _ = self.backend.login(session, UserType::User, "test_pin");

            let spec = test_data::rsa_key_spec(2048, Some("test_rsa".to_string()));
            let (private_key, public_key) = self.backend.generate_key_pair(session, &spec)?;

            assert_ne!(private_key, public_key, "Private and public key handles should be different");

            // Verify key info
            let private_info = self.backend.get_key_info(session, private_key)?;
            let public_info = self.backend.get_key_info(session, public_key)?;

            assert_eq!(private_info.key_type, KeyType::Rsa);
            assert_eq!(public_info.key_type, KeyType::Rsa);
            assert_eq!(private_info.key_size, 2048);
            assert_eq!(public_info.key_size, 2048);

            // Clean up
            let _ = self.backend.delete_key(session, private_key);
            let _ = self.backend.delete_key(session, public_key);
            self.backend.close_session(session)?;
            Ok(())
        })?;

        // Test ECDSA key pair generation
        result.add_test("ecdsa_key_pair_generation", || {
            let slots = self.backend.get_slot_list(false)?;
            let flags = test_data::session_flags(true, true);
            let session = self.backend.open_session(slots[0], flags)?;

            let _ = self.backend.login(session, UserType::User, "test_pin");

            let spec = test_data::ecdsa_key_spec(EllipticCurve::P256, Some("test_ecdsa".to_string()));
            let (private_key, public_key) = self.backend.generate_key_pair(session, &spec)?;

            let private_info = self.backend.get_key_info(session, private_key)?;
            assert_eq!(private_info.key_type, KeyType::EllipticCurve);
            assert_eq!(private_info.key_size, 256);

            let _ = self.backend.delete_key(session, private_key);
            let _ = self.backend.delete_key(session, public_key);
            self.backend.close_session(session)?;
            Ok(())
        })?;

        // Test symmetric key generation
        result.add_test("symmetric_key_generation", || {
            let slots = self.backend.get_slot_list(false)?;
            let flags = test_data::session_flags(true, true);
            let session = self.backend.open_session(slots[0], flags)?;

            let _ = self.backend.login(session, UserType::User, "test_pin");

            let spec = test_data::aes_key_spec(256, Some("test_aes".to_string()));
            let key = self.backend.generate_key(session, &spec)?;

            let key_info = self.backend.get_key_info(session, key)?;
            assert_eq!(key_info.key_type, KeyType::Aes);
            assert_eq!(key_info.key_size, 256);

            let _ = self.backend.delete_key(session, key);
            self.backend.close_session(session)?;
            Ok(())
        })?;

        Ok(result)
    }

    /// Test cryptographic operations
    pub fn test_cryptographic_operations(&mut self) -> TestResult<TestCategoryResult> {
        let mut result = TestCategoryResult::new("Cryptographic Operations");

        // Test signing and verification
        result.add_test("sign_verify_operations", || {
            let slots = self.backend.get_slot_list(false)?;
            let flags = test_data::session_flags(true, true);
            let session = self.backend.open_session(slots[0], flags)?;

            let _ = self.backend.login(session, UserType::User, "test_pin");

            // Generate RSA key pair
            let spec = test_data::rsa_key_spec(2048, Some("sign_test".to_string()));
            let (private_key, public_key) = self.backend.generate_key_pair(session, &spec)?;

            // Test signing
            let data = test_data::signing_test_data();
            let mechanisms = test_data::signing_mechanisms();
            
            for mechanism in &mechanisms {
                match self.backend.sign(session, private_key, mechanism, &data) {
                    Ok(signature) => {
                        assert!(!signature.is_empty(), "Signature should not be empty");
                        
                        // Test verification
                        let verified = self.backend.verify(session, public_key, mechanism, &data, &signature)?;
                        assert!(verified, "Signature verification should succeed");
                    }
                    Err(_) => {
                        // Some mechanisms might not be supported, which is acceptable
                    }
                }
            }

            let _ = self.backend.delete_key(session, private_key);
            let _ = self.backend.delete_key(session, public_key);
            self.backend.close_session(session)?;
            Ok(())
        })?;

        // Test digest operations
        result.add_test("digest_operations", || {
            let slots = self.backend.get_slot_list(false)?;
            let flags = test_data::session_flags(true, true);
            let session = self.backend.open_session(slots[0], flags)?;

            let _ = self.backend.login(session, UserType::User, "test_pin");

            let data = test_data::signing_test_data();
            let mechanisms = test_data::digest_mechanisms();

            for mechanism in &mechanisms {
                match self.backend.digest(session, mechanism, &data) {
                    Ok(digest) => {
                        assert!(!digest.is_empty(), "Digest should not be empty");
                        
                        // Verify digest length based on algorithm
                        match mechanism.0 {
                            x if x == cryptoki_sys::CKM_SHA256 as u32 => {
                                assert_eq!(digest.len(), 32, "SHA-256 digest should be 32 bytes");
                            }
                            x if x == cryptoki_sys::CKM_SHA384 as u32 => {
                                assert_eq!(digest.len(), 48, "SHA-384 digest should be 48 bytes");
                            }
                            x if x == cryptoki_sys::CKM_SHA512 as u32 => {
                                assert_eq!(digest.len(), 64, "SHA-512 digest should be 64 bytes");
                            }
                            _ => {} // Other algorithms
                        }
                    }
                    Err(_) => {
                        // Some digest algorithms might not be supported
                    }
                }
            }

            self.backend.close_session(session)?;
            Ok(())
        })?;

        // Test random number generation
        result.add_test("random_generation", || {
            let slots = self.backend.get_slot_list(false)?;
            let flags = test_data::session_flags(true, true);
            let session = self.backend.open_session(slots[0], flags)?;

            let _ = self.backend.login(session, UserType::User, "test_pin");

            let random1 = self.backend.generate_random(session, 32)?;
            let random2 = self.backend.generate_random(session, 32)?;

            assert_eq!(random1.len(), 32, "Random data should be 32 bytes");
            assert_eq!(random2.len(), 32, "Random data should be 32 bytes");
            assert_ne!(random1, random2, "Random data should be different");

            self.backend.close_session(session)?;
            Ok(())
        })?;

        Ok(result)
    }

    /// Test error conditions
    pub fn test_error_conditions(&mut self) -> TestResult<TestCategoryResult> {
        let mut result = TestCategoryResult::new("Error Conditions");

        // Test invalid slot ID
        result.add_test("invalid_slot_id", || {
            let invalid_slot = SlotId(9999);
            let flags = test_data::session_flags(true, true);
            
            match self.backend.open_session(invalid_slot, flags) {
                Err(_) => Ok(()), // Expected error
                Ok(_) => Err("Should have failed with invalid slot ID".into()),
            }
        })?;

        // Test invalid session handle
        result.add_test("invalid_session_handle", || {
            let invalid_session = SessionHandle(9999);
            
            match self.backend.get_session_info(invalid_session) {
                Err(_) => Ok(()), // Expected error
                Ok(_) => Err("Should have failed with invalid session handle".into()),
            }
        })?;

        // Test invalid key handle
        result.add_test("invalid_key_handle", || {
            let slots = self.backend.get_slot_list(false)?;
            let flags = test_data::session_flags(true, true);
            let session = self.backend.open_session(slots[0], flags)?;

            let _ = self.backend.login(session, UserType::User, "test_pin");

            let invalid_key = KeyHandle(9999);
            
            match self.backend.get_key_info(session, invalid_key) {
                Err(_) => {
                    self.backend.close_session(session)?;
                    Ok(()) // Expected error
                }
                Ok(_) => {
                    self.backend.close_session(session)?;
                    Err("Should have failed with invalid key handle".into())
                }
            }
        })?;

        Ok(result)
    }

    /// Test performance characteristics
    pub fn test_performance(&mut self) -> TestResult<TestCategoryResult> {
        let mut result = TestCategoryResult::new("Performance");

        // Test key generation performance
        result.add_test("key_generation_performance", || {
            let slots = self.backend.get_slot_list(false)?;
            let flags = test_data::session_flags(true, true);
            let session = self.backend.open_session(slots[0], flags)?;

            let _ = self.backend.login(session, UserType::User, "test_pin");

            let start = std::time::Instant::now();
            let spec = test_data::rsa_key_spec(2048, Some("perf_test".to_string()));
            let (private_key, public_key) = self.backend.generate_key_pair(session, &spec)?;
            let duration = start.elapsed();

            println!("RSA 2048-bit key generation took: {:?}", duration);

            let _ = self.backend.delete_key(session, private_key);
            let _ = self.backend.delete_key(session, public_key);
            self.backend.close_session(session)?;
            Ok(())
        })?;

        // Test signing performance
        result.add_test("signing_performance", || {
            let slots = self.backend.get_slot_list(false)?;
            let flags = test_data::session_flags(true, true);
            let session = self.backend.open_session(slots[0], flags)?;

            let _ = self.backend.login(session, UserType::User, "test_pin");

            let spec = test_data::rsa_key_spec(2048, Some("perf_sign".to_string()));
            let (private_key, _public_key) = self.backend.generate_key_pair(session, &spec)?;

            let data = test_data::signing_test_data();
            let mechanism = &test_data::signing_mechanisms()[0];

            let start = std::time::Instant::now();
            for _ in 0..10 {
                let _ = self.backend.sign(session, private_key, mechanism, &data)?;
            }
            let duration = start.elapsed();

            println!("10 RSA signatures took: {:?} (avg: {:?})", duration, duration / 10);

            let _ = self.backend.delete_key(session, private_key);
            self.backend.close_session(session)?;
            Ok(())
        })?;

        Ok(result)
    }
}

/// Results from running the backend test suite
#[derive(Debug)]
pub struct BackendTestResults {
    pub session_management: Option<TestCategoryResult>,
    pub authentication: Option<TestCategoryResult>,
    pub key_generation: Option<TestCategoryResult>,
    pub cryptographic_operations: Option<TestCategoryResult>,
    pub error_conditions: Option<TestCategoryResult>,
    pub performance: Option<TestCategoryResult>,
}

impl BackendTestResults {
    pub fn new() -> Self {
        Self {
            session_management: None,
            authentication: None,
            key_generation: None,
            cryptographic_operations: None,
            error_conditions: None,
            performance: None,
        }
    }

    /// Get total number of tests run
    pub fn total_tests(&self) -> usize {
        [
            &self.session_management,
            &self.authentication,
            &self.key_generation,
            &self.cryptographic_operations,
            &self.error_conditions,
            &self.performance,
        ]
        .iter()
        .filter_map(|r| r.as_ref())
        .map(|r| r.tests.len())
        .sum()
    }

    /// Get number of passed tests
    pub fn passed_tests(&self) -> usize {
        [
            &self.session_management,
            &self.authentication,
            &self.key_generation,
            &self.cryptographic_operations,
            &self.error_conditions,
            &self.performance,
        ]
        .iter()
        .filter_map(|r| r.as_ref())
        .map(|r| r.passed_count())
        .sum()
    }

    /// Check if all tests passed
    pub fn all_passed(&self) -> bool {
        self.total_tests() == self.passed_tests()
    }
}

/// Results for a category of tests
#[derive(Debug)]
pub struct TestCategoryResult {
    pub category: String,
    pub tests: Vec<TestResult<()>>,
    pub test_names: Vec<String>,
}

impl TestCategoryResult {
    pub fn new(category: &str) -> Self {
        Self {
            category: category.to_string(),
            tests: Vec::new(),
            test_names: Vec::new(),
        }
    }

    pub fn add_test<F>(&mut self, name: &str, test_fn: F) -> TestResult<()>
    where
        F: FnOnce() -> TestResult<()>,
    {
        let result = test_fn();
        self.test_names.push(name.to_string());
        self.tests.push(result.clone());
        result
    }

    pub fn passed_count(&self) -> usize {
        self.tests.iter().filter(|r| r.is_ok()).count()
    }

    pub fn failed_count(&self) -> usize {
        self.tests.iter().filter(|r| r.is_err()).count()
    }
}

/// Utility function to run backend tests with any CryptoBackend implementation
pub fn run_backend_tests<T: CryptoBackend>(
    backend: T,
    config: Option<BackendTestConfig>,
) -> TestResult<BackendTestResults> {
    let config = config.unwrap_or_default();
    let mut test_suite = BackendTestSuite::new(backend, config);
    test_suite.run_all_tests()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_test_config() {
        let config = BackendTestConfig::default();
        assert!(config.test_key_generation);
        assert!(config.test_cryptographic_operations);
        assert!(!config.test_performance);
    }

    #[test]
    fn test_test_category_result() {
        let mut result = TestCategoryResult::new("Test Category");
        
        result.add_test("test1", || Ok(())).unwrap();
        result.add_test("test2", || Err("test error".into())).unwrap_err();
        
        assert_eq!(result.passed_count(), 1);
        assert_eq!(result.failed_count(), 1);
        assert_eq!(result.tests.len(), 2);
    }
}