//! Common test scenarios for PKCS#11 testing.
//!
//! This module provides pre-defined test scenarios that can be used across
//! different backend implementations to ensure consistent behavior.

use pkcs11_core::backend::types::*;
use crate::common::{TestResult, test_data};

/// A complete test scenario that can be executed against any backend
pub struct TestScenario {
    pub name: String,
    pub description: String,
    pub steps: Vec<TestStep>,
    pub cleanup_steps: Vec<TestStep>,
}

/// Individual test step within a scenario
#[derive(Clone)]
pub enum TestStep {
    OpenSession {
        slot_id: SlotId,
        flags: SessionFlags,
        expected_session_var: String,
    },
    Login {
        session_var: String,
        user_type: UserType,
        pin: String,
    },
    GenerateKeyPair {
        session_var: String,
        spec: KeyGenerationSpec,
        private_key_var: String,
        public_key_var: String,
    },
    GenerateKey {
        session_var: String,
        spec: KeyGenerationSpec,
        key_var: String,
    },
    Sign {
        session_var: String,
        key_var: String,
        mechanism: SignMechanism,
        data: Vec<u8>,
        signature_var: String,
    },
    Verify {
        session_var: String,
        key_var: String,
        mechanism: SignMechanism,
        data: Vec<u8>,
        signature_var: String,
        expected_result: bool,
    },
    Encrypt {
        session_var: String,
        key_var: String,
        mechanism: EncryptMechanism,
        data: Vec<u8>,
        encrypted_var: String,
    },
    Decrypt {
        session_var: String,
        key_var: String,
        mechanism: EncryptMechanism,
        encrypted_var: String,
        expected_data: Vec<u8>,
    },
    DeleteKey {
        session_var: String,
        key_var: String,
    },
    CloseSession {
        session_var: String,
    },
    AssertKeyInfo {
        session_var: String,
        key_var: String,
        expected_type: KeyType,
        expected_size: u32,
    },
    AssertSessionState {
        session_var: String,
        expected_state: SessionState,
    },
}

impl TestScenario {
    /// Create a basic RSA signing scenario
    pub fn rsa_signing_scenario() -> Self {
        Self {
            name: "RSA Signing".to_string(),
            description: "Generate RSA key pair, sign data, and verify signature".to_string(),
            steps: vec![
                TestStep::OpenSession {
                    slot_id: SlotId(0),
                    flags: test_data::session_flags(true, true),
                    expected_session_var: "session".to_string(),
                },
                TestStep::Login {
                    session_var: "session".to_string(),
                    user_type: UserType::User,
                    pin: "test_pin".to_string(),
                },
                TestStep::GenerateKeyPair {
                    session_var: "session".to_string(),
                    spec: test_data::rsa_key_spec(2048, Some("rsa_sign_test".to_string())),
                    private_key_var: "private_key".to_string(),
                    public_key_var: "public_key".to_string(),
                },
                TestStep::AssertKeyInfo {
                    session_var: "session".to_string(),
                    key_var: "private_key".to_string(),
                    expected_type: KeyType::Rsa,
                    expected_size: 2048,
                },
                TestStep::Sign {
                    session_var: "session".to_string(),
                    key_var: "private_key".to_string(),
                    mechanism: SignMechanism {
                        mechanism_type: MechanismType(cryptoki_sys::CKM_RSA_PKCS as u32),
                        parameters: None,
                    },
                    data: test_data::signing_test_data(),
                    signature_var: "signature".to_string(),
                },
                TestStep::Verify {
                    session_var: "session".to_string(),
                    key_var: "public_key".to_string(),
                    mechanism: SignMechanism {
                        mechanism_type: MechanismType(cryptoki_sys::CKM_RSA_PKCS as u32),
                        parameters: None,
                    },
                    data: test_data::signing_test_data(),
                    signature_var: "signature".to_string(),
                    expected_result: true,
                },
            ],
            cleanup_steps: vec![
                TestStep::DeleteKey {
                    session_var: "session".to_string(),
                    key_var: "private_key".to_string(),
                },
                TestStep::DeleteKey {
                    session_var: "session".to_string(),
                    key_var: "public_key".to_string(),
                },
                TestStep::CloseSession {
                    session_var: "session".to_string(),
                },
            ],
        }
    }

    /// Create an ECDSA signing scenario
    pub fn ecdsa_signing_scenario() -> Self {
        Self {
            name: "ECDSA Signing".to_string(),
            description: "Generate ECDSA key pair, sign data, and verify signature".to_string(),
            steps: vec![
                TestStep::OpenSession {
                    slot_id: SlotId(0),
                    flags: test_data::session_flags(true, true),
                    expected_session_var: "session".to_string(),
                },
                TestStep::Login {
                    session_var: "session".to_string(),
                    user_type: UserType::User,
                    pin: "test_pin".to_string(),
                },
                TestStep::GenerateKeyPair {
                    session_var: "session".to_string(),
                    spec: test_data::ecdsa_key_spec(EllipticCurve::P256, Some("ecdsa_sign_test".to_string())),
                    private_key_var: "private_key".to_string(),
                    public_key_var: "public_key".to_string(),
                },
                TestStep::Sign {
                    session_var: "session".to_string(),
                    key_var: "private_key".to_string(),
                    mechanism: SignMechanism {
                        mechanism_type: MechanismType(cryptoki_sys::CKM_ECDSA as u32),
                        parameters: None,
                    },
                    data: test_data::signing_test_data(),
                    signature_var: "signature".to_string(),
                },
                TestStep::Verify {
                    session_var: "session".to_string(),
                    key_var: "public_key".to_string(),
                    mechanism: SignMechanism {
                        mechanism_type: MechanismType(cryptoki_sys::CKM_ECDSA as u32),
                        parameters: None,
                    },
                    data: test_data::signing_test_data(),
                    signature_var: "signature".to_string(),
                    expected_result: true,
                },
            ],
            cleanup_steps: vec![
                TestStep::DeleteKey {
                    session_var: "session".to_string(),
                    key_var: "private_key".to_string(),
                },
                TestStep::DeleteKey {
                    session_var: "session".to_string(),
                    key_var: "public_key".to_string(),
                },
                TestStep::CloseSession {
                    session_var: "session".to_string(),
                },
            ],
        }
    }

    /// Create an AES encryption scenario
    pub fn aes_encryption_scenario() -> Self {
        Self {
            name: "AES Encryption".to_string(),
            description: "Generate AES key, encrypt data, and decrypt it back".to_string(),
            steps: vec![
                TestStep::OpenSession {
                    slot_id: SlotId(0),
                    flags: test_data::session_flags(true, true),
                    expected_session_var: "session".to_string(),
                },
                TestStep::Login {
                    session_var: "session".to_string(),
                    user_type: UserType::User,
                    pin: "test_pin".to_string(),
                },
                TestStep::GenerateKey {
                    session_var: "session".to_string(),
                    spec: test_data::aes_key_spec(256, Some("aes_encrypt_test".to_string())),
                    key_var: "aes_key".to_string(),
                },
                TestStep::Encrypt {
                    session_var: "session".to_string(),
                    key_var: "aes_key".to_string(),
                    mechanism: EncryptMechanism {
                        mechanism_type: MechanismType(cryptoki_sys::CKM_AES_CBC as u32),
                        parameters: Some(EncryptParameters::AesCbc {
                            iv: vec![0; 16], // Zero IV for testing
                        }),
                    },
                    data: test_data::encryption_test_data(),
                    encrypted_var: "encrypted_data".to_string(),
                },
                TestStep::Decrypt {
                    session_var: "session".to_string(),
                    key_var: "aes_key".to_string(),
                    mechanism: EncryptMechanism {
                        mechanism_type: MechanismType(cryptoki_sys::CKM_AES_CBC as u32),
                        parameters: Some(EncryptParameters::AesCbc {
                            iv: vec![0; 16], // Same IV as encryption
                        }),
                    },
                    encrypted_var: "encrypted_data".to_string(),
                    expected_data: test_data::encryption_test_data(),
                },
            ],
            cleanup_steps: vec![
                TestStep::DeleteKey {
                    session_var: "session".to_string(),
                    key_var: "aes_key".to_string(),
                },
                TestStep::CloseSession {
                    session_var: "session".to_string(),
                },
            ],
        }
    }

    /// Create a session management scenario
    pub fn session_management_scenario() -> Self {
        Self {
            name: "Session Management".to_string(),
            description: "Test session lifecycle and state transitions".to_string(),
            steps: vec![
                TestStep::OpenSession {
                    slot_id: SlotId(0),
                    flags: test_data::session_flags(true, true),
                    expected_session_var: "session1".to_string(),
                },
                TestStep::AssertSessionState {
                    session_var: "session1".to_string(),
                    expected_state: SessionState::RwPublicSession,
                },
                TestStep::Login {
                    session_var: "session1".to_string(),
                    user_type: UserType::User,
                    pin: "test_pin".to_string(),
                },
                TestStep::AssertSessionState {
                    session_var: "session1".to_string(),
                    expected_state: SessionState::RwUserSession,
                },
                TestStep::OpenSession {
                    slot_id: SlotId(0),
                    flags: test_data::session_flags(false, true),
                    expected_session_var: "session2".to_string(),
                },
                TestStep::AssertSessionState {
                    session_var: "session2".to_string(),
                    expected_state: SessionState::RoUserSession,
                },
            ],
            cleanup_steps: vec![
                TestStep::CloseSession {
                    session_var: "session1".to_string(),
                },
                TestStep::CloseSession {
                    session_var: "session2".to_string(),
                },
            ],
        }
    }

    /// Create a multi-key scenario
    pub fn multi_key_scenario() -> Self {
        Self {
            name: "Multi-Key Operations".to_string(),
            description: "Generate multiple keys and perform operations with them".to_string(),
            steps: vec![
                TestStep::OpenSession {
                    slot_id: SlotId(0),
                    flags: test_data::session_flags(true, true),
                    expected_session_var: "session".to_string(),
                },
                TestStep::Login {
                    session_var: "session".to_string(),
                    user_type: UserType::User,
                    pin: "test_pin".to_string(),
                },
                TestStep::GenerateKeyPair {
                    session_var: "session".to_string(),
                    spec: test_data::rsa_key_spec(2048, Some("rsa_key_1".to_string())),
                    private_key_var: "rsa_private_1".to_string(),
                    public_key_var: "rsa_public_1".to_string(),
                },
                TestStep::GenerateKeyPair {
                    session_var: "session".to_string(),
                    spec: test_data::rsa_key_spec(2048, Some("rsa_key_2".to_string())),
                    private_key_var: "rsa_private_2".to_string(),
                    public_key_var: "rsa_public_2".to_string(),
                },
                TestStep::GenerateKey {
                    session_var: "session".to_string(),
                    spec: test_data::aes_key_spec(256, Some("aes_key_1".to_string())),
                    key_var: "aes_key_1".to_string(),
                },
                TestStep::Sign {
                    session_var: "session".to_string(),
                    key_var: "rsa_private_1".to_string(),
                    mechanism: SignMechanism {
                        mechanism_type: MechanismType(cryptoki_sys::CKM_RSA_PKCS as u32),
                        parameters: None,
                    },
                    data: b"data for key 1".to_vec(),
                    signature_var: "signature_1".to_string(),
                },
                TestStep::Sign {
                    session_var: "session".to_string(),
                    key_var: "rsa_private_2".to_string(),
                    mechanism: SignMechanism {
                        mechanism_type: MechanismType(cryptoki_sys::CKM_RSA_PKCS as u32),
                        parameters: None,
                    },
                    data: b"data for key 2".to_vec(),
                    signature_var: "signature_2".to_string(),
                },
            ],
            cleanup_steps: vec![
                TestStep::DeleteKey {
                    session_var: "session".to_string(),
                    key_var: "rsa_private_1".to_string(),
                },
                TestStep::DeleteKey {
                    session_var: "session".to_string(),
                    key_var: "rsa_public_1".to_string(),
                },
                TestStep::DeleteKey {
                    session_var: "session".to_string(),
                    key_var: "rsa_private_2".to_string(),
                },
                TestStep::DeleteKey {
                    session_var: "session".to_string(),
                    key_var: "rsa_public_2".to_string(),
                },
                TestStep::DeleteKey {
                    session_var: "session".to_string(),
                    key_var: "aes_key_1".to_string(),
                },
                TestStep::CloseSession {
                    session_var: "session".to_string(),
                },
            ],
        }
    }

    /// Create an error handling scenario
    pub fn error_handling_scenario() -> Self {
        Self {
            name: "Error Handling".to_string(),
            description: "Test various error conditions and recovery".to_string(),
            steps: vec![
                TestStep::OpenSession {
                    slot_id: SlotId(0),
                    flags: test_data::session_flags(true, true),
                    expected_session_var: "session".to_string(),
                },
                // Test operations without login (should fail for some backends)
                TestStep::GenerateKeyPair {
                    session_var: "session".to_string(),
                    spec: test_data::rsa_key_spec(2048, Some("test_key".to_string())),
                    private_key_var: "private_key".to_string(),
                    public_key_var: "public_key".to_string(),
                },
                TestStep::Login {
                    session_var: "session".to_string(),
                    user_type: UserType::User,
                    pin: "test_pin".to_string(),
                },
                // Now operations should succeed
                TestStep::GenerateKeyPair {
                    session_var: "session".to_string(),
                    spec: test_data::rsa_key_spec(2048, Some("valid_key".to_string())),
                    private_key_var: "valid_private".to_string(),
                    public_key_var: "valid_public".to_string(),
                },
            ],
            cleanup_steps: vec![
                TestStep::DeleteKey {
                    session_var: "session".to_string(),
                    key_var: "valid_private".to_string(),
                },
                TestStep::DeleteKey {
                    session_var: "session".to_string(),
                    key_var: "valid_public".to_string(),
                },
                TestStep::CloseSession {
                    session_var: "session".to_string(),
                },
            ],
        }
    }

    /// Get all predefined scenarios
    pub fn all_scenarios() -> Vec<Self> {
        vec![
            Self::rsa_signing_scenario(),
            Self::ecdsa_signing_scenario(),
            Self::aes_encryption_scenario(),
            Self::session_management_scenario(),
            Self::multi_key_scenario(),
            Self::error_handling_scenario(),
        ]
    }

    /// Get scenarios suitable for quick testing
    pub fn quick_scenarios() -> Vec<Self> {
        vec![
            Self::rsa_signing_scenario(),
            Self::session_management_scenario(),
        ]
    }

    /// Get scenarios for comprehensive testing
    pub fn comprehensive_scenarios() -> Vec<Self> {
        Self::all_scenarios()
    }
}

/// Scenario execution context
pub struct ScenarioContext {
    variables: std::collections::HashMap<String, ScenarioVariable>,
}

/// Variable types that can be stored in scenario context
#[derive(Clone)]
pub enum ScenarioVariable {
    Session(SessionHandle),
    Key(KeyHandle),
    Data(Vec<u8>),
    Boolean(bool),
}

impl ScenarioContext {
    pub fn new() -> Self {
        Self {
            variables: std::collections::HashMap::new(),
        }
    }

    pub fn set_session(&mut self, name: &str, session: SessionHandle) {
        self.variables.insert(name.to_string(), ScenarioVariable::Session(session));
    }

    pub fn get_session(&self, name: &str) -> TestResult<SessionHandle> {
        match self.variables.get(name) {
            Some(ScenarioVariable::Session(session)) => Ok(*session),
            _ => Err(format!("Session variable '{}' not found", name).into()),
        }
    }

    pub fn set_key(&mut self, name: &str, key: KeyHandle) {
        self.variables.insert(name.to_string(), ScenarioVariable::Key(key));
    }

    pub fn get_key(&self, name: &str) -> TestResult<KeyHandle> {
        match self.variables.get(name) {
            Some(ScenarioVariable::Key(key)) => Ok(*key),
            _ => Err(format!("Key variable '{}' not found", name).into()),
        }
    }

    pub fn set_data(&mut self, name: &str, data: Vec<u8>) {
        self.variables.insert(name.to_string(), ScenarioVariable::Data(data));
    }

    pub fn get_data(&self, name: &str) -> TestResult<Vec<u8>> {
        match self.variables.get(name) {
            Some(ScenarioVariable::Data(data)) => Ok(data.clone()),
            _ => Err(format!("Data variable '{}' not found", name).into()),
        }
    }

    pub fn set_boolean(&mut self, name: &str, value: bool) {
        self.variables.insert(name.to_string(), ScenarioVariable::Boolean(value));
    }

    pub fn get_boolean(&self, name: &str) -> TestResult<bool> {
        match self.variables.get(name) {
            Some(ScenarioVariable::Boolean(value)) => Ok(*value),
            _ => Err(format!("Boolean variable '{}' not found", name).into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scenario_creation() {
        let scenario = TestScenario::rsa_signing_scenario();
        assert_eq!(scenario.name, "RSA Signing");
        assert!(!scenario.steps.is_empty());
        assert!(!scenario.cleanup_steps.is_empty());
    }

    #[test]
    fn test_all_scenarios() {
        let scenarios = TestScenario::all_scenarios();
        assert!(scenarios.len() >= 6);
        
        let names: Vec<String> = scenarios.iter().map(|s| s.name.clone()).collect();
        assert!(names.contains(&"RSA Signing".to_string()));
        assert!(names.contains(&"ECDSA Signing".to_string()));
        assert!(names.contains(&"AES Encryption".to_string()));
    }

    #[test]
    fn test_scenario_context() {
        let mut context = ScenarioContext::new();
        
        let session = SessionHandle(123);
        context.set_session("test_session", session);
        assert_eq!(context.get_session("test_session").unwrap(), session);
        
        let key = KeyHandle(456);
        context.set_key("test_key", key);
        assert_eq!(context.get_key("test_key").unwrap(), key);
        
        let data = vec![1, 2, 3, 4];
        context.set_data("test_data", data.clone());
        assert_eq!(context.get_data("test_data").unwrap(), data);
    }
}