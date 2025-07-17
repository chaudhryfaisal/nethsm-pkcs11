//! Test data generation utilities for PKCS#11 testing.
//!
//! This module provides functions to generate consistent test data including
//! keys, certificates, configurations, and test vectors for cryptographic operations.

use pkcs11_core::backend::types::*;
use std::collections::HashMap;

/// Generate test RSA key specification
pub fn rsa_key_spec(key_size: u32, label: Option<String>) -> KeyGenerationSpec {
    KeyGenerationSpec {
        key_type: KeyType::Rsa,
        key_size,
        label,
        id: Some(vec![0x01, 0x02, 0x03, 0x04]),
        usage: KeyUsage {
            sign: true,
            verify: true,
            encrypt: true,
            decrypt: true,
            derive: false,
            extractable: false,
            sensitive: true,
        },
        mechanism: MechanismType(cryptoki_sys::CKM_RSA_PKCS_KEY_PAIR_GEN as u32),
        parameters: None,
    }
}

/// Generate test ECDSA key specification
pub fn ecdsa_key_spec(curve: EllipticCurve, label: Option<String>) -> KeyGenerationSpec {
    let key_size = match curve {
        EllipticCurve::P256 => 256,
        EllipticCurve::P384 => 384,
        EllipticCurve::P521 => 521,
    };

    KeyGenerationSpec {
        key_type: KeyType::EllipticCurve,
        key_size,
        label,
        id: Some(vec![0x05, 0x06, 0x07, 0x08]),
        usage: KeyUsage {
            sign: true,
            verify: true,
            encrypt: false,
            decrypt: false,
            derive: true,
            extractable: false,
            sensitive: true,
        },
        mechanism: MechanismType(cryptoki_sys::CKM_EC_KEY_PAIR_GEN as u32),
        parameters: Some(KeyParameters::EllipticCurve { curve }),
    }
}

/// Generate test AES key specification
pub fn aes_key_spec(key_size: u32, label: Option<String>) -> KeyGenerationSpec {
    KeyGenerationSpec {
        key_type: KeyType::Aes,
        key_size,
        label,
        id: Some(vec![0x09, 0x0A, 0x0B, 0x0C]),
        usage: KeyUsage {
            sign: false,
            verify: false,
            encrypt: true,
            decrypt: true,
            derive: false,
            extractable: false,
            sensitive: true,
        },
        mechanism: MechanismType(cryptoki_sys::CKM_AES_KEY_GEN as u32),
        parameters: None,
    }
}

/// Generate test key filter
pub fn key_filter_by_type(key_type: KeyType) -> KeyFilter {
    KeyFilter {
        key_type: Some(key_type),
        label: None,
        id: None,
        usage: None,
    }
}

/// Generate test key filter by label
pub fn key_filter_by_label(label: &str) -> KeyFilter {
    KeyFilter {
        key_type: None,
        label: Some(label.to_string()),
        id: None,
        usage: None,
    }
}

/// Generate test session flags
pub fn session_flags(rw: bool, serial: bool) -> SessionFlags {
    SessionFlags {
        rw_session: rw,
        serial_session: serial,
    }
}

/// Generate test data for signing operations
pub fn signing_test_data() -> Vec<u8> {
    b"Hello, PKCS#11 World! This is test data for signing operations.".to_vec()
}

/// Generate test data for encryption operations
pub fn encryption_test_data() -> Vec<u8> {
    b"This is secret data that should be encrypted.".to_vec()
}

/// Generate large test data for performance testing
pub fn large_test_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

/// Generate test RSA key import data
pub fn rsa_key_import_data() -> KeyImportData {
    // These are test values - not real cryptographic material
    let modulus = vec![
        0x00, 0xC0, 0x8B, 0x4E, 0x72, 0x8B, 0x9A, 0x3D,
        0x8B, 0x4E, 0x72, 0x8B, 0x9A, 0x3D, 0x8B, 0x4E,
        // ... (truncated for brevity, would be full 2048-bit modulus)
    ];
    
    let public_exponent = vec![0x01, 0x00, 0x01]; // 65537
    
    let private_exponent = vec![
        0x7A, 0x8B, 0x4E, 0x72, 0x8B, 0x9A, 0x3D, 0x8B,
        0x4E, 0x72, 0x8B, 0x9A, 0x3D, 0x8B, 0x4E, 0x72,
        // ... (truncated for brevity, would be full private exponent)
    ];

    KeyImportData {
        key_type: KeyType::Rsa,
        label: Some("imported_rsa_key".to_string()),
        id: Some(vec![0x10, 0x11, 0x12, 0x13]),
        usage: KeyUsage {
            sign: true,
            verify: false,
            encrypt: false,
            decrypt: true,
            derive: false,
            extractable: false,
            sensitive: true,
        },
        key_material: KeyMaterial::Rsa {
            modulus,
            public_exponent,
            private_exponent,
        },
    }
}

/// Generate test ECDSA key import data
pub fn ecdsa_key_import_data() -> KeyImportData {
    // These are test values - not real cryptographic material
    let public_point = vec![
        0x04, // Uncompressed point indicator
        0x8B, 0x4E, 0x72, 0x8B, 0x9A, 0x3D, 0x8B, 0x4E,
        0x72, 0x8B, 0x9A, 0x3D, 0x8B, 0x4E, 0x72, 0x8B,
        // ... (truncated for brevity, would be full P-256 point)
    ];
    
    let private_scalar = vec![
        0x7A, 0x8B, 0x4E, 0x72, 0x8B, 0x9A, 0x3D, 0x8B,
        0x4E, 0x72, 0x8B, 0x9A, 0x3D, 0x8B, 0x4E, 0x72,
        // ... (truncated for brevity, would be full private scalar)
    ];

    KeyImportData {
        key_type: KeyType::EllipticCurve,
        label: Some("imported_ecdsa_key".to_string()),
        id: Some(vec![0x14, 0x15, 0x16, 0x17]),
        usage: KeyUsage {
            sign: true,
            verify: false,
            encrypt: false,
            decrypt: false,
            derive: true,
            extractable: false,
            sensitive: true,
        },
        key_material: KeyMaterial::EllipticCurve {
            curve: EllipticCurve::P256,
            public_point,
            private_scalar,
        },
    }
}

/// Generate test AES key import data
pub fn aes_key_import_data() -> KeyImportData {
    // Test AES-256 key
    let key_data = vec![
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
    ];

    KeyImportData {
        key_type: KeyType::Aes,
        label: Some("imported_aes_key".to_string()),
        id: Some(vec![0x18, 0x19, 0x1A, 0x1B]),
        usage: KeyUsage {
            sign: false,
            verify: false,
            encrypt: true,
            decrypt: true,
            derive: false,
            extractable: false,
            sensitive: true,
        },
        key_material: KeyMaterial::Symmetric { key_data },
    }
}

/// Generate test signing mechanisms
pub fn signing_mechanisms() -> Vec<SignMechanism> {
    vec![
        SignMechanism {
            mechanism_type: MechanismType(cryptoki_sys::CKM_RSA_PKCS as u32),
            parameters: None,
        },
        SignMechanism {
            mechanism_type: MechanismType(cryptoki_sys::CKM_RSA_PKCS_PSS as u32),
            parameters: Some(SignParameters::RsaPss {
                hash_algorithm: MechanismType(cryptoki_sys::CKM_SHA256 as u32),
                mgf: MechanismType(cryptoki_sys::CKG_MGF1_SHA256 as u32),
                salt_length: 32,
            }),
        },
        SignMechanism {
            mechanism_type: MechanismType(cryptoki_sys::CKM_ECDSA as u32),
            parameters: None,
        },
    ]
}

/// Generate test encryption mechanisms
pub fn encryption_mechanisms() -> Vec<EncryptMechanism> {
    vec![
        EncryptMechanism {
            mechanism_type: MechanismType(cryptoki_sys::CKM_RSA_PKCS as u32),
            parameters: None,
        },
        EncryptMechanism {
            mechanism_type: MechanismType(cryptoki_sys::CKM_AES_CBC as u32),
            parameters: Some(EncryptParameters::AesCbc {
                iv: vec![0; 16], // Zero IV for testing
            }),
        },
    ]
}

/// Generate test mechanism types for digest operations
pub fn digest_mechanisms() -> Vec<MechanismType> {
    vec![
        MechanismType(cryptoki_sys::CKM_SHA256 as u32),
        MechanismType(cryptoki_sys::CKM_SHA384 as u32),
        MechanismType(cryptoki_sys::CKM_SHA512 as u32),
        MechanismType(cryptoki_sys::CKM_SHA1 as u32),
        MechanismType(cryptoki_sys::CKM_MD5 as u32),
    ]
}

/// Generate test vectors for cryptographic operations
pub struct TestVectors {
    pub rsa_pkcs_sign: TestVector,
    pub rsa_pss_sign: TestVector,
    pub ecdsa_sign: TestVector,
    pub aes_encrypt: TestVector,
    pub sha256_digest: TestVector,
}

pub struct TestVector {
    pub input: Vec<u8>,
    pub expected_output: Option<Vec<u8>>, // None for non-deterministic operations
    pub mechanism: String,
    pub key_size: Option<u32>,
}

impl TestVectors {
    pub fn new() -> Self {
        Self {
            rsa_pkcs_sign: TestVector {
                input: b"test data for RSA PKCS#1 v1.5 signing".to_vec(),
                expected_output: None, // Signing is non-deterministic
                mechanism: "CKM_RSA_PKCS".to_string(),
                key_size: Some(2048),
            },
            rsa_pss_sign: TestVector {
                input: b"test data for RSA PSS signing".to_vec(),
                expected_output: None, // PSS is non-deterministic
                mechanism: "CKM_RSA_PKCS_PSS".to_string(),
                key_size: Some(2048),
            },
            ecdsa_sign: TestVector {
                input: b"test data for ECDSA signing".to_vec(),
                expected_output: None, // ECDSA is non-deterministic
                mechanism: "CKM_ECDSA".to_string(),
                key_size: Some(256),
            },
            aes_encrypt: TestVector {
                input: b"test data for AES encryption, must be 16 bytes".to_vec(),
                expected_output: None, // Depends on key and IV
                mechanism: "CKM_AES_CBC".to_string(),
                key_size: Some(256),
            },
            sha256_digest: TestVector {
                input: b"test data for SHA-256 hashing".to_vec(),
                expected_output: Some(vec![
                    0x8a, 0x8b, 0x4e, 0x72, 0x8b, 0x9a, 0x3d, 0x8b,
                    0x4e, 0x72, 0x8b, 0x9a, 0x3d, 0x8b, 0x4e, 0x72,
                    0x8b, 0x9a, 0x3d, 0x8b, 0x4e, 0x72, 0x8b, 0x9a,
                    0x3d, 0x8b, 0x4e, 0x72, 0x8b, 0x9a, 0x3d, 0x8b,
                ]), // This would be the actual SHA-256 hash
                mechanism: "CKM_SHA256".to_string(),
                key_size: None,
            },
        }
    }
}

/// Generate performance test configurations
pub struct PerformanceTestConfig {
    pub operation_counts: Vec<usize>,
    pub data_sizes: Vec<usize>,
    pub key_sizes: Vec<u32>,
    pub concurrent_sessions: Vec<usize>,
}

impl PerformanceTestConfig {
    pub fn default() -> Self {
        Self {
            operation_counts: vec![1, 10, 100, 1000],
            data_sizes: vec![64, 1024, 4096, 65536],
            key_sizes: vec![1024, 2048, 4096],
            concurrent_sessions: vec![1, 4, 8, 16],
        }
    }

    pub fn quick() -> Self {
        Self {
            operation_counts: vec![1, 10],
            data_sizes: vec![64, 1024],
            key_sizes: vec![2048],
            concurrent_sessions: vec![1, 4],
        }
    }
}

/// Generate error injection test scenarios
pub struct ErrorInjectionScenarios {
    pub scenarios: HashMap<String, ErrorScenario>,
}

pub struct ErrorScenario {
    pub operation: String,
    pub trigger_count: u32,
    pub error_type: String,
    pub description: String,
}

impl ErrorInjectionScenarios {
    pub fn new() -> Self {
        let mut scenarios = HashMap::new();
        
        scenarios.insert("network_failure".to_string(), ErrorScenario {
            operation: "sign".to_string(),
            trigger_count: 5,
            error_type: "NetworkError".to_string(),
            description: "Simulate network failure during signing".to_string(),
        });
        
        scenarios.insert("authentication_failure".to_string(), ErrorScenario {
            operation: "login".to_string(),
            trigger_count: 1,
            error_type: "AuthenticationError".to_string(),
            description: "Simulate authentication failure".to_string(),
        });
        
        scenarios.insert("key_not_found".to_string(), ErrorScenario {
            operation: "get_key_info".to_string(),
            trigger_count: 3,
            error_type: "ObjectNotFound".to_string(),
            description: "Simulate key not found error".to_string(),
        });

        Self { scenarios }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_key_spec_generation() {
        let spec = rsa_key_spec(2048, Some("test_rsa".to_string()));
        assert_eq!(spec.key_type, KeyType::Rsa);
        assert_eq!(spec.key_size, 2048);
        assert_eq!(spec.label, Some("test_rsa".to_string()));
        assert!(spec.usage.sign);
        assert!(spec.usage.verify);
    }

    #[test]
    fn test_ecdsa_key_spec_generation() {
        let spec = ecdsa_key_spec(EllipticCurve::P256, Some("test_ecdsa".to_string()));
        assert_eq!(spec.key_type, KeyType::EllipticCurve);
        assert_eq!(spec.key_size, 256);
        assert!(spec.usage.sign);
        assert!(spec.usage.derive);
    }

    #[test]
    fn test_test_vectors_creation() {
        let vectors = TestVectors::new();
        assert!(!vectors.rsa_pkcs_sign.input.is_empty());
        assert!(!vectors.ecdsa_sign.input.is_empty());
        assert!(vectors.sha256_digest.expected_output.is_some());
    }

    #[test]
    fn test_performance_config() {
        let config = PerformanceTestConfig::quick();
        assert_eq!(config.operation_counts.len(), 2);
        assert_eq!(config.data_sizes.len(), 2);
    }
}