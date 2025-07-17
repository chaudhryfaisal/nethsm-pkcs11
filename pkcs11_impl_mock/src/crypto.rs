//! Mock cryptographic operations for the PKCS#11 implementation.

use crate::error::{MockError, MockResult};
use crate::storage::MockKeyMaterial;
use pkcs11_core::backend::types::*;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// Mock cryptographic operations provider.
#[derive(Debug)]
pub struct MockCrypto {
    /// Whether to use deterministic behavior
    deterministic: bool,
    /// Random seed for deterministic operations
    random_seed: Option<u64>,
    /// Operation counter for deterministic behavior
    operation_counter: std::sync::atomic::AtomicU32,
}

impl MockCrypto {
    /// Create a new mock crypto provider.
    pub fn new(deterministic: bool, random_seed: Option<u64>) -> Self {
        Self {
            deterministic,
            random_seed,
            operation_counter: std::sync::atomic::AtomicU32::new(0),
        }
    }

    /// Get the next operation counter value.
    fn next_operation_count(&self) -> u32 {
        self.operation_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    /// Generate deterministic or random data.
    fn generate_data(&self, length: usize) -> Vec<u8> {
        if self.deterministic {
            let seed = self.random_seed.unwrap_or(42) + self.next_operation_count() as u64;
            use rand::{Rng, SeedableRng};
            let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
            let mut data = vec![0u8; length];
            rng.fill(&mut data[..]);
            data
        } else {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let mut data = vec![0u8; length];
            rng.fill(&mut data[..]);
            data
        }
    }

    // === Random Number Generation ===

    /// Generate random data.
    pub fn generate_random(&self, length: usize) -> MockResult<Vec<u8>> {
        if length == 0 {
            return Err(MockError::Random("Invalid length: 0".to_string()));
        }
        if length > 1024 * 1024 {
            return Err(MockError::Random("Length too large".to_string()));
        }

        Ok(self.generate_data(length))
    }

    // === Digest Operations ===

    /// Compute a digest using the specified mechanism.
    pub fn digest(&self, mechanism: &MechanismType, data: &[u8]) -> MockResult<Vec<u8>> {
        match mechanism.0 {
            x if x == cryptoki_sys::CKM_SHA256 as u32 => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            }
            x if x == cryptoki_sys::CKM_SHA384 as u32 => {
                let mut hasher = Sha384::new();
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            }
            x if x == cryptoki_sys::CKM_SHA512 as u32 => {
                let mut hasher = Sha512::new();
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            }
            _ => Err(MockError::Digest(format!(
                "Unsupported digest mechanism: {}",
                mechanism.0
            ))),
        }
    }

    // === Signing Operations ===

    /// Sign data using the specified key and mechanism.
    pub fn sign(
        &self,
        key_material: &MockKeyMaterial,
        mechanism: &SignMechanism,
        data: &[u8],
    ) -> MockResult<Vec<u8>> {
        match mechanism.mechanism_type.0 {
            x if x == cryptoki_sys::CKM_RSA_PKCS as u32 => {
                self.sign_rsa_pkcs(key_material, data)
            }
            x if x == cryptoki_sys::CKM_RSA_PKCS_PSS as u32 => {
                self.sign_rsa_pss(key_material, data)
            }
            x if x == cryptoki_sys::CKM_ECDSA as u32 => {
                self.sign_ecdsa(key_material, data)
            }
            _ => Err(MockError::Signature(format!(
                "Unsupported signing mechanism: {}",
                mechanism.mechanism_type.0
            ))),
        }
    }

    /// Verify a signature using the specified key and mechanism.
    pub fn verify(
        &self,
        key_material: &MockKeyMaterial,
        mechanism: &SignMechanism,
        data: &[u8],
        signature: &[u8],
    ) -> MockResult<bool> {
        // For mock verification, we regenerate the signature and compare
        let expected_signature = self.sign(key_material, mechanism, data)?;
        Ok(expected_signature == signature)
    }

    /// Mock RSA PKCS#1 v1.5 signing.
    fn sign_rsa_pkcs(&self, key_material: &MockKeyMaterial, data: &[u8]) -> MockResult<Vec<u8>> {
        match key_material {
            MockKeyMaterial::Rsa { key_size, private_exponent, .. } => {
                if private_exponent.is_none() {
                    return Err(MockError::Signature("Private key required for signing".to_string()));
                }

                // Generate deterministic mock signature based on data and key
                let signature_size = (*key_size / 8) as usize;
                let mut signature_data = data.to_vec();
                signature_data.extend_from_slice(&key_size.to_le_bytes());
                
                if self.deterministic {
                    let seed = self.random_seed.unwrap_or(42);
                    signature_data.extend_from_slice(&seed.to_le_bytes());
                }

                let hash = Sha256::digest(&signature_data);
                let mut signature = vec![0u8; signature_size];
                
                // Fill signature with deterministic data based on hash
                for (i, chunk) in signature.chunks_mut(32).enumerate() {
                    let mut hasher = Sha256::new();
                    hasher.update(&hash);
                    hasher.update(&(i as u32).to_le_bytes());
                    let chunk_hash = hasher.finalize();
                    let copy_len = chunk.len().min(chunk_hash.len());
                    chunk[..copy_len].copy_from_slice(&chunk_hash[..copy_len]);
                }

                Ok(signature)
            }
            _ => Err(MockError::Signature("Invalid key type for RSA signing".to_string())),
        }
    }

    /// Mock RSA PSS signing.
    fn sign_rsa_pss(&self, key_material: &MockKeyMaterial, data: &[u8]) -> MockResult<Vec<u8>> {
        match key_material {
            MockKeyMaterial::Rsa { key_size, private_exponent, .. } => {
                if private_exponent.is_none() {
                    return Err(MockError::Signature("Private key required for signing".to_string()));
                }

                let signature_size = (*key_size / 8) as usize;
                let mut signature_data = data.to_vec();
                signature_data.extend_from_slice(b"PSS"); // Differentiate from PKCS#1 v1.5
                signature_data.extend_from_slice(&key_size.to_le_bytes());
                
                if self.deterministic {
                    let seed = self.random_seed.unwrap_or(42);
                    signature_data.extend_from_slice(&seed.to_le_bytes());
                }

                let hash = Sha256::digest(&signature_data);
                let mut signature = vec![0u8; signature_size];
                
                for (i, chunk) in signature.chunks_mut(32).enumerate() {
                    let mut hasher = Sha256::new();
                    hasher.update(&hash);
                    hasher.update(b"PSS");
                    hasher.update(&(i as u32).to_le_bytes());
                    let chunk_hash = hasher.finalize();
                    let copy_len = chunk.len().min(chunk_hash.len());
                    chunk[..copy_len].copy_from_slice(&chunk_hash[..copy_len]);
                }

                Ok(signature)
            }
            _ => Err(MockError::Signature("Invalid key type for RSA PSS signing".to_string())),
        }
    }

    /// Mock ECDSA signing.
    fn sign_ecdsa(&self, key_material: &MockKeyMaterial, data: &[u8]) -> MockResult<Vec<u8>> {
        match key_material {
            MockKeyMaterial::EllipticCurve { curve, private_scalar, .. } => {
                if private_scalar.is_none() {
                    return Err(MockError::Signature("Private key required for signing".to_string()));
                }

                // ECDSA signature is typically r || s, each component is the size of the curve order
                let component_size = match curve {
                    EcCurve::P256 => 32,
                    EcCurve::P384 => 48,
                    EcCurve::P521 => 66,
                    EcCurve::Ed25519 => 32,
                };

                let signature_size = component_size * 2;
                let mut signature_data = data.to_vec();
                signature_data.extend_from_slice(b"ECDSA");
                signature_data.extend_from_slice(&(component_size as u32).to_le_bytes());
                
                if self.deterministic {
                    let seed = self.random_seed.unwrap_or(42);
                    signature_data.extend_from_slice(&seed.to_le_bytes());
                }

                let hash = Sha256::digest(&signature_data);
                let mut signature = vec![0u8; signature_size];
                
                for (i, chunk) in signature.chunks_mut(32).enumerate() {
                    let mut hasher = Sha256::new();
                    hasher.update(&hash);
                    hasher.update(b"ECDSA");
                    hasher.update(&(i as u32).to_le_bytes());
                    let chunk_hash = hasher.finalize();
                    let copy_len = chunk.len().min(chunk_hash.len());
                    chunk[..copy_len].copy_from_slice(&chunk_hash[..copy_len]);
                }

                Ok(signature)
            }
            _ => Err(MockError::Signature("Invalid key type for ECDSA signing".to_string())),
        }
    }

    // === Encryption/Decryption Operations ===

    /// Encrypt data using the specified key and mechanism.
    pub fn encrypt(
        &self,
        key_material: &MockKeyMaterial,
        mechanism: &EncryptMechanism,
        data: &[u8],
    ) -> MockResult<Vec<u8>> {
        match mechanism.mechanism_type.0 {
            x if x == cryptoki_sys::CKM_RSA_PKCS as u32 => {
                self.encrypt_rsa_pkcs(key_material, data)
            }
            x if x == cryptoki_sys::CKM_AES_CBC as u32 => {
                self.encrypt_aes_cbc(key_material, data)
            }
            _ => Err(MockError::Encryption(format!(
                "Unsupported encryption mechanism: {}",
                mechanism.mechanism_type.0
            ))),
        }
    }

    /// Decrypt data using the specified key and mechanism.
    pub fn decrypt(
        &self,
        key_material: &MockKeyMaterial,
        mechanism: &EncryptMechanism,
        data: &[u8],
    ) -> MockResult<Vec<u8>> {
        match mechanism.mechanism_type.0 {
            x if x == cryptoki_sys::CKM_RSA_PKCS as u32 => {
                self.decrypt_rsa_pkcs(key_material, data)
            }
            x if x == cryptoki_sys::CKM_AES_CBC as u32 => {
                self.decrypt_aes_cbc(key_material, data)
            }
            _ => Err(MockError::Decryption(format!(
                "Unsupported decryption mechanism: {}",
                mechanism.mechanism_type.0
            ))),
        }
    }

    /// Mock RSA PKCS#1 v1.5 encryption.
    fn encrypt_rsa_pkcs(&self, key_material: &MockKeyMaterial, data: &[u8]) -> MockResult<Vec<u8>> {
        match key_material {
            MockKeyMaterial::Rsa { key_size, .. } => {
                let max_data_size = (*key_size / 8) as usize - 11; // PKCS#1 v1.5 padding overhead
                if data.len() > max_data_size {
                    return Err(MockError::Encryption("Data too large for RSA encryption".to_string()));
                }

                // For mock encryption, we'll use a simple transformation
                let encrypted_size = (*key_size / 8) as usize;
                let mut encrypted_data = data.to_vec();
                encrypted_data.extend_from_slice(b"RSA_ENCRYPT");
                encrypted_data.extend_from_slice(&key_size.to_le_bytes());
                
                if self.deterministic {
                    let seed = self.random_seed.unwrap_or(42);
                    encrypted_data.extend_from_slice(&seed.to_le_bytes());
                }

                let hash = Sha256::digest(&encrypted_data);
                let mut result = vec![0u8; encrypted_size];
                
                for (i, chunk) in result.chunks_mut(32).enumerate() {
                    let mut hasher = Sha256::new();
                    hasher.update(&hash);
                    hasher.update(b"ENCRYPT");
                    hasher.update(&(i as u32).to_le_bytes());
                    let chunk_hash = hasher.finalize();
                    let copy_len = chunk.len().min(chunk_hash.len());
                    chunk[..copy_len].copy_from_slice(&chunk_hash[..copy_len]);
                }

                Ok(result)
            }
            _ => Err(MockError::Encryption("Invalid key type for RSA encryption".to_string())),
        }
    }

    /// Mock RSA PKCS#1 v1.5 decryption.
    fn decrypt_rsa_pkcs(&self, key_material: &MockKeyMaterial, data: &[u8]) -> MockResult<Vec<u8>> {
        match key_material {
            MockKeyMaterial::Rsa { key_size, private_exponent, .. } => {
                if private_exponent.is_none() {
                    return Err(MockError::Decryption("Private key required for decryption".to_string()));
                }

                let expected_size = (*key_size / 8) as usize;
                if data.len() != expected_size {
                    return Err(MockError::Decryption("Invalid encrypted data size".to_string()));
                }

                // For mock decryption, we'll return a fixed plaintext based on the encrypted data
                let mut plaintext_data = data.to_vec();
                plaintext_data.extend_from_slice(b"RSA_DECRYPT");
                
                let hash = Sha256::digest(&plaintext_data);
                // Return first 32 bytes as mock decrypted data
                Ok(hash[..32.min(hash.len())].to_vec())
            }
            _ => Err(MockError::Decryption("Invalid key type for RSA decryption".to_string())),
        }
    }

    /// Mock AES CBC encryption.
    fn encrypt_aes_cbc(&self, key_material: &MockKeyMaterial, data: &[u8]) -> MockResult<Vec<u8>> {
        match key_material {
            MockKeyMaterial::Symmetric { key_size, key_data } => {
                // AES requires data to be padded to block size (16 bytes)
                let block_size = 16;
                let padding_len = block_size - (data.len() % block_size);
                let mut padded_data = data.to_vec();
                padded_data.extend(vec![padding_len as u8; padding_len]);

                // Mock AES encryption using XOR with key-derived data
                let mut encrypted = Vec::new();
                for chunk in padded_data.chunks(block_size) {
                    let mut encrypted_chunk = vec![0u8; block_size];
                    for (i, &byte) in chunk.iter().enumerate() {
                        let key_byte = key_data[i % key_data.len()];
                        encrypted_chunk[i] = byte ^ key_byte;
                    }
                    encrypted.extend_from_slice(&encrypted_chunk);
                }

                Ok(encrypted)
            }
            _ => Err(MockError::Encryption("Invalid key type for AES encryption".to_string())),
        }
    }

    /// Mock AES CBC decryption.
    fn decrypt_aes_cbc(&self, key_material: &MockKeyMaterial, data: &[u8]) -> MockResult<Vec<u8>> {
        match key_material {
            MockKeyMaterial::Symmetric { key_size, key_data } => {
                let block_size = 16;
                if data.len() % block_size != 0 {
                    return Err(MockError::Decryption("Invalid encrypted data size for AES".to_string()));
                }

                // Mock AES decryption using XOR with key-derived data
                let mut decrypted = Vec::new();
                for chunk in data.chunks(block_size) {
                    let mut decrypted_chunk = vec![0u8; block_size];
                    for (i, &byte) in chunk.iter().enumerate() {
                        let key_byte = key_data[i % key_data.len()];
                        decrypted_chunk[i] = byte ^ key_byte;
                    }
                    decrypted.extend_from_slice(&decrypted_chunk);
                }

                // Remove padding
                if let Some(&padding_len) = decrypted.last() {
                    if padding_len as usize <= block_size && padding_len > 0 {
                        let new_len = decrypted.len() - padding_len as usize;
                        decrypted.truncate(new_len);
                    }
                }

                Ok(decrypted)
            }
            _ => Err(MockError::Decryption("Invalid key type for AES decryption".to_string())),
        }
    }

    // === Key Generation ===

    /// Generate a new key pair.
    pub fn generate_key_pair(&self, spec: &KeyGenerationSpec) -> MockResult<(MockKeyMaterial, MockKeyMaterial)> {
        let seed = if self.deterministic {
            self.random_seed.unwrap_or(42) + self.next_operation_count() as u64
        } else {
            rand::random()
        };

        match spec.key_type {
            KeyType::Rsa => {
                let private_key = MockKeyMaterial::generate_deterministic(spec.key_type, spec.key_size, seed);
                
                // Create public key from private key
                if let MockKeyMaterial::Rsa { key_size, modulus, public_exponent, .. } = &private_key {
                    let public_key = MockKeyMaterial::Rsa {
                        key_size: *key_size,
                        modulus: modulus.clone(),
                        public_exponent: public_exponent.clone(),
                        private_exponent: None, // Public key has no private exponent
                    };
                    Ok((private_key, public_key))
                } else {
                    Err(MockError::KeyGeneration("Failed to generate RSA key pair".to_string()))
                }
            }
            KeyType::EllipticCurve => {
                let private_key = MockKeyMaterial::generate_deterministic(spec.key_type, spec.key_size, seed);
                
                // Create public key from private key
                if let MockKeyMaterial::EllipticCurve { curve, public_point, .. } = &private_key {
                    let public_key = MockKeyMaterial::EllipticCurve {
                        curve: *curve,
                        public_point: public_point.clone(),
                        private_scalar: None, // Public key has no private scalar
                    };
                    Ok((private_key, public_key))
                } else {
                    Err(MockError::KeyGeneration("Failed to generate EC key pair".to_string()))
                }
            }
            _ => Err(MockError::KeyGeneration(format!(
                "Key pair generation not supported for key type: {:?}",
                spec.key_type
            ))),
        }
    }

    /// Generate a symmetric key.
    pub fn generate_symmetric_key(&self, spec: &KeyGenerationSpec) -> MockResult<MockKeyMaterial> {
        let seed = if self.deterministic {
            self.random_seed.unwrap_or(42) + self.next_operation_count() as u64
        } else {
            rand::random()
        };

        match spec.key_type {
            KeyType::Aes | KeyType::GenericSecret => {
                Ok(MockKeyMaterial::generate_deterministic(spec.key_type, spec.key_size, seed))
            }
            _ => Err(MockError::KeyGeneration(format!(
                "Symmetric key generation not supported for key type: {:?}",
                spec.key_type
            ))),
        }
    }
}