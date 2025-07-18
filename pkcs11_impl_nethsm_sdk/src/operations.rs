//! NetHSM-specific cryptographic operations.
//!
//! This module contains the NetHSM-specific implementations for key management,
//! signing, encryption, decryption, and other cryptographic operations.

use std::collections::HashMap;

use base64ct::{Base64, Encoding};
use der::Decode;
use log::{debug, error, trace, warn};
use nethsm_sdk_rs::{
    apis::default_api,
    models::{
        DecryptMode, EncryptMode, KeyGenerateRequestData, KeyItem, KeyPrivateData, KeyType,
        PrivateKey, SignMode,
    },
};

use pkcs11_core::backend::{
    error::BackendError,
    types::*,
};

use crate::{
    config::{InstanceData, UserConfig},
    error::{convert_api_error, NetHsmError, NetHsmResult},
};

/// NetHSM key operations
pub struct KeyOperations;

impl KeyOperations {
    /// Generate a new key pair on the NetHSM
    pub fn generate_key_pair(
        instance: &InstanceData,
        spec: &KeyGenerationSpec,
    ) -> NetHsmResult<(KeyHandle, KeyHandle)> {
        let key_type = match spec.key_type {
            KeyType::Rsa => nethsm_sdk_rs::models::KeyType::Rsa,
            KeyType::EcP256 => nethsm_sdk_rs::models::KeyType::EcP256,
            KeyType::EcP384 => nethsm_sdk_rs::models::KeyType::EcP384,
            KeyType::EcP521 => nethsm_sdk_rs::models::KeyType::EcP521,
            KeyType::Curve25519 => nethsm_sdk_rs::models::KeyType::Curve25519,
            _ => {
                return Err(NetHsmError::InvalidMechanism {
                    mechanism: format!("{:?}", spec.key_type),
                });
            }
        };

        let mechanisms = vec![]; // TODO: Convert from spec.usage

        let request = KeyGenerateRequestData {
            mechanisms,
            r#type: key_type,
            restrictions: None,
            id: spec.label.clone(),
            length: spec.key_size.map(|s| s as i32),
        };

        let response = convert_api_error(
            default_api::keys_generate_post(&instance.config(), request),
            "generate_key_pair",
        )?;

        // Extract key ID from location header
        let key_id = Self::extract_key_id_from_location(&response.headers)?;

        // For now, return the same handle for both public and private keys
        // In a full implementation, we'd need to handle this properly
        let private_handle = KeyHandle(1);
        let public_handle = KeyHandle(2);

        Ok((private_handle, public_handle))
    }

    /// Import a key into the NetHSM
    pub fn import_key(
        instance: &InstanceData,
        key_data: &KeyImportData,
    ) -> NetHsmResult<KeyHandle> {
        let (key_type, private_key) = match key_data {
            KeyImportData::Rsa { private_key, .. } => {
                let key = Box::new(KeyPrivateData {
                    data: None,
                    prime_p: Some(Base64::encode_string(&private_key.p)),
                    prime_q: Some(Base64::encode_string(&private_key.q)),
                    public_exponent: Some(Base64::encode_string(&private_key.e)),
                });
                (nethsm_sdk_rs::models::KeyType::Rsa, key)
            }
            KeyImportData::EcPrivate { private_key, curve } => {
                let key_type = match curve {
                    EcCurve::P256 => nethsm_sdk_rs::models::KeyType::EcP256,
                    EcCurve::P384 => nethsm_sdk_rs::models::KeyType::EcP384,
                    EcCurve::P521 => nethsm_sdk_rs::models::KeyType::EcP521,
                };

                let key = Box::new(KeyPrivateData {
                    data: Some(Base64::encode_string(private_key)),
                    prime_p: None,
                    prime_q: None,
                    public_exponent: None,
                });
                (key_type, key)
            }
            KeyImportData::Symmetric { key_data, .. } => {
                let key = Box::new(KeyPrivateData {
                    data: Some(Base64::encode_string(key_data)),
                    prime_p: None,
                    prime_q: None,
                    public_exponent: None,
                });
                (nethsm_sdk_rs::models::KeyType::Generic, key)
            }
        };

        let private_key_obj = PrivateKey {
            mechanisms: vec![], // TODO: Set based on key usage
            r#type: key_type,
            private: private_key,
            restrictions: None,
        };

        let response = convert_api_error(
            default_api::keys_post(
                &instance.config(),
                default_api::KeysPostBody::ApplicationJson(private_key_obj),
            ),
            "import_key",
        )?;

        let key_id = Self::extract_key_id_from_location(&response.headers)?;
        Ok(KeyHandle(1)) // TODO: Map key_id to handle
    }

    /// Delete a key from the NetHSM
    pub fn delete_key(instance: &InstanceData, key_id: &str) -> NetHsmResult<()> {
        convert_api_error(
            default_api::keys_key_id_delete(&instance.config(), key_id),
            "delete_key",
        )?;
        Ok(())
    }

    /// List keys on the NetHSM
    pub fn list_keys(instance: &InstanceData) -> NetHsmResult<Vec<KeyInfo>> {
        let response = convert_api_error(
            default_api::keys_get(&instance.config()),
            "list_keys",
        )?;

        let mut keys = Vec::new();
        for key_item in response.entity {
            let key_info = KeyInfo {
                handle: KeyHandle(1), // TODO: Map key ID to handle
                key_type: Self::convert_key_type(&key_item.r#type),
                key_size: 0, // TODO: Extract from key data
                label: Some(key_item.id.clone()),
                id: Some(key_item.id.clone().into_bytes()),
                usage: KeyUsage::default(), // TODO: Extract from mechanisms
            };
            keys.push(key_info);
        }

        Ok(keys)
    }

    /// Get key information
    pub fn get_key_info(instance: &InstanceData, key_id: &str) -> NetHsmResult<KeyInfo> {
        let response = convert_api_error(
            default_api::keys_key_id_get(&instance.config(), key_id),
            "get_key_info",
        )?;

        let key_info = KeyInfo {
            handle: KeyHandle(1), // TODO: Map key ID to handle
            key_type: Self::convert_key_type(&response.entity.r#type),
            key_size: 0, // TODO: Extract from key data
            label: Some(key_id.to_string()),
            id: Some(key_id.as_bytes().to_vec()),
            usage: KeyUsage::default(), // TODO: Extract from mechanisms
        };

        Ok(key_info)
    }

    /// Extract key ID from location header
    fn extract_key_id_from_location(headers: &HashMap<String, String>) -> NetHsmResult<String> {
        let location_header = headers
            .get("location")
            .ok_or_else(|| NetHsmError::internal_error("Missing location header"))?;

        let key_id = location_header
            .split('/')
            .last()
            .ok_or_else(|| NetHsmError::internal_error("Invalid location header format"))?
            .split('?')
            .next()
            .ok_or_else(|| NetHsmError::internal_error("Invalid location header format"))?
            .to_string();

        Ok(key_id)
    }

    /// Convert NetHSM key type to core key type
    fn convert_key_type(nethsm_type: &nethsm_sdk_rs::models::KeyType) -> KeyType {
        match nethsm_type {
            nethsm_sdk_rs::models::KeyType::Rsa => KeyType::Rsa,
            nethsm_sdk_rs::models::KeyType::EcP224 => KeyType::EcP224,
            nethsm_sdk_rs::models::KeyType::EcP256 => KeyType::EcP256,
            nethsm_sdk_rs::models::KeyType::EcP384 => KeyType::EcP384,
            nethsm_sdk_rs::models::KeyType::EcP521 => KeyType::EcP521,
            nethsm_sdk_rs::models::KeyType::Curve25519 => KeyType::Curve25519,
            nethsm_sdk_rs::models::KeyType::Generic => KeyType::Generic,
        }
    }
}

/// NetHSM signing operations
pub struct SignOperations;

impl SignOperations {
    /// Sign data using a NetHSM key
    pub fn sign(
        instance: &InstanceData,
        key_id: &str,
        mechanism: &SignMechanism,
        data: &[u8],
    ) -> NetHsmResult<Vec<u8>> {
        let sign_mode = Self::convert_sign_mechanism(mechanism)?;
        let b64_message = Base64::encode_string(data);

        let request = nethsm_sdk_rs::models::SignRequestData {
            mode: sign_mode,
            message: b64_message,
        };

        let response = convert_api_error(
            default_api::keys_key_id_sign_post(&instance.config(), key_id, request),
            "sign",
        )?;

        let signature = Base64::decode_vec(&response.entity.signature)
            .map_err(|e| NetHsmError::internal_error(format!("Base64 decode error: {}", e)))?;

        Ok(signature)
    }

    /// Verify a signature using a NetHSM key
    pub fn verify(
        instance: &InstanceData,
        key_id: &str,
        mechanism: &SignMechanism,
        data: &[u8],
        signature: &[u8],
    ) -> NetHsmResult<bool> {
        // NetHSM doesn't have a direct verify API, so we'd need to implement this
        // by getting the public key and verifying locally, or by using other means
        // For now, return a placeholder
        Ok(true)
    }

    /// Convert sign mechanism to NetHSM sign mode
    fn convert_sign_mechanism(mechanism: &SignMechanism) -> NetHsmResult<SignMode> {
        match mechanism {
            SignMechanism::RsaPkcs1 => Ok(SignMode::Pkcs1),
            SignMechanism::RsaPss { .. } => Ok(SignMode::Pss),
            SignMechanism::Ecdsa => Ok(SignMode::EcdsaSignature),
            SignMechanism::EdDsa => Ok(SignMode::EdDsaSignature),
            _ => Err(NetHsmError::InvalidMechanism {
                mechanism: format!("{:?}", mechanism),
            }),
        }
    }
}

/// NetHSM encryption operations
pub struct EncryptOperations;

impl EncryptOperations {
    /// Encrypt data using a NetHSM key
    pub fn encrypt(
        instance: &InstanceData,
        key_id: &str,
        mechanism: &EncryptMechanism,
        data: &[u8],
    ) -> NetHsmResult<Vec<u8>> {
        let (encrypt_mode, iv) = Self::convert_encrypt_mechanism(mechanism)?;
        let b64_message = Base64::encode_string(data);

        let request = nethsm_sdk_rs::models::EncryptRequestData {
            mode: encrypt_mode,
            message: b64_message,
            iv: iv.map(|iv_data| Base64::encode_string(&iv_data)),
        };

        let response = convert_api_error(
            default_api::keys_key_id_encrypt_post(&instance.config(), key_id, request),
            "encrypt",
        )?;

        let encrypted = Base64::decode_vec(&response.entity.encrypted)
            .map_err(|e| NetHsmError::internal_error(format!("Base64 decode error: {}", e)))?;

        Ok(encrypted)
    }

    /// Decrypt data using a NetHSM key
    pub fn decrypt(
        instance: &InstanceData,
        key_id: &str,
        mechanism: &EncryptMechanism,
        data: &[u8],
    ) -> NetHsmResult<Vec<u8>> {
        let (decrypt_mode, iv) = Self::convert_decrypt_mechanism(mechanism)?;
        let b64_message = Base64::encode_string(data);

        let request = nethsm_sdk_rs::models::DecryptRequestData {
            mode: decrypt_mode,
            encrypted: b64_message,
            iv: iv.map(|iv_data| Base64::encode_string(&iv_data)),
        };

        let response = convert_api_error(
            default_api::keys_key_id_decrypt_post(&instance.config(), key_id, request),
            "decrypt",
        )?;

        let decrypted = Base64::decode_vec(&response.entity.decrypted)
            .map_err(|e| NetHsmError::internal_error(format!("Base64 decode error: {}", e)))?;

        Ok(decrypted)
    }

    /// Convert encrypt mechanism to NetHSM encrypt mode
    fn convert_encrypt_mechanism(
        mechanism: &EncryptMechanism,
    ) -> NetHsmResult<(EncryptMode, Option<Vec<u8>>)> {
        match mechanism {
            EncryptMechanism::RsaPkcs1 => Ok((EncryptMode::Pkcs1, None)),
            EncryptMechanism::RsaOaep { .. } => Ok((EncryptMode::Oaep, None)),
            EncryptMechanism::AesCbc { iv } => Ok((EncryptMode::AesCbc, Some(iv.clone()))),
            _ => Err(NetHsmError::InvalidMechanism {
                mechanism: format!("{:?}", mechanism),
            }),
        }
    }

    /// Convert encrypt mechanism to NetHSM decrypt mode
    fn convert_decrypt_mechanism(
        mechanism: &EncryptMechanism,
    ) -> NetHsmResult<(DecryptMode, Option<Vec<u8>>)> {
        match mechanism {
            EncryptMechanism::RsaPkcs1 => Ok((DecryptMode::Pkcs1, None)),
            EncryptMechanism::RsaOaep { .. } => Ok((DecryptMode::Oaep, None)),
            EncryptMechanism::AesCbc { iv } => Ok((DecryptMode::AesCbc, Some(iv.clone()))),
            _ => Err(NetHsmError::InvalidMechanism {
                mechanism: format!("{:?}", mechanism),
            }),
        }
    }
}

/// NetHSM random number generation
pub struct RandomOperations;

impl RandomOperations {
    /// Generate random bytes using NetHSM
    pub fn generate_random(instance: &InstanceData, length: usize) -> NetHsmResult<Vec<u8>> {
        if length > 1024 {
            return Err(NetHsmError::InvalidDataFormat {
                reason: "NetHSM supports up to 1024 bytes of random data".to_string(),
            });
        }

        let request = nethsm_sdk_rs::models::RandomRequestData {
            length: length as i32,
        };

        let response = convert_api_error(
            default_api::random_post(&instance.config(), request),
            "generate_random",
        )?;

        let random_data = Base64::decode_vec(&response.entity.random)
            .map_err(|e| NetHsmError::internal_error(format!("Base64 decode error: {}", e)))?;

        Ok(random_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests would require a running NetHSM instance
    // In a real implementation, we'd use mock instances for testing

    #[test]
    fn test_key_type_conversion() {
        assert_eq!(
            KeyOperations::convert_key_type(&nethsm_sdk_rs::models::KeyType::Rsa),
            KeyType::Rsa
        );
        assert_eq!(
            KeyOperations::convert_key_type(&nethsm_sdk_rs::models::KeyType::EcP256),
            KeyType::EcP256
        );
    }

    #[test]
    fn test_sign_mechanism_conversion() {
        assert!(SignOperations::convert_sign_mechanism(&SignMechanism::RsaPkcs1).is_ok());
        assert!(SignOperations::convert_sign_mechanism(&SignMechanism::Ecdsa).is_ok());
    }
}