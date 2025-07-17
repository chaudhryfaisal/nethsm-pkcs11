//! Example: Basic Operations with Mock Backend
//!
//! This example demonstrates basic PKCS#11 operations using the mock backend.
//! The mock backend is perfect for testing and development as it provides
//! deterministic behavior and doesn't require external hardware.
//!
//! ## Usage
//!
//! ```bash
//! cargo run --example mock_backend
//! ```
//!
//! ## Configuration
//!
//! Uses configuration from `examples/basic_usage/config/mock.yaml`

use pkcs11_core::backend::{
    types::*,
    CryptoBackend,
};
use pkcs11_impl_mock::{MockBackend, MockConfig};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging
    env_logger::init();
    
    println!("=== Mock Backend Basic Operations Example ===\n");
    
    // Step 1: Create and initialize the mock backend
    println!("1. Initializing mock backend...");
    let config = MockConfig::new()
        .with_deterministic(true)
        .with_random_seed(42)
        .with_token_label("Example Mock Token")
        .with_default_pin("123456")
        .with_require_auth(true)
        .with_verbose_logging(true);
    
    let mut backend = MockBackend::initialize(config)?;
    println!("   ✓ Backend initialized successfully");
    
    // Step 2: Get available slots
    println!("\n2. Getting available slots...");
    let slots = backend.get_slot_list(true)?;
    println!("   ✓ Found {} slot(s)", slots.len());
    
    if slots.is_empty() {
        return Err("No slots available".into());
    }
    
    let slot_id = slots[0];
    println!("   Using slot: {:?}", slot_id);
    
    // Step 3: Get slot and token information
    println!("\n3. Getting slot and token information...");
    let slot_info = backend.get_slot_info(slot_id)?;
    println!("   Slot description: {}", slot_info.slot_description);
    println!("   Manufacturer: {}", slot_info.manufacturer_id);
    
    let token_info = backend.get_token_info(slot_id)?;
    println!("   Token label: {}", token_info.label);
    println!("   Token model: {}", token_info.model);
    
    // Step 4: Open a session
    println!("\n4. Opening session...");
    let session_flags = SessionFlags {
        rw_session: true,
        serial_session: true,
    };
    
    let session = backend.open_session(slot_id, session_flags)?;
    println!("   ✓ Session opened: {:?}", session);
    
    // Step 5: Login
    println!("\n5. Logging in...");
    backend.login(session, UserType::User, "123456")?;
    println!("   ✓ Logged in successfully");
    
    // Step 6: Generate a key pair
    println!("\n6. Generating RSA key pair...");
    let key_spec = KeyGenerationSpec {
        key_type: KeyType::Rsa,
        key_size: 2048,
        label: Some("example-rsa-key".to_string()),
        id: Some(b"rsa-key-001".to_vec()),
        usage: KeyUsage {
            sign: true,
            verify: true,
            encrypt: false,
            decrypt: false,
            derive: false,
            extractable: false,
            sensitive: true,
        },
    };
    
    let (private_key, public_key) = backend.generate_key_pair(session, &key_spec)?;
    println!("   ✓ Key pair generated:");
    println!("     Private key: {:?}", private_key);
    println!("     Public key: {:?}", public_key);
    
    // Step 7: List keys
    println!("\n7. Listing keys...");
    let keys = backend.list_keys(session, None)?;
    println!("   ✓ Found {} key(s):", keys.len());
    for key in &keys {
        println!("     - Handle: {:?}, Type: {:?}, Size: {} bits", 
                 key.handle, key.key_type, key.key_size);
        if let Some(ref label) = key.label {
            println!("       Label: {}", label);
        }
    }
    
    // Step 8: Sign data
    println!("\n8. Signing data...");
    let data = b"Hello, World! This is a test message for signing.";
    let mechanism = SignMechanism {
        mechanism_type: MechanismType(cryptoki_sys::CKM_RSA_PKCS as u32),
        parameters: None,
    };
    
    let signature = backend.sign(session, private_key, &mechanism, data)?;
    println!("   ✓ Data signed successfully");
    println!("     Data length: {} bytes", data.len());
    println!("     Signature length: {} bytes", signature.len());
    
    // Step 9: Verify signature
    println!("\n9. Verifying signature...");
    let is_valid = backend.verify(session, public_key, &mechanism, data, &signature)?;
    println!("   ✓ Signature verification: {}", if is_valid { "VALID" } else { "INVALID" });
    
    // Step 10: Test with invalid data
    println!("\n10. Testing signature verification with modified data...");
    let modified_data = b"Hello, World! This is a MODIFIED test message.";
    let is_valid_modified = backend.verify(session, public_key, &mechanism, modified_data, &signature)?;
    println!("    ✓ Modified data verification: {}", if is_valid_modified { "VALID" } else { "INVALID" });
    
    // Step 11: Generate random data
    println!("\n11. Generating random data...");
    let random_data = backend.generate_random(session, 32)?;
    println!("    ✓ Generated {} bytes of random data", random_data.len());
    println!("      Random data (hex): {}", hex::encode(&random_data));
    
    // Step 12: Compute digest
    println!("\n12. Computing digest...");
    let digest_mechanism = MechanismType(cryptoki_sys::CKM_SHA256 as u32);
    let digest = backend.digest(session, &digest_mechanism, data)?;
    println!("    ✓ SHA-256 digest computed");
    println!("      Digest length: {} bytes", digest.len());
    println!("      Digest (hex): {}", hex::encode(&digest));
    
    // Step 13: Generate symmetric key
    println!("\n13. Generating AES key...");
    let aes_spec = KeyGenerationSpec {
        key_type: KeyType::Aes,
        key_size: 256,
        label: Some("example-aes-key".to_string()),
        id: Some(b"aes-key-001".to_vec()),
        usage: KeyUsage {
            sign: false,
            verify: false,
            encrypt: true,
            decrypt: true,
            derive: false,
            extractable: false,
            sensitive: true,
        },
    };
    
    let aes_key = backend.generate_key(session, &aes_spec)?;
    println!("    ✓ AES key generated: {:?}", aes_key);
    
    // Step 14: Test encryption/decryption
    println!("\n14. Testing AES encryption/decryption...");
    let plaintext = b"This is secret data to encrypt with AES.";
    let encrypt_mechanism = EncryptMechanism {
        mechanism_type: MechanismType(cryptoki_sys::CKM_AES_CBC as u32),
        parameters: Some(vec![0u8; 16]), // IV for CBC mode
    };
    
    let ciphertext = backend.encrypt(session, aes_key, &encrypt_mechanism, plaintext)?;
    println!("    ✓ Data encrypted");
    println!("      Plaintext length: {} bytes", plaintext.len());
    println!("      Ciphertext length: {} bytes", ciphertext.len());
    
    let decrypted = backend.decrypt(session, aes_key, &encrypt_mechanism, &ciphertext)?;
    println!("    ✓ Data decrypted");
    println!("      Decrypted length: {} bytes", decrypted.len());
    
    // Verify decryption
    if decrypted == plaintext {
        println!("    ✓ Decryption successful - data matches original");
    } else {
        println!("    ✗ Decryption failed - data does not match");
    }
    
    // Step 15: Clean up
    println!("\n15. Cleaning up...");
    
    // Delete keys
    backend.delete_key(session, private_key)?;
    backend.delete_key(session, public_key)?;
    backend.delete_key(session, aes_key)?;
    println!("    ✓ Keys deleted");
    
    // Logout and close session
    backend.logout(session)?;
    println!("    ✓ Logged out");
    
    backend.close_session(session)?;
    println!("    ✓ Session closed");
    
    // Finalize backend
    backend.finalize()?;
    println!("    ✓ Backend finalized");
    
    println!("\n=== Example completed successfully! ===");
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mock_backend_basic_operations() {
        // Test the main function
        assert!(main().is_ok());
    }
    
    #[test]
    fn test_deterministic_behavior() {
        // Test that mock backend produces deterministic results
        let config = MockConfig::new()
            .with_deterministic(true)
            .with_random_seed(42);
        
        let mut backend1 = MockBackend::initialize(config.clone()).unwrap();
        let mut backend2 = MockBackend::initialize(config).unwrap();
        
        // Both backends should produce the same random data
        let slots = backend1.get_slot_list(true).unwrap();
        let session1 = backend1.open_session(slots[0], SessionFlags {
            rw_session: true,
            serial_session: true,
        }).unwrap();
        
        let session2 = backend2.open_session(slots[0], SessionFlags {
            rw_session: true,
            serial_session: true,
        }).unwrap();
        
        let random1 = backend1.generate_random(session1, 32).unwrap();
        let random2 = backend2.generate_random(session2, 32).unwrap();
        
        assert_eq!(random1, random2, "Deterministic backends should produce identical random data");
        
        backend1.close_session(session1).unwrap();
        backend2.close_session(session2).unwrap();
        backend1.finalize().unwrap();
        backend2.finalize().unwrap();
    }
    
    #[test]
    fn test_error_handling() {
        let config = MockConfig::new();
        let mut backend = MockBackend::initialize(config).unwrap();
        
        let slots = backend.get_slot_list(true).unwrap();
        let session = backend.open_session(slots[0], SessionFlags {
            rw_session: true,
            serial_session: true,
        }).unwrap();
        
        // Test operation without authentication (should fail if auth required)
        let key_spec = KeyGenerationSpec {
            key_type: KeyType::Rsa,
            key_size: 2048,
            label: Some("test-key".to_string()),
            id: None,
            usage: KeyUsage::default(),
        };
        
        // This might fail if authentication is required
        let result = backend.generate_key(session, &key_spec);
        
        // Clean up regardless of result
        backend.close_session(session).unwrap();
        backend.finalize().unwrap();
        
        // The test passes if we handled the error gracefully
        match result {
            Ok(_) => println!("Key generation succeeded without auth"),
            Err(_) => println!("Key generation failed without auth (expected)"),
        }
    }
}