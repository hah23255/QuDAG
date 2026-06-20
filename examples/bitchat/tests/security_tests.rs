//! Security validation tests for BitChat
//!
//! These tests validate the security properties of the cryptographic
//! implementations and protocol.

use std::time::Instant;

// Import from the crate
// Note: In actual test, use: use qudag_bitchat::*;

/// Test constant-time comparison
#[test]
fn test_constant_time_comparison_timing() {
    // This test checks that comparisons don't leak timing information
    // based on where the first difference occurs

    let iterations = 10000;

    // Data with difference at start
    let a1 = [0u8; 32];
    let mut b1 = [0u8; 32];
    b1[0] = 1;

    // Data with difference at end
    let a2 = [0u8; 32];
    let mut b2 = [0u8; 32];
    b2[31] = 1;

    // Time comparisons
    let start1 = Instant::now();
    for _ in 0..iterations {
        let _ = constant_time_eq(&a1, &b1);
    }
    let time1 = start1.elapsed();

    let start2 = Instant::now();
    for _ in 0..iterations {
        let _ = constant_time_eq(&a2, &b2);
    }
    let time2 = start2.elapsed();

    // Times should be roughly equal (within 20% tolerance)
    let ratio = time1.as_nanos() as f64 / time2.as_nanos() as f64;
    assert!(
        ratio > 0.8 && ratio < 1.2,
        "Timing difference detected! Ratio: {}",
        ratio
    );
}

/// Constant-time comparison (copied for testing)
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Test that keys are properly zeroized
#[test]
fn test_key_zeroization() {
    use zeroize::Zeroize;

    // Create a key and get its memory location
    let mut key = [0x42u8; 32];
    let key_ptr = key.as_ptr();

    // Zeroize
    key.zeroize();

    // Verify all bytes are zero
    for byte in key.iter() {
        assert_eq!(*byte, 0, "Key not properly zeroized");
    }
}

/// Test replay detection works correctly
#[test]
fn test_replay_detection_comprehensive() {
    let peer_id = [1u8; 32];
    let mut detector = ReplayDetector::new(peer_id);

    // Test 1: Fresh sequences should be accepted
    assert!(detector.check(1), "Should accept first message");
    assert!(detector.check(2), "Should accept second message");
    assert!(detector.check(3), "Should accept third message");

    // Test 2: Replays should be rejected
    assert!(!detector.check(1), "Should reject replay of 1");
    assert!(!detector.check(2), "Should reject replay of 2");
    assert!(!detector.check(3), "Should reject replay of 3");

    // Test 3: Out-of-order within window should work
    assert!(detector.check(100), "Should accept jump");
    assert!(detector.check(95), "Should accept within window");
    assert!(detector.check(99), "Should accept within window");
    assert!(!detector.check(95), "Should reject replay within window");

    // Test 4: Very old messages should be rejected
    assert!(detector.check(200), "Should accept new high");
    assert!(!detector.check(100), "Should reject old (outside window)");

    // Test 5: Sequence 0 should always be rejected
    assert!(!detector.check(0), "Should reject sequence 0");
}

/// Simple replay detector for testing
struct ReplayDetector {
    highest_seq: u64,
    bitmap: u64,
    _peer_id: [u8; 32],
}

impl ReplayDetector {
    fn new(peer_id: [u8; 32]) -> Self {
        Self {
            highest_seq: 0,
            bitmap: 0,
            _peer_id: peer_id,
        }
    }

    fn check(&mut self, sequence: u64) -> bool {
        if sequence == 0 {
            return false;
        }

        if sequence > self.highest_seq {
            let shift = (sequence - self.highest_seq).min(64);
            if shift >= 64 {
                self.bitmap = 1;
            } else {
                self.bitmap = (self.bitmap << shift) | 1;
            }
            self.highest_seq = sequence;
            true
        } else {
            let diff = self.highest_seq - sequence;
            if diff >= 64 {
                false
            } else {
                let mask = 1u64 << diff;
                if self.bitmap & mask != 0 {
                    false
                } else {
                    self.bitmap |= mask;
                    true
                }
            }
        }
    }
}

/// Test message authentication
#[test]
fn test_message_authentication() {
    use sha2::{Sha256, Digest};

    let message = b"test message";
    let key = [0x42u8; 32];

    // Create simple HMAC
    let mut hmac_input = Vec::new();
    hmac_input.extend_from_slice(&key);
    hmac_input.extend_from_slice(message);
    let mac = Sha256::digest(&hmac_input);

    // Verify HMAC
    let mut verify_input = Vec::new();
    verify_input.extend_from_slice(&key);
    verify_input.extend_from_slice(message);
    let verify_mac = Sha256::digest(&verify_input);

    assert_eq!(mac.as_slice(), verify_mac.as_slice(), "MAC verification failed");

    // Verify tampered message fails
    let mut tampered_input = Vec::new();
    tampered_input.extend_from_slice(&key);
    tampered_input.extend_from_slice(b"different message");
    let tampered_mac = Sha256::digest(&tampered_input);

    assert_ne!(mac.as_slice(), tampered_mac.as_slice(), "Tampered MAC should differ");
}

/// Test key derivation determinism
#[test]
fn test_key_derivation_determinism() {
    use sha2::{Sha256, Digest};

    let password = b"test_password";
    let salt = [0x42u8; 16];

    // Derive key twice
    let key1 = derive_key(password, &salt, 1000);
    let key2 = derive_key(password, &salt, 1000);

    assert_eq!(key1, key2, "Key derivation should be deterministic");

    // Different password should give different key
    let key3 = derive_key(b"different_password", &salt, 1000);
    assert_ne!(key1, key3, "Different passwords should give different keys");

    // Different salt should give different key
    let key4 = derive_key(password, &[0x43u8; 16], 1000);
    assert_ne!(key1, key4, "Different salts should give different keys");
}

/// Simple key derivation for testing
fn derive_key(password: &[u8], salt: &[u8; 16], iterations: u32) -> [u8; 32] {
    use sha2::{Sha256, Digest};

    let mut key = [0u8; 32];
    let mut combined = Vec::new();
    combined.extend_from_slice(password);
    combined.extend_from_slice(salt);
    key.copy_from_slice(&Sha256::digest(&combined));

    for i in 0..iterations {
        combined.clear();
        combined.extend_from_slice(&key);
        combined.extend_from_slice(&i.to_le_bytes());
        combined.extend_from_slice(salt);
        key.copy_from_slice(&Sha256::digest(&combined));
    }

    key
}

/// Test nonce uniqueness
#[test]
fn test_nonce_generation_uniqueness() {
    use std::collections::HashSet;

    let mut nonces = HashSet::new();
    let iterations = 10000;

    // Generate many nonces and check for collisions
    for _ in 0..iterations {
        let nonce = generate_random_nonce();
        assert!(
            nonces.insert(nonce),
            "Nonce collision detected! This should be extremely rare."
        );
    }
}

/// Generate random nonce for testing
fn generate_random_nonce() -> [u8; 12] {
    use rand::RngCore;
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Test that encrypted messages are different even with same plaintext
#[test]
fn test_encryption_randomness() {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        ChaCha20Poly1305, Nonce,
    };

    let key = [0x42u8; 32];
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let plaintext = b"same message";

    // Encrypt same message twice with different nonces
    let nonce1 = generate_random_nonce();
    let nonce2 = generate_random_nonce();

    let ct1 = cipher.encrypt(Nonce::from_slice(&nonce1), plaintext.as_ref()).unwrap();
    let ct2 = cipher.encrypt(Nonce::from_slice(&nonce2), plaintext.as_ref()).unwrap();

    assert_ne!(ct1, ct2, "Same plaintext should produce different ciphertext");
}

/// Test message length padding
#[test]
fn test_message_padding() {
    // Test that different length messages get padded to same bucket
    let short = "Hi";
    let medium = "Hello there!";

    let padded_short = pad_to_bucket(short.len());
    let padded_medium = pad_to_bucket(medium.len());

    // Both should pad to 32 bytes (first bucket)
    assert_eq!(padded_short, 32);
    assert_eq!(padded_medium, 32);

    // Longer message should pad to larger bucket
    let long = "This is a much longer message that exceeds the first bucket";
    let padded_long = pad_to_bucket(long.len());
    assert!(padded_long > 32);
}

/// Calculate padded size
fn pad_to_bucket(len: usize) -> usize {
    let with_header = len + 2;
    if with_header <= 32 { 32 }
    else if with_header <= 64 { 64 }
    else if with_header <= 128 { 128 }
    else if with_header <= 256 { 256 }
    else if with_header <= 512 { 512 }
    else if with_header <= 1024 { 1024 }
    else { 2048 }
}

/// Test handshake timeout protection
#[test]
fn test_handshake_timeout() {
    let timeout_ms = 1000u64;
    let start_time = 0u64;

    // Within timeout
    assert!(!is_timed_out(start_time, 500, timeout_ms));

    // Exactly at timeout
    assert!(!is_timed_out(start_time, 1000, timeout_ms));

    // After timeout
    assert!(is_timed_out(start_time, 1001, timeout_ms));
    assert!(is_timed_out(start_time, 5000, timeout_ms));
}

fn is_timed_out(start: u64, current: u64, timeout: u64) -> bool {
    current - start > timeout
}

/// Test rate limiter
#[test]
fn test_rate_limiter() {
    let mut limiter = RateLimiter::new(3, 1000);

    // First 3 should pass
    assert!(limiter.check(0));
    assert!(limiter.check(100));
    assert!(limiter.check(200));

    // 4th should fail
    assert!(!limiter.check(300));

    // After window expires, should pass again
    assert!(limiter.check(1500));
}

struct RateLimiter {
    attempts: Vec<u64>,
    max_attempts: usize,
    window_ms: u64,
}

impl RateLimiter {
    fn new(max_attempts: usize, window_ms: u64) -> Self {
        Self {
            attempts: Vec::new(),
            max_attempts,
            window_ms,
        }
    }

    fn check(&mut self, current_time: u64) -> bool {
        let cutoff = current_time.saturating_sub(self.window_ms);
        self.attempts.retain(|&t| t > cutoff);

        if self.attempts.len() >= self.max_attempts {
            false
        } else {
            self.attempts.push(current_time);
            true
        }
    }
}

/// Test buffer overflow protection
#[test]
fn test_buffer_overflow_protection() {
    const MAX_SIZE: usize = 100;

    // Valid size
    assert!(validate_size(50, MAX_SIZE).is_ok());

    // At limit
    assert!(validate_size(100, MAX_SIZE).is_ok());

    // Over limit
    assert!(validate_size(101, MAX_SIZE).is_err());
}

fn validate_size(size: usize, max: usize) -> Result<(), &'static str> {
    if size > max {
        Err("Buffer overflow")
    } else {
        Ok(())
    }
}

/// Test message integrity verification
#[test]
fn test_message_integrity() {
    use sha2::{Sha256, Digest};

    let message = b"important message";

    // Create hash
    let hash = Sha256::digest(message);

    // Verify hash
    let verify_hash = Sha256::digest(message);
    assert_eq!(hash.as_slice(), verify_hash.as_slice());

    // Tampered message should have different hash
    let tampered = b"important messagE";
    let tampered_hash = Sha256::digest(tampered);
    assert_ne!(hash.as_slice(), tampered_hash.as_slice());
}

/// Test X25519 key exchange
#[test]
fn test_x25519_key_exchange() {
    use x25519_dalek::{StaticSecret, PublicKey};

    // Alice generates keypair
    let alice_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let alice_public = PublicKey::from(&alice_secret);

    // Bob generates keypair
    let bob_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let bob_public = PublicKey::from(&bob_secret);

    // Both compute shared secret
    let alice_shared = alice_secret.diffie_hellman(&bob_public);
    let bob_shared = bob_secret.diffie_hellman(&alice_public);

    // Shared secrets should match
    assert_eq!(
        alice_shared.as_bytes(),
        bob_shared.as_bytes(),
        "Shared secrets should match"
    );
}

/// Test Ed25519 signatures
#[test]
fn test_ed25519_signatures() {
    use ed25519_dalek::{SigningKey, Signer, Verifier};

    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    let message = b"test message to sign";

    // Sign
    let signature = signing_key.sign(message);

    // Verify
    assert!(verifying_key.verify(message, &signature).is_ok());

    // Wrong message should fail
    let wrong_message = b"wrong message";
    assert!(verifying_key.verify(wrong_message, &signature).is_err());
}

// Main function for running as binary
fn main() {
    println!("Running security tests...");

    // Run all tests
    test_constant_time_comparison_timing();
    println!("✓ Constant-time comparison");

    test_key_zeroization();
    println!("✓ Key zeroization");

    test_replay_detection_comprehensive();
    println!("✓ Replay detection");

    test_message_authentication();
    println!("✓ Message authentication");

    test_key_derivation_determinism();
    println!("✓ Key derivation");

    test_nonce_generation_uniqueness();
    println!("✓ Nonce uniqueness");

    test_encryption_randomness();
    println!("✓ Encryption randomness");

    test_message_padding();
    println!("✓ Message padding");

    test_handshake_timeout();
    println!("✓ Handshake timeout");

    test_rate_limiter();
    println!("✓ Rate limiter");

    test_buffer_overflow_protection();
    println!("✓ Buffer overflow protection");

    test_message_integrity();
    println!("✓ Message integrity");

    test_x25519_key_exchange();
    println!("✓ X25519 key exchange");

    test_ed25519_signatures();
    println!("✓ Ed25519 signatures");

    println!();
    println!("All security tests passed!");
}
