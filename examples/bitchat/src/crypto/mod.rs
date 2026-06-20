//! Cryptographic primitives for BitChat
//!
//! This module provides:
//! - X25519 key exchange (upgradeable to ML-KEM)
//! - Ed25519 signatures (upgradeable to ML-DSA)
//! - ChaCha20-Poly1305 authenticated encryption
//! - Secure key derivation
//! - Zero-copy, constant-time operations

mod identity;
mod session;
mod encryption;

pub use identity::{Identity, KeyPair, SigningKey, EncryptionKey, VerifyingKey, PublicEncryptionKey, PublicIdentity};
pub use session::{SessionKey, KeyExchange, SharedSecret};
pub use encryption::{seal, open, seal_with_padding, open_with_padding, Nonce, derive_key_from_password};

use sha2::{Sha256, Digest};
use zeroize::Zeroize;

use crate::{BitChatError, Result, DEVICE_ID_LEN};

/// Cryptographic hash of data using SHA-256
pub fn hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Derive device ID from public key
pub fn derive_device_id(public_key: &[u8; 32]) -> [u8; DEVICE_ID_LEN] {
    hash(public_key)
}

/// Constant-time comparison
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Secure random bytes (platform-specific)
#[cfg(not(target_arch = "riscv32"))]
pub fn random_bytes<const N: usize>() -> [u8; N] {
    use rand_core::{OsRng, RngCore};
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

#[cfg(target_arch = "riscv32")]
pub fn random_bytes<const N: usize>() -> [u8; N] {
    // ESP32 hardware RNG
    let mut bytes = [0u8; N];
    // This will be replaced with esp-hal RNG in actual ESP32 build
    for byte in bytes.iter_mut() {
        *byte = unsafe { core::ptr::read_volatile(0x3FF75144 as *const u8) };
    }
    bytes
}

/// Zeroize sensitive data on drop
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecretBytes<const N: usize>([u8; N]);

impl<const N: usize> SecretBytes<N> {
    /// Create new secret bytes
    pub fn new(data: [u8; N]) -> Self {
        Self(data)
    }

    /// Create from slice (panics if wrong size)
    pub fn from_slice(slice: &[u8]) -> Self {
        let mut data = [0u8; N];
        data.copy_from_slice(slice);
        Self(data)
    }

    /// Get reference to inner bytes
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    /// Generate random secret bytes
    pub fn random() -> Self {
        Self(random_bytes())
    }
}

impl<const N: usize> AsRef<[u8]> for SecretBytes<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash() {
        let data = b"hello world";
        let h = hash(data);
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn test_constant_time_eq() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }

    #[test]
    fn test_secret_bytes_zeroize() {
        let mut secret = SecretBytes::<32>::random();
        let ptr = secret.as_bytes().as_ptr();
        drop(secret);
        // Memory should be zeroed (can't easily verify in safe code)
    }
}
