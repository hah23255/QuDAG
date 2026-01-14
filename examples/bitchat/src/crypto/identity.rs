//! Identity management for BitChat
//!
//! Each device has a unique identity consisting of:
//! - Signing keypair (Ed25519, upgradeable to ML-DSA)
//! - Encryption keypair (X25519, upgradeable to ML-KEM)
//! - Device ID (SHA-256 hash of public keys)

use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey, Signature, Signer, Verifier};
use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};
use zeroize::Zeroize;

use super::{hash, derive_device_id, random_bytes, SecretBytes};
use crate::{BitChatError, Result, DEVICE_ID_LEN};

/// Ed25519 signing key (secret)
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SigningKey {
    secret: [u8; 32],
}

impl SigningKey {
    /// Generate new random signing key
    pub fn generate() -> Self {
        Self {
            secret: random_bytes(),
        }
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { secret: bytes }
    }

    /// Get public verifying key
    pub fn verifying_key(&self) -> VerifyingKey {
        let signing = Ed25519SigningKey::from_bytes(&self.secret);
        let verifying = signing.verifying_key();
        VerifyingKey {
            bytes: verifying.to_bytes(),
        }
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let signing = Ed25519SigningKey::from_bytes(&self.secret);
        signing.sign(message).to_bytes()
    }

    /// Get raw bytes (use with caution)
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.secret
    }
}

/// Ed25519 verifying key (public)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyingKey {
    bytes: [u8; 32],
}

impl VerifyingKey {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<()> {
        let verifying = Ed25519VerifyingKey::from_bytes(&self.bytes)
            .map_err(|_| BitChatError::InvalidMessage)?;
        let sig = Signature::from_bytes(signature);
        verifying.verify(message, &sig)
            .map_err(|_| BitChatError::InvalidMessage)
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// X25519 encryption key (secret)
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct EncryptionKey {
    secret: [u8; 32],
}

impl EncryptionKey {
    /// Generate new random encryption key
    pub fn generate() -> Self {
        Self {
            secret: random_bytes(),
        }
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { secret: bytes }
    }

    /// Get public key
    pub fn public_key(&self) -> PublicEncryptionKey {
        let secret = StaticSecret::from(self.secret);
        let public = X25519PublicKey::from(&secret);
        PublicEncryptionKey {
            bytes: public.to_bytes(),
        }
    }

    /// Perform Diffie-Hellman key exchange
    pub fn diffie_hellman(&self, their_public: &PublicEncryptionKey) -> SharedSecret {
        let secret = StaticSecret::from(self.secret);
        let their_public = X25519PublicKey::from(their_public.bytes);
        let shared = secret.diffie_hellman(&their_public);
        SharedSecret {
            bytes: shared.to_bytes(),
        }
    }

    /// Get raw bytes (use with caution)
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.secret
    }
}

/// X25519 public encryption key
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicEncryptionKey {
    bytes: [u8; 32],
}

impl PublicEncryptionKey {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// Shared secret from DH exchange
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SharedSecret {
    bytes: [u8; 32],
}

impl SharedSecret {
    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// Combined signing and encryption keypair
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct KeyPair {
    /// Signing key (Ed25519)
    pub signing: [u8; 32],
    /// Encryption key (X25519)
    pub encryption: [u8; 32],
}

impl KeyPair {
    /// Generate new keypair
    pub fn generate() -> Self {
        Self {
            signing: random_bytes(),
            encryption: random_bytes(),
        }
    }

    /// Get signing key
    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(self.signing)
    }

    /// Get encryption key
    pub fn encryption_key(&self) -> EncryptionKey {
        EncryptionKey::from_bytes(self.encryption)
    }
}

/// Device identity containing all keys
pub struct Identity {
    /// Signing keypair
    pub signing_key: SigningKey,
    /// Encryption keypair
    pub encryption_key: EncryptionKey,
    /// Device ID (hash of public keys)
    device_id: [u8; DEVICE_ID_LEN],
}

impl Identity {
    /// Generate new identity
    pub fn generate() -> Result<Self> {
        let signing_key = SigningKey::generate();
        let encryption_key = EncryptionKey::generate();

        // Derive device ID from public keys
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(signing_key.verifying_key().as_bytes());
        combined[32..].copy_from_slice(encryption_key.public_key().as_bytes());
        let device_id = hash(&combined);

        Ok(Self {
            signing_key,
            encryption_key,
            device_id,
        })
    }

    /// Restore identity from stored keys
    pub fn from_keys(signing: [u8; 32], encryption: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(signing);
        let encryption_key = EncryptionKey::from_bytes(encryption);

        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(signing_key.verifying_key().as_bytes());
        combined[32..].copy_from_slice(encryption_key.public_key().as_bytes());
        let device_id = hash(&combined);

        Self {
            signing_key,
            encryption_key,
            device_id,
        }
    }

    /// Get device ID
    pub fn device_id(&self) -> [u8; DEVICE_ID_LEN] {
        self.device_id
    }

    /// Get public signing key
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Get public encryption key
    pub fn public_encryption_key(&self) -> PublicEncryptionKey {
        self.encryption_key.public_key()
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message)
    }

    /// Perform key exchange with peer
    pub fn key_exchange(&self, peer_public: &PublicEncryptionKey) -> SharedSecret {
        self.encryption_key.diffie_hellman(peer_public)
    }

    /// Export public identity for sharing
    pub fn export_public(&self) -> PublicIdentity {
        PublicIdentity {
            device_id: self.device_id,
            verifying_key: self.verifying_key(),
            encryption_key: self.public_encryption_key(),
        }
    }
}

/// Public identity for sharing with peers
#[derive(Clone, Copy, Debug)]
pub struct PublicIdentity {
    /// Device ID
    pub device_id: [u8; DEVICE_ID_LEN],
    /// Public signing key
    pub verifying_key: VerifyingKey,
    /// Public encryption key
    pub encryption_key: PublicEncryptionKey,
}

impl PublicIdentity {
    /// Serialize to bytes (96 bytes total)
    pub fn to_bytes(&self) -> [u8; 96] {
        let mut bytes = [0u8; 96];
        bytes[..32].copy_from_slice(&self.device_id);
        bytes[32..64].copy_from_slice(self.verifying_key.as_bytes());
        bytes[64..96].copy_from_slice(self.encryption_key.as_bytes());
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8; 96]) -> Self {
        let mut device_id = [0u8; 32];
        let mut verifying = [0u8; 32];
        let mut encryption = [0u8; 32];

        device_id.copy_from_slice(&bytes[..32]);
        verifying.copy_from_slice(&bytes[32..64]);
        encryption.copy_from_slice(&bytes[64..96]);

        Self {
            device_id,
            verifying_key: VerifyingKey::from_bytes(verifying),
            encryption_key: PublicEncryptionKey::from_bytes(encryption),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signing_key_generation() {
        let key = SigningKey::generate();
        let verifying = key.verifying_key();

        let message = b"test message";
        let signature = key.sign(message);

        assert!(verifying.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_encryption_key_dh() {
        let alice = EncryptionKey::generate();
        let bob = EncryptionKey::generate();

        let alice_public = alice.public_key();
        let bob_public = bob.public_key();

        let shared_alice = alice.diffie_hellman(&bob_public);
        let shared_bob = bob.diffie_hellman(&alice_public);

        assert_eq!(shared_alice.as_bytes(), shared_bob.as_bytes());
    }

    #[test]
    fn test_identity_generation() {
        let identity = Identity::generate().unwrap();
        let device_id = identity.device_id();
        assert_eq!(device_id.len(), 32);
    }

    #[test]
    fn test_public_identity_serialization() {
        let identity = Identity::generate().unwrap();
        let public = identity.export_public();

        let bytes = public.to_bytes();
        let restored = PublicIdentity::from_bytes(&bytes);

        assert_eq!(public.device_id, restored.device_id);
        assert_eq!(public.verifying_key, restored.verifying_key);
        assert_eq!(public.encryption_key, restored.encryption_key);
    }
}
