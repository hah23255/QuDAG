//! Session key management for BitChat
//!
//! Provides ephemeral session keys derived from X25519 key exchange
//! using HKDF for key derivation.

use sha2::{Sha256, Digest};
use zeroize::Zeroize;

use super::{EncryptionKey, PublicEncryptionKey, SharedSecret, hash};
use crate::{BitChatError, Result};

/// Session key derived from key exchange
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SessionKey {
    /// Encryption key (first 32 bytes of derived key)
    encryption: [u8; 32],
    /// MAC key (second 32 bytes of derived key)
    mac: [u8; 32],
}

impl SessionKey {
    /// Derive session key from shared secret
    pub fn derive(shared_secret: &SharedSecret, context: &[u8]) -> Self {
        // Simple HKDF-like derivation using SHA-256
        let mut prk = [0u8; 32];

        // Extract: PRK = HMAC(salt, IKM)
        // Using a fixed salt for simplicity
        let salt = b"bitchat-session-v1";
        let prk_data = [salt.as_slice(), shared_secret.as_bytes()].concat();
        prk.copy_from_slice(&hash(&prk_data));

        // Expand: OKM = HMAC(PRK, info || 0x01) || HMAC(PRK, T(1) || info || 0x02)
        let mut expand_input = Vec::new();
        expand_input.extend_from_slice(&prk);
        expand_input.extend_from_slice(context);
        expand_input.push(0x01);
        let encryption = hash(&expand_input);

        expand_input.clear();
        expand_input.extend_from_slice(&prk);
        expand_input.extend_from_slice(&encryption);
        expand_input.extend_from_slice(context);
        expand_input.push(0x02);
        let mac = hash(&expand_input);

        // Zeroize intermediate values
        prk.zeroize();

        Self { encryption, mac }
    }

    /// Get encryption key
    pub fn encryption_key(&self) -> &[u8; 32] {
        &self.encryption
    }

    /// Get MAC key
    pub fn mac_key(&self) -> &[u8; 32] {
        &self.mac
    }
}

/// Key exchange state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyExchangeState {
    /// Initial state
    Initial,
    /// Ephemeral key generated
    EphemeralGenerated,
    /// Received peer's ephemeral key
    ReceivedPeer,
    /// Session established
    Established,
    /// Error occurred
    Failed,
}

/// Key exchange handler
pub struct KeyExchange {
    state: KeyExchangeState,
    /// Our ephemeral key
    ephemeral_key: Option<EncryptionKey>,
    /// Our ephemeral public key
    ephemeral_public: Option<PublicEncryptionKey>,
    /// Peer's ephemeral public key
    peer_ephemeral: Option<PublicEncryptionKey>,
    /// Derived session key
    session_key: Option<SessionKey>,
    /// Our static encryption key
    static_key: EncryptionKey,
}

impl KeyExchange {
    /// Create new key exchange with our static key
    pub fn new(static_key: EncryptionKey) -> Self {
        Self {
            state: KeyExchangeState::Initial,
            ephemeral_key: None,
            ephemeral_public: None,
            peer_ephemeral: None,
            session_key: None,
            static_key,
        }
    }

    /// Get current state
    pub fn state(&self) -> KeyExchangeState {
        self.state
    }

    /// Generate ephemeral key and return public key
    pub fn generate_ephemeral(&mut self) -> Result<PublicEncryptionKey> {
        let ephemeral = EncryptionKey::generate();
        let public = ephemeral.public_key();

        self.ephemeral_key = Some(ephemeral);
        self.ephemeral_public = Some(public);
        self.state = KeyExchangeState::EphemeralGenerated;

        Ok(public)
    }

    /// Get our ephemeral public key
    pub fn ephemeral_public(&self) -> Option<&PublicEncryptionKey> {
        self.ephemeral_public.as_ref()
    }

    /// Process peer's ephemeral public key
    pub fn process_peer_ephemeral(
        &mut self,
        peer_ephemeral: PublicEncryptionKey,
        peer_static: &PublicEncryptionKey,
    ) -> Result<&SessionKey> {
        if self.state != KeyExchangeState::EphemeralGenerated {
            self.state = KeyExchangeState::Failed;
            return Err(BitChatError::KeyExchangeFailed);
        }

        self.peer_ephemeral = Some(peer_ephemeral);

        // Perform double DH (similar to X3DH but simpler)
        let ephemeral = self.ephemeral_key.as_ref()
            .ok_or(BitChatError::KeyExchangeFailed)?;

        // DH1: ephemeral <-> peer_static
        let dh1 = ephemeral.diffie_hellman(peer_static);

        // DH2: ephemeral <-> peer_ephemeral
        let dh2 = ephemeral.diffie_hellman(&peer_ephemeral);

        // DH3: static <-> peer_ephemeral
        let dh3 = self.static_key.diffie_hellman(&peer_ephemeral);

        // Combine all shared secrets
        let mut combined = [0u8; 96];
        combined[..32].copy_from_slice(dh1.as_bytes());
        combined[32..64].copy_from_slice(dh2.as_bytes());
        combined[64..].copy_from_slice(dh3.as_bytes());

        // Create "virtual" shared secret from combined
        let combined_hash = hash(&combined);
        combined.zeroize();

        // Wrap in SharedSecret-like struct for SessionKey derivation
        struct CombinedSecret([u8; 32]);
        impl CombinedSecret {
            fn as_bytes(&self) -> &[u8; 32] { &self.0 }
        }

        // Derive session key
        let context = b"bitchat-ke-v1";
        let prk_data = [context.as_slice(), &combined_hash].concat();
        let prk = hash(&prk_data);

        let mut expand_input = Vec::new();
        expand_input.extend_from_slice(&prk);
        expand_input.extend_from_slice(context);
        expand_input.push(0x01);
        let encryption = hash(&expand_input);

        expand_input.clear();
        expand_input.extend_from_slice(&prk);
        expand_input.extend_from_slice(&encryption);
        expand_input.extend_from_slice(context);
        expand_input.push(0x02);
        let mac = hash(&expand_input);

        let session_key = SessionKey {
            encryption,
            mac,
        };

        self.session_key = Some(session_key);
        self.state = KeyExchangeState::Established;

        self.session_key.as_ref().ok_or(BitChatError::KeyExchangeFailed)
    }

    /// Get established session key
    pub fn session_key(&self) -> Option<&SessionKey> {
        if self.state == KeyExchangeState::Established {
            self.session_key.as_ref()
        } else {
            None
        }
    }

    /// Check if key exchange is complete
    pub fn is_established(&self) -> bool {
        self.state == KeyExchangeState::Established
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_key_derivation() {
        let alice_key = EncryptionKey::generate();
        let bob_key = EncryptionKey::generate();

        let alice_pub = alice_key.public_key();
        let bob_pub = bob_key.public_key();

        let shared_alice = alice_key.diffie_hellman(&bob_pub);
        let shared_bob = bob_key.diffie_hellman(&alice_pub);

        let session_alice = SessionKey::derive(&shared_alice, b"test");
        let session_bob = SessionKey::derive(&shared_bob, b"test");

        assert_eq!(session_alice.encryption_key(), session_bob.encryption_key());
        assert_eq!(session_alice.mac_key(), session_bob.mac_key());
    }

    #[test]
    fn test_key_exchange_flow() {
        let alice_static = EncryptionKey::generate();
        let bob_static = EncryptionKey::generate();
        let alice_pub = alice_static.public_key();
        let bob_pub = bob_static.public_key();

        let mut alice_ke = KeyExchange::new(alice_static);
        let mut bob_ke = KeyExchange::new(bob_static);

        // Alice generates ephemeral
        let alice_ephemeral = alice_ke.generate_ephemeral().unwrap();

        // Bob generates ephemeral
        let bob_ephemeral = bob_ke.generate_ephemeral().unwrap();

        // Both process each other's ephemeral
        let alice_session = alice_ke.process_peer_ephemeral(bob_ephemeral, &bob_pub).unwrap();
        let bob_session = bob_ke.process_peer_ephemeral(alice_ephemeral, &alice_pub).unwrap();

        // Both should derive same session key
        assert_eq!(alice_session.encryption_key(), bob_session.encryption_key());
    }
}
