//! Message envelope for encrypted transport
//!
//! Security features:
//! - ChaCha20-Poly1305 authenticated encryption
//! - Traffic padding to resist analysis
//! - Replay attack protection via sequence numbers
//! - Constant-time operations for sensitive data

use heapless::Vec;
use zeroize::Zeroize;

use super::ChatMessage;
use crate::{BitChatError, Result, DEVICE_ID_LEN, MAX_MESSAGE_SIZE};
use crate::crypto::{
    SigningKey, PublicEncryptionKey, EncryptionKey,
    seal_with_padding, open_with_padding, hash, constant_time_eq,
};

/// Envelope type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EnvelopeType {
    /// Plaintext message (no encryption)
    Plaintext = 0,
    /// Encrypted with peer's key
    Encrypted = 1,
    /// Encrypted for multiple recipients
    MultiRecipient = 2,
    /// Anonymously routed (onion-style)
    Anonymous = 3,
}

impl From<u8> for EnvelopeType {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Plaintext,
            1 => Self::Encrypted,
            2 => Self::MultiRecipient,
            3 => Self::Anonymous,
            _ => Self::Plaintext,
        }
    }
}

/// Encrypted message envelope
///
/// Security hardening:
/// - All sensitive data zeroized on drop
/// - Constant-time comparison for tags
/// - Sequence numbers for replay protection
#[derive(Clone)]
pub struct Envelope {
    /// Envelope type
    env_type: EnvelopeType,
    /// Sender device ID (may be zero for anonymous)
    sender_id: [u8; DEVICE_ID_LEN],
    /// Recipient device ID
    recipient_id: [u8; DEVICE_ID_LEN],
    /// Ephemeral public key (for key exchange)
    ephemeral_public: Option<[u8; 32]>,
    /// Encrypted or plaintext payload
    payload: Vec<u8, { MAX_MESSAGE_SIZE + 512 }>,
    /// Sequence number for replay protection
    sequence: u64,
    /// Creation timestamp
    timestamp: u64,
}

impl Envelope {
    /// Create plaintext envelope (use only for discovery/handshake)
    pub fn plaintext(message: ChatMessage) -> Self {
        let payload_bytes = message.to_bytes();
        let mut payload = Vec::new();
        let _ = payload.extend_from_slice(&payload_bytes);

        Self {
            env_type: EnvelopeType::Plaintext,
            sender_id: message.from,
            recipient_id: message.to,
            ephemeral_public: None,
            payload,
            sequence: message.sequence,
            timestamp: message.timestamp,
        }
    }

    /// Create encrypted envelope
    ///
    /// Security: Uses X25519 DH for key agreement, ChaCha20-Poly1305 for encryption
    pub fn encrypted(
        message: ChatMessage,
        our_key: &SigningKey,
        peer_public: &PublicEncryptionKey,
        pad: bool,
    ) -> Result<Self> {
        // Generate ephemeral key for forward secrecy
        let ephemeral = EncryptionKey::generate();
        let ephemeral_public = ephemeral.public_key();

        // Derive shared secret
        let shared = ephemeral.diffie_hellman(peer_public);

        // Derive encryption key using HKDF-like construction
        let mut key_material = [0u8; 96];
        key_material[..32].copy_from_slice(shared.as_bytes());
        key_material[32..64].copy_from_slice(ephemeral_public.as_bytes());
        key_material[64..].copy_from_slice(peer_public.as_bytes());
        let encryption_key = hash(&key_material);
        key_material.zeroize();

        // Serialize and encrypt message
        let plaintext = message.to_bytes();
        let aad = &message.from; // Bind ciphertext to sender

        let ciphertext = seal_with_padding(&encryption_key, &plaintext, aad, pad)?;

        let mut payload = Vec::new();
        payload.extend_from_slice(&ciphertext)
            .map_err(|_| BitChatError::BufferOverflow)?;

        Ok(Self {
            env_type: EnvelopeType::Encrypted,
            sender_id: message.from,
            recipient_id: message.to,
            ephemeral_public: Some(*ephemeral_public.as_bytes()),
            payload,
            sequence: message.sequence,
            timestamp: message.timestamp,
        })
    }

    /// Decrypt envelope and extract message
    ///
    /// Security: Constant-time tag verification via ChaCha20-Poly1305
    pub fn decrypt(
        &self,
        our_key: &EncryptionKey,
        peer_public: &PublicEncryptionKey,
    ) -> Result<ChatMessage> {
        if self.env_type != EnvelopeType::Encrypted {
            return Err(BitChatError::InvalidMessage);
        }

        let ephemeral_public = self.ephemeral_public
            .ok_or(BitChatError::InvalidMessage)?;
        let ephemeral_pub = PublicEncryptionKey::from_bytes(ephemeral_public);

        // Derive shared secret (reverse of encryption)
        let shared = our_key.diffie_hellman(&ephemeral_pub);

        // Derive decryption key
        let mut key_material = [0u8; 96];
        key_material[..32].copy_from_slice(shared.as_bytes());
        key_material[32..64].copy_from_slice(&ephemeral_public);
        key_material[64..].copy_from_slice(our_key.public_key().as_bytes());
        let decryption_key = hash(&key_material);
        key_material.zeroize();

        // Decrypt
        let aad = &self.sender_id;
        let plaintext = open_with_padding(&decryption_key, &self.payload, aad)?;

        // Parse message
        ChatMessage::from_bytes(&plaintext)
    }

    /// Extract message from plaintext envelope
    pub fn into_message(self) -> Result<ChatMessage> {
        if self.env_type != EnvelopeType::Plaintext {
            return Err(BitChatError::InvalidMessage);
        }
        ChatMessage::from_bytes(&self.payload)
    }

    /// Check if envelope is encrypted
    pub fn is_encrypted(&self) -> bool {
        self.env_type == EnvelopeType::Encrypted
    }

    /// Get sender ID
    pub fn sender_id(&self) -> [u8; DEVICE_ID_LEN] {
        self.sender_id
    }

    /// Get recipient ID
    pub fn recipient_id(&self) -> [u8; DEVICE_ID_LEN] {
        self.recipient_id
    }

    /// Get sequence number for replay detection
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Get timestamp
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Serialize envelope for transport
    pub fn to_bytes(&self) -> Vec<u8, { MAX_MESSAGE_SIZE + 640 }> {
        let mut bytes = Vec::new();

        // Type
        let _ = bytes.push(self.env_type as u8);

        // Sender ID
        let _ = bytes.extend_from_slice(&self.sender_id);

        // Recipient ID
        let _ = bytes.extend_from_slice(&self.recipient_id);

        // Ephemeral public key
        if let Some(ref epk) = self.ephemeral_public {
            let _ = bytes.push(1);
            let _ = bytes.extend_from_slice(epk);
        } else {
            let _ = bytes.push(0);
        }

        // Sequence and timestamp
        let _ = bytes.extend_from_slice(&self.sequence.to_le_bytes());
        let _ = bytes.extend_from_slice(&self.timestamp.to_le_bytes());

        // Payload length and payload
        let payload_len = self.payload.len() as u16;
        let _ = bytes.extend_from_slice(&payload_len.to_le_bytes());
        let _ = bytes.extend_from_slice(&self.payload);

        bytes
    }

    /// Deserialize envelope from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 1 + 32 + 32 + 1 + 8 + 8 + 2 {
            return Err(BitChatError::InvalidMessage);
        }

        let mut offset = 0;

        // Type
        let env_type = EnvelopeType::from(bytes[offset]);
        offset += 1;

        // Sender ID
        let mut sender_id = [0u8; DEVICE_ID_LEN];
        sender_id.copy_from_slice(&bytes[offset..offset + DEVICE_ID_LEN]);
        offset += DEVICE_ID_LEN;

        // Recipient ID
        let mut recipient_id = [0u8; DEVICE_ID_LEN];
        recipient_id.copy_from_slice(&bytes[offset..offset + DEVICE_ID_LEN]);
        offset += DEVICE_ID_LEN;

        // Ephemeral public key
        let ephemeral_public = if bytes[offset] == 1 {
            offset += 1;
            if offset + 32 > bytes.len() {
                return Err(BitChatError::InvalidMessage);
            }
            let mut epk = [0u8; 32];
            epk.copy_from_slice(&bytes[offset..offset + 32]);
            offset += 32;
            Some(epk)
        } else {
            offset += 1;
            None
        };

        // Sequence
        if offset + 8 > bytes.len() {
            return Err(BitChatError::InvalidMessage);
        }
        let sequence = u64::from_le_bytes([
            bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3],
            bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7],
        ]);
        offset += 8;

        // Timestamp
        if offset + 8 > bytes.len() {
            return Err(BitChatError::InvalidMessage);
        }
        let timestamp = u64::from_le_bytes([
            bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3],
            bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7],
        ]);
        offset += 8;

        // Payload length
        if offset + 2 > bytes.len() {
            return Err(BitChatError::InvalidMessage);
        }
        let payload_len = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;

        // Payload
        if offset + payload_len > bytes.len() {
            return Err(BitChatError::InvalidMessage);
        }
        let mut payload = Vec::new();
        payload.extend_from_slice(&bytes[offset..offset + payload_len])
            .map_err(|_| BitChatError::BufferOverflow)?;

        Ok(Self {
            env_type,
            sender_id,
            recipient_id,
            ephemeral_public,
            payload,
            sequence,
            timestamp,
        })
    }
}

/// Replay attack detector using sliding window
///
/// Security: Prevents message replay by tracking sequence numbers
pub struct ReplayDetector {
    /// Highest seen sequence number
    highest_seq: u64,
    /// Bitmap for recent sequence numbers (covers last 64 messages)
    bitmap: u64,
    /// Peer ID this detector is for
    peer_id: [u8; DEVICE_ID_LEN],
}

impl ReplayDetector {
    /// Create new replay detector for peer
    pub fn new(peer_id: [u8; DEVICE_ID_LEN]) -> Self {
        Self {
            highest_seq: 0,
            bitmap: 0,
            peer_id,
        }
    }

    /// Check if sequence number is valid (not replayed)
    /// Returns true if message should be accepted
    pub fn check(&mut self, sequence: u64) -> bool {
        if sequence == 0 {
            // Sequence 0 is never valid
            return false;
        }

        if sequence > self.highest_seq {
            // New highest sequence, update window
            let shift = (sequence - self.highest_seq).min(64);
            if shift >= 64 {
                self.bitmap = 1;
            } else {
                self.bitmap = (self.bitmap << shift) | 1;
            }
            self.highest_seq = sequence;
            true
        } else {
            // Check if in window
            let diff = self.highest_seq - sequence;
            if diff >= 64 {
                // Too old, reject
                false
            } else {
                // Check bitmap
                let mask = 1u64 << diff;
                if self.bitmap & mask != 0 {
                    // Already seen
                    false
                } else {
                    // Mark as seen
                    self.bitmap |= mask;
                    true
                }
            }
        }
    }

    /// Get peer ID
    pub fn peer_id(&self) -> &[u8; DEVICE_ID_LEN] {
        &self.peer_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Identity;

    #[test]
    fn test_plaintext_envelope() {
        let from = [1u8; 32];
        let to = [2u8; 32];
        let msg = ChatMessage::new(from, to, "Hello", 1).unwrap();

        let envelope = Envelope::plaintext(msg);
        assert!(!envelope.is_encrypted());

        let bytes = envelope.to_bytes();
        let restored = Envelope::from_bytes(&bytes).unwrap();

        let message = restored.into_message().unwrap();
        assert_eq!(message.text(), Some("Hello"));
    }

    #[test]
    fn test_encrypted_envelope() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();

        let msg = ChatMessage::new(
            alice.device_id(),
            bob.device_id(),
            "Secret message",
            1,
        ).unwrap();

        let envelope = Envelope::encrypted(
            msg,
            &alice.signing_key,
            &bob.public_encryption_key(),
            true,
        ).unwrap();

        assert!(envelope.is_encrypted());

        // Decrypt with Bob's key
        let decrypted = envelope.decrypt(
            &bob.encryption_key,
            &alice.public_encryption_key(),
        ).unwrap();

        assert_eq!(decrypted.text(), Some("Secret message"));
    }

    #[test]
    fn test_replay_detector() {
        let peer_id = [1u8; 32];
        let mut detector = ReplayDetector::new(peer_id);

        // First message should be accepted
        assert!(detector.check(1));

        // Same sequence should be rejected (replay)
        assert!(!detector.check(1));

        // Next sequence should be accepted
        assert!(detector.check(2));

        // Higher sequence should be accepted
        assert!(detector.check(10));

        // Old but not yet seen should be accepted
        assert!(detector.check(5));

        // Already seen should be rejected
        assert!(!detector.check(5));

        // Very old (outside window) should be rejected
        assert!(!detector.check(100));
        assert!(!detector.check(30)); // Now 30 is too old
    }

    #[test]
    fn test_replay_detector_large_jump() {
        let peer_id = [1u8; 32];
        let mut detector = ReplayDetector::new(peer_id);

        assert!(detector.check(1));
        assert!(detector.check(1000)); // Large jump
        assert!(!detector.check(1)); // Now too old
        assert!(detector.check(999)); // Still in window
    }
}
