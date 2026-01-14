//! Chat message definitions

use heapless::{String, Vec};
use serde::{Serialize, Deserialize};

use super::{PROTOCOL_VERSION, MAGIC};
use crate::{BitChatError, Result, DEVICE_ID_LEN, MAX_MESSAGE_SIZE};
use crate::crypto::{SigningKey, PublicEncryptionKey, hash};
use crate::protocol::Envelope;

/// Message type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    /// Plain text message
    Text = 0,
    /// Acknowledgment
    Ack = 1,
    /// Delivery receipt
    Delivered = 2,
    /// Read receipt
    Read = 3,
    /// Typing indicator
    Typing = 4,
    /// Presence update
    Presence = 5,
    /// Key exchange request
    KeyExchange = 6,
    /// Key exchange response
    KeyExchangeResponse = 7,
    /// Peer discovery announcement
    Discovery = 8,
    /// File transfer request
    FileRequest = 9,
    /// File chunk
    FileChunk = 10,
    /// Group message
    Group = 11,
    /// System message
    System = 12,
}

impl From<u8> for MessageType {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Text,
            1 => Self::Ack,
            2 => Self::Delivered,
            3 => Self::Read,
            4 => Self::Typing,
            5 => Self::Presence,
            6 => Self::KeyExchange,
            7 => Self::KeyExchangeResponse,
            8 => Self::Discovery,
            9 => Self::FileRequest,
            10 => Self::FileChunk,
            11 => Self::Group,
            _ => Self::System,
        }
    }
}

/// Message flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MessageFlags(u8);

impl MessageFlags {
    /// Empty flags
    pub const NONE: Self = Self(0);
    /// Message is encrypted
    pub const ENCRYPTED: Self = Self(1 << 0);
    /// Message is signed
    pub const SIGNED: Self = Self(1 << 1);
    /// Message requires acknowledgment
    pub const REQUIRE_ACK: Self = Self(1 << 2);
    /// Message is a reply
    pub const REPLY: Self = Self(1 << 3);
    /// Message is forwarded
    pub const FORWARDED: Self = Self(1 << 4);
    /// Message has padding
    pub const PADDED: Self = Self(1 << 5);

    /// Check if flag is set
    pub fn has(&self, flag: Self) -> bool {
        self.0 & flag.0 != 0
    }

    /// Set a flag
    pub fn set(&mut self, flag: Self) {
        self.0 |= flag.0;
    }

    /// Clear a flag
    pub fn clear(&mut self, flag: Self) {
        self.0 &= !flag.0;
    }

    /// Get raw value
    pub fn bits(&self) -> u8 {
        self.0
    }

    /// Create from raw value
    pub fn from_bits(bits: u8) -> Self {
        Self(bits)
    }
}

/// Chat message
#[derive(Debug, Clone)]
pub struct ChatMessage {
    /// Sender device ID
    pub from: [u8; DEVICE_ID_LEN],
    /// Recipient device ID
    pub to: [u8; DEVICE_ID_LEN],
    /// Message type
    pub msg_type: MessageType,
    /// Message flags
    pub flags: MessageFlags,
    /// Message sequence number
    pub sequence: u64,
    /// Timestamp (Unix milliseconds)
    pub timestamp: u64,
    /// Message content
    pub content: Vec<u8, MAX_MESSAGE_SIZE>,
    /// Signature (64 bytes if signed)
    pub signature: Option<[u8; 64]>,
    /// Reply-to message ID (hash of original message)
    pub reply_to: Option<[u8; 32]>,
}

impl ChatMessage {
    /// Create new text message
    pub fn new(
        from: [u8; DEVICE_ID_LEN],
        to: [u8; DEVICE_ID_LEN],
        text: &str,
        sequence: u64,
    ) -> Result<Self> {
        let mut content = Vec::new();
        content.extend_from_slice(text.as_bytes())
            .map_err(|_| BitChatError::MessageTooLarge)?;

        // Use current time (or placeholder for no_std)
        let timestamp = Self::current_timestamp();

        Ok(Self {
            from,
            to,
            msg_type: MessageType::Text,
            flags: MessageFlags::REQUIRE_ACK,
            sequence,
            timestamp,
            content,
            signature: None,
            reply_to: None,
        })
    }

    /// Create acknowledgment message
    pub fn ack(from: [u8; DEVICE_ID_LEN], to: [u8; DEVICE_ID_LEN], original_hash: [u8; 32], sequence: u64) -> Self {
        let mut content = Vec::new();
        let _ = content.extend_from_slice(&original_hash);

        Self {
            from,
            to,
            msg_type: MessageType::Ack,
            flags: MessageFlags::NONE,
            sequence,
            timestamp: Self::current_timestamp(),
            content,
            signature: None,
            reply_to: None,
        }
    }

    /// Create typing indicator
    pub fn typing(from: [u8; DEVICE_ID_LEN], to: [u8; DEVICE_ID_LEN], is_typing: bool, sequence: u64) -> Self {
        let mut content = Vec::new();
        let _ = content.push(if is_typing { 1 } else { 0 });

        Self {
            from,
            to,
            msg_type: MessageType::Typing,
            flags: MessageFlags::NONE,
            sequence,
            timestamp: Self::current_timestamp(),
            content,
            signature: None,
            reply_to: None,
        }
    }

    /// Create presence update
    pub fn presence(from: [u8; DEVICE_ID_LEN], status: u8, sequence: u64) -> Self {
        let mut content = Vec::new();
        let _ = content.push(status);

        Self {
            from,
            to: [0u8; DEVICE_ID_LEN], // Broadcast
            msg_type: MessageType::Presence,
            flags: MessageFlags::NONE,
            sequence,
            timestamp: Self::current_timestamp(),
            content,
            signature: None,
            reply_to: None,
        }
    }

    /// Create discovery announcement
    pub fn discovery(from: [u8; DEVICE_ID_LEN], public_identity: &[u8], sequence: u64) -> Result<Self> {
        let mut content = Vec::new();
        content.extend_from_slice(public_identity)
            .map_err(|_| BitChatError::MessageTooLarge)?;

        Ok(Self {
            from,
            to: [0xFFu8; DEVICE_ID_LEN], // Broadcast
            msg_type: MessageType::Discovery,
            flags: MessageFlags::NONE,
            sequence,
            timestamp: Self::current_timestamp(),
            content,
            signature: None,
            reply_to: None,
        })
    }

    /// Get message hash (for ACKs and references)
    pub fn hash(&self) -> [u8; 32] {
        let bytes = self.to_bytes_for_signing();
        hash(&bytes)
    }

    /// Sign message
    pub fn sign(&mut self, key: &SigningKey) {
        let bytes = self.to_bytes_for_signing();
        self.signature = Some(key.sign(&bytes));
        self.flags.set(MessageFlags::SIGNED);
    }

    /// Get content as text (if text message)
    pub fn text(&self) -> Option<&str> {
        if self.msg_type == MessageType::Text {
            core::str::from_utf8(&self.content).ok()
        } else {
            None
        }
    }

    /// Serialize for signing (excludes signature)
    fn to_bytes_for_signing(&self) -> Vec<u8, { MAX_MESSAGE_SIZE + 128 }> {
        let mut bytes = Vec::new();

        let _ = bytes.extend_from_slice(&MAGIC);
        let _ = bytes.push(PROTOCOL_VERSION);
        let _ = bytes.extend_from_slice(&self.from);
        let _ = bytes.extend_from_slice(&self.to);
        let _ = bytes.push(self.msg_type as u8);
        let _ = bytes.push(self.flags.bits());
        let _ = bytes.extend_from_slice(&self.sequence.to_le_bytes());
        let _ = bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        let content_len = self.content.len() as u16;
        let _ = bytes.extend_from_slice(&content_len.to_le_bytes());
        let _ = bytes.extend_from_slice(&self.content);

        if let Some(ref reply_to) = self.reply_to {
            let _ = bytes.push(1);
            let _ = bytes.extend_from_slice(reply_to);
        } else {
            let _ = bytes.push(0);
        }

        bytes
    }

    /// Serialize complete message
    pub fn to_bytes(&self) -> Vec<u8, { MAX_MESSAGE_SIZE + 256 }> {
        let mut bytes = Vec::new();

        // Header
        let _ = bytes.extend_from_slice(&MAGIC);
        let _ = bytes.push(PROTOCOL_VERSION);

        // Addresses
        let _ = bytes.extend_from_slice(&self.from);
        let _ = bytes.extend_from_slice(&self.to);

        // Type and flags
        let _ = bytes.push(self.msg_type as u8);
        let _ = bytes.push(self.flags.bits());

        // Sequence and timestamp
        let _ = bytes.extend_from_slice(&self.sequence.to_le_bytes());
        let _ = bytes.extend_from_slice(&self.timestamp.to_le_bytes());

        // Content length and content
        let content_len = self.content.len() as u16;
        let _ = bytes.extend_from_slice(&content_len.to_le_bytes());
        let _ = bytes.extend_from_slice(&self.content);

        // Reply-to
        if let Some(ref reply_to) = self.reply_to {
            let _ = bytes.push(1);
            let _ = bytes.extend_from_slice(reply_to);
        } else {
            let _ = bytes.push(0);
        }

        // Signature
        if let Some(ref sig) = self.signature {
            let _ = bytes.push(1);
            let _ = bytes.extend_from_slice(sig);
        } else {
            let _ = bytes.push(0);
        }

        bytes
    }

    /// Deserialize message
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 + 1 + 32 + 32 + 1 + 1 + 8 + 8 + 2 {
            return Err(BitChatError::InvalidMessage);
        }

        let mut offset = 0;

        // Check magic
        if &bytes[offset..offset + 4] != &MAGIC {
            return Err(BitChatError::InvalidMessage);
        }
        offset += 4;

        // Check version
        let version = bytes[offset];
        if version > PROTOCOL_VERSION {
            return Err(BitChatError::InvalidMessage);
        }
        offset += 1;

        // From
        let mut from = [0u8; DEVICE_ID_LEN];
        from.copy_from_slice(&bytes[offset..offset + DEVICE_ID_LEN]);
        offset += DEVICE_ID_LEN;

        // To
        let mut to = [0u8; DEVICE_ID_LEN];
        to.copy_from_slice(&bytes[offset..offset + DEVICE_ID_LEN]);
        offset += DEVICE_ID_LEN;

        // Type and flags
        let msg_type = MessageType::from(bytes[offset]);
        offset += 1;
        let flags = MessageFlags::from_bits(bytes[offset]);
        offset += 1;

        // Sequence
        let sequence = u64::from_le_bytes([
            bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3],
            bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7],
        ]);
        offset += 8;

        // Timestamp
        let timestamp = u64::from_le_bytes([
            bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3],
            bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7],
        ]);
        offset += 8;

        // Content length
        let content_len = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;

        if offset + content_len > bytes.len() {
            return Err(BitChatError::InvalidMessage);
        }

        // Content
        let mut content = Vec::new();
        content.extend_from_slice(&bytes[offset..offset + content_len])
            .map_err(|_| BitChatError::MessageTooLarge)?;
        offset += content_len;

        // Reply-to
        let reply_to = if offset < bytes.len() && bytes[offset] == 1 {
            offset += 1;
            if offset + 32 > bytes.len() {
                return Err(BitChatError::InvalidMessage);
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&bytes[offset..offset + 32]);
            offset += 32;
            Some(hash)
        } else {
            if offset < bytes.len() {
                offset += 1;
            }
            None
        };

        // Signature
        let signature = if offset < bytes.len() && bytes[offset] == 1 {
            offset += 1;
            if offset + 64 > bytes.len() {
                return Err(BitChatError::InvalidMessage);
            }
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&bytes[offset..offset + 64]);
            Some(sig)
        } else {
            None
        };

        Ok(Self {
            from,
            to,
            msg_type,
            flags,
            sequence,
            timestamp,
            content,
            signature,
            reply_to,
        })
    }

    /// Convert to envelope (unencrypted)
    pub fn into_envelope(self) -> Envelope {
        Envelope::plaintext(self)
    }

    /// Encrypt and convert to envelope
    pub fn encrypt(
        self,
        our_key: &SigningKey,
        peer_public: &PublicEncryptionKey,
        pad: bool,
    ) -> Result<Envelope> {
        Envelope::encrypted(self, our_key, peer_public, pad)
    }

    /// Get current timestamp
    fn current_timestamp() -> u64 {
        // In no_std, we'd use a hardware timer
        // For now, return 0 (will be set by actual implementation)
        #[cfg(feature = "std")]
        {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0)
        }
        #[cfg(not(feature = "std"))]
        {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_creation() {
        let from = [1u8; 32];
        let to = [2u8; 32];
        let msg = ChatMessage::new(from, to, "Hello", 1).unwrap();

        assert_eq!(msg.msg_type, MessageType::Text);
        assert_eq!(msg.text(), Some("Hello"));
    }

    #[test]
    fn test_message_serialization() {
        let from = [1u8; 32];
        let to = [2u8; 32];
        let msg = ChatMessage::new(from, to, "Hello, World!", 42).unwrap();

        let bytes = msg.to_bytes();
        let restored = ChatMessage::from_bytes(&bytes).unwrap();

        assert_eq!(msg.from, restored.from);
        assert_eq!(msg.to, restored.to);
        assert_eq!(msg.msg_type, restored.msg_type);
        assert_eq!(msg.sequence, restored.sequence);
        assert_eq!(msg.text(), restored.text());
    }

    #[test]
    fn test_message_hash_consistency() {
        let from = [1u8; 32];
        let to = [2u8; 32];
        let msg = ChatMessage::new(from, to, "Test", 1).unwrap();

        let hash1 = msg.hash();
        let hash2 = msg.hash();

        assert_eq!(hash1, hash2);
    }
}
