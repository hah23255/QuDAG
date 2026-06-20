//! Persistent storage for BitChat
//!
//! Provides secure storage for:
//! - Identity keys (encrypted)
//! - Message history
//! - Peer information
//! - Configuration

use heapless::Vec;
use zeroize::Zeroize;

use crate::{BitChatError, Result, DEVICE_ID_LEN, MAX_MESSAGE_SIZE};
use crate::crypto::{Identity, derive_key_from_password, seal, open, random_bytes};
use crate::protocol::ChatMessage;

/// Maximum stored messages per peer
pub const MAX_MESSAGES_PER_PEER: usize = 32;

/// Maximum stored peers
pub const MAX_STORED_PEERS: usize = 16;

/// Storage key for identity
pub const KEY_IDENTITY: &[u8] = b"identity";

/// Storage key for config
pub const KEY_CONFIG: &[u8] = b"config";

/// Message storage entry
#[derive(Clone)]
pub struct StoredMessage {
    /// Message hash (ID)
    pub hash: [u8; 32],
    /// Peer device ID
    pub peer_id: [u8; DEVICE_ID_LEN],
    /// Is outgoing (true) or incoming (false)
    pub outgoing: bool,
    /// Timestamp (Unix ms)
    pub timestamp: u64,
    /// Message text (truncated if too long)
    pub text: heapless::String<256>,
    /// Read status
    pub read: bool,
    /// Delivery confirmed
    pub delivered: bool,
}

impl StoredMessage {
    /// Create from chat message
    pub fn from_message(msg: &ChatMessage, outgoing: bool, our_id: &[u8; DEVICE_ID_LEN]) -> Self {
        let peer_id = if outgoing { msg.to } else { msg.from };
        let mut text = heapless::String::new();
        if let Some(t) = msg.text() {
            let _ = text.push_str(&t[..t.len().min(256)]);
        }

        Self {
            hash: msg.hash(),
            peer_id,
            outgoing,
            timestamp: msg.timestamp,
            text,
            read: outgoing, // Outgoing are always "read"
            delivered: false,
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8, 384> {
        let mut bytes = Vec::new();

        let _ = bytes.extend_from_slice(&self.hash);
        let _ = bytes.extend_from_slice(&self.peer_id);
        let _ = bytes.push(if self.outgoing { 1 } else { 0 });
        let _ = bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        let _ = bytes.push(if self.read { 1 } else { 0 });
        let _ = bytes.push(if self.delivered { 1 } else { 0 });

        let text_bytes = self.text.as_bytes();
        let text_len = text_bytes.len() as u16;
        let _ = bytes.extend_from_slice(&text_len.to_le_bytes());
        let _ = bytes.extend_from_slice(text_bytes);

        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 32 + 32 + 1 + 8 + 1 + 1 + 2 {
            return Err(BitChatError::InvalidMessage);
        }

        let mut offset = 0;

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;

        let mut peer_id = [0u8; DEVICE_ID_LEN];
        peer_id.copy_from_slice(&bytes[offset..offset + DEVICE_ID_LEN]);
        offset += DEVICE_ID_LEN;

        let outgoing = bytes[offset] != 0;
        offset += 1;

        let timestamp = u64::from_le_bytes([
            bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3],
            bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7],
        ]);
        offset += 8;

        let read = bytes[offset] != 0;
        offset += 1;

        let delivered = bytes[offset] != 0;
        offset += 1;

        let text_len = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;

        if offset + text_len > bytes.len() {
            return Err(BitChatError::InvalidMessage);
        }

        let mut text = heapless::String::new();
        if let Ok(s) = core::str::from_utf8(&bytes[offset..offset + text_len]) {
            let _ = text.push_str(s);
        }

        Ok(Self {
            hash,
            peer_id,
            outgoing,
            timestamp,
            text,
            read,
            delivered,
        })
    }
}

/// Message store for a single peer
pub struct PeerMessageStore {
    /// Peer device ID
    pub peer_id: [u8; DEVICE_ID_LEN],
    /// Stored messages (oldest first)
    messages: Vec<StoredMessage, MAX_MESSAGES_PER_PEER>,
    /// Unread count
    unread_count: u8,
}

impl PeerMessageStore {
    /// Create new store for peer
    pub fn new(peer_id: [u8; DEVICE_ID_LEN]) -> Self {
        Self {
            peer_id,
            messages: Vec::new(),
            unread_count: 0,
        }
    }

    /// Add message
    pub fn add(&mut self, msg: StoredMessage) {
        if !msg.read {
            self.unread_count = self.unread_count.saturating_add(1);
        }

        // Remove oldest if full
        if self.messages.len() >= MAX_MESSAGES_PER_PEER {
            if !self.messages[0].read {
                self.unread_count = self.unread_count.saturating_sub(1);
            }
            self.messages.remove(0);
        }

        let _ = self.messages.push(msg);
    }

    /// Mark message as read
    pub fn mark_read(&mut self, hash: &[u8; 32]) {
        if let Some(msg) = self.messages.iter_mut().find(|m| &m.hash == hash) {
            if !msg.read {
                msg.read = true;
                self.unread_count = self.unread_count.saturating_sub(1);
            }
        }
    }

    /// Mark message as delivered
    pub fn mark_delivered(&mut self, hash: &[u8; 32]) {
        if let Some(msg) = self.messages.iter_mut().find(|m| &m.hash == hash) {
            msg.delivered = true;
        }
    }

    /// Mark all as read
    pub fn mark_all_read(&mut self) {
        for msg in self.messages.iter_mut() {
            msg.read = true;
        }
        self.unread_count = 0;
    }

    /// Get messages
    pub fn messages(&self) -> &[StoredMessage] {
        &self.messages
    }

    /// Get unread count
    pub fn unread_count(&self) -> u8 {
        self.unread_count
    }

    /// Get last message
    pub fn last_message(&self) -> Option<&StoredMessage> {
        self.messages.last()
    }
}

/// Main message store
pub struct MessageStore {
    /// Per-peer message stores
    peer_stores: Vec<PeerMessageStore, MAX_STORED_PEERS>,
}

impl MessageStore {
    /// Create new message store
    pub fn new() -> Self {
        Self {
            peer_stores: Vec::new(),
        }
    }

    /// Get or create store for peer
    pub fn get_or_create(&mut self, peer_id: [u8; DEVICE_ID_LEN]) -> &mut PeerMessageStore {
        // Check if exists
        if let Some(pos) = self.peer_stores.iter().position(|s| s.peer_id == peer_id) {
            return &mut self.peer_stores[pos];
        }

        // Create new
        if self.peer_stores.len() >= MAX_STORED_PEERS {
            // Remove oldest (by last message time)
            let oldest = self.peer_stores
                .iter()
                .enumerate()
                .min_by_key(|(_, s)| s.last_message().map(|m| m.timestamp).unwrap_or(0))
                .map(|(i, _)| i);

            if let Some(i) = oldest {
                self.peer_stores.swap_remove(i);
            }
        }

        let store = PeerMessageStore::new(peer_id);
        let _ = self.peer_stores.push(store);
        self.peer_stores.last_mut().unwrap()
    }

    /// Get store for peer
    pub fn get(&self, peer_id: &[u8; DEVICE_ID_LEN]) -> Option<&PeerMessageStore> {
        self.peer_stores.iter().find(|s| &s.peer_id == peer_id)
    }

    /// Get mutable store for peer
    pub fn get_mut(&mut self, peer_id: &[u8; DEVICE_ID_LEN]) -> Option<&mut PeerMessageStore> {
        self.peer_stores.iter_mut().find(|s| &s.peer_id == peer_id)
    }

    /// Add message
    pub fn add_message(&mut self, msg: StoredMessage) {
        let peer_id = msg.peer_id;
        let store = self.get_or_create(peer_id);
        store.add(msg);
    }

    /// Get total unread count
    pub fn total_unread(&self) -> u32 {
        self.peer_stores.iter().map(|s| s.unread_count() as u32).sum()
    }

    /// Get all peer stores
    pub fn peer_stores(&self) -> &[PeerMessageStore] {
        &self.peer_stores
    }
}

impl Default for MessageStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Encrypted identity storage
pub struct IdentityStorage {
    /// Salt for key derivation
    salt: [u8; 16],
    /// Encrypted identity data
    encrypted_data: Vec<u8, 256>,
}

impl IdentityStorage {
    /// Create new encrypted identity storage
    pub fn encrypt(identity: &Identity, password: &[u8]) -> Result<Self> {
        // Generate salt
        let salt: [u8; 16] = random_bytes();

        // Derive encryption key
        let key = derive_key_from_password(password, &salt, 10000);

        // Serialize identity (signing + encryption keys)
        let mut plaintext = [0u8; 64];
        plaintext[..32].copy_from_slice(identity.signing_key.as_bytes());
        plaintext[32..].copy_from_slice(identity.encryption_key.as_bytes());

        // Encrypt
        let ciphertext = seal(&key, &plaintext, &salt)?;

        let mut encrypted_data = Vec::new();
        encrypted_data.extend_from_slice(&ciphertext)
            .map_err(|_| BitChatError::BufferOverflow)?;

        // Zeroize sensitive data
        let mut key = key;
        let mut plaintext = plaintext;
        key.zeroize();
        plaintext.zeroize();

        Ok(Self {
            salt,
            encrypted_data,
        })
    }

    /// Decrypt and restore identity
    pub fn decrypt(&self, password: &[u8]) -> Result<Identity> {
        // Derive decryption key
        let key = derive_key_from_password(password, &self.salt, 10000);

        // Decrypt
        let plaintext = open(&key, &self.encrypted_data, &self.salt)?;

        if plaintext.len() < 64 {
            return Err(BitChatError::DecryptionFailed);
        }

        // Restore identity
        let mut signing = [0u8; 32];
        let mut encryption = [0u8; 32];
        signing.copy_from_slice(&plaintext[..32]);
        encryption.copy_from_slice(&plaintext[32..64]);

        let identity = Identity::from_keys(signing, encryption);

        // Zeroize
        let mut key = key;
        key.zeroize();
        signing.zeroize();
        encryption.zeroize();

        Ok(identity)
    }

    /// Serialize for storage
    pub fn to_bytes(&self) -> Vec<u8, 512> {
        let mut bytes = Vec::new();

        let _ = bytes.extend_from_slice(&self.salt);
        let len = self.encrypted_data.len() as u16;
        let _ = bytes.extend_from_slice(&len.to_le_bytes());
        let _ = bytes.extend_from_slice(&self.encrypted_data);

        bytes
    }

    /// Deserialize from storage
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 16 + 2 {
            return Err(BitChatError::InvalidMessage);
        }

        let mut salt = [0u8; 16];
        salt.copy_from_slice(&bytes[..16]);

        let len = u16::from_le_bytes([bytes[16], bytes[17]]) as usize;

        if bytes.len() < 18 + len {
            return Err(BitChatError::InvalidMessage);
        }

        let mut encrypted_data = Vec::new();
        encrypted_data.extend_from_slice(&bytes[18..18 + len])
            .map_err(|_| BitChatError::BufferOverflow)?;

        Ok(Self {
            salt,
            encrypted_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_store() {
        let mut store = MessageStore::new();
        let peer_id = [1u8; 32];

        let msg = StoredMessage {
            hash: [0u8; 32],
            peer_id,
            outgoing: false,
            timestamp: 1000,
            text: heapless::String::try_from("Hello").unwrap(),
            read: false,
            delivered: false,
        };

        store.add_message(msg);

        assert_eq!(store.total_unread(), 1);

        let peer_store = store.get(&peer_id).unwrap();
        assert_eq!(peer_store.messages().len(), 1);
        assert_eq!(peer_store.unread_count(), 1);
    }

    #[test]
    fn test_identity_encryption() {
        let identity = Identity::generate().unwrap();
        let original_id = identity.device_id();

        let password = b"test_password_123";
        let storage = IdentityStorage::encrypt(&identity, password).unwrap();

        // Serialize and deserialize
        let bytes = storage.to_bytes();
        let restored_storage = IdentityStorage::from_bytes(&bytes).unwrap();

        // Decrypt
        let restored = restored_storage.decrypt(password).unwrap();
        assert_eq!(original_id, restored.device_id());
    }

    #[test]
    fn test_identity_wrong_password() {
        let identity = Identity::generate().unwrap();

        let password = b"correct_password";
        let storage = IdentityStorage::encrypt(&identity, password).unwrap();

        let wrong_password = b"wrong_password";
        let result = storage.decrypt(wrong_password);
        assert!(result.is_err());
    }
}
