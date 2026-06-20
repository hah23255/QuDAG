//! # QuDAG BitChat - Quantum-Resistant Secure Messaging for ESP32
//!
//! BitChat is a secure, peer-to-peer messaging protocol designed for embedded
//! devices, specifically targeting the ESP32-C6 with quantum-resistant cryptography.
//!
//! ## Features
//!
//! - **Quantum-Resistant Cryptography**: Uses X25519 for key exchange with
//!   ChaCha20-Poly1305 for symmetric encryption (upgradeable to ML-KEM/ML-DSA)
//! - **Peer-to-Peer**: Direct device-to-device communication over WiFi
//! - **Offline-First**: Messages queued when peers unavailable
//! - **Privacy-Preserving**: Ephemeral keys and message padding
//! - **Resource-Efficient**: Designed for constrained embedded devices
//!
//! ## Supported Devices
//!
//! - ESP32-C6 (primary target, WiFi 6 support)
//! - ESP32-C3 (RISC-V, WiFi 4)
//! - ESP32-S3 (Xtensa, WiFi 4 + BLE 5)
//!
//! ## Example
//!
//! ```rust,no_run
//! use qudag_bitchat::{BitChat, Config};
//!
//! let config = Config::default();
//! let mut chat = BitChat::new(config);
//!
//! // Generate identity
//! chat.generate_identity();
//!
//! // Connect to peer
//! chat.discover_peers();
//!
//! // Send message
//! chat.send_message("peer_id", "Hello, quantum world!");
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(feature = "std", deny(unsafe_code))]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod crypto;
pub mod network;
pub mod protocol;
pub mod storage;

#[cfg(feature = "display")]
pub mod ui;

#[cfg(feature = "std")]
pub mod bench;

// Re-exports
pub use crypto::{Identity, KeyPair, SessionKey};
pub use network::{Peer, PeerDiscovery, Transport};
pub use protocol::{ChatMessage, MessageType, Envelope};
pub use storage::MessageStore;

#[cfg(feature = "display")]
pub use ui::{ChatUI, Screen};

use heapless::{String, Vec};

/// Maximum message size in bytes
pub const MAX_MESSAGE_SIZE: usize = 4096;

/// Maximum number of peers
pub const MAX_PEERS: usize = 16;

/// Maximum message queue depth
pub const MAX_QUEUE_DEPTH: usize = 64;

/// Device ID length in bytes
pub const DEVICE_ID_LEN: usize = 32;

/// BitChat configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// Device name (max 32 chars)
    pub device_name: String<32>,
    /// WiFi SSID
    pub wifi_ssid: String<32>,
    /// WiFi password
    pub wifi_password: String<64>,
    /// Enable WiFi 6 features (ESP32-C6 only)
    pub wifi6_enabled: bool,
    /// Broadcast discovery port
    pub discovery_port: u16,
    /// Message port
    pub message_port: u16,
    /// Enable message encryption
    pub encryption_enabled: bool,
    /// Enable traffic padding
    pub traffic_padding: bool,
    /// Display brightness (0-255)
    pub display_brightness: u8,
    /// Auto-sleep timeout in seconds (0 = disabled)
    pub auto_sleep_secs: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            device_name: String::try_from("BitChat-Device").unwrap(),
            wifi_ssid: String::new(),
            wifi_password: String::new(),
            wifi6_enabled: true,
            discovery_port: 8765,
            message_port: 8766,
            encryption_enabled: true,
            traffic_padding: true,
            display_brightness: 128,
            auto_sleep_secs: 300,
        }
    }
}

/// BitChat application state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppState {
    /// Initializing system
    Initializing,
    /// Connecting to WiFi
    ConnectingWifi,
    /// WiFi connected, discovering peers
    Discovering,
    /// Ready for chat
    Ready,
    /// Active chat session
    Chatting,
    /// Error state
    Error,
    /// Low power sleep mode
    Sleeping,
}

/// BitChat error types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitChatError {
    /// WiFi connection failed
    WifiConnectionFailed,
    /// Peer not found
    PeerNotFound,
    /// Message too large
    MessageTooLarge,
    /// Encryption failed
    EncryptionFailed,
    /// Decryption failed
    DecryptionFailed,
    /// Storage full
    StorageFull,
    /// Invalid message format
    InvalidMessage,
    /// Key exchange failed
    KeyExchangeFailed,
    /// Network timeout
    Timeout,
    /// Display error
    DisplayError,
    /// Buffer overflow
    BufferOverflow,
}

/// Result type for BitChat operations
pub type Result<T> = core::result::Result<T, BitChatError>;

/// Main BitChat instance
pub struct BitChat {
    /// Current application state
    state: AppState,
    /// Configuration
    config: Config,
    /// Local identity
    identity: Option<Identity>,
    /// Connected peers
    peers: Vec<Peer, MAX_PEERS>,
    /// Outgoing message queue
    outbox: Vec<Envelope, MAX_QUEUE_DEPTH>,
    /// Incoming message queue
    inbox: Vec<Envelope, MAX_QUEUE_DEPTH>,
    /// Message counter for ordering
    message_counter: u64,
}

impl BitChat {
    /// Create a new BitChat instance
    pub fn new(config: Config) -> Self {
        Self {
            state: AppState::Initializing,
            config,
            identity: None,
            peers: Vec::new(),
            outbox: Vec::new(),
            inbox: Vec::new(),
            message_counter: 0,
        }
    }

    /// Get current application state
    pub fn state(&self) -> AppState {
        self.state
    }

    /// Get configuration
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Update configuration
    pub fn set_config(&mut self, config: Config) {
        self.config = config;
    }

    /// Generate a new identity (keypair)
    pub fn generate_identity(&mut self) -> Result<&Identity> {
        let identity = Identity::generate()?;
        self.identity = Some(identity);
        self.identity.as_ref().ok_or(BitChatError::KeyExchangeFailed)
    }

    /// Get local identity
    pub fn identity(&self) -> Option<&Identity> {
        self.identity.as_ref()
    }

    /// Get device ID (public key hash)
    pub fn device_id(&self) -> Option<[u8; DEVICE_ID_LEN]> {
        self.identity.as_ref().map(|i| i.device_id())
    }

    /// Get connected peers
    pub fn peers(&self) -> &[Peer] {
        &self.peers
    }

    /// Add a discovered peer
    pub fn add_peer(&mut self, peer: Peer) -> Result<()> {
        if self.peers.iter().any(|p| p.id == peer.id) {
            return Ok(()); // Already known
        }
        self.peers.push(peer).map_err(|_| BitChatError::BufferOverflow)
    }

    /// Remove a peer
    pub fn remove_peer(&mut self, peer_id: &[u8; DEVICE_ID_LEN]) -> Option<Peer> {
        if let Some(pos) = self.peers.iter().position(|p| &p.id == peer_id) {
            Some(self.peers.swap_remove(pos))
        } else {
            None
        }
    }

    /// Queue a message for sending
    pub fn queue_message(&mut self, to: [u8; DEVICE_ID_LEN], content: &str) -> Result<u64> {
        let identity = self.identity.as_ref().ok_or(BitChatError::KeyExchangeFailed)?;

        if content.len() > MAX_MESSAGE_SIZE {
            return Err(BitChatError::MessageTooLarge);
        }

        self.message_counter += 1;

        let message = ChatMessage::new(
            identity.device_id(),
            to,
            content,
            self.message_counter,
        )?;

        let envelope = if self.config.encryption_enabled {
            // Find peer's public key
            let peer = self.peers.iter()
                .find(|p| p.id == to)
                .ok_or(BitChatError::PeerNotFound)?;

            message.encrypt(&identity.signing_key, peer.public_key().ok_or(BitChatError::PeerNotFound)?, self.config.traffic_padding)?
        } else {
            message.into_envelope()
        };

        self.outbox.push(envelope).map_err(|_| BitChatError::StorageFull)?;
        Ok(self.message_counter)
    }

    /// Process received message envelope
    pub fn receive_envelope(&mut self, envelope: Envelope) -> Result<ChatMessage> {
        let identity = self.identity.as_ref().ok_or(BitChatError::KeyExchangeFailed)?;

        if envelope.is_encrypted() {
            // Find sender's public key
            let sender_id = envelope.sender_id();
            let peer = self.peers.iter()
                .find(|p| p.id == sender_id)
                .ok_or(BitChatError::PeerNotFound)?;

            let message = envelope.decrypt(&identity.encryption_key, peer.public_key().ok_or(BitChatError::PeerNotFound)?)?;
            self.inbox.push(envelope).map_err(|_| BitChatError::StorageFull)?;
            Ok(message)
        } else {
            let message = envelope.into_message()?;
            self.inbox.push(envelope).map_err(|_| BitChatError::StorageFull)?;
            Ok(message)
        }
    }

    /// Get pending outgoing messages
    pub fn pending_outbox(&self) -> &[Envelope] {
        &self.outbox
    }

    /// Clear sent messages from outbox
    pub fn clear_sent(&mut self, count: usize) {
        for _ in 0..count.min(self.outbox.len()) {
            self.outbox.remove(0);
        }
    }

    /// Get received messages
    pub fn inbox(&self) -> &[Envelope] {
        &self.inbox
    }

    /// Set application state
    pub fn set_state(&mut self, state: AppState) {
        self.state = state;
    }

    /// Check if ready to chat
    pub fn is_ready(&self) -> bool {
        matches!(self.state, AppState::Ready | AppState::Chatting)
    }

    /// Get message statistics
    pub fn stats(&self) -> BitChatStats {
        BitChatStats {
            peers_connected: self.peers.len(),
            messages_sent: self.message_counter,
            inbox_count: self.inbox.len(),
            outbox_count: self.outbox.len(),
        }
    }
}

/// BitChat statistics
#[derive(Debug, Clone, Copy)]
pub struct BitChatStats {
    /// Number of connected peers
    pub peers_connected: usize,
    /// Total messages sent
    pub messages_sent: u64,
    /// Messages in inbox
    pub inbox_count: usize,
    /// Messages in outbox
    pub outbox_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.discovery_port, 8765);
        assert!(config.encryption_enabled);
    }

    #[test]
    fn test_bitchat_new() {
        let chat = BitChat::new(Config::default());
        assert_eq!(chat.state(), AppState::Initializing);
        assert!(chat.identity().is_none());
    }
}
