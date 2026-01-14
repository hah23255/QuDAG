//! Peer discovery for BitChat
//!
//! Uses UDP broadcast for local network discovery
//! and optional mDNS for more robust discovery.

use heapless::Vec;

use super::{IpAddr, SocketAddr};
use crate::{BitChatError, Result, DEVICE_ID_LEN};
use crate::crypto::{PublicIdentity, hash};
use crate::protocol::MAGIC;

/// Discovery configuration
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// UDP broadcast port
    pub port: u16,
    /// Announcement interval in ms
    pub announce_interval_ms: u32,
    /// Discovery timeout in ms
    pub timeout_ms: u32,
    /// Maximum peers to discover
    pub max_peers: u8,
    /// Enable mDNS (if available)
    pub mdns_enabled: bool,
    /// Service name for mDNS
    pub service_name: heapless::String<32>,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        let mut service_name = heapless::String::new();
        let _ = service_name.push_str("_bitchat._udp.local");

        Self {
            port: 8765,
            announce_interval_ms: 5000,
            timeout_ms: 2000,
            max_peers: 16,
            mdns_enabled: false,
            service_name,
        }
    }
}

/// Discovery announcement message
#[derive(Debug, Clone)]
pub struct Announcement {
    /// Magic bytes for identification
    pub magic: [u8; 4],
    /// Protocol version
    pub version: u8,
    /// Announcement type
    pub ann_type: AnnouncementType,
    /// Device ID
    pub device_id: [u8; DEVICE_ID_LEN],
    /// Message port (TCP)
    pub message_port: u16,
    /// Public identity (optional for queries)
    pub public_identity: Option<PublicIdentity>,
    /// Device name
    pub name: heapless::String<32>,
    /// Timestamp
    pub timestamp: u64,
    /// Nonce for freshness
    pub nonce: [u8; 8],
}

/// Announcement type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AnnouncementType {
    /// Query for peers
    Query = 0,
    /// Response to query
    Response = 1,
    /// Periodic announcement
    Announce = 2,
    /// Leaving the network
    Goodbye = 3,
}

impl From<u8> for AnnouncementType {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Query,
            1 => Self::Response,
            2 => Self::Announce,
            3 => Self::Goodbye,
            _ => Self::Query,
        }
    }
}

impl Announcement {
    /// Create query announcement
    pub fn query(device_id: [u8; DEVICE_ID_LEN], message_port: u16, timestamp: u64) -> Self {
        Self {
            magic: MAGIC,
            version: 1,
            ann_type: AnnouncementType::Query,
            device_id,
            message_port,
            public_identity: None,
            name: heapless::String::new(),
            timestamp,
            nonce: Self::generate_nonce(),
        }
    }

    /// Create response announcement
    pub fn response(
        device_id: [u8; DEVICE_ID_LEN],
        message_port: u16,
        public_identity: PublicIdentity,
        name: &str,
        timestamp: u64,
    ) -> Self {
        let mut ann_name = heapless::String::new();
        let _ = ann_name.push_str(name);

        Self {
            magic: MAGIC,
            version: 1,
            ann_type: AnnouncementType::Response,
            device_id,
            message_port,
            public_identity: Some(public_identity),
            name: ann_name,
            timestamp,
            nonce: Self::generate_nonce(),
        }
    }

    /// Create periodic announcement
    pub fn announce(
        device_id: [u8; DEVICE_ID_LEN],
        message_port: u16,
        public_identity: PublicIdentity,
        name: &str,
        timestamp: u64,
    ) -> Self {
        let mut ann = Self::response(device_id, message_port, public_identity, name, timestamp);
        ann.ann_type = AnnouncementType::Announce;
        ann
    }

    /// Create goodbye announcement
    pub fn goodbye(device_id: [u8; DEVICE_ID_LEN], timestamp: u64) -> Self {
        Self {
            magic: MAGIC,
            version: 1,
            ann_type: AnnouncementType::Goodbye,
            device_id,
            message_port: 0,
            public_identity: None,
            name: heapless::String::new(),
            timestamp,
            nonce: Self::generate_nonce(),
        }
    }

    /// Generate random nonce
    fn generate_nonce() -> [u8; 8] {
        crate::crypto::random_bytes()
    }

    /// Serialize announcement
    pub fn to_bytes(&self) -> Vec<u8, 256> {
        let mut bytes = Vec::new();

        // Header
        let _ = bytes.extend_from_slice(&self.magic);
        let _ = bytes.push(self.version);
        let _ = bytes.push(self.ann_type as u8);

        // Device ID
        let _ = bytes.extend_from_slice(&self.device_id);

        // Port
        let _ = bytes.extend_from_slice(&self.message_port.to_be_bytes());

        // Timestamp
        let _ = bytes.extend_from_slice(&self.timestamp.to_le_bytes());

        // Nonce
        let _ = bytes.extend_from_slice(&self.nonce);

        // Name (length-prefixed)
        let name_bytes = self.name.as_bytes();
        let _ = bytes.push(name_bytes.len() as u8);
        let _ = bytes.extend_from_slice(name_bytes);

        // Public identity (optional)
        if let Some(ref pi) = self.public_identity {
            let _ = bytes.push(1);
            let _ = bytes.extend_from_slice(&pi.to_bytes());
        } else {
            let _ = bytes.push(0);
        }

        bytes
    }

    /// Deserialize announcement
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 + 1 + 1 + 32 + 2 + 8 + 8 + 1 {
            return Err(BitChatError::InvalidMessage);
        }

        let mut offset = 0;

        // Magic
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&bytes[offset..offset + 4]);
        if magic != MAGIC {
            return Err(BitChatError::InvalidMessage);
        }
        offset += 4;

        // Version
        let version = bytes[offset];
        offset += 1;

        // Type
        let ann_type = AnnouncementType::from(bytes[offset]);
        offset += 1;

        // Device ID
        let mut device_id = [0u8; DEVICE_ID_LEN];
        device_id.copy_from_slice(&bytes[offset..offset + DEVICE_ID_LEN]);
        offset += DEVICE_ID_LEN;

        // Port
        let message_port = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        offset += 2;

        // Timestamp
        let timestamp = u64::from_le_bytes([
            bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3],
            bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7],
        ]);
        offset += 8;

        // Nonce
        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&bytes[offset..offset + 8]);
        offset += 8;

        // Name
        let name_len = bytes[offset] as usize;
        offset += 1;
        if offset + name_len > bytes.len() {
            return Err(BitChatError::InvalidMessage);
        }
        let mut name = heapless::String::new();
        if let Ok(s) = core::str::from_utf8(&bytes[offset..offset + name_len]) {
            let _ = name.push_str(s);
        }
        offset += name_len;

        // Public identity
        let public_identity = if offset < bytes.len() && bytes[offset] == 1 {
            offset += 1;
            if offset + 96 > bytes.len() {
                return Err(BitChatError::InvalidMessage);
            }
            let mut pi_bytes = [0u8; 96];
            pi_bytes.copy_from_slice(&bytes[offset..offset + 96]);
            Some(PublicIdentity::from_bytes(&pi_bytes))
        } else {
            None
        };

        Ok(Self {
            magic,
            version,
            ann_type,
            device_id,
            message_port,
            public_identity,
            name,
            timestamp,
            nonce,
        })
    }

    /// Check if announcement is fresh (within timeout)
    pub fn is_fresh(&self, current_time: u64, timeout_ms: u64) -> bool {
        current_time.saturating_sub(self.timestamp) < timeout_ms
    }
}

/// Peer discovery state machine
pub struct PeerDiscovery {
    /// Configuration
    config: DiscoveryConfig,
    /// Our device ID
    device_id: [u8; DEVICE_ID_LEN],
    /// Our public identity
    public_identity: Option<PublicIdentity>,
    /// Device name
    name: heapless::String<32>,
    /// Last announcement time
    last_announce: u64,
    /// Discovery state
    state: DiscoveryState,
    /// Recent nonces (for replay protection)
    recent_nonces: Vec<[u8; 8], 32>,
}

/// Discovery state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryState {
    /// Idle, not discovering
    Idle,
    /// Actively discovering
    Discovering,
    /// Announcing presence
    Announcing,
    /// Error state
    Error,
}

impl PeerDiscovery {
    /// Create new peer discovery
    pub fn new(config: DiscoveryConfig, device_id: [u8; DEVICE_ID_LEN]) -> Self {
        Self {
            config,
            device_id,
            public_identity: None,
            name: heapless::String::new(),
            last_announce: 0,
            state: DiscoveryState::Idle,
            recent_nonces: Vec::new(),
        }
    }

    /// Set public identity
    pub fn set_identity(&mut self, identity: PublicIdentity) {
        self.public_identity = Some(identity);
    }

    /// Set device name
    pub fn set_name(&mut self, name: &str) {
        self.name.clear();
        let _ = self.name.push_str(name);
    }

    /// Start discovery
    pub fn start(&mut self) {
        self.state = DiscoveryState::Discovering;
    }

    /// Stop discovery
    pub fn stop(&mut self) {
        self.state = DiscoveryState::Idle;
    }

    /// Get current state
    pub fn state(&self) -> DiscoveryState {
        self.state
    }

    /// Create query message
    pub fn create_query(&self, message_port: u16, timestamp: u64) -> Announcement {
        Announcement::query(self.device_id, message_port, timestamp)
    }

    /// Create announce message
    pub fn create_announce(&mut self, message_port: u16, timestamp: u64) -> Option<Announcement> {
        let identity = self.public_identity.as_ref()?;
        self.last_announce = timestamp;
        Some(Announcement::announce(
            self.device_id,
            message_port,
            *identity,
            &self.name,
            timestamp,
        ))
    }

    /// Create response to query
    pub fn create_response(&self, message_port: u16, timestamp: u64) -> Option<Announcement> {
        let identity = self.public_identity.as_ref()?;
        Some(Announcement::response(
            self.device_id,
            message_port,
            *identity,
            &self.name,
            timestamp,
        ))
    }

    /// Create goodbye message
    pub fn create_goodbye(&self, timestamp: u64) -> Announcement {
        Announcement::goodbye(self.device_id, timestamp)
    }

    /// Check if should announce
    pub fn should_announce(&self, current_time: u64) -> bool {
        self.state == DiscoveryState::Announcing
            && current_time - self.last_announce >= self.config.announce_interval_ms as u64
    }

    /// Process received announcement
    /// Returns Some(announcement) if valid and new, None otherwise
    pub fn process_announcement<'a>(
        &mut self,
        announcement: &'a Announcement,
        current_time: u64,
    ) -> Option<&'a Announcement> {
        // Check freshness
        if !announcement.is_fresh(current_time, self.config.timeout_ms as u64) {
            return None;
        }

        // Check for replay (nonce already seen)
        if self.recent_nonces.iter().any(|n| n == &announcement.nonce) {
            return None;
        }

        // Store nonce
        if self.recent_nonces.len() >= 32 {
            self.recent_nonces.remove(0);
        }
        let _ = self.recent_nonces.push(announcement.nonce);

        // Don't process our own announcements
        if announcement.device_id == self.device_id {
            return None;
        }

        Some(announcement)
    }

    /// Get broadcast address for discovery
    pub fn broadcast_address(&self) -> SocketAddr {
        SocketAddr::new(
            IpAddr::new(255, 255, 255, 255),
            self.config.port,
        )
    }

    /// Get configuration
    pub fn config(&self) -> &DiscoveryConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Identity;

    #[test]
    fn test_announcement_serialization() {
        let id = [1u8; 32];
        let ann = Announcement::query(id, 8080, 1000);

        let bytes = ann.to_bytes();
        let restored = Announcement::from_bytes(&bytes).unwrap();

        assert_eq!(ann.device_id, restored.device_id);
        assert_eq!(ann.message_port, restored.message_port);
        assert_eq!(ann.ann_type, restored.ann_type);
    }

    #[test]
    fn test_announcement_with_identity() {
        let identity = Identity::generate().unwrap();
        let public = identity.export_public();

        let ann = Announcement::announce(
            identity.device_id(),
            8080,
            public,
            "TestDevice",
            1000,
        );

        let bytes = ann.to_bytes();
        let restored = Announcement::from_bytes(&bytes).unwrap();

        assert!(restored.public_identity.is_some());
        assert_eq!(restored.name.as_str(), "TestDevice");
    }

    #[test]
    fn test_discovery_replay_protection() {
        let config = DiscoveryConfig::default();
        let id = [1u8; 32];
        let mut discovery = PeerDiscovery::new(config, id);

        let other_id = [2u8; 32];
        let ann = Announcement::query(other_id, 8080, 1000);

        // First should succeed
        assert!(discovery.process_announcement(&ann, 1000).is_some());

        // Replay should fail
        assert!(discovery.process_announcement(&ann, 1001).is_none());
    }

    #[test]
    fn test_discovery_freshness() {
        let config = DiscoveryConfig::default();
        let id = [1u8; 32];
        let mut discovery = PeerDiscovery::new(config, id);

        let other_id = [2u8; 32];
        let ann = Announcement::query(other_id, 8080, 1000);

        // Within timeout should succeed
        assert!(discovery.process_announcement(&ann, 1500).is_some());
    }
}
