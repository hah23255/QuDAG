//! Peer management for BitChat
//!
//! Tracks connected peers, their state, and connection quality.

use heapless::Vec;

use super::{IpAddr, SocketAddr};
use crate::{BitChatError, Result, DEVICE_ID_LEN, MAX_PEERS};
use crate::crypto::PublicIdentity;
use crate::protocol::{PresenceStatus, ReplayDetector};

/// Peer connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// Discovered but not connected
    Discovered,
    /// Connection in progress
    Connecting,
    /// Handshake in progress
    Handshaking,
    /// Connected and ready
    Connected,
    /// Temporarily disconnected (will retry)
    Disconnected,
    /// Banned (will not reconnect)
    Banned,
}

/// Peer information
#[derive(Clone)]
pub struct Peer {
    /// Unique device ID (SHA-256 of public keys)
    pub id: [u8; DEVICE_ID_LEN],
    /// Public identity (keys)
    pub public_identity: Option<PublicIdentity>,
    /// Display name
    pub name: heapless::String<32>,
    /// Current address
    pub address: Option<SocketAddr>,
    /// Connection state
    pub state: PeerState,
    /// Presence status
    pub presence: PresenceStatus,
    /// Last seen timestamp (Unix ms)
    pub last_seen: u64,
    /// Last message sequence (for ordering)
    pub last_sequence: u64,
    /// Round-trip time in ms
    pub rtt_ms: u16,
    /// Connection quality (0-100)
    pub quality: u8,
    /// Number of failed connection attempts
    pub failed_attempts: u8,
    /// Replay detector for this peer
    replay_detector: Option<ReplayDetector>,
}

impl Peer {
    /// Create new peer from discovery
    pub fn new(id: [u8; DEVICE_ID_LEN], address: SocketAddr) -> Self {
        Self {
            id,
            public_identity: None,
            name: heapless::String::new(),
            address: Some(address),
            state: PeerState::Discovered,
            presence: PresenceStatus::Offline,
            last_seen: 0,
            last_sequence: 0,
            rtt_ms: 0,
            quality: 50,
            failed_attempts: 0,
            replay_detector: Some(ReplayDetector::new(id)),
        }
    }

    /// Create peer from public identity
    pub fn from_identity(identity: PublicIdentity, address: SocketAddr) -> Self {
        Self {
            id: identity.device_id,
            public_identity: Some(identity),
            name: heapless::String::new(),
            address: Some(address),
            state: PeerState::Discovered,
            presence: PresenceStatus::Offline,
            last_seen: 0,
            last_sequence: 0,
            rtt_ms: 0,
            quality: 50,
            failed_attempts: 0,
            replay_detector: Some(ReplayDetector::new(identity.device_id)),
        }
    }

    /// Get public encryption key
    pub fn public_key(&self) -> Option<&crate::crypto::PublicEncryptionKey> {
        self.public_identity.as_ref().map(|i| &i.encryption_key)
    }

    /// Check if message sequence is valid (not replay)
    pub fn check_sequence(&mut self, sequence: u64) -> bool {
        if let Some(ref mut detector) = self.replay_detector {
            detector.check(sequence)
        } else {
            // If no detector, reject
            false
        }
    }

    /// Update connection quality based on RTT
    pub fn update_quality(&mut self, rtt_ms: u16) {
        self.rtt_ms = rtt_ms;

        // Quality formula: lower RTT = higher quality
        self.quality = if rtt_ms < 50 {
            100
        } else if rtt_ms < 100 {
            90
        } else if rtt_ms < 200 {
            75
        } else if rtt_ms < 500 {
            50
        } else if rtt_ms < 1000 {
            25
        } else {
            10
        };
    }

    /// Mark as connected
    pub fn mark_connected(&mut self, current_time: u64) {
        self.state = PeerState::Connected;
        self.presence = PresenceStatus::Online;
        self.last_seen = current_time;
        self.failed_attempts = 0;
    }

    /// Mark as disconnected
    pub fn mark_disconnected(&mut self) {
        self.state = PeerState::Disconnected;
        self.presence = PresenceStatus::Offline;
        self.failed_attempts += 1;
    }

    /// Check if should retry connection
    pub fn should_retry(&self, max_attempts: u8) -> bool {
        self.state == PeerState::Disconnected && self.failed_attempts < max_attempts
    }

    /// Ban peer
    pub fn ban(&mut self) {
        self.state = PeerState::Banned;
    }

    /// Check if banned
    pub fn is_banned(&self) -> bool {
        self.state == PeerState::Banned
    }

    /// Serialize peer info for storage
    pub fn to_bytes(&self) -> heapless::Vec<u8, 256> {
        let mut bytes = heapless::Vec::new();

        // ID
        let _ = bytes.extend_from_slice(&self.id);

        // Name length + name
        let name_bytes = self.name.as_bytes();
        let _ = bytes.push(name_bytes.len() as u8);
        let _ = bytes.extend_from_slice(name_bytes);

        // Address
        if let Some(ref addr) = self.address {
            let _ = bytes.push(1);
            let _ = bytes.extend_from_slice(&addr.to_bytes());
        } else {
            let _ = bytes.push(0);
        }

        // State
        let _ = bytes.push(self.state as u8);

        // Presence
        let _ = bytes.push(self.presence as u8);

        // Last seen
        let _ = bytes.extend_from_slice(&self.last_seen.to_le_bytes());

        bytes
    }
}

/// List of known peers with management functions
pub struct PeerList {
    /// Known peers
    peers: Vec<Peer, MAX_PEERS>,
    /// Maximum connection attempts before giving up
    max_attempts: u8,
    /// Ban duration in seconds
    ban_duration_secs: u32,
}

impl PeerList {
    /// Create new peer list
    pub fn new() -> Self {
        Self {
            peers: Vec::new(),
            max_attempts: 5,
            ban_duration_secs: 300,
        }
    }

    /// Add or update peer
    pub fn add_or_update(&mut self, peer: Peer) -> Result<()> {
        // Check if already exists
        if let Some(existing) = self.get_mut(&peer.id) {
            // Update existing
            if peer.address.is_some() {
                existing.address = peer.address;
            }
            if peer.public_identity.is_some() {
                existing.public_identity = peer.public_identity;
            }
            existing.last_seen = peer.last_seen.max(existing.last_seen);
            Ok(())
        } else {
            // Add new
            self.peers.push(peer).map_err(|_| BitChatError::BufferOverflow)
        }
    }

    /// Get peer by ID
    pub fn get(&self, id: &[u8; DEVICE_ID_LEN]) -> Option<&Peer> {
        self.peers.iter().find(|p| &p.id == id)
    }

    /// Get mutable peer by ID
    pub fn get_mut(&mut self, id: &[u8; DEVICE_ID_LEN]) -> Option<&mut Peer> {
        self.peers.iter_mut().find(|p| &p.id == id)
    }

    /// Remove peer by ID
    pub fn remove(&mut self, id: &[u8; DEVICE_ID_LEN]) -> Option<Peer> {
        if let Some(pos) = self.peers.iter().position(|p| &p.id == id) {
            Some(self.peers.swap_remove(pos))
        } else {
            None
        }
    }

    /// Get all connected peers
    pub fn connected(&self) -> impl Iterator<Item = &Peer> {
        self.peers.iter().filter(|p| p.state == PeerState::Connected)
    }

    /// Get peers to retry
    pub fn to_retry(&self) -> impl Iterator<Item = &Peer> {
        let max = self.max_attempts;
        self.peers.iter().filter(move |p| p.should_retry(max))
    }

    /// Get all peers
    pub fn all(&self) -> &[Peer] {
        &self.peers
    }

    /// Count connected peers
    pub fn connected_count(&self) -> usize {
        self.peers.iter().filter(|p| p.state == PeerState::Connected).count()
    }

    /// Count total peers
    pub fn total_count(&self) -> usize {
        self.peers.len()
    }

    /// Clean up old disconnected peers
    pub fn cleanup(&mut self, current_time: u64, max_age_secs: u32) {
        let cutoff = current_time.saturating_sub((max_age_secs as u64) * 1000);
        self.peers.retain(|p| {
            p.state == PeerState::Connected
                || p.state == PeerState::Connecting
                || p.state == PeerState::Handshaking
                || p.last_seen > cutoff
        });
    }

    /// Ban peer
    pub fn ban(&mut self, id: &[u8; DEVICE_ID_LEN]) {
        if let Some(peer) = self.get_mut(id) {
            peer.ban();
        }
    }
}

impl Default for PeerList {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_creation() {
        let id = [1u8; 32];
        let addr = SocketAddr::new(IpAddr::new(192, 168, 1, 100), 8080);
        let peer = Peer::new(id, addr);

        assert_eq!(peer.state, PeerState::Discovered);
        assert_eq!(peer.quality, 50);
    }

    #[test]
    fn test_peer_quality_update() {
        let id = [1u8; 32];
        let addr = SocketAddr::new(IpAddr::new(192, 168, 1, 100), 8080);
        let mut peer = Peer::new(id, addr);

        peer.update_quality(30);
        assert_eq!(peer.quality, 100);

        peer.update_quality(150);
        assert_eq!(peer.quality, 75);

        peer.update_quality(800);
        assert_eq!(peer.quality, 25);
    }

    #[test]
    fn test_peer_list() {
        let mut list = PeerList::new();

        let id1 = [1u8; 32];
        let id2 = [2u8; 32];
        let addr = SocketAddr::new(IpAddr::new(192, 168, 1, 100), 8080);

        list.add_or_update(Peer::new(id1, addr)).unwrap();
        list.add_or_update(Peer::new(id2, addr)).unwrap();

        assert_eq!(list.total_count(), 2);
        assert!(list.get(&id1).is_some());
        assert!(list.get(&id2).is_some());

        list.remove(&id1);
        assert_eq!(list.total_count(), 1);
        assert!(list.get(&id1).is_none());
    }

    #[test]
    fn test_replay_detection() {
        let id = [1u8; 32];
        let addr = SocketAddr::new(IpAddr::new(192, 168, 1, 100), 8080);
        let mut peer = Peer::new(id, addr);

        // First message should be accepted
        assert!(peer.check_sequence(1));

        // Replay should be rejected
        assert!(!peer.check_sequence(1));

        // New message should be accepted
        assert!(peer.check_sequence(2));
    }
}
