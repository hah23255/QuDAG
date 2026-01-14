//! BitChat protocol definitions
//!
//! This module defines the message formats and protocol operations
//! for BitChat communication.

mod message;
mod envelope;
mod handshake;

pub use message::{ChatMessage, MessageType, MessageFlags};
pub use envelope::{Envelope, EnvelopeType, ReplayDetector};
pub use handshake::{Handshake, HandshakeStep};

use heapless::String;

/// Protocol version
pub const PROTOCOL_VERSION: u8 = 1;

/// Magic bytes for protocol identification
pub const MAGIC: [u8; 4] = [0x42, 0x43, 0x48, 0x54]; // "BCHT"

/// Maximum username length
pub const MAX_USERNAME_LEN: usize = 32;

/// Maximum status message length
pub const MAX_STATUS_LEN: usize = 64;

/// User presence status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum PresenceStatus {
    /// Online and available
    #[default]
    Online = 0,
    /// Away/idle
    Away = 1,
    /// Do not disturb
    Busy = 2,
    /// Offline (disconnected)
    Offline = 3,
    /// Invisible (online but hidden)
    Invisible = 4,
}

impl From<u8> for PresenceStatus {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Online,
            1 => Self::Away,
            2 => Self::Busy,
            3 => Self::Offline,
            4 => Self::Invisible,
            _ => Self::Offline,
        }
    }
}

/// User profile information
#[derive(Debug, Clone)]
pub struct UserProfile {
    /// Display name
    pub name: String<MAX_USERNAME_LEN>,
    /// Status message
    pub status: String<MAX_STATUS_LEN>,
    /// Presence status
    pub presence: PresenceStatus,
    /// Last seen timestamp (Unix seconds)
    pub last_seen: u64,
}

impl Default for UserProfile {
    fn default() -> Self {
        Self {
            name: String::new(),
            status: String::new(),
            presence: PresenceStatus::Offline,
            last_seen: 0,
        }
    }
}

impl UserProfile {
    /// Create new profile with name
    pub fn new(name: &str) -> Self {
        let mut profile = Self::default();
        let _ = profile.name.push_str(name);
        profile
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> heapless::Vec<u8, 128> {
        let mut bytes = heapless::Vec::new();

        // Name length + name
        let name_bytes = self.name.as_bytes();
        let _ = bytes.push(name_bytes.len() as u8);
        let _ = bytes.extend_from_slice(name_bytes);

        // Status length + status
        let status_bytes = self.status.as_bytes();
        let _ = bytes.push(status_bytes.len() as u8);
        let _ = bytes.extend_from_slice(status_bytes);

        // Presence
        let _ = bytes.push(self.presence as u8);

        // Last seen (8 bytes)
        let _ = bytes.extend_from_slice(&self.last_seen.to_le_bytes());

        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() {
            return None;
        }

        let mut offset = 0;

        // Name
        let name_len = bytes.get(offset)? .clone() as usize;
        offset += 1;
        if offset + name_len > bytes.len() {
            return None;
        }
        let name_str = core::str::from_utf8(&bytes[offset..offset + name_len]).ok()?;
        let mut name = String::new();
        name.push_str(name_str).ok()?;
        offset += name_len;

        // Status
        let status_len = bytes.get(offset)?.clone() as usize;
        offset += 1;
        if offset + status_len > bytes.len() {
            return None;
        }
        let status_str = core::str::from_utf8(&bytes[offset..offset + status_len]).ok()?;
        let mut status = String::new();
        status.push_str(status_str).ok()?;
        offset += status_len;

        // Presence
        let presence = PresenceStatus::from(*bytes.get(offset)?);
        offset += 1;

        // Last seen
        if offset + 8 > bytes.len() {
            return None;
        }
        let last_seen = u64::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]);

        Some(Self {
            name,
            status,
            presence,
            last_seen,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_profile_serialization() {
        let mut profile = UserProfile::new("Alice");
        let _ = profile.status.push_str("Hello!");
        profile.presence = PresenceStatus::Online;
        profile.last_seen = 1234567890;

        let bytes = profile.to_bytes();
        let restored = UserProfile::from_bytes(&bytes).unwrap();

        assert_eq!(profile.name.as_str(), restored.name.as_str());
        assert_eq!(profile.status.as_str(), restored.status.as_str());
        assert_eq!(profile.presence, restored.presence);
        assert_eq!(profile.last_seen, restored.last_seen);
    }
}
