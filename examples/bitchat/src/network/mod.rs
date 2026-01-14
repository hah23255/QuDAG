//! P2P networking for BitChat
//!
//! This module provides:
//! - Peer discovery via UDP broadcast
//! - TCP connections for reliable messaging
//! - WiFi management for ESP32
//! - NAT traversal helpers

mod peer;
mod transport;
mod discovery;

pub use peer::{Peer, PeerState, PeerList};
pub use transport::{Transport, TransportConfig, Connection};
pub use discovery::{PeerDiscovery, DiscoveryConfig, Announcement};

use heapless::Vec;

use crate::{BitChatError, Result, DEVICE_ID_LEN, MAX_PEERS};

/// Network event types
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// WiFi connected
    WifiConnected {
        ip: [u8; 4],
        ssid: heapless::String<32>,
    },
    /// WiFi disconnected
    WifiDisconnected,
    /// Peer discovered
    PeerDiscovered {
        peer_id: [u8; DEVICE_ID_LEN],
        ip: [u8; 4],
        port: u16,
    },
    /// Peer connected
    PeerConnected {
        peer_id: [u8; DEVICE_ID_LEN],
    },
    /// Peer disconnected
    PeerDisconnected {
        peer_id: [u8; DEVICE_ID_LEN],
    },
    /// Message received
    MessageReceived {
        from: [u8; DEVICE_ID_LEN],
        data: Vec<u8, 4096>,
    },
    /// Message sent successfully
    MessageSent {
        to: [u8; DEVICE_ID_LEN],
        sequence: u64,
    },
    /// Error occurred
    Error {
        error: BitChatError,
    },
}

/// Network statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct NetworkStats {
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Messages sent
    pub messages_sent: u64,
    /// Messages received
    pub messages_received: u64,
    /// Connection errors
    pub connection_errors: u32,
    /// WiFi reconnections
    pub wifi_reconnects: u32,
    /// Current signal strength (dBm)
    pub rssi: i8,
}

/// WiFi configuration
#[derive(Debug, Clone)]
pub struct WifiConfig {
    /// SSID (network name)
    pub ssid: heapless::String<32>,
    /// Password
    pub password: heapless::String<64>,
    /// Use WiFi 6 (802.11ax) if available
    pub wifi6_enabled: bool,
    /// Power save mode
    pub power_save: bool,
    /// Auto reconnect on disconnect
    pub auto_reconnect: bool,
    /// Maximum reconnect attempts
    pub max_reconnect_attempts: u8,
}

impl Default for WifiConfig {
    fn default() -> Self {
        Self {
            ssid: heapless::String::new(),
            password: heapless::String::new(),
            wifi6_enabled: true,
            power_save: true,
            auto_reconnect: true,
            max_reconnect_attempts: 10,
        }
    }
}

/// IP address helper
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpAddr {
    octets: [u8; 4],
}

impl IpAddr {
    /// Create from octets
    pub fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self {
            octets: [a, b, c, d],
        }
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 4]) -> Self {
        Self { octets: bytes }
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; 4] {
        &self.octets
    }

    /// Check if broadcast address
    pub fn is_broadcast(&self) -> bool {
        self.octets == [255, 255, 255, 255]
    }

    /// Check if loopback
    pub fn is_loopback(&self) -> bool {
        self.octets[0] == 127
    }

    /// Check if private address
    pub fn is_private(&self) -> bool {
        match self.octets[0] {
            10 => true,
            172 => self.octets[1] >= 16 && self.octets[1] <= 31,
            192 => self.octets[1] == 168,
            _ => false,
        }
    }
}

impl core::fmt::Display for IpAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.octets[0], self.octets[1], self.octets[2], self.octets[3]
        )
    }
}

/// Socket address (IP + port)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketAddr {
    /// IP address
    pub ip: IpAddr,
    /// Port number
    pub port: u16,
}

impl SocketAddr {
    /// Create new socket address
    pub fn new(ip: IpAddr, port: u16) -> Self {
        Self { ip, port }
    }

    /// Create from bytes (6 bytes: 4 IP + 2 port)
    pub fn from_bytes(bytes: &[u8; 6]) -> Self {
        let ip = IpAddr::from_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let port = u16::from_be_bytes([bytes[4], bytes[5]]);
        Self { ip, port }
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; 6] {
        let port_bytes = self.port.to_be_bytes();
        [
            self.ip.octets[0],
            self.ip.octets[1],
            self.ip.octets[2],
            self.ip.octets[3],
            port_bytes[0],
            port_bytes[1],
        ]
    }
}

impl core::fmt::Display for SocketAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}:{}", self.ip, self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_addr() {
        let ip = IpAddr::new(192, 168, 1, 100);
        assert!(ip.is_private());
        assert!(!ip.is_broadcast());
        assert!(!ip.is_loopback());
    }

    #[test]
    fn test_socket_addr_serialization() {
        let addr = SocketAddr::new(IpAddr::new(192, 168, 1, 100), 8080);
        let bytes = addr.to_bytes();
        let restored = SocketAddr::from_bytes(&bytes);
        assert_eq!(addr, restored);
    }
}
