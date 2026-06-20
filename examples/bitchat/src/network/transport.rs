//! Transport layer for BitChat
//!
//! Provides TCP connections for reliable message delivery
//! with connection pooling and automatic reconnection.

use heapless::Vec;

use super::{IpAddr, SocketAddr, NetworkStats};
use crate::{BitChatError, Result, DEVICE_ID_LEN, MAX_MESSAGE_SIZE};

/// Transport configuration
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Message port
    pub port: u16,
    /// Connection timeout in ms
    pub connect_timeout_ms: u32,
    /// Read timeout in ms
    pub read_timeout_ms: u32,
    /// Write timeout in ms
    pub write_timeout_ms: u32,
    /// Maximum message size
    pub max_message_size: usize,
    /// Enable TCP keepalive
    pub tcp_keepalive: bool,
    /// Keepalive interval in seconds
    pub keepalive_interval_secs: u16,
    /// Maximum concurrent connections
    pub max_connections: u8,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            port: 8766,
            connect_timeout_ms: 5000,
            read_timeout_ms: 30000,
            write_timeout_ms: 10000,
            max_message_size: MAX_MESSAGE_SIZE,
            tcp_keepalive: true,
            keepalive_interval_secs: 30,
            max_connections: 8,
        }
    }
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Not connected
    Disconnected,
    /// Connecting
    Connecting,
    /// Connected and ready
    Connected,
    /// Error state
    Error,
}

/// Individual connection handle
///
/// Note: Actual socket operations are platform-specific
/// This provides the abstraction layer
pub struct Connection {
    /// Peer device ID
    pub peer_id: [u8; DEVICE_ID_LEN],
    /// Remote address
    pub remote_addr: SocketAddr,
    /// Connection state
    pub state: ConnectionState,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Last activity timestamp
    pub last_activity: u64,
    /// Read buffer
    read_buffer: Vec<u8, MAX_MESSAGE_SIZE>,
    /// Write buffer
    write_buffer: Vec<u8, MAX_MESSAGE_SIZE>,
}

impl Connection {
    /// Create new connection
    pub fn new(peer_id: [u8; DEVICE_ID_LEN], remote_addr: SocketAddr) -> Self {
        Self {
            peer_id,
            remote_addr,
            state: ConnectionState::Disconnected,
            bytes_sent: 0,
            bytes_received: 0,
            last_activity: 0,
            read_buffer: Vec::new(),
            write_buffer: Vec::new(),
        }
    }

    /// Queue data for sending
    pub fn queue_send(&mut self, data: &[u8]) -> Result<()> {
        // Add length prefix (2 bytes, big endian)
        let len = data.len() as u16;
        self.write_buffer.extend_from_slice(&len.to_be_bytes())
            .map_err(|_| BitChatError::BufferOverflow)?;
        self.write_buffer.extend_from_slice(data)
            .map_err(|_| BitChatError::BufferOverflow)?;
        Ok(())
    }

    /// Get pending write data
    pub fn pending_write(&self) -> &[u8] {
        &self.write_buffer
    }

    /// Clear sent data from buffer
    pub fn clear_sent(&mut self, count: usize) {
        if count >= self.write_buffer.len() {
            self.write_buffer.clear();
        } else {
            // Shift remaining data to front
            for i in 0..self.write_buffer.len() - count {
                self.write_buffer[i] = self.write_buffer[i + count];
            }
            self.write_buffer.truncate(self.write_buffer.len() - count);
        }
        self.bytes_sent += count as u64;
    }

    /// Add received data to buffer
    pub fn add_received(&mut self, data: &[u8]) -> Result<()> {
        self.read_buffer.extend_from_slice(data)
            .map_err(|_| BitChatError::BufferOverflow)?;
        self.bytes_received += data.len() as u64;
        Ok(())
    }

    /// Try to extract a complete message from buffer
    pub fn try_read_message(&mut self) -> Option<Vec<u8, MAX_MESSAGE_SIZE>> {
        if self.read_buffer.len() < 2 {
            return None;
        }

        // Read length prefix
        let len = u16::from_be_bytes([self.read_buffer[0], self.read_buffer[1]]) as usize;

        if self.read_buffer.len() < 2 + len {
            return None;
        }

        // Extract message
        let mut message = Vec::new();
        if message.extend_from_slice(&self.read_buffer[2..2 + len]).is_err() {
            return None;
        }

        // Remove from buffer
        for i in 0..self.read_buffer.len() - 2 - len {
            self.read_buffer[i] = self.read_buffer[i + 2 + len];
        }
        self.read_buffer.truncate(self.read_buffer.len() - 2 - len);

        Some(message)
    }

    /// Check if connection is idle
    pub fn is_idle(&self, current_time: u64, timeout_ms: u64) -> bool {
        current_time - self.last_activity > timeout_ms
    }

    /// Update last activity time
    pub fn touch(&mut self, current_time: u64) {
        self.last_activity = current_time;
    }
}

/// Transport manager for multiple connections
pub struct Transport {
    /// Configuration
    config: TransportConfig,
    /// Active connections
    connections: Vec<Connection, 16>,
    /// Local address
    local_addr: Option<SocketAddr>,
    /// Statistics
    stats: NetworkStats,
}

impl Transport {
    /// Create new transport manager
    pub fn new(config: TransportConfig) -> Self {
        Self {
            config,
            connections: Vec::new(),
            local_addr: None,
            stats: NetworkStats::default(),
        }
    }

    /// Set local address
    pub fn set_local_addr(&mut self, addr: SocketAddr) {
        self.local_addr = Some(addr);
    }

    /// Get local address
    pub fn local_addr(&self) -> Option<&SocketAddr> {
        self.local_addr.as_ref()
    }

    /// Create connection to peer
    pub fn connect(&mut self, peer_id: [u8; DEVICE_ID_LEN], addr: SocketAddr) -> Result<&mut Connection> {
        // Check if already connected
        if self.get_connection(&peer_id).is_some() {
            return self.get_connection_mut(&peer_id).ok_or(BitChatError::PeerNotFound);
        }

        // Check connection limit
        if self.connections.len() >= self.config.max_connections as usize {
            return Err(BitChatError::BufferOverflow);
        }

        let mut conn = Connection::new(peer_id, addr);
        conn.state = ConnectionState::Connecting;

        self.connections.push(conn).map_err(|_| BitChatError::BufferOverflow)?;

        // Return reference to new connection
        self.connections.last_mut().ok_or(BitChatError::PeerNotFound)
    }

    /// Get connection by peer ID
    pub fn get_connection(&self, peer_id: &[u8; DEVICE_ID_LEN]) -> Option<&Connection> {
        self.connections.iter().find(|c| &c.peer_id == peer_id)
    }

    /// Get mutable connection by peer ID
    pub fn get_connection_mut(&mut self, peer_id: &[u8; DEVICE_ID_LEN]) -> Option<&mut Connection> {
        self.connections.iter_mut().find(|c| &c.peer_id == peer_id)
    }

    /// Remove connection
    pub fn disconnect(&mut self, peer_id: &[u8; DEVICE_ID_LEN]) {
        if let Some(pos) = self.connections.iter().position(|c| &c.peer_id == peer_id) {
            self.connections.swap_remove(pos);
        }
    }

    /// Get all connections
    pub fn connections(&self) -> &[Connection] {
        &self.connections
    }

    /// Get connected peer count
    pub fn connected_count(&self) -> usize {
        self.connections.iter()
            .filter(|c| c.state == ConnectionState::Connected)
            .count()
    }

    /// Clean up idle connections
    pub fn cleanup_idle(&mut self, current_time: u64) {
        let timeout = self.config.read_timeout_ms as u64;
        self.connections.retain(|c| !c.is_idle(current_time, timeout));
    }

    /// Get statistics
    pub fn stats(&self) -> &NetworkStats {
        &self.stats
    }

    /// Update statistics from connections
    pub fn update_stats(&mut self) {
        self.stats.bytes_sent = self.connections.iter().map(|c| c.bytes_sent).sum();
        self.stats.bytes_received = self.connections.iter().map(|c| c.bytes_received).sum();
    }

    /// Get configuration
    pub fn config(&self) -> &TransportConfig {
        &self.config
    }
}

/// Frame encoder/decoder for message framing
///
/// Security: Length-prefixed framing prevents buffer overflow attacks
pub struct FrameCodec {
    /// Maximum frame size
    max_size: usize,
}

impl FrameCodec {
    /// Create new frame codec
    pub fn new(max_size: usize) -> Self {
        Self { max_size }
    }

    /// Encode frame with length prefix
    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8, { MAX_MESSAGE_SIZE + 4 }>> {
        if data.len() > self.max_size {
            return Err(BitChatError::MessageTooLarge);
        }

        let mut frame = Vec::new();

        // 4-byte length prefix for larger messages
        let len = data.len() as u32;
        frame.extend_from_slice(&len.to_be_bytes())
            .map_err(|_| BitChatError::BufferOverflow)?;
        frame.extend_from_slice(data)
            .map_err(|_| BitChatError::BufferOverflow)?;

        Ok(frame)
    }

    /// Decode frame, returns (message, consumed_bytes) or None if incomplete
    pub fn decode<'a>(&self, buffer: &'a [u8]) -> Option<(&'a [u8], usize)> {
        if buffer.len() < 4 {
            return None;
        }

        let len = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;

        if len > self.max_size {
            return None; // Invalid frame
        }

        if buffer.len() < 4 + len {
            return None; // Incomplete
        }

        Some((&buffer[4..4 + len], 4 + len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_buffers() {
        let id = [1u8; 32];
        let addr = SocketAddr::new(IpAddr::new(192, 168, 1, 100), 8080);
        let mut conn = Connection::new(id, addr);

        // Queue message
        conn.queue_send(b"Hello").unwrap();
        assert!(!conn.pending_write().is_empty());

        // Simulate send
        let len = conn.pending_write().len();
        conn.clear_sent(len);
        assert!(conn.pending_write().is_empty());
    }

    #[test]
    fn test_connection_message_extraction() {
        let id = [1u8; 32];
        let addr = SocketAddr::new(IpAddr::new(192, 168, 1, 100), 8080);
        let mut conn = Connection::new(id, addr);

        // Simulate receiving framed data
        let msg = b"Hello, World!";
        let mut frame = Vec::<u8, 256>::new();
        let _ = frame.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        let _ = frame.extend_from_slice(msg);

        conn.add_received(&frame).unwrap();

        // Extract message
        let extracted = conn.try_read_message().unwrap();
        assert_eq!(extracted.as_slice(), msg);
    }

    #[test]
    fn test_frame_codec() {
        let codec = FrameCodec::new(1024);

        let data = b"Test message";
        let encoded = codec.encode(data).unwrap();

        let (decoded, consumed) = codec.decode(&encoded).unwrap();
        assert_eq!(decoded, data);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn test_transport_connections() {
        let config = TransportConfig::default();
        let mut transport = Transport::new(config);

        let id1 = [1u8; 32];
        let id2 = [2u8; 32];
        let addr = SocketAddr::new(IpAddr::new(192, 168, 1, 100), 8080);

        transport.connect(id1, addr).unwrap();
        transport.connect(id2, addr).unwrap();

        assert_eq!(transport.connections().len(), 2);

        transport.disconnect(&id1);
        assert_eq!(transport.connections().len(), 1);
    }
}
