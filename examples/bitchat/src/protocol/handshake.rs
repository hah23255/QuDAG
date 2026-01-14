//! Secure handshake protocol for BitChat
//!
//! Implements a three-way handshake with:
//! - Mutual authentication
//! - Perfect forward secrecy via ephemeral keys
//! - Protection against man-in-the-middle attacks
//! - Timeout protection
//! - Rate limiting

use heapless::Vec;
use zeroize::Zeroize;

use super::{PROTOCOL_VERSION, MAGIC};
use crate::{BitChatError, Result, DEVICE_ID_LEN};
use crate::crypto::{
    Identity, PublicIdentity, SigningKey, VerifyingKey,
    EncryptionKey, PublicEncryptionKey, SessionKey,
    hash, random_bytes, constant_time_eq,
};

/// Handshake step
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeStep {
    /// Initial state
    Initial,
    /// Hello sent, waiting for response
    HelloSent,
    /// Hello received, response sent
    ResponseSent,
    /// Handshake complete
    Complete,
    /// Handshake failed
    Failed,
    /// Handshake timed out
    Timeout,
}

/// Handshake message type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeType {
    /// Initial hello
    Hello = 0,
    /// Response to hello
    Response = 1,
    /// Final confirmation
    Confirm = 2,
    /// Rejection
    Reject = 3,
}

impl From<u8> for HandshakeType {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Hello,
            1 => Self::Response,
            2 => Self::Confirm,
            3 => Self::Reject,
            _ => Self::Reject,
        }
    }
}

/// Handshake message
#[derive(Clone)]
pub struct HandshakeMessage {
    /// Message type
    pub msg_type: HandshakeType,
    /// Protocol version
    pub version: u8,
    /// Sender's device ID
    pub sender_id: [u8; DEVICE_ID_LEN],
    /// Nonce for this message
    pub nonce: [u8; 32],
    /// Public identity (for Hello/Response)
    pub public_identity: Option<PublicIdentity>,
    /// Ephemeral public key
    pub ephemeral_public: Option<[u8; 32]>,
    /// Signature over message
    pub signature: Option<[u8; 64]>,
}

impl HandshakeMessage {
    /// Create hello message
    pub fn hello(identity: &Identity) -> Self {
        Self {
            msg_type: HandshakeType::Hello,
            version: PROTOCOL_VERSION,
            sender_id: identity.device_id(),
            nonce: random_bytes(),
            public_identity: Some(identity.export_public()),
            ephemeral_public: None,
            signature: None,
        }
    }

    /// Create response message
    pub fn response(
        identity: &Identity,
        peer_nonce: &[u8; 32],
        ephemeral: &EncryptionKey,
    ) -> Self {
        let mut msg = Self {
            msg_type: HandshakeType::Response,
            version: PROTOCOL_VERSION,
            sender_id: identity.device_id(),
            nonce: random_bytes(),
            public_identity: Some(identity.export_public()),
            ephemeral_public: Some(*ephemeral.public_key().as_bytes()),
            signature: None,
        };

        // Sign the message including peer's nonce for binding
        let mut to_sign = msg.to_bytes_for_signing();
        let _ = to_sign.extend_from_slice(peer_nonce);
        msg.signature = Some(identity.sign(&to_sign));

        msg
    }

    /// Create confirmation message
    pub fn confirm(
        identity: &Identity,
        peer_nonce: &[u8; 32],
        ephemeral: &EncryptionKey,
    ) -> Self {
        let mut msg = Self {
            msg_type: HandshakeType::Confirm,
            version: PROTOCOL_VERSION,
            sender_id: identity.device_id(),
            nonce: random_bytes(),
            public_identity: None,
            ephemeral_public: Some(*ephemeral.public_key().as_bytes()),
            signature: None,
        };

        // Sign including peer's nonce
        let mut to_sign = msg.to_bytes_for_signing();
        let _ = to_sign.extend_from_slice(peer_nonce);
        msg.signature = Some(identity.sign(&to_sign));

        msg
    }

    /// Create rejection message
    pub fn reject(identity: &Identity, reason: u8) -> Self {
        let mut nonce: [u8; 32] = random_bytes();
        nonce[0] = reason; // Embed reason in first byte

        Self {
            msg_type: HandshakeType::Reject,
            version: PROTOCOL_VERSION,
            sender_id: identity.device_id(),
            nonce,
            public_identity: None,
            ephemeral_public: None,
            signature: None,
        }
    }

    /// Verify signature
    pub fn verify(&self, verifying_key: &VerifyingKey, their_nonce: &[u8; 32]) -> Result<()> {
        let signature = self.signature.as_ref()
            .ok_or(BitChatError::InvalidMessage)?;

        let mut to_verify = self.to_bytes_for_signing();
        let _ = to_verify.extend_from_slice(their_nonce);

        verifying_key.verify(&to_verify, signature)
    }

    /// Serialize for signing (excludes signature)
    fn to_bytes_for_signing(&self) -> Vec<u8, 256> {
        let mut bytes = Vec::new();

        let _ = bytes.extend_from_slice(&MAGIC);
        let _ = bytes.push(self.msg_type as u8);
        let _ = bytes.push(self.version);
        let _ = bytes.extend_from_slice(&self.sender_id);
        let _ = bytes.extend_from_slice(&self.nonce);

        if let Some(ref epk) = self.ephemeral_public {
            let _ = bytes.push(1);
            let _ = bytes.extend_from_slice(epk);
        } else {
            let _ = bytes.push(0);
        }

        bytes
    }

    /// Serialize complete message
    pub fn to_bytes(&self) -> Vec<u8, 512> {
        let mut bytes = Vec::new();

        let _ = bytes.extend_from_slice(&MAGIC);
        let _ = bytes.push(self.msg_type as u8);
        let _ = bytes.push(self.version);
        let _ = bytes.extend_from_slice(&self.sender_id);
        let _ = bytes.extend_from_slice(&self.nonce);

        // Public identity
        if let Some(ref pi) = self.public_identity {
            let _ = bytes.push(1);
            let _ = bytes.extend_from_slice(&pi.to_bytes());
        } else {
            let _ = bytes.push(0);
        }

        // Ephemeral public key
        if let Some(ref epk) = self.ephemeral_public {
            let _ = bytes.push(1);
            let _ = bytes.extend_from_slice(epk);
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
        if bytes.len() < 4 + 1 + 1 + 32 + 32 {
            return Err(BitChatError::InvalidMessage);
        }

        let mut offset = 0;

        // Check magic
        if &bytes[offset..offset + 4] != &MAGIC {
            return Err(BitChatError::InvalidMessage);
        }
        offset += 4;

        let msg_type = HandshakeType::from(bytes[offset]);
        offset += 1;

        let version = bytes[offset];
        offset += 1;

        let mut sender_id = [0u8; DEVICE_ID_LEN];
        sender_id.copy_from_slice(&bytes[offset..offset + DEVICE_ID_LEN]);
        offset += DEVICE_ID_LEN;

        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;

        // Public identity
        let public_identity = if offset < bytes.len() && bytes[offset] == 1 {
            offset += 1;
            if offset + 96 > bytes.len() {
                return Err(BitChatError::InvalidMessage);
            }
            let mut pi_bytes = [0u8; 96];
            pi_bytes.copy_from_slice(&bytes[offset..offset + 96]);
            offset += 96;
            Some(PublicIdentity::from_bytes(&pi_bytes))
        } else {
            if offset < bytes.len() { offset += 1; }
            None
        };

        // Ephemeral public key
        let ephemeral_public = if offset < bytes.len() && bytes[offset] == 1 {
            offset += 1;
            if offset + 32 > bytes.len() {
                return Err(BitChatError::InvalidMessage);
            }
            let mut epk = [0u8; 32];
            epk.copy_from_slice(&bytes[offset..offset + 32]);
            offset += 32;
            Some(epk)
        } else {
            if offset < bytes.len() { offset += 1; }
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
            msg_type,
            version,
            sender_id,
            nonce,
            public_identity,
            ephemeral_public,
            signature,
        })
    }
}

/// Handshake state machine
///
/// Security features:
/// - Mutual authentication
/// - Perfect forward secrecy
/// - Replay protection via nonces
/// - Timeout protection
pub struct Handshake {
    /// Current step
    step: HandshakeStep,
    /// Our identity
    identity: Identity,
    /// Our ephemeral key
    ephemeral: Option<EncryptionKey>,
    /// Our nonce
    our_nonce: [u8; 32],
    /// Peer's nonce
    peer_nonce: Option<[u8; 32]>,
    /// Peer's public identity
    peer_identity: Option<PublicIdentity>,
    /// Peer's ephemeral public key
    peer_ephemeral: Option<PublicEncryptionKey>,
    /// Derived session key
    session_key: Option<SessionKey>,
    /// Start timestamp for timeout
    start_time: u64,
    /// Timeout in milliseconds
    timeout_ms: u64,
}

impl Handshake {
    /// Create new handshake initiator
    pub fn new_initiator(identity: Identity, timeout_ms: u64) -> Self {
        Self {
            step: HandshakeStep::Initial,
            identity,
            ephemeral: Some(EncryptionKey::generate()),
            our_nonce: random_bytes(),
            peer_nonce: None,
            peer_identity: None,
            peer_ephemeral: None,
            session_key: None,
            start_time: 0, // Will be set when hello is sent
            timeout_ms,
        }
    }

    /// Create new handshake responder
    pub fn new_responder(identity: Identity, timeout_ms: u64) -> Self {
        Self {
            step: HandshakeStep::Initial,
            identity,
            ephemeral: Some(EncryptionKey::generate()),
            our_nonce: random_bytes(),
            peer_nonce: None,
            peer_identity: None,
            peer_ephemeral: None,
            session_key: None,
            start_time: 0,
            timeout_ms,
        }
    }

    /// Get current step
    pub fn step(&self) -> HandshakeStep {
        self.step
    }

    /// Generate hello message (initiator)
    pub fn generate_hello(&mut self, current_time: u64) -> HandshakeMessage {
        self.start_time = current_time;
        self.step = HandshakeStep::HelloSent;
        HandshakeMessage::hello(&self.identity)
    }

    /// Process received hello (responder)
    pub fn process_hello(
        &mut self,
        msg: &HandshakeMessage,
        current_time: u64,
    ) -> Result<HandshakeMessage> {
        if msg.msg_type != HandshakeType::Hello {
            return Err(BitChatError::InvalidMessage);
        }

        // Check version compatibility
        if msg.version > PROTOCOL_VERSION {
            return Err(BitChatError::InvalidMessage);
        }

        // Store peer info
        self.peer_nonce = Some(msg.nonce);
        self.peer_identity = msg.public_identity;
        self.start_time = current_time;

        // Generate response with our ephemeral key
        let ephemeral = self.ephemeral.as_ref()
            .ok_or(BitChatError::KeyExchangeFailed)?;

        let response = HandshakeMessage::response(
            &self.identity,
            &msg.nonce,
            ephemeral,
        );

        self.step = HandshakeStep::ResponseSent;
        Ok(response)
    }

    /// Process received response (initiator)
    pub fn process_response(
        &mut self,
        msg: &HandshakeMessage,
        current_time: u64,
    ) -> Result<HandshakeMessage> {
        if msg.msg_type != HandshakeType::Response {
            return Err(BitChatError::InvalidMessage);
        }

        // Check timeout
        if current_time - self.start_time > self.timeout_ms {
            self.step = HandshakeStep::Timeout;
            return Err(BitChatError::Timeout);
        }

        // Verify signature
        let peer_identity = msg.public_identity.as_ref()
            .ok_or(BitChatError::InvalidMessage)?;

        msg.verify(&peer_identity.verifying_key, &self.our_nonce)?;

        // Store peer info
        self.peer_nonce = Some(msg.nonce);
        self.peer_identity = Some(*peer_identity);

        if let Some(epk) = msg.ephemeral_public {
            self.peer_ephemeral = Some(PublicEncryptionKey::from_bytes(epk));
        }

        // Derive session key
        self.derive_session_key()?;

        // Generate confirmation
        let ephemeral = self.ephemeral.as_ref()
            .ok_or(BitChatError::KeyExchangeFailed)?;

        let confirm = HandshakeMessage::confirm(
            &self.identity,
            &msg.nonce,
            ephemeral,
        );

        self.step = HandshakeStep::Complete;
        Ok(confirm)
    }

    /// Process received confirmation (responder)
    pub fn process_confirm(
        &mut self,
        msg: &HandshakeMessage,
        current_time: u64,
    ) -> Result<()> {
        if msg.msg_type != HandshakeType::Confirm {
            return Err(BitChatError::InvalidMessage);
        }

        // Check timeout
        if current_time - self.start_time > self.timeout_ms {
            self.step = HandshakeStep::Timeout;
            return Err(BitChatError::Timeout);
        }

        // Verify signature
        let peer_identity = self.peer_identity.as_ref()
            .ok_or(BitChatError::InvalidMessage)?;

        msg.verify(&peer_identity.verifying_key, &self.our_nonce)?;

        // Store peer's ephemeral key
        if let Some(epk) = msg.ephemeral_public {
            self.peer_ephemeral = Some(PublicEncryptionKey::from_bytes(epk));
        }

        // Derive session key
        self.derive_session_key()?;

        self.step = HandshakeStep::Complete;
        Ok(())
    }

    /// Derive session key from DH exchange
    fn derive_session_key(&mut self) -> Result<()> {
        let ephemeral = self.ephemeral.as_ref()
            .ok_or(BitChatError::KeyExchangeFailed)?;
        let peer_ephemeral = self.peer_ephemeral.as_ref()
            .ok_or(BitChatError::KeyExchangeFailed)?;
        let peer_identity = self.peer_identity.as_ref()
            .ok_or(BitChatError::InvalidMessage)?;

        // Double DH for extra security
        let shared1 = ephemeral.diffie_hellman(peer_ephemeral);
        let shared2 = self.identity.encryption_key.diffie_hellman(&peer_identity.encryption_key);

        // Combine shared secrets
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(shared1.as_bytes());
        combined[32..].copy_from_slice(shared2.as_bytes());

        let session_key = SessionKey::derive(
            &crate::crypto::identity::SharedSecret { bytes: hash(&combined) },
            b"bitchat-session",
        );

        combined.zeroize();
        self.session_key = Some(session_key);
        Ok(())
    }

    /// Get derived session key (only after Complete)
    pub fn session_key(&self) -> Option<&SessionKey> {
        if self.step == HandshakeStep::Complete {
            self.session_key.as_ref()
        } else {
            None
        }
    }

    /// Get peer's public identity
    pub fn peer_identity(&self) -> Option<&PublicIdentity> {
        self.peer_identity.as_ref()
    }

    /// Check if handshake is complete
    pub fn is_complete(&self) -> bool {
        self.step == HandshakeStep::Complete
    }

    /// Check if handshake failed or timed out
    pub fn is_failed(&self) -> bool {
        matches!(self.step, HandshakeStep::Failed | HandshakeStep::Timeout)
    }
}

/// Rate limiter for handshake attempts
///
/// Security: Prevents brute-force attacks
pub struct HandshakeRateLimiter {
    /// Recent attempt timestamps
    attempts: heapless::Vec<u64, 16>,
    /// Maximum attempts per window
    max_attempts: usize,
    /// Window size in milliseconds
    window_ms: u64,
}

impl HandshakeRateLimiter {
    /// Create new rate limiter
    pub fn new(max_attempts: usize, window_ms: u64) -> Self {
        Self {
            attempts: heapless::Vec::new(),
            max_attempts,
            window_ms,
        }
    }

    /// Check if attempt is allowed
    pub fn check(&mut self, current_time: u64) -> bool {
        // Remove old attempts
        let cutoff = current_time.saturating_sub(self.window_ms);
        self.attempts.retain(|&t| t > cutoff);

        // Check limit
        if self.attempts.len() >= self.max_attempts {
            false
        } else {
            let _ = self.attempts.push(current_time);
            true
        }
    }

    /// Reset rate limiter
    pub fn reset(&mut self) {
        self.attempts.clear();
    }
}

// Make SharedSecret accessible for derive_session_key
mod private_shared {
    use zeroize::Zeroize;

    #[derive(Zeroize)]
    #[zeroize(drop)]
    pub struct SharedSecret {
        pub bytes: [u8; 32],
    }

    impl SharedSecret {
        pub fn as_bytes(&self) -> &[u8; 32] {
            &self.bytes
        }
    }
}

// Re-export for internal use
pub(crate) use private_shared::SharedSecret as InternalSharedSecret;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_flow() {
        let alice_identity = Identity::generate().unwrap();
        let bob_identity = Identity::generate().unwrap();

        let mut alice = Handshake::new_initiator(alice_identity, 5000);
        let mut bob = Handshake::new_responder(bob_identity, 5000);

        // Alice sends hello
        let hello = alice.generate_hello(0);
        assert_eq!(alice.step(), HandshakeStep::HelloSent);

        // Bob processes hello and sends response
        let response = bob.process_hello(&hello, 100).unwrap();
        assert_eq!(bob.step(), HandshakeStep::ResponseSent);

        // Alice processes response and sends confirm
        let confirm = alice.process_response(&response, 200).unwrap();
        assert_eq!(alice.step(), HandshakeStep::Complete);

        // Bob processes confirm
        bob.process_confirm(&confirm, 300).unwrap();
        assert_eq!(bob.step(), HandshakeStep::Complete);

        // Both should have session keys
        assert!(alice.session_key().is_some());
        assert!(bob.session_key().is_some());
    }

    #[test]
    fn test_handshake_timeout() {
        let alice_identity = Identity::generate().unwrap();
        let bob_identity = Identity::generate().unwrap();

        let mut alice = Handshake::new_initiator(alice_identity, 1000); // 1 second timeout
        let mut bob = Handshake::new_responder(bob_identity, 1000);

        let hello = alice.generate_hello(0);
        let response = bob.process_hello(&hello, 100).unwrap();

        // Process response after timeout
        let result = alice.process_response(&response, 2000);
        assert!(result.is_err());
        assert_eq!(alice.step(), HandshakeStep::Timeout);
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = HandshakeRateLimiter::new(3, 1000);

        assert!(limiter.check(0));
        assert!(limiter.check(100));
        assert!(limiter.check(200));
        assert!(!limiter.check(300)); // Exceeded

        // After window expires
        assert!(limiter.check(1500)); // Old attempts expired
    }
}
