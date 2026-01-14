//! Authenticated encryption for BitChat
//!
//! Uses ChaCha20-Poly1305 for symmetric encryption with:
//! - 256-bit key
//! - 96-bit nonce
//! - 128-bit authentication tag
//! - Optional traffic padding for privacy

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce as ChachaNonce,
    aead::{Aead, KeyInit},
};
use chacha20poly1305::aead::generic_array::GenericArray;
use zeroize::Zeroize;

use super::{random_bytes, hash};
use crate::{BitChatError, Result, MAX_MESSAGE_SIZE};

/// Nonce for ChaCha20-Poly1305 (96 bits)
pub type Nonce = [u8; 12];

/// Authentication tag size
pub const TAG_SIZE: usize = 16;

/// Maximum padding size for traffic obfuscation
pub const MAX_PADDING: usize = 256;

/// Generate random nonce
pub fn generate_nonce() -> Nonce {
    random_bytes()
}

/// Encrypt data with ChaCha20-Poly1305
///
/// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
pub fn seal(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<heapless::Vec<u8, { MAX_MESSAGE_SIZE + 12 + TAG_SIZE }>> {
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
    let nonce = generate_nonce();
    let nonce_array = ChachaNonce::from_slice(&nonce);

    let ciphertext = cipher
        .encrypt(nonce_array, plaintext)
        .map_err(|_| BitChatError::EncryptionFailed)?;

    let mut result = heapless::Vec::new();
    result.extend_from_slice(&nonce).map_err(|_| BitChatError::BufferOverflow)?;
    result.extend_from_slice(&ciphertext).map_err(|_| BitChatError::BufferOverflow)?;

    Ok(result)
}

/// Decrypt data with ChaCha20-Poly1305
///
/// Input: nonce (12 bytes) || ciphertext || tag (16 bytes)
pub fn open(key: &[u8; 32], ciphertext: &[u8], aad: &[u8]) -> Result<heapless::Vec<u8, MAX_MESSAGE_SIZE>> {
    if ciphertext.len() < 12 + TAG_SIZE {
        return Err(BitChatError::InvalidMessage);
    }

    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
    let nonce = ChachaNonce::from_slice(&ciphertext[..12]);

    let plaintext = cipher
        .decrypt(nonce, &ciphertext[12..])
        .map_err(|_| BitChatError::DecryptionFailed)?;

    let mut result = heapless::Vec::new();
    result.extend_from_slice(&plaintext).map_err(|_| BitChatError::BufferOverflow)?;

    Ok(result)
}

/// Encrypt with traffic padding for obfuscation
///
/// Pads message to nearest power of 2 (up to MAX_PADDING) to resist
/// traffic analysis attacks.
pub fn seal_with_padding(
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
    enable_padding: bool,
) -> Result<heapless::Vec<u8, { MAX_MESSAGE_SIZE + MAX_PADDING + 12 + TAG_SIZE }>> {
    let padded = if enable_padding {
        pad_message(plaintext)?
    } else {
        let mut padded = heapless::Vec::<u8, { MAX_MESSAGE_SIZE + MAX_PADDING }>::new();
        // Add length prefix (2 bytes)
        let len = plaintext.len() as u16;
        padded.extend_from_slice(&len.to_le_bytes()).map_err(|_| BitChatError::BufferOverflow)?;
        padded.extend_from_slice(plaintext).map_err(|_| BitChatError::BufferOverflow)?;
        padded
    };

    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
    let nonce = generate_nonce();
    let nonce_array = ChachaNonce::from_slice(&nonce);

    let ciphertext = cipher
        .encrypt(nonce_array, padded.as_slice())
        .map_err(|_| BitChatError::EncryptionFailed)?;

    let mut result = heapless::Vec::new();
    result.extend_from_slice(&nonce).map_err(|_| BitChatError::BufferOverflow)?;
    result.extend_from_slice(&ciphertext).map_err(|_| BitChatError::BufferOverflow)?;

    Ok(result)
}

/// Decrypt with padding removal
pub fn open_with_padding(
    key: &[u8; 32],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<heapless::Vec<u8, MAX_MESSAGE_SIZE>> {
    if ciphertext.len() < 12 + TAG_SIZE + 2 {
        return Err(BitChatError::InvalidMessage);
    }

    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
    let nonce = ChachaNonce::from_slice(&ciphertext[..12]);

    let padded = cipher
        .decrypt(nonce, &ciphertext[12..])
        .map_err(|_| BitChatError::DecryptionFailed)?;

    // Extract original length
    if padded.len() < 2 {
        return Err(BitChatError::InvalidMessage);
    }

    let len = u16::from_le_bytes([padded[0], padded[1]]) as usize;
    if len > padded.len() - 2 {
        return Err(BitChatError::InvalidMessage);
    }

    let mut result = heapless::Vec::new();
    result.extend_from_slice(&padded[2..2 + len]).map_err(|_| BitChatError::BufferOverflow)?;

    Ok(result)
}

/// Pad message to nearest power of 2
fn pad_message(plaintext: &[u8]) -> Result<heapless::Vec<u8, { MAX_MESSAGE_SIZE + MAX_PADDING }>> {
    let actual_len = plaintext.len();
    let with_header = actual_len + 2; // 2 bytes for length

    // Find next power of 2, minimum 32 bytes
    let target_len = if with_header <= 32 {
        32
    } else if with_header <= 64 {
        64
    } else if with_header <= 128 {
        128
    } else if with_header <= 256 {
        256
    } else if with_header <= 512 {
        512
    } else if with_header <= 1024 {
        1024
    } else if with_header <= 2048 {
        2048
    } else {
        4096
    };

    let padding_len = target_len - with_header;

    let mut padded = heapless::Vec::new();

    // Add length prefix
    let len_bytes = (actual_len as u16).to_le_bytes();
    padded.extend_from_slice(&len_bytes).map_err(|_| BitChatError::BufferOverflow)?;

    // Add plaintext
    padded.extend_from_slice(plaintext).map_err(|_| BitChatError::BufferOverflow)?;

    // Add random padding
    for _ in 0..padding_len {
        let random_byte: [u8; 1] = random_bytes();
        padded.push(random_byte[0]).map_err(|_| BitChatError::BufferOverflow)?;
    }

    Ok(padded)
}

/// Key derivation from password (Argon2-lite for embedded)
///
/// Uses iterated SHA-256 with salt for memory-constrained devices.
/// NOT as secure as full Argon2, but suitable for embedded.
pub fn derive_key_from_password(password: &[u8], salt: &[u8; 16], iterations: u32) -> [u8; 32] {
    let mut key = [0u8; 32];

    // Initial hash: password || salt
    let mut combined = heapless::Vec::<u8, 256>::new();
    let _ = combined.extend_from_slice(password);
    let _ = combined.extend_from_slice(salt);
    key.copy_from_slice(&hash(combined.as_slice()));

    // Iterate
    for i in 0..iterations {
        combined.clear();
        let _ = combined.extend_from_slice(&key);
        let _ = combined.extend_from_slice(&i.to_le_bytes());
        let _ = combined.extend_from_slice(salt);
        key.copy_from_slice(&hash(combined.as_slice()));
    }

    combined.zeroize();
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_open() {
        let key: [u8; 32] = random_bytes();
        let plaintext = b"Hello, BitChat!";
        let aad = b"associated data";

        let ciphertext = seal(&key, plaintext, aad).unwrap();
        let decrypted = open(&key, &ciphertext, aad).unwrap();

        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_seal_open_with_padding() {
        let key: [u8; 32] = random_bytes();
        let plaintext = b"Hello, BitChat!";
        let aad = b"associated data";

        let ciphertext = seal_with_padding(&key, plaintext, aad, true).unwrap();
        let decrypted = open_with_padding(&key, &ciphertext, aad).unwrap();

        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_padding_sizes() {
        let key: [u8; 32] = random_bytes();
        let aad = b"";

        // Short message should be padded to 32 bytes
        let short = b"Hi";
        let ct_short = seal_with_padding(&key, short, aad, true).unwrap();

        // Longer message should be padded to larger size
        let long = b"This is a longer message that should be padded differently";
        let ct_long = seal_with_padding(&key, long, aad, true).unwrap();

        // Both should decrypt correctly
        let dec_short = open_with_padding(&key, &ct_short, aad).unwrap();
        let dec_long = open_with_padding(&key, &ct_long, aad).unwrap();

        assert_eq!(dec_short.as_slice(), short);
        assert_eq!(dec_long.as_slice(), long);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key: [u8; 32] = random_bytes();
        let plaintext = b"Hello, BitChat!";
        let aad = b"associated data";

        let mut ciphertext = seal(&key, plaintext, aad).unwrap();

        // Tamper with ciphertext
        if let Some(byte) = ciphertext.get_mut(20) {
            *byte ^= 0xFF;
        }

        let result = open(&key, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_derivation() {
        let password = b"my_secure_password";
        let salt: [u8; 16] = random_bytes();

        let key1 = derive_key_from_password(password, &salt, 1000);
        let key2 = derive_key_from_password(password, &salt, 1000);

        assert_eq!(key1, key2);

        // Different salt should give different key
        let salt2: [u8; 16] = random_bytes();
        let key3 = derive_key_from_password(password, &salt2, 1000);

        assert_ne!(key1, key3);
    }
}
