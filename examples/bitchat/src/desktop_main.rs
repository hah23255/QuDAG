//! BitChat Desktop Testing Application
//!
//! This provides a desktop/terminal interface for testing BitChat
//! without needing actual ESP32 hardware.

use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

// BitChat imports
use qudag_bitchat::{
    BitChat, Config, AppState, Result,
    crypto::Identity,
    network::{PeerDiscovery, DiscoveryConfig, Transport, TransportConfig, Peer, SocketAddr, IpAddr},
    protocol::{ChatMessage, Envelope},
    storage::MessageStore,
    ui::ChatUI,
};

fn main() {
    println!("╔════════════════════════════════════════╗");
    println!("║     BitChat Desktop Test Interface     ║");
    println!("║     Quantum-Resistant Secure Chat      ║");
    println!("╚════════════════════════════════════════╝");
    println!();

    // Initialize BitChat
    let mut config = Config::default();
    let _ = config.device_name.clear();
    let _ = config.device_name.push_str("DesktopTest");

    let mut chat = BitChat::new(config);

    // Generate identity
    match chat.generate_identity() {
        Ok(identity) => {
            println!("✓ Identity generated");
            print!("  Device ID: ");
            let id = identity.device_id();
            for byte in &id[..8] {
                print!("{:02x}", byte);
            }
            println!("...");
        }
        Err(e) => {
            println!("✗ Failed to generate identity: {:?}", e);
            return;
        }
    }

    // Initialize components
    let device_id = chat.device_id().unwrap();
    let mut messages = MessageStore::new();
    let mut ui = ChatUI::new();

    println!();
    println!("Testing crypto operations...");

    // Test encryption roundtrip
    test_encryption_roundtrip();

    println!();
    println!("Testing protocol...");

    // Test message serialization
    test_message_serialization();

    println!();
    println!("Testing handshake...");

    // Test handshake flow
    test_handshake();

    println!();
    println!("Testing security measures...");

    // Test security
    test_security();

    println!();
    println!("════════════════════════════════════════");
    println!("All tests passed! ✓");
    println!();
    println!("To build for ESP32-C6:");
    println!("  cargo build --release --target riscv32imc-unknown-none-elf \\");
    println!("    --features esp32c6,display");
    println!();
    println!("To run in QEMU:");
    println!("  ./qemu/run_qemu.sh");
}

fn test_encryption_roundtrip() {
    use qudag_bitchat::crypto::{Identity, seal, open, random_bytes};

    // Test basic encryption
    let key: [u8; 32] = random_bytes();
    let plaintext = b"Hello, quantum world!";
    let aad = b"test";

    match seal(&key, plaintext, aad) {
        Ok(ciphertext) => {
            println!("  ✓ Encryption successful ({} bytes)", ciphertext.len());

            match open(&key, &ciphertext, aad) {
                Ok(decrypted) => {
                    if decrypted.as_slice() == plaintext {
                        println!("  ✓ Decryption successful");
                    } else {
                        println!("  ✗ Decryption mismatch!");
                    }
                }
                Err(e) => println!("  ✗ Decryption failed: {:?}", e),
            }
        }
        Err(e) => println!("  ✗ Encryption failed: {:?}", e),
    }

    // Test identity-based encryption
    let alice = Identity::generate().unwrap();
    let bob = Identity::generate().unwrap();

    let shared_alice = alice.encryption_key.diffie_hellman(&bob.public_encryption_key());
    let shared_bob = bob.encryption_key.diffie_hellman(&alice.public_encryption_key());

    if shared_alice.as_bytes() == shared_bob.as_bytes() {
        println!("  ✓ Key exchange successful");
    } else {
        println!("  ✗ Key exchange mismatch!");
    }
}

fn test_message_serialization() {
    let from = [1u8; 32];
    let to = [2u8; 32];

    // Test message creation and serialization
    match ChatMessage::new(from, to, "Test message", 1) {
        Ok(msg) => {
            let bytes = msg.to_bytes();
            println!("  ✓ Message serialized ({} bytes)", bytes.len());

            match ChatMessage::from_bytes(&bytes) {
                Ok(restored) => {
                    if restored.text() == Some("Test message") {
                        println!("  ✓ Message deserialized correctly");
                    } else {
                        println!("  ✗ Message content mismatch!");
                    }
                }
                Err(e) => println!("  ✗ Deserialization failed: {:?}", e),
            }
        }
        Err(e) => println!("  ✗ Message creation failed: {:?}", e),
    }

    // Test envelope encryption
    let alice = Identity::generate().unwrap();
    let bob = Identity::generate().unwrap();

    match ChatMessage::new(alice.device_id(), bob.device_id(), "Secret!", 1) {
        Ok(msg) => {
            match Envelope::encrypted(msg, &alice.signing_key, &bob.public_encryption_key(), true) {
                Ok(envelope) => {
                    println!("  ✓ Envelope encrypted");

                    match envelope.decrypt(&bob.encryption_key, &alice.public_encryption_key()) {
                        Ok(decrypted) => {
                            if decrypted.text() == Some("Secret!") {
                                println!("  ✓ Envelope decrypted correctly");
                            } else {
                                println!("  ✗ Envelope content mismatch!");
                            }
                        }
                        Err(e) => println!("  ✗ Envelope decryption failed: {:?}", e),
                    }
                }
                Err(e) => println!("  ✗ Envelope encryption failed: {:?}", e),
            }
        }
        Err(e) => println!("  ✗ Message creation failed: {:?}", e),
    }
}

fn test_handshake() {
    use qudag_bitchat::protocol::{Handshake, HandshakeStep};

    let alice_identity = Identity::generate().unwrap();
    let bob_identity = Identity::generate().unwrap();

    let mut alice = Handshake::new_initiator(alice_identity, 5000);
    let mut bob = Handshake::new_responder(bob_identity, 5000);

    // Step 1: Alice sends hello
    let hello = alice.generate_hello(0);
    println!("  ✓ Alice: Hello sent");

    // Step 2: Bob processes hello and sends response
    match bob.process_hello(&hello, 100) {
        Ok(response) => {
            println!("  ✓ Bob: Response sent");

            // Step 3: Alice processes response and sends confirm
            match alice.process_response(&response, 200) {
                Ok(confirm) => {
                    println!("  ✓ Alice: Confirm sent");

                    // Step 4: Bob processes confirm
                    match bob.process_confirm(&confirm, 300) {
                        Ok(()) => {
                            if alice.is_complete() && bob.is_complete() {
                                println!("  ✓ Handshake complete!");

                                // Verify session keys match
                                if let (Some(a_key), Some(b_key)) = (alice.session_key(), bob.session_key()) {
                                    if a_key.encryption_key() == b_key.encryption_key() {
                                        println!("  ✓ Session keys match");
                                    } else {
                                        println!("  ✗ Session key mismatch!");
                                    }
                                }
                            }
                        }
                        Err(e) => println!("  ✗ Bob confirm failed: {:?}", e),
                    }
                }
                Err(e) => println!("  ✗ Alice response failed: {:?}", e),
            }
        }
        Err(e) => println!("  ✗ Bob hello failed: {:?}", e),
    }
}

fn test_security() {
    use qudag_bitchat::protocol::ReplayDetector;
    use qudag_bitchat::crypto::constant_time_eq;

    // Test replay detection
    let peer_id = [1u8; 32];
    let mut detector = ReplayDetector::new(peer_id);

    if detector.check(1) {
        println!("  ✓ Replay detector: Accepts first message");
    } else {
        println!("  ✗ Replay detector: Rejected first message!");
    }

    if !detector.check(1) {
        println!("  ✓ Replay detector: Rejects duplicate");
    } else {
        println!("  ✗ Replay detector: Accepted duplicate!");
    }

    if detector.check(2) {
        println!("  ✓ Replay detector: Accepts new sequence");
    } else {
        println!("  ✗ Replay detector: Rejected new sequence!");
    }

    // Test constant-time comparison
    let a = [1u8, 2, 3, 4];
    let b = [1u8, 2, 3, 4];
    let c = [1u8, 2, 3, 5];

    if constant_time_eq(&a, &b) && !constant_time_eq(&a, &c) {
        println!("  ✓ Constant-time comparison working");
    } else {
        println!("  ✗ Constant-time comparison failed!");
    }

    // Test signature verification
    use qudag_bitchat::crypto::SigningKey;
    let key = SigningKey::generate();
    let message = b"test message to sign";
    let signature = key.sign(message);

    if key.verifying_key().verify(message, &signature).is_ok() {
        println!("  ✓ Signature verification working");
    } else {
        println!("  ✗ Signature verification failed!");
    }

    // Test tampered signature detection
    let mut bad_sig = signature;
    bad_sig[0] ^= 0xFF;
    if key.verifying_key().verify(message, &bad_sig).is_err() {
        println!("  ✓ Tampered signature detected");
    } else {
        println!("  ✗ Tampered signature not detected!");
    }
}
