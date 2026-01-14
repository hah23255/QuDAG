# BitChat - Quantum-Resistant Secure Messaging for ESP32

<p align="center">
  <img src="https://img.shields.io/badge/Platform-ESP32--C6-blue" alt="ESP32-C6">
  <img src="https://img.shields.io/badge/Crypto-Quantum--Resistant-green" alt="Quantum-Resistant">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="MIT License">
</p>

BitChat is a peer-to-peer, quantum-resistant secure messaging application designed for embedded devices, specifically targeting the ESP32-C6 with the Waveshare 1.47" LCD display.

## Features

- **Quantum-Resistant Cryptography**: Uses X25519 + ChaCha20-Poly1305 (upgradeable to ML-KEM/ML-DSA)
- **Peer-to-Peer Communication**: Direct device-to-device messaging over WiFi
- **Perfect Forward Secrecy**: Ephemeral keys for each session
- **Privacy-Preserving**: Traffic padding and replay protection
- **Embedded-Optimized**: Runs on resource-constrained devices with ~32KB RAM
- **Beautiful UI**: Full-color display interface with touch/button navigation

## How It Works

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        BitChat App                          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Chat UI   │  │  Messages   │  │    Peer Manager     │ │
│  │  (Display)  │  │   (Store)   │  │    (Discovery)      │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐   │
│  │               Protocol Layer                         │   │
│  │  • Message Serialization  • Handshake Protocol      │   │
│  │  • Envelope Encryption    • Replay Detection        │   │
│  └─────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐   │
│  │               Crypto Layer                           │   │
│  │  • X25519 Key Exchange    • ChaCha20-Poly1305      │   │
│  │  • Ed25519 Signatures     • BLAKE3/SHA-256 Hash    │   │
│  └─────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐   │
│  │               Network Layer                          │   │
│  │  • UDP Discovery          • TCP Messaging           │   │
│  │  • WiFi Management        • Connection Pooling      │   │
│  └─────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│                     ESP32-C6 Hardware                       │
│  • WiFi 6 (802.11ax)  • RISC-V Core  • ST7789 Display     │
└─────────────────────────────────────────────────────────────┘
```

### Security Model

1. **Identity Generation**: Each device generates a unique identity consisting of:
   - Ed25519 signing keypair for authentication
   - X25519 encryption keypair for key exchange
   - Device ID = SHA-256(public_keys)

2. **Peer Discovery**: Devices announce themselves via UDP broadcast:
   - Announcements include public identity
   - Nonce-based freshness to prevent replay
   - Rate limiting against flooding

3. **Handshake Protocol**: Mutual authentication with forward secrecy:
   ```
   Alice                                  Bob
     │                                     │
     │──────── Hello + PublicKey ─────────>│
     │                                     │
     │<─────── Response + Signature ───────│
     │                                     │
     │──────── Confirm + Signature ───────>│
     │                                     │
     │         [Session Established]       │
   ```

4. **Message Encryption**: Every message is encrypted with:
   - Ephemeral X25519 key exchange (forward secrecy)
   - ChaCha20-Poly1305 authenticated encryption
   - Optional traffic padding for privacy

5. **Replay Protection**: Sliding window sequence numbers prevent message replay

## Supported Devices

### Primary Target: ESP32-C6 + Waveshare 1.47" LCD

| Component | Specification |
|-----------|--------------|
| **MCU** | ESP32-C6 (RISC-V, 160MHz) |
| **WiFi** | WiFi 6 (802.11ax) |
| **Bluetooth** | BLE 5.0 |
| **Display** | 1.47" IPS LCD (172x320, ST7789) |
| **RAM** | 512KB SRAM |
| **Flash** | 4MB |

**Waveshare SKU**: ESP32-C6 1.47Inch LCD Screen WiFi 6 & Bluetooth Display Type-C Development Board

### Compatible Devices

| Device | WiFi | Display | Notes |
|--------|------|---------|-------|
| ESP32-C6 DevKit | WiFi 6 | External | Primary development board |
| ESP32-C3 | WiFi 4 | External | QEMU-testable |
| ESP32-S3 | WiFi 4 | External | Xtensa architecture |
| M5Stack Core2 | WiFi 4 | Built-in | Different display driver |
| LILYGO T-Display S3 | WiFi 4 | ST7789 | Alternative display board |

### Display Compatibility

The UI is designed for the Waveshare 1.47" ST7789 display but can work with:

- Any ST7789-based display (adjust resolution in config)
- 240x320 standard displays
- 135x240 compact displays (limited UI)

## Getting Started

### Prerequisites

1. **Rust toolchain** with RISC-V target:
   ```bash
   rustup target add riscv32imc-unknown-none-elf
   ```

2. **ESP-IDF toolchain** (optional, for WiFi):
   ```bash
   # Install espup for ESP32 development
   cargo install espup
   espup install
   ```

3. **espflash** for flashing:
   ```bash
   cargo install espflash
   ```

### Building

**Desktop Testing** (recommended for development):
```bash
cargo build --features desktop,std
cargo run --features desktop,std
```

**ESP32-C6 Build**:
```bash
cargo build --release --target riscv32imc-unknown-none-elf --features esp32c6,display
```

**ESP32-C3 Build** (QEMU-compatible):
```bash
cargo build --release --target riscv32imc-unknown-none-elf --features esp32c3
```

### Flashing to Hardware

```bash
# Flash to ESP32-C6
espflash flash --monitor target/riscv32imc-unknown-none-elf/release/bitchat-esp32

# Or with specific port
espflash flash --monitor --port /dev/ttyUSB0 target/riscv32imc-unknown-none-elf/release/bitchat-esp32
```

### Running Tests

```bash
# Unit tests
cargo test --features std

# Security tests
cargo test --features std -- security

# QEMU testing (interactive)
./qemu/run_qemu.sh

# QEMU testing (automated)
./qemu/run_qemu.sh --test
./qemu/run_qemu.sh --security
```

## User Interface

### Screen Layout (172x320)

```
┌────────────────────┐
│ ⚡ BitChat   12:34 │ ← Status Bar (WiFi, time, battery)
├────────────────────┤
│                    │
│   Chat Messages    │ ← Message List (scrollable)
│                    │
│  ┌──────────────┐  │
│  │ Hi there!    │  │ ← Incoming bubble
│  └──────────────┘  │
│                    │
│  ┌──────────────┐  │
│  │ Hello! 👋   │  │ ← Outgoing bubble
│  └──────────────┘  │
│                    │
├────────────────────┤
│ [Type a message..] │ ← Input field
└────────────────────┘
```

### Navigation

| Input | Action |
|-------|--------|
| UP/DOWN | Navigate list |
| SELECT | Open chat / Send |
| BACK | Return to previous screen |
| LONG PRESS | Settings menu |

### Screens

1. **Splash Screen**: BitChat logo and initialization
2. **Chat List**: Recent conversations with unread counts
3. **Chat View**: Message history with a peer
4. **Peer List**: Discovered devices
5. **Settings**: WiFi config, display settings

## Configuration

### WiFi Setup

Edit `src/main.rs` or use the settings screen:

```rust
let mut config = Config::default();
config.wifi_ssid.push_str("YourNetworkName").unwrap();
config.wifi_password.push_str("YourPassword").unwrap();
config.wifi6_enabled = true; // ESP32-C6 only
```

### Display Settings

```rust
use qudag_bitchat::ui::{DisplayConfig, WavesharePins};

// Waveshare 1.47" ESP32-C6
let display_config = DisplayConfig::waveshare_147();
let pins = WavesharePins::waveshare_c6();
```

## Security Considerations

### Implemented Security Features

| Feature | Status | Description |
|---------|--------|-------------|
| Authenticated Encryption | ✅ | ChaCha20-Poly1305 AEAD |
| Key Exchange | ✅ | X25519 Diffie-Hellman |
| Digital Signatures | ✅ | Ed25519 |
| Forward Secrecy | ✅ | Ephemeral keys per session |
| Replay Protection | ✅ | Sequence number windowing |
| Traffic Padding | ✅ | Message size obfuscation |
| Constant-Time Crypto | ✅ | Timing attack resistance |
| Zeroization | ✅ | Sensitive data cleared |
| Rate Limiting | ✅ | Handshake flood protection |
| Identity Encryption | ✅ | Password-protected storage |

### Security Hardening

1. **Timing Attacks**: All cryptographic comparisons use constant-time operations
2. **Memory Safety**: `#![deny(unsafe_code)]` in crypto module
3. **Key Zeroization**: All secret keys implement `Zeroize` and are cleared on drop
4. **Input Validation**: All network input is validated before processing
5. **Buffer Overflow**: Fixed-size `heapless` buffers prevent overflow

### Quantum Resistance Roadmap

Current cryptography (X25519, Ed25519) is secure against classical computers but vulnerable to quantum attacks. The architecture supports upgrading to:

- **ML-KEM-768** (CRYSTALS-Kyber): Lattice-based key encapsulation
- **ML-DSA-65** (CRYSTALS-Dilithium): Lattice-based signatures
- **HQC**: Code-based backup encryption

## API Reference

### Core Types

```rust
// Main application
let mut chat = BitChat::new(Config::default());
chat.generate_identity()?;

// Send message
chat.queue_message(peer_id, "Hello!")?;

// Receive message
let message = chat.receive_envelope(envelope)?;
```

### Crypto Operations

```rust
use qudag_bitchat::crypto::{Identity, seal, open};

// Generate identity
let identity = Identity::generate()?;

// Encrypt data
let ciphertext = seal(&key, plaintext, &aad)?;

// Decrypt data
let plaintext = open(&key, &ciphertext, &aad)?;
```

### Network Discovery

```rust
use qudag_bitchat::network::{PeerDiscovery, Announcement};

let mut discovery = PeerDiscovery::new(config, device_id);
discovery.start();

// Create announcement
let announcement = discovery.create_announce(port, timestamp)?;

// Process received announcement
if let Some(ann) = discovery.process_announcement(&received, time) {
    // New peer discovered
}
```

## Troubleshooting

### Common Issues

**Build fails with "target not found"**
```bash
rustup target add riscv32imc-unknown-none-elf
```

**Flash fails with permission error**
```bash
# Linux: Add user to dialout group
sudo usermod -a -G dialout $USER
# Then logout and login again
```

**Display shows nothing**
- Check SPI connections
- Verify pin configuration matches your board
- Try `inverted: true` in DisplayConfig

**WiFi won't connect**
- Ensure ESP32-C6 (not C3) for WiFi 6
- Check SSID/password
- Try moving closer to AP

### Debug Output

Enable serial output:
```rust
// ESP32
esp_println::println!("Debug: {}", value);
```

## Contributing

Contributions are welcome! Please focus on:

1. **Security improvements**: Additional hardening
2. **Device support**: New ESP32 variants
3. **UI enhancements**: Better user experience
4. **Documentation**: Examples and guides

## License

MIT License - see [LICENSE](../../LICENSE) for details.

## Acknowledgments

- [QuDAG](https://github.com/ruvnet/QuDAG) - Parent project
- [esp-hal](https://github.com/esp-rs/esp-hal) - ESP32 HAL
- [embedded-graphics](https://github.com/embedded-graphics/embedded-graphics) - Graphics library
- [RustCrypto](https://github.com/RustCrypto) - Cryptographic primitives

---

<p align="center">
  <b>BitChat</b> - Secure messaging for the quantum era
</p>
