//! Performance benchmarks for BitChat on ESP32
//!
//! Benchmarks critical operations to ensure they meet real-time requirements
//! on resource-constrained embedded devices.

use core::time::Duration;

/// Benchmark results structure
#[derive(Debug, Clone, Copy)]
pub struct BenchResult {
    /// Operation name
    pub name: &'static str,
    /// Number of iterations
    pub iterations: u32,
    /// Total time in microseconds
    pub total_us: u64,
    /// Average time per operation in microseconds
    pub avg_us: u64,
    /// Operations per second
    pub ops_per_sec: u32,
    /// Memory usage in bytes (if tracked)
    pub memory_bytes: Option<usize>,
}

impl BenchResult {
    /// Check if operation meets target latency
    pub fn meets_target(&self, target_us: u64) -> bool {
        self.avg_us <= target_us
    }

    /// Format as string for display
    #[cfg(feature = "std")]
    pub fn to_string(&self) -> String {
        format!(
            "{}: {} ops in {}us (avg: {}us, {} ops/sec)",
            self.name, self.iterations, self.total_us, self.avg_us, self.ops_per_sec
        )
    }
}

/// Target latencies for ESP32-C6 @ 160MHz
pub mod targets {
    /// SHA-256 hash (32 bytes) - target: 50us
    pub const HASH_32B_US: u64 = 50;

    /// SHA-256 hash (1KB) - target: 500us
    pub const HASH_1KB_US: u64 = 500;

    /// X25519 key exchange - target: 5ms
    pub const X25519_US: u64 = 5000;

    /// Ed25519 sign - target: 5ms
    pub const ED25519_SIGN_US: u64 = 5000;

    /// Ed25519 verify - target: 8ms
    pub const ED25519_VERIFY_US: u64 = 8000;

    /// ChaCha20-Poly1305 encrypt (256 bytes) - target: 100us
    pub const ENCRYPT_256B_US: u64 = 100;

    /// ChaCha20-Poly1305 decrypt (256 bytes) - target: 100us
    pub const DECRYPT_256B_US: u64 = 100;

    /// Message serialization - target: 50us
    pub const MSG_SERIALIZE_US: u64 = 50;

    /// Message deserialization - target: 50us
    pub const MSG_DESERIALIZE_US: u64 = 50;

    /// Full message encrypt + send prep - target: 10ms
    pub const MSG_ENCRYPT_FULL_US: u64 = 10000;
}

/// Memory budget for ESP32 (32KB heap)
pub mod memory {
    /// Maximum message buffer size
    pub const MAX_MSG_BUFFER: usize = 4096;

    /// Maximum peer count in memory
    pub const MAX_PEERS: usize = 16;

    /// Message history per peer
    pub const MSG_HISTORY_PER_PEER: usize = 32;

    /// Crypto key storage
    pub const KEY_STORAGE: usize = 512;

    /// UI framebuffer (if double-buffered)
    pub const UI_BUFFER: usize = 0; // ST7789 is direct write

    /// Network buffers
    pub const NET_BUFFERS: usize = 8192;

    /// Total estimated heap usage
    pub const TOTAL_ESTIMATE: usize =
        MAX_MSG_BUFFER + (MAX_PEERS * 256) + (MAX_PEERS * MSG_HISTORY_PER_PEER * 128)
            + KEY_STORAGE + NET_BUFFERS;
}

/// Optimized crypto operations for ESP32
pub mod optimized {
    use sha2::{Sha256, Digest};

    /// Optimized hash for small inputs (avoids allocation)
    #[inline(always)]
    pub fn hash_small(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Optimized hash for message payloads with streaming
    pub fn hash_streaming<I: Iterator<Item = u8>>(iter: I, len_hint: usize) -> [u8; 32] {
        let mut hasher = Sha256::new();

        // Process in chunks for cache efficiency
        let mut buffer = [0u8; 64];
        let mut buf_pos = 0;

        for byte in iter {
            buffer[buf_pos] = byte;
            buf_pos += 1;

            if buf_pos == 64 {
                hasher.update(&buffer);
                buf_pos = 0;
            }
        }

        if buf_pos > 0 {
            hasher.update(&buffer[..buf_pos]);
        }

        hasher.finalize().into()
    }

    /// Pre-computed lookup table for hex encoding
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    /// Fast hex encoding without allocation
    #[inline]
    pub fn to_hex_byte(byte: u8) -> (u8, u8) {
        (
            HEX_CHARS[(byte >> 4) as usize],
            HEX_CHARS[(byte & 0x0f) as usize],
        )
    }
}

/// ESP32-specific optimizations
pub mod esp32 {
    /// CPU frequency in MHz
    pub const CPU_FREQ_MHZ: u32 = 160;

    /// Cycles per microsecond
    pub const CYCLES_PER_US: u32 = CPU_FREQ_MHZ;

    /// Estimate cycles for operation
    #[inline]
    pub fn estimate_cycles(us: u64) -> u64 {
        us * CYCLES_PER_US as u64
    }

    /// SPI clock divider for ST7789 display
    /// 80MHz SPI / 2 = 40MHz effective
    pub const SPI_DIVIDER: u8 = 2;

    /// DMA threshold - use DMA for transfers larger than this
    pub const DMA_THRESHOLD: usize = 64;

    /// WiFi power save modes
    #[derive(Debug, Clone, Copy)]
    pub enum PowerSaveMode {
        /// No power save (maximum throughput)
        None,
        /// Light sleep between beacons
        LightSleep,
        /// Modem sleep when idle
        ModemSleep,
    }

    /// Recommended power save based on activity
    pub fn recommended_power_save(is_chatting: bool, battery_level: Option<u8>) -> PowerSaveMode {
        match (is_chatting, battery_level) {
            (true, _) => PowerSaveMode::None, // Full power when chatting
            (false, Some(level)) if level < 20 => PowerSaveMode::ModemSleep, // Low battery
            (false, _) => PowerSaveMode::LightSleep, // Default idle
        }
    }
}

/// Benchmark runner
pub struct Benchmarker {
    /// Results collected
    results: heapless::Vec<BenchResult, 32>,
}

impl Benchmarker {
    /// Create new benchmarker
    pub fn new() -> Self {
        Self {
            results: heapless::Vec::new(),
        }
    }

    /// Run a benchmark
    pub fn run<F>(&mut self, name: &'static str, iterations: u32, mut f: F)
    where
        F: FnMut(),
    {
        // Warm-up
        for _ in 0..10 {
            f();
        }

        // Get start time
        let start = get_time_us();

        // Run benchmark
        for _ in 0..iterations {
            f();
        }

        // Get end time
        let end = get_time_us();
        let total_us = end - start;
        let avg_us = total_us / iterations as u64;
        let ops_per_sec = if avg_us > 0 {
            (1_000_000 / avg_us) as u32
        } else {
            u32::MAX
        };

        let result = BenchResult {
            name,
            iterations,
            total_us,
            avg_us,
            ops_per_sec,
            memory_bytes: None,
        };

        let _ = self.results.push(result);
    }

    /// Get results
    pub fn results(&self) -> &[BenchResult] {
        &self.results
    }

    /// Check if all benchmarks meet targets
    pub fn all_pass(&self, targets: &[(&str, u64)]) -> bool {
        for (name, target) in targets {
            if let Some(result) = self.results.iter().find(|r| r.name == *name) {
                if !result.meets_target(*target) {
                    return false;
                }
            }
        }
        true
    }
}

/// Get current time in microseconds
#[cfg(feature = "std")]
fn get_time_us() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

#[cfg(not(feature = "std"))]
fn get_time_us() -> u64 {
    // ESP32: Use hardware timer
    // This is a placeholder - actual implementation uses esp-hal timer
    0
}

/// Run all benchmarks
#[cfg(feature = "std")]
pub fn run_all_benchmarks() -> Benchmarker {
    use sha2::{Sha256, Digest};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit}};

    let mut bench = Benchmarker::new();

    // Hash benchmarks
    let data_32 = [0u8; 32];
    bench.run("hash_32b", 10000, || {
        let _ = Sha256::digest(&data_32);
    });

    let data_1k = [0u8; 1024];
    bench.run("hash_1kb", 1000, || {
        let _ = Sha256::digest(&data_1k);
    });

    // Encryption benchmarks
    let key = Key::from_slice(&[0x42u8; 32]);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(&[0u8; 12]);
    let plaintext = [0u8; 256];

    bench.run("encrypt_256b", 1000, || {
        let _ = cipher.encrypt(nonce, plaintext.as_ref());
    });

    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
    bench.run("decrypt_256b", 1000, || {
        let _ = cipher.decrypt(nonce, ciphertext.as_ref());
    });

    // Key exchange benchmarks
    use x25519_dalek::{StaticSecret, PublicKey};

    let secret = StaticSecret::random_from_rng(rand::thread_rng());
    let public = PublicKey::from([0x42u8; 32]);

    bench.run("x25519_dh", 100, || {
        let _ = secret.diffie_hellman(&public);
    });

    // Signature benchmarks
    use ed25519_dalek::{SigningKey, Signer, Verifier};

    let signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
    let message = [0u8; 64];

    bench.run("ed25519_sign", 100, || {
        let _ = signing_key.sign(&message);
    });

    let signature = signing_key.sign(&message);
    let verifying_key = signing_key.verifying_key();

    bench.run("ed25519_verify", 100, || {
        let _ = verifying_key.verify(&message, &signature);
    });

    bench
}

/// Print benchmark report
#[cfg(feature = "std")]
pub fn print_report(bench: &Benchmarker) {
    println!("\n╔═══════════════════════════════════════════════════════════╗");
    println!("║            BitChat ESP32 Benchmark Results                ║");
    println!("╠═══════════════════════════════════════════════════════════╣");

    let targets = [
        ("hash_32b", targets::HASH_32B_US),
        ("hash_1kb", targets::HASH_1KB_US),
        ("encrypt_256b", targets::ENCRYPT_256B_US),
        ("decrypt_256b", targets::DECRYPT_256B_US),
        ("x25519_dh", targets::X25519_US),
        ("ed25519_sign", targets::ED25519_SIGN_US),
        ("ed25519_verify", targets::ED25519_VERIFY_US),
    ];

    for result in bench.results() {
        let target = targets.iter().find(|(n, _)| *n == result.name).map(|(_, t)| *t);
        let status = if let Some(t) = target {
            if result.meets_target(t) { "✓ PASS" } else { "✗ FAIL" }
        } else {
            "  ----"
        };

        println!(
            "║ {:<20} {:>8}us avg {:>8} ops/s {:>6} ║",
            result.name,
            result.avg_us,
            result.ops_per_sec,
            status
        );
    }

    println!("╠═══════════════════════════════════════════════════════════╣");

    // Memory estimate
    println!("║ Memory Budget Estimate:                                   ║");
    println!("║   Message buffers:  {:>6} bytes                          ║", memory::MAX_MSG_BUFFER);
    println!("║   Peer storage:     {:>6} bytes                          ║", memory::MAX_PEERS * 256);
    println!("║   Message history:  {:>6} bytes                          ║", memory::MAX_PEERS * memory::MSG_HISTORY_PER_PEER * 128);
    println!("║   Network buffers:  {:>6} bytes                          ║", memory::NET_BUFFERS);
    println!("║   Total estimate:   {:>6} bytes (~{}KB)                 ║",
        memory::TOTAL_ESTIMATE, memory::TOTAL_ESTIMATE / 1024);

    println!("╚═══════════════════════════════════════════════════════════╝");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_budget() {
        // Ensure we stay within 32KB heap
        assert!(memory::TOTAL_ESTIMATE < 32 * 1024, "Memory budget exceeded!");
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_benchmarks_run() {
        let bench = run_all_benchmarks();
        assert!(!bench.results().is_empty());
    }

    #[test]
    fn test_optimized_hash() {
        let data = b"test data";
        let hash = optimized::hash_small(data);
        assert_eq!(hash.len(), 32);
    }
}
