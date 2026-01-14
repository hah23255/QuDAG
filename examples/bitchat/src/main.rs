//! BitChat ESP32 Application Entry Point
//!
//! This is the main entry point for the BitChat application on ESP32-C6.
//! It initializes hardware, sets up WiFi, and runs the chat application.

#![no_std]
#![no_main]

// ESP32-C6 specific imports
#[cfg(target_arch = "riscv32")]
use esp_backtrace as _;
#[cfg(target_arch = "riscv32")]
use esp_println::println;

extern crate alloc;

use core::cell::RefCell;
use heapless::String;

// BitChat imports
use qudag_bitchat::{
    BitChat, Config, AppState, BitChatError, Result,
    crypto::Identity,
    network::{WifiConfig, PeerDiscovery, DiscoveryConfig, Transport, TransportConfig},
    protocol::{Handshake, ChatMessage},
    storage::MessageStore,
};

#[cfg(feature = "display")]
use qudag_bitchat::ui::{ChatUI, Display, DisplayConfig, UIState};

/// Heap allocator for ESP32
#[cfg(target_arch = "riscv32")]
#[global_allocator]
static ALLOCATOR: esp_alloc::EspHeap = esp_alloc::EspHeap::empty();

/// Initialize heap
#[cfg(target_arch = "riscv32")]
fn init_heap() {
    const HEAP_SIZE: usize = 32 * 1024;
    static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];
    unsafe {
        ALLOCATOR.init(HEAP.as_mut_ptr(), HEAP_SIZE);
    }
}

/// Application state
struct App {
    /// BitChat core
    chat: BitChat,
    /// Message store
    messages: MessageStore,
    /// Discovery service
    discovery: PeerDiscovery,
    /// Transport layer
    transport: Transport,
    /// UI controller
    #[cfg(feature = "display")]
    ui: ChatUI,
    /// WiFi configuration
    wifi_config: WifiConfig,
    /// Start timestamp
    start_time: u64,
    /// Last tick timestamp
    last_tick: u64,
}

impl App {
    /// Create new application
    fn new() -> Self {
        let config = Config::default();
        let mut chat = BitChat::new(config);

        // Generate identity
        let identity = chat.generate_identity()
            .expect("Failed to generate identity");

        let device_id = chat.device_id().unwrap();

        let discovery_config = DiscoveryConfig::default();
        let discovery = PeerDiscovery::new(discovery_config, device_id);

        let transport_config = TransportConfig::default();
        let transport = Transport::new(transport_config);

        Self {
            chat,
            messages: MessageStore::new(),
            discovery,
            transport,
            #[cfg(feature = "display")]
            ui: ChatUI::new(),
            wifi_config: WifiConfig::default(),
            start_time: 0,
            last_tick: 0,
        }
    }

    /// Initialize application
    fn init(&mut self, current_time: u64) {
        self.start_time = current_time;
        self.chat.set_state(AppState::Initializing);

        #[cfg(feature = "display")]
        {
            self.ui.set_state(UIState::Splash);
        }

        #[cfg(target_arch = "riscv32")]
        println!("BitChat initialized");
    }

    /// Main tick function
    fn tick(&mut self, current_time: u64) {
        let elapsed = current_time - self.start_time;
        let _delta = current_time - self.last_tick;
        self.last_tick = current_time;

        match self.chat.state() {
            AppState::Initializing => {
                #[cfg(feature = "display")]
                if !self.ui.should_show_splash(elapsed) {
                    self.chat.set_state(AppState::ConnectingWifi);
                    self.ui.set_state(UIState::ChatList);
                }
                #[cfg(not(feature = "display"))]
                if elapsed > 1000 {
                    self.chat.set_state(AppState::ConnectingWifi);
                }
            }
            AppState::ConnectingWifi => {
                // WiFi connection handled by platform code
                // This is a placeholder for the actual implementation
                #[cfg(target_arch = "riscv32")]
                {
                    // esp-wifi would handle actual connection
                }
            }
            AppState::Discovering => {
                // Send discovery announcement periodically
                if self.discovery.should_announce(current_time) {
                    if let Some(identity) = self.chat.identity() {
                        let public = identity.export_public();
                        self.discovery.set_identity(public);
                    }
                }
            }
            AppState::Ready | AppState::Chatting => {
                // Process incoming messages
                // Handle user input
                #[cfg(feature = "display")]
                self.ui.tick(current_time);
            }
            _ => {}
        }
    }

    /// Handle received network data
    fn on_receive(&mut self, data: &[u8], from_addr: &[u8; 6]) {
        // Try to parse as discovery announcement first
        if let Ok(announcement) = qudag_bitchat::network::Announcement::from_bytes(data) {
            if let Some(_valid) = self.discovery.process_announcement(&announcement, self.last_tick) {
                // Add discovered peer
                if let Some(public_identity) = announcement.public_identity {
                    let addr = qudag_bitchat::network::SocketAddr::from_bytes(from_addr);
                    let peer = qudag_bitchat::network::Peer::from_identity(public_identity, addr);
                    let _ = self.chat.add_peer(peer);
                }
            }
            return;
        }

        // Try to parse as message envelope
        if let Ok(envelope) = qudag_bitchat::protocol::Envelope::from_bytes(data) {
            if let Ok(message) = self.chat.receive_envelope(envelope) {
                // Store received message
                let stored = qudag_bitchat::storage::StoredMessage::from_message(
                    &message,
                    false,
                    &self.chat.device_id().unwrap_or([0u8; 32]),
                );
                self.messages.add_message(stored);

                #[cfg(feature = "display")]
                {
                    self.ui.update_status(
                        self.chat.state(),
                        true,
                        self.chat.peers().len() as u8,
                        self.messages.total_unread() as u8,
                        None,
                    );
                }
            }
        }
    }

    /// Send a message
    fn send_message(&mut self, to: [u8; 32], text: &str) -> Result<u64> {
        let seq = self.chat.queue_message(to, text)?;

        // Store sent message
        if let Some(identity) = self.chat.identity() {
            let msg = ChatMessage::new(identity.device_id(), to, text, seq)?;
            let stored = qudag_bitchat::storage::StoredMessage::from_message(
                &msg,
                true,
                &identity.device_id(),
            );
            self.messages.add_message(stored);
        }

        Ok(seq)
    }
}

/// Entry point for ESP32-C6
#[cfg(target_arch = "riscv32")]
#[esp_hal::entry]
fn main() -> ! {
    init_heap();

    println!("BitChat starting on ESP32-C6...");

    let peripherals = esp_hal::init(esp_hal::Config::default());

    // Get current time (simplified - would use RTC in production)
    let mut current_time: u64 = 0;

    // Create application
    let mut app = App::new();
    app.init(current_time);

    println!("BitChat ready!");

    // Main loop
    loop {
        current_time += 10; // Simplified time increment
        app.tick(current_time);

        // Small delay to prevent CPU hogging
        // In production, use proper async/await with embassy
        for _ in 0..10000 {
            core::hint::spin_loop();
        }
    }
}

/// Entry point for non-ESP32 targets (testing)
#[cfg(not(target_arch = "riscv32"))]
fn main() {
    println!("BitChat - ESP32 build required for full functionality");
    println!("Run with: cargo build --target riscv32imc-unknown-none-elf --features esp32c6");

    // Create app for testing
    let mut app = App::new();
    app.init(0);

    println!("Identity generated successfully");
    if let Some(id) = app.chat.device_id() {
        print!("Device ID: ");
        for byte in &id[..8] {
            print!("{:02x}", byte);
        }
        println!("...");
    }

    // Test message flow
    let test_peer_id = [0x42u8; 32];
    match app.send_message(test_peer_id, "Hello from BitChat!") {
        Ok(seq) => println!("Message queued with sequence: {}", seq),
        Err(e) => println!("Failed to queue message: {:?}", e),
    }

    println!("BitChat test complete!");
}

// Panic handler for non-ESP32
#[cfg(not(target_arch = "riscv32"))]
use std::println;
