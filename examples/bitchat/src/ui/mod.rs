//! UI module for BitChat
//!
//! Provides a graphical user interface for the Waveshare 1.47" LCD display
//! using embedded-graphics.
//!
//! ## Supported Displays
//!
//! - Waveshare 1.47" LCD (172x320, ST7789 driver)
//! - ESP32-C6 DevKit with integrated display
//! - Any ST7789-based display with similar resolution

#[cfg(feature = "display")]
mod display;
#[cfg(feature = "display")]
mod screens;
#[cfg(feature = "display")]
mod widgets;
#[cfg(feature = "display")]
mod theme;
#[cfg(feature = "display")]
mod input;

#[cfg(feature = "display")]
pub use display::{Display, DisplayConfig};
#[cfg(feature = "display")]
pub use screens::{Screen, ChatScreen, PeerListScreen, SettingsScreen, SplashScreen};
#[cfg(feature = "display")]
pub use widgets::{MessageBubble, StatusBar, InputField, Button, ProgressBar};
#[cfg(feature = "display")]
pub use theme::{Theme, ColorScheme};
#[cfg(feature = "display")]
pub use input::{InputEvent, TouchPoint, ButtonPress};

use heapless::{String, Vec};
use crate::{DEVICE_ID_LEN, AppState};
use crate::protocol::PresenceStatus;

/// Display width for Waveshare 1.47"
pub const DISPLAY_WIDTH: u16 = 172;

/// Display height for Waveshare 1.47"
pub const DISPLAY_HEIGHT: u16 = 320;

/// Maximum visible messages on screen
pub const MAX_VISIBLE_MESSAGES: usize = 6;

/// Maximum visible peers on screen
pub const MAX_VISIBLE_PEERS: usize = 8;

/// UI state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UIState {
    /// Splash/boot screen
    Splash,
    /// Main chat list
    ChatList,
    /// Individual chat view
    Chat,
    /// Peer list/discovery
    Peers,
    /// Settings menu
    Settings,
    /// Text input mode
    Input,
    /// Error display
    Error,
}

/// Navigation direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavDirection {
    Up,
    Down,
    Left,
    Right,
    Select,
    Back,
}

/// Chat list entry for display
#[derive(Clone)]
pub struct ChatListEntry {
    /// Peer device ID
    pub peer_id: [u8; DEVICE_ID_LEN],
    /// Display name
    pub name: String<32>,
    /// Last message preview
    pub last_message: String<48>,
    /// Last message time
    pub timestamp: u64,
    /// Unread count
    pub unread: u8,
    /// Online status
    pub online: bool,
}

/// Message entry for display
#[derive(Clone)]
pub struct MessageEntry {
    /// Is outgoing message
    pub outgoing: bool,
    /// Message text
    pub text: String<256>,
    /// Timestamp
    pub timestamp: u64,
    /// Delivery status (for outgoing)
    pub delivered: bool,
    /// Read status (for outgoing)
    pub read: bool,
}

/// Peer entry for display
#[derive(Clone)]
pub struct PeerEntry {
    /// Device ID
    pub id: [u8; DEVICE_ID_LEN],
    /// Display name
    pub name: String<32>,
    /// Presence status
    pub status: PresenceStatus,
    /// Signal quality (0-100)
    pub quality: u8,
    /// Is connected
    pub connected: bool,
}

/// Main UI controller
pub struct ChatUI {
    /// Current UI state
    state: UIState,
    /// Previous state (for back navigation)
    prev_state: UIState,
    /// Current selection index
    selection: usize,
    /// Scroll offset
    scroll_offset: usize,
    /// Currently selected peer (for chat view)
    selected_peer: Option<[u8; DEVICE_ID_LEN]>,
    /// Input buffer for text entry
    input_buffer: String<256>,
    /// Error message to display
    error_message: Option<String<64>>,
    /// App state for status display
    app_state: AppState,
    /// WiFi connected
    wifi_connected: bool,
    /// Peer count
    peer_count: u8,
    /// Unread message count
    unread_count: u8,
    /// Battery level (if available)
    battery_level: Option<u8>,
    /// Last update time
    last_update: u64,
    /// Animation frame
    anim_frame: u8,
}

impl ChatUI {
    /// Create new UI controller
    pub fn new() -> Self {
        Self {
            state: UIState::Splash,
            prev_state: UIState::Splash,
            selection: 0,
            scroll_offset: 0,
            selected_peer: None,
            input_buffer: String::new(),
            error_message: None,
            app_state: AppState::Initializing,
            wifi_connected: false,
            peer_count: 0,
            unread_count: 0,
            battery_level: None,
            last_update: 0,
            anim_frame: 0,
        }
    }

    /// Get current UI state
    pub fn state(&self) -> UIState {
        self.state
    }

    /// Set UI state
    pub fn set_state(&mut self, state: UIState) {
        self.prev_state = self.state;
        self.state = state;
        self.selection = 0;
        self.scroll_offset = 0;
    }

    /// Navigate back
    pub fn go_back(&mut self) {
        let new_state = match self.state {
            UIState::Chat => UIState::ChatList,
            UIState::Input => self.prev_state,
            UIState::Settings => UIState::ChatList,
            UIState::Peers => UIState::ChatList,
            UIState::Error => self.prev_state,
            _ => UIState::ChatList,
        };
        self.set_state(new_state);
    }

    /// Handle navigation input
    pub fn navigate(&mut self, direction: NavDirection, max_items: usize) {
        match direction {
            NavDirection::Up => {
                if self.selection > 0 {
                    self.selection -= 1;
                    if self.selection < self.scroll_offset {
                        self.scroll_offset = self.selection;
                    }
                }
            }
            NavDirection::Down => {
                if self.selection < max_items.saturating_sub(1) {
                    self.selection += 1;
                    let visible = match self.state {
                        UIState::ChatList | UIState::Peers => MAX_VISIBLE_PEERS,
                        UIState::Chat => MAX_VISIBLE_MESSAGES,
                        _ => 5,
                    };
                    if self.selection >= self.scroll_offset + visible {
                        self.scroll_offset = self.selection - visible + 1;
                    }
                }
            }
            NavDirection::Select => {
                // Handled by caller
            }
            NavDirection::Back => {
                self.go_back();
            }
            _ => {}
        }
    }

    /// Get current selection index
    pub fn selection(&self) -> usize {
        self.selection
    }

    /// Get scroll offset
    pub fn scroll_offset(&self) -> usize {
        self.scroll_offset
    }

    /// Set selected peer for chat view
    pub fn select_peer(&mut self, peer_id: [u8; DEVICE_ID_LEN]) {
        self.selected_peer = Some(peer_id);
        self.set_state(UIState::Chat);
    }

    /// Get selected peer
    pub fn selected_peer(&self) -> Option<&[u8; DEVICE_ID_LEN]> {
        self.selected_peer.as_ref()
    }

    /// Enter input mode
    pub fn enter_input_mode(&mut self) {
        self.input_buffer.clear();
        self.prev_state = self.state;
        self.state = UIState::Input;
    }

    /// Add character to input
    pub fn input_char(&mut self, c: char) {
        let _ = self.input_buffer.push(c);
    }

    /// Remove last character from input
    pub fn input_backspace(&mut self) {
        self.input_buffer.pop();
    }

    /// Get input buffer
    pub fn input_buffer(&self) -> &str {
        &self.input_buffer
    }

    /// Clear input buffer and exit input mode
    pub fn finish_input(&mut self) -> String<256> {
        let result = self.input_buffer.clone();
        self.input_buffer.clear();
        self.state = self.prev_state;
        result
    }

    /// Cancel input
    pub fn cancel_input(&mut self) {
        self.input_buffer.clear();
        self.state = self.prev_state;
    }

    /// Show error message
    pub fn show_error(&mut self, message: &str) {
        let mut err = String::new();
        let _ = err.push_str(&message[..message.len().min(64)]);
        self.error_message = Some(err);
        self.prev_state = self.state;
        self.state = UIState::Error;
    }

    /// Clear error
    pub fn clear_error(&mut self) {
        self.error_message = None;
        self.state = self.prev_state;
    }

    /// Get error message
    pub fn error_message(&self) -> Option<&str> {
        self.error_message.as_ref().map(|s| s.as_str())
    }

    /// Update status indicators
    pub fn update_status(
        &mut self,
        app_state: AppState,
        wifi: bool,
        peers: u8,
        unread: u8,
        battery: Option<u8>,
    ) {
        self.app_state = app_state;
        self.wifi_connected = wifi;
        self.peer_count = peers;
        self.unread_count = unread;
        self.battery_level = battery;
    }

    /// Get app state
    pub fn app_state(&self) -> AppState {
        self.app_state
    }

    /// Check if WiFi connected
    pub fn is_wifi_connected(&self) -> bool {
        self.wifi_connected
    }

    /// Get peer count
    pub fn peer_count(&self) -> u8 {
        self.peer_count
    }

    /// Get unread count
    pub fn unread_count(&self) -> u8 {
        self.unread_count
    }

    /// Get battery level
    pub fn battery_level(&self) -> Option<u8> {
        self.battery_level
    }

    /// Advance animation frame
    pub fn tick(&mut self, current_time: u64) {
        if current_time - self.last_update > 100 {
            self.anim_frame = self.anim_frame.wrapping_add(1);
            self.last_update = current_time;
        }
    }

    /// Get animation frame
    pub fn anim_frame(&self) -> u8 {
        self.anim_frame
    }

    /// Should show splash screen
    pub fn should_show_splash(&self, elapsed_ms: u64) -> bool {
        self.state == UIState::Splash && elapsed_ms < 2000
    }
}

impl Default for ChatUI {
    fn default() -> Self {
        Self::new()
    }
}

/// Format timestamp for display (HH:MM format)
pub fn format_time(timestamp_ms: u64) -> String<8> {
    let secs = (timestamp_ms / 1000) % 86400;
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;

    let mut result = String::new();
    let _ = core::fmt::write(
        &mut StringWriter(&mut result),
        format_args!("{:02}:{:02}", hours, minutes),
    );
    result
}

/// Format device ID for display (first 4 bytes as hex)
pub fn format_device_id(id: &[u8; DEVICE_ID_LEN]) -> String<12> {
    let mut result = String::new();
    for byte in &id[..4] {
        let _ = core::fmt::write(
            &mut StringWriter(&mut result),
            format_args!("{:02X}", byte),
        );
    }
    result
}

/// Helper for writing to heapless String
struct StringWriter<'a>(&'a mut String<256>);

impl<'a> core::fmt::Write for StringWriter<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.0.push_str(s).map_err(|_| core::fmt::Error)
    }
}

// Implement for smaller strings too
struct StringWriter8<'a>(&'a mut String<8>);
impl<'a> core::fmt::Write for StringWriter8<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.0.push_str(s).map_err(|_| core::fmt::Error)
    }
}

struct StringWriter12<'a>(&'a mut String<12>);
impl<'a> core::fmt::Write for StringWriter12<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.0.push_str(s).map_err(|_| core::fmt::Error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ui_navigation() {
        let mut ui = ChatUI::new();
        ui.set_state(UIState::ChatList);

        // Navigate down
        ui.navigate(NavDirection::Down, 10);
        assert_eq!(ui.selection(), 1);

        // Navigate up
        ui.navigate(NavDirection::Up, 10);
        assert_eq!(ui.selection(), 0);

        // Navigate up at 0 stays at 0
        ui.navigate(NavDirection::Up, 10);
        assert_eq!(ui.selection(), 0);
    }

    #[test]
    fn test_ui_state_transitions() {
        let mut ui = ChatUI::new();

        ui.set_state(UIState::ChatList);
        assert_eq!(ui.state(), UIState::ChatList);

        ui.set_state(UIState::Chat);
        assert_eq!(ui.state(), UIState::Chat);

        ui.go_back();
        assert_eq!(ui.state(), UIState::ChatList);
    }

    #[test]
    fn test_input_mode() {
        let mut ui = ChatUI::new();
        ui.set_state(UIState::Chat);

        ui.enter_input_mode();
        assert_eq!(ui.state(), UIState::Input);

        ui.input_char('H');
        ui.input_char('i');
        assert_eq!(ui.input_buffer(), "Hi");

        ui.input_backspace();
        assert_eq!(ui.input_buffer(), "H");

        let result = ui.finish_input();
        assert_eq!(result.as_str(), "H");
        assert_eq!(ui.state(), UIState::Chat);
    }
}
