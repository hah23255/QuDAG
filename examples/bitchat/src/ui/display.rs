//! Display driver for Waveshare 1.47" ST7789 LCD
//!
//! Configuration for ESP32-C6 with the Waveshare 1.47" display:
//! - Resolution: 172x320 pixels
//! - Driver: ST7789
//! - Interface: SPI
//! - Color: RGB565

#[cfg(feature = "display")]
use embedded_graphics::{
    pixelcolor::Rgb565,
    prelude::*,
    primitives::{PrimitiveStyleBuilder, Rectangle},
    mono_font::{ascii::FONT_6X10, MonoTextStyle},
    text::Text,
};

#[cfg(feature = "display")]
use st7789::ST7789;

use super::{DISPLAY_WIDTH, DISPLAY_HEIGHT};

/// Display configuration
#[derive(Debug, Clone)]
pub struct DisplayConfig {
    /// Display width in pixels
    pub width: u16,
    /// Display height in pixels
    pub height: u16,
    /// SPI clock speed in Hz
    pub spi_freq_hz: u32,
    /// Backlight brightness (0-255)
    pub brightness: u8,
    /// Rotation (0, 90, 180, 270)
    pub rotation: u16,
    /// Invert colors
    pub inverted: bool,
    /// X offset for display area
    pub offset_x: u16,
    /// Y offset for display area
    pub offset_y: u16,
}

impl Default for DisplayConfig {
    fn default() -> Self {
        Self {
            width: DISPLAY_WIDTH,
            height: DISPLAY_HEIGHT,
            spi_freq_hz: 80_000_000, // 80MHz for ESP32
            brightness: 200,
            rotation: 0,
            inverted: false,
            offset_x: 34, // Waveshare 1.47" offset
            offset_y: 0,
        }
    }
}

impl DisplayConfig {
    /// Configuration for Waveshare 1.47" ESP32-C6 display
    pub fn waveshare_147() -> Self {
        Self {
            width: 172,
            height: 320,
            spi_freq_hz: 80_000_000,
            brightness: 200,
            rotation: 0,
            inverted: true, // Waveshare uses inverted colors
            offset_x: 34,
            offset_y: 0,
        }
    }

    /// Configuration for generic ST7789 240x320 display
    pub fn generic_st7789() -> Self {
        Self {
            width: 240,
            height: 320,
            spi_freq_hz: 40_000_000,
            brightness: 255,
            rotation: 0,
            inverted: false,
            offset_x: 0,
            offset_y: 0,
        }
    }
}

/// Display abstraction for BitChat
///
/// This provides a platform-independent interface for display operations.
/// The actual display implementation is provided by the hardware-specific code.
pub struct Display {
    /// Configuration
    config: DisplayConfig,
    /// Current brightness
    brightness: u8,
    /// Display enabled
    enabled: bool,
    /// Dirty flag (needs redraw)
    dirty: bool,
}

impl Display {
    /// Create new display with configuration
    pub fn new(config: DisplayConfig) -> Self {
        let brightness = config.brightness;
        Self {
            config,
            brightness,
            enabled: false,
            dirty: true,
        }
    }

    /// Get configuration
    pub fn config(&self) -> &DisplayConfig {
        &self.config
    }

    /// Get display width
    pub fn width(&self) -> u16 {
        self.config.width
    }

    /// Get display height
    pub fn height(&self) -> u16 {
        self.config.height
    }

    /// Enable display
    pub fn enable(&mut self) {
        self.enabled = true;
        self.dirty = true;
    }

    /// Disable display (for power saving)
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Check if display is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set brightness
    pub fn set_brightness(&mut self, brightness: u8) {
        self.brightness = brightness;
    }

    /// Get brightness
    pub fn brightness(&self) -> u8 {
        self.brightness
    }

    /// Mark display as dirty (needs redraw)
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Check if display needs redraw
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Clear dirty flag
    pub fn clear_dirty(&mut self) {
        self.dirty = false;
    }
}

/// Color constants for BitChat UI
pub mod colors {
    #[cfg(feature = "display")]
    use embedded_graphics::pixelcolor::Rgb565;

    /// Background color (dark)
    #[cfg(feature = "display")]
    pub const BACKGROUND: Rgb565 = Rgb565::new(1, 2, 2);

    /// Primary text color
    #[cfg(feature = "display")]
    pub const TEXT_PRIMARY: Rgb565 = Rgb565::new(31, 63, 31);

    /// Secondary text color
    #[cfg(feature = "display")]
    pub const TEXT_SECONDARY: Rgb565 = Rgb565::new(16, 32, 16);

    /// Accent color (blue)
    #[cfg(feature = "display")]
    pub const ACCENT: Rgb565 = Rgb565::new(0, 32, 31);

    /// Success color (green)
    #[cfg(feature = "display")]
    pub const SUCCESS: Rgb565 = Rgb565::new(0, 48, 0);

    /// Warning color (yellow)
    #[cfg(feature = "display")]
    pub const WARNING: Rgb565 = Rgb565::new(31, 48, 0);

    /// Error color (red)
    #[cfg(feature = "display")]
    pub const ERROR: Rgb565 = Rgb565::new(31, 0, 0);

    /// Outgoing message bubble
    #[cfg(feature = "display")]
    pub const BUBBLE_OUT: Rgb565 = Rgb565::new(0, 24, 16);

    /// Incoming message bubble
    #[cfg(feature = "display")]
    pub const BUBBLE_IN: Rgb565 = Rgb565::new(4, 8, 4);

    /// Status bar background
    #[cfg(feature = "display")]
    pub const STATUS_BAR: Rgb565 = Rgb565::new(2, 4, 3);

    /// Selection highlight
    #[cfg(feature = "display")]
    pub const SELECTION: Rgb565 = Rgb565::new(4, 12, 8);

    // Non-display versions for testing
    #[cfg(not(feature = "display"))]
    pub const BACKGROUND: u16 = 0x0842;
    #[cfg(not(feature = "display"))]
    pub const TEXT_PRIMARY: u16 = 0xFFFF;
}

/// Pin configuration for Waveshare ESP32-C6 1.47" display
pub struct WavesharePins {
    /// SPI MOSI (data) - GPIO6
    pub mosi: u8,
    /// SPI CLK (clock) - GPIO7
    pub clk: u8,
    /// Chip Select - GPIO14
    pub cs: u8,
    /// Data/Command - GPIO15
    pub dc: u8,
    /// Reset - GPIO21
    pub rst: u8,
    /// Backlight - GPIO22
    pub bl: u8,
}

impl Default for WavesharePins {
    fn default() -> Self {
        Self {
            mosi: 6,
            clk: 7,
            cs: 14,
            dc: 15,
            rst: 21,
            bl: 22,
        }
    }
}

/// ESP32-C6 pin configuration
impl WavesharePins {
    /// Standard Waveshare 1.47" ESP32-C6 DevKit
    pub fn waveshare_c6() -> Self {
        Self {
            mosi: 6,
            clk: 7,
            cs: 14,
            dc: 15,
            rst: 21,
            bl: 22,
        }
    }

    /// Alternative pin configuration
    pub fn alternative() -> Self {
        Self {
            mosi: 11,
            clk: 12,
            cs: 10,
            dc: 9,
            rst: 8,
            bl: 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_config() {
        let config = DisplayConfig::waveshare_147();
        assert_eq!(config.width, 172);
        assert_eq!(config.height, 320);
        assert!(config.inverted);
    }

    #[test]
    fn test_display_state() {
        let mut display = Display::new(DisplayConfig::default());

        assert!(!display.is_enabled());
        display.enable();
        assert!(display.is_enabled());

        assert!(display.is_dirty());
        display.clear_dirty();
        assert!(!display.is_dirty());
    }

    #[test]
    fn test_pins_config() {
        let pins = WavesharePins::waveshare_c6();
        assert_eq!(pins.mosi, 6);
        assert_eq!(pins.clk, 7);
    }
}
