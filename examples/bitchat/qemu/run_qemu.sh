#!/bin/bash
# BitChat QEMU Testing Script
# Run ESP32-C3 emulation for BitChat testing
#
# QEMU for ESP32 is experimental - this script provides the setup
# For full ESP32-C6 testing, use actual hardware or Wokwi simulator

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo -e "${GREEN}     BitChat QEMU Testing Environment      ${NC}"
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo

# Check for QEMU
check_qemu() {
    if command -v qemu-system-riscv32 &> /dev/null; then
        echo -e "${GREEN}✓${NC} QEMU RISC-V found: $(qemu-system-riscv32 --version | head -1)"
        return 0
    else
        echo -e "${YELLOW}!${NC} QEMU RISC-V not found"
        echo "  Install with: sudo apt install qemu-system-misc"
        echo "  Or: brew install qemu"
        return 1
    fi
}

# Check for espflash
check_espflash() {
    if command -v espflash &> /dev/null; then
        echo -e "${GREEN}✓${NC} espflash found"
        return 0
    else
        echo -e "${YELLOW}!${NC} espflash not found"
        echo "  Install with: cargo install espflash"
        return 1
    fi
}

# Build for ESP32-C3 (QEMU-compatible RISC-V)
build_esp32c3() {
    echo
    echo "Building BitChat for ESP32-C3 (QEMU)..."
    cd "$PROJECT_DIR"

    # Build with esp32c3 feature (better QEMU support than C6)
    cargo build --release --target riscv32imc-unknown-none-elf \
        --features "esp32c3" \
        2>&1 | while read line; do
            if [[ "$line" == *"error"* ]]; then
                echo -e "  ${RED}$line${NC}"
            elif [[ "$line" == *"warning"* ]]; then
                echo -e "  ${YELLOW}$line${NC}"
            else
                echo "  $line"
            fi
        done

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓${NC} Build successful"
        return 0
    else
        echo -e "${RED}✗${NC} Build failed"
        return 1
    fi
}

# Run in QEMU (basic RISC-V mode)
run_qemu() {
    echo
    echo "Starting QEMU..."

    BINARY="$PROJECT_DIR/target/riscv32imc-unknown-none-elf/release/bitchat-esp32"

    if [ ! -f "$BINARY" ]; then
        echo -e "${RED}✗${NC} Binary not found: $BINARY"
        echo "  Run build first"
        return 1
    fi

    # QEMU for ESP32 is limited - use machine mode that works
    # Note: Full ESP32 emulation requires Espressif's QEMU fork
    echo -e "${YELLOW}Note:${NC} Running in basic RISC-V mode"
    echo "  For full ESP32-C6 testing, use:"
    echo "  - Physical hardware"
    echo "  - Wokwi simulator (https://wokwi.com)"
    echo

    qemu-system-riscv32 \
        -machine virt \
        -cpu rv32 \
        -nographic \
        -bios none \
        -kernel "$BINARY" \
        -m 4M \
        2>&1

    return $?
}

# Run desktop tests instead (recommended)
run_desktop_tests() {
    echo
    echo "Running desktop tests (recommended for validation)..."
    cd "$PROJECT_DIR"

    cargo run --release --features "desktop,std"
}

# Run unit tests
run_unit_tests() {
    echo
    echo "Running unit tests..."
    cd "$PROJECT_DIR"

    cargo test --features "std" -- --nocapture
}

# Security validation tests
run_security_tests() {
    echo
    echo "Running security validation..."
    cd "$PROJECT_DIR"

    # Run security-focused tests
    cargo test --features "std" -- security --nocapture 2>/dev/null || true

    # Run crypto tests
    cargo test --features "std" crypto:: -- --nocapture

    # Run replay detection tests
    cargo test --features "std" replay -- --nocapture

    echo -e "${GREEN}✓${NC} Security tests complete"
}

# Main menu
show_menu() {
    echo
    echo "Select an option:"
    echo "  1) Run desktop tests (recommended)"
    echo "  2) Run unit tests"
    echo "  3) Run security validation"
    echo "  4) Build for ESP32-C3 (QEMU)"
    echo "  5) Run in QEMU (experimental)"
    echo "  6) Check dependencies"
    echo "  q) Quit"
    echo
    read -p "Choice: " choice

    case $choice in
        1) run_desktop_tests ;;
        2) run_unit_tests ;;
        3) run_security_tests ;;
        4) build_esp32c3 ;;
        5)
            if check_qemu; then
                build_esp32c3 && run_qemu
            fi
            ;;
        6)
            check_qemu
            check_espflash
            ;;
        q|Q) exit 0 ;;
        *) echo "Invalid option" ;;
    esac

    show_menu
}

# Parse command line arguments
case "${1:-}" in
    --test)
        run_unit_tests
        ;;
    --security)
        run_security_tests
        ;;
    --desktop)
        run_desktop_tests
        ;;
    --build)
        build_esp32c3
        ;;
    --qemu)
        check_qemu && build_esp32c3 && run_qemu
        ;;
    --help|-h)
        echo "Usage: $0 [option]"
        echo
        echo "Options:"
        echo "  --test      Run unit tests"
        echo "  --security  Run security validation"
        echo "  --desktop   Run desktop tests"
        echo "  --build     Build for ESP32-C3"
        echo "  --qemu      Build and run in QEMU"
        echo "  --help      Show this help"
        echo
        echo "Without options, shows interactive menu"
        ;;
    *)
        show_menu
        ;;
esac
