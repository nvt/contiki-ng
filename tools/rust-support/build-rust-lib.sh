#!/bin/bash
# Build script for Rust support library

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Check if cargo is available
if ! command -v cargo &> /dev/null; then
    echo "Error: Cargo (Rust package manager) not found. Please install Rust."
    exit 1
fi

# Build for all common targets
TARGETS=(
    "thumbv7m-none-eabi"      # ARM Cortex-M3 (cc2538, etc)
    "thumbv7em-none-eabihf"   # ARM Cortex-M4F (nrf52840, etc)
    "msp430-none-elf"         # MSP430 (sky, z1)
)

echo "Building Rust support library..."

# Install targets if not already installed
for target in "${TARGETS[@]}"; do
    if ! rustup target list --installed | grep -q "$target"; then
        echo "Installing Rust target: $target"
        rustup target add "$target"
    fi
done

# Build for each target
for target in "${TARGETS[@]}"; do
    echo "Building for target: $target"
    cargo build --release --target="$target"
done

# Also build for native
echo "Building for native target"
cargo build --release

echo "Rust support library built successfully!"