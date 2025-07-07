# Rust Hello World Example

This example demonstrates how to integrate Rust code into Contiki-NG applications.

## Features

- Shows how to call Rust functions from C code
- Demonstrates Rust functions calling back into Contiki-NG APIs
- Includes a simple Fibonacci calculator written in Rust
- Shows proper FFI (Foreign Function Interface) setup

## Requirements

- Rust toolchain (install from https://rustup.rs/)
- Required Rust targets (will be installed automatically):
  - `thumbv7m-none-eabi` for ARM Cortex-M3 platforms
  - `thumbv7em-none-eabihf` for ARM Cortex-M4F platforms
  - Native target for simulation

## Building

```bash
# Build for native (simulation)
make

# Build for specific platform
make TARGET=zoul
make TARGET=nrf52840

# Clean build artifacts
make clean
```

## Code Structure

- `hello-world.c` - Main Contiki-NG process that calls Rust functions
- `rust_module.rs` - Rust implementation with exported functions
- `Makefile` - Build configuration with Rust support enabled

## How It Works

1. The Makefile includes Rust support via `RUST_SUPPORT = 1`
2. Rust source files (`.rs`) are compiled to object files
3. The linker combines C and Rust object files into the final binary
4. Functions are exposed across the FFI boundary using `#[no_mangle]` and `extern "C"`

## Extending

To add more Rust code:

1. Add new `.rs` files to `PROJECT_SOURCEFILES` in the Makefile
2. Use `#[no_mangle]` and `extern "C"` for functions called from C
3. Declare the functions in your C code with `extern`
4. Follow Rust's `no_std` practices for embedded development

## Platform Support

Currently supported platforms:
- Native (Linux/macOS)
- ARM Cortex-M based platforms (zoul, cc2538dk, nrf52840)

Not yet supported:
- MSP430 platforms (sky, z1) - requires additional Rust target configuration