# Rust Hello World Example

This example demonstrates how to integrate Rust code into Contiki-NG applications.

## Features

- Shows how to call Rust functions from C code
- Demonstrates Rust functions calling back into Contiki-NG APIs
- Includes a Fibonacci calculator (with overflow protection)
- Shows proper FFI (Foreign Function Interface) setup
- Demonstrates static buffers (zero heap allocation)
- Shows safe random number generation
- Includes sensor data processing example
- Comprehensive unit tests for all functions

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

# Run unit tests (on native platform)
make rust-test

# Check code size
make rust-size-report
```

## Code Structure

- `hello-world.c` - Main Contiki-NG process that calls Rust functions
- `rust_module.rs` - Rust implementation with exported functions
- `Makefile` - Build configuration with Rust support enabled

## Rust Functions

The example exports several functions that demonstrate different aspects of Rust integration:

### `rust_hello_world()`
Simple "Hello World" function that calls printf via FFI.

### `rust_calculate_fibonacci(n: u32) -> u32`
Calculates the nth Fibonacci number with overflow protection using saturating arithmetic.

### `rust_print_system_info()`
Demonstrates calling back into Contiki-NG APIs (clock_seconds) and conditional compilation for different architectures.

### `rust_demo_static_buffer() -> u32`
Shows how to use static buffers without heap allocation, perfect for embedded systems.

### `rust_random_range(max: u32) -> u32`
Safe random number generation within a specified range.

### `rust_process_sensor_data(data: *const i16, len: u32) -> i16`
Demonstrates processing arrays passed from C, with input validation and safe error handling.

## How It Works

1. The Makefile includes Rust support via `RUST_SUPPORT = 1`
2. Rust source files (`.rs`) are **automatically detected** - no need to list them manually!
3. Rust files are compiled to object files with size optimization enabled
4. The linker combines C and Rust object files into the final binary
5. Functions are exposed across the FFI boundary using `#[no_mangle]` and `extern "C"`
6. ARM EABI runtime functions are provided by shared rust-runtime.c

## Extending

To add more Rust code:

1. Simply create new `.rs` files in your project directory (auto-detected!)
2. Use `#[no_mangle]` and `extern "C"` for functions called from C
3. Declare the functions in your C code with `extern`
4. Follow Rust's `no_std` practices for embedded development
5. Add `#[cfg(test)]` test modules for unit testing
6. Use `make rust-size-report` to monitor code size impact

## Best Practices

- **Use static buffers** instead of heap allocation (no malloc needed!)
- **Leverage type-safe wrappers** from `contiki_sys` crate (zero overhead)
- **Add unit tests** for all non-trivial functions
- **Check code size** regularly with `make rust-size-report`
- **Read SIZE_GUIDE.md** in `tools/rust-support/` for optimization tips
- **Use saturating arithmetic** to prevent integer overflow
- **Validate inputs** for FFI functions (check for null pointers, bounds, etc.)

## Available Rust APIs

The `contiki_sys` crate provides type-safe wrappers for:

- **Timers:** `ETimer` wrapper for safe event timer management
- **LEDs:** `Leds` wrapper for LED control
- **Random:** `Random` wrapper with range support
- **Clock:** `Clock` wrapper for time functions
- **Static Buffers:** `StaticBuffer<N>` for fixed-size buffers
- **Process Macros:** `rust_process!` for ergonomic process definitions
- **FFI Helpers:** `c_str!` macro for static string literals

See `tools/rust-support/contiki-sys.rs` for the complete API.

## Platform Support

Currently supported platforms:
- Native (Linux/macOS)
- ARM Cortex-M based platforms (zoul, cc2538dk, nrf52840)

Not yet supported:
- MSP430 platforms (sky, z1) - requires additional Rust target configuration