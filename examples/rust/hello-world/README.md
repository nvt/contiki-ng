# Rust Hello World for Contiki-NG

This example demonstrates the fundamental pattern for writing Contiki-NG processes in Rust. It showcases timer-based event handling, safe FFI patterns, and proper state management.

## Architecture Overview

The integration uses a minimal C wrapper pattern:
- **C side** (`hello-world.c`): Handles process registration using Contiki-NG macros
- **Rust side** (`hello_world_process.rs`): Implements all process logic and state management

This separation keeps the FFI boundary minimal while allowing maximum flexibility in Rust.

## Key Concepts

### FFI (Foreign Function Interface)

This code bridges Rust and C, requiring careful handling of:
- `unsafe` blocks for operations that can't be verified by Rust's compiler
- `extern "C"` to match C calling conventions
- `#[no_mangle]` to prevent Rust from changing function names

The example demonstrates best practices for minimizing unsafe code surface area by encapsulating unsafe operations in small, well-documented helper functions.

### Static State Management

Since C calls into Rust repeatedly, we need persistent state across calls:
- Static variables persist for the program's lifetime
- `#[used]` prevents the linker from removing "unused" variables
- `#[no_mangle]` ensures predictable symbol names for debugging

**Important**: Each static variable must have both attributes. Using a single struct to group state doesn't work reliably due to how Rust's compiler handles const initialization with LTO enabled.

### Safety Model

Contiki-NG runs single-threaded with cooperative scheduling:
- No concurrent access to static variables (no data races)
- Mutable statics are safe when properly documented
- Small, focused `unsafe` blocks minimize risk

All unsafe operations in this example are documented with explicit safety comments explaining why they're safe in Contiki-NG's execution model.

## Process Flow

1. **Init**: `PROCESS_EVENT_INIT` - Called once at startup
   - Initializes counter to 0
   - Sets up 2-second timer

2. **Timer Events**: `PROCESS_EVENT_TIMER` - Called when timer expires
   - Increments counter
   - Prints current count
   - Resets timer (repeats) or ends process (at count 10)

The event-driven model means our handler function is called repeatedly with different events, and we return a protothread state (`PT_YIELDED` or `PT_ENDED`) to indicate whether to continue.

## Files

- **`hello-world.c`**: Minimal C wrapper that registers the process with Contiki-NG
- **`hello_world_process.rs`**: Complete process implementation in Rust
- **`Cargo.toml`**: Rust project configuration with embedded optimizations
- **`Makefile`**: Build configuration that integrates Rust with Contiki-NG's build system

## Building and Running

### Native Platform (Linux/macOS)

```bash
# Build for native platform
make TARGET=native

# Run the example
./build/native/hello-world.native
```

### Expected Output

```
[INFO: Main      ] Starting Contiki-NG-release/v5.1
Hello from Rust using contiki-sys!
Starting timer-based execution...
Hello from Rust! Counter: 1
Hello from Rust! Counter: 2
Hello from Rust! Counter: 3
...
Hello from Rust! Counter: 10
Rust process completed!
```

### Embedded Targets

```bash
# Build for specific hardware platform
make TARGET=zoul
make TARGET=cc2538dk

# Upload to device (method varies by platform)
make TARGET=zoul hello-world.upload
```

## Code Structure

The Rust code (`hello_world_process.rs`) is organized into clear sections:

1. **Configuration** - `no_std` setup and compiler attributes
2. **FFI Bindings** - Import of `contiki-sys` module
3. **Static Variables** - Persistent state with documented safety
4. **Helper Functions** - Small wrappers that encapsulate unsafe operations
5. **Main Handler** - Event-driven process logic

Each section has extensive inline comments explaining the "why" behind the code.

Note: The panic handler is provided by the `contiki-sys` library and uses `watchdog_reboot()` for a portable system restart on panic. Applications can override it by providing their own `#[panic_handler]` if custom panic behavior is needed.

## Key Patterns Demonstrated

### Minimal Unsafe Surface Area

Instead of one large `unsafe` block, we use small helper functions:

```rust
/// Increment the counter and return the new value
/// # Safety
/// Safe because Contiki-NG is single-threaded - no concurrent access possible
#[inline]
fn increment_counter() -> u32 {
    unsafe {
        COUNTER += 1;
        COUNTER
    }
}
```

This makes security audits easier and clearly documents each unsafe operation.

### Documented Safety Invariants

Following Rust conventions, unsafe operations are documented with inline `SAFETY` comments:

```rust
// SAFETY: Single-threaded execution in Contiki-NG means no data races possible
unsafe {
    COUNTER = 0;
}
```

Public `unsafe fn` declarations use `# Safety` sections in their doc comments to document caller obligations.

### Platform Constants from FFI

Platform-specific constants like `CLOCK_SECOND` are provided by the Contiki-NG build system through the FFI layer:

```rust
/// Get the platform's clock ticks per second
fn clock_second() -> clock_time_t {
    unsafe { CLOCK_SECOND }  // Extern static from contiki-sys
}
```

This ensures the correct value is used for each target platform automatically.

### Event-Driven Architecture

The main handler uses pattern matching for clean event handling:

```rust
match ev {
    PROCESS_EVENT_INIT => {
        // Initialize
        PT_YIELDED
    }
    PROCESS_EVENT_TIMER => {
        // Handle timer
        PT_YIELDED
    }
    _ => PT_YIELDED,
}
```

## Learning Resources

- **Contiki-NG Process Model**: See `os/sys/process.h` for C process API
- **Rust FFI**: The Rust reference chapter on FFI and `unsafe`
- **Embedded Rust**: The Embedded Rust Book for `no_std` development
- **Inline Documentation**: Read `hello_world_process.rs` for detailed explanations

## Troubleshooting

**Build errors about missing symbols:**
- Ensure `contiki-sys.rs` path is correct
- Check that Rust toolchain is installed for your target

**Runtime panics:**
- Check the panic handler output for file/line information
- Verify timer initialization in `PROCESS_EVENT_INIT`

**Counter doesn't increment:**
- Ensure both `#[no_mangle]` and `#[used]` are on each static variable
- Verify LTO settings in `Cargo.toml`

## Next Steps

After understanding this example, you can:

1. **Add more event handlers** - Handle button presses, network events, etc.
2. **Use peripherals** - Access LEDs, sensors, radios through `contiki-sys`
3. **Implement protocols** - Build on Contiki-NG's networking stack
4. **Optimize for size** - Experiment with Cargo profile settings

See other examples in `examples/rust/` for more advanced patterns.
