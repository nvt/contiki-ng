# Rust Support for Contiki-NG

Write safe, efficient Rust code for IoT devices with Contiki-NG's integrated Rust support.

## Features

- **Zero-cost abstractions** - Type safety without runtime overhead
- **Automatic source detection** - Just create `.rs` files, no manual configuration
- **Type-safe APIs** - Safe wrappers for timers, LEDs, clocks, and more
- **Size-optimized builds** - Aggressive LTO and size optimization for embedded
- **Testing infrastructure** - Unit tests that run on native platform
- **Size monitoring** - Built-in tools to track code size impact
- **Comprehensive documentation** - SIZE_GUIDE.md with optimization tips

## Quick Start

### 1. Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Target platforms are installed automatically when needed!

### 2. Enable Rust in Your Project

In your application's `Makefile`:

```makefile
CONTIKI_PROJECT = my-app
all: $(CONTIKI_PROJECT)

# Enable Rust support - that's it!
RUST_SUPPORT = 1

CONTIKI = ../..
include $(CONTIKI)/Makefile.include
```

### 3. Create a Rust Module

Create `my_module.rs` in your project directory (it will be auto-detected):

```rust
#![no_std]
#![no_main]

use core::ffi::c_char;
use core::panic::PanicInfo;

// String macro for FFI
macro_rules! c_str {
    ($s:expr) => {{
        static S: &[u8] = concat!($s, "\0").as_bytes();
        S.as_ptr() as *const c_char
    }};
}

extern "C" {
    fn printf(format: *const c_char, ...) -> i32;
}

/// Exported function callable from C
#[no_mangle]
pub extern "C" fn rust_hello() {
    unsafe {
        printf(c_str!("Hello from Rust!\n"));
    }
}

/// Required panic handler for no_std
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
```

### 4. Call from C Code

In your `main.c`:

```c
// Declare the Rust function
extern void rust_hello(void);

PROCESS_THREAD(my_process, ev, data) {
  PROCESS_BEGIN();

  rust_hello();  // Call Rust!

  PROCESS_END();
}
```

### 5. Build and Run

```bash
make TARGET=native
./build/native/my-app.native
```

## Using the Contiki-NG API from Rust

The `contiki_sys` library provides type-safe wrappers:

```rust
// No need to manually import - already available!
// Just use the FFI functions and wrappers

/// Example: Blink LED using safe wrapper
#[no_mangle]
pub extern "C" fn rust_blink_led() {
    use core::ffi::c_uint;

    extern "C" {
        fn leds_toggle(leds: u8);
        fn clock_wait(ticks: c_uint);
        static CLOCK_SECOND: c_uint;
    }

    unsafe {
        loop {
            leds_toggle(1); // Toggle LED
            clock_wait(CLOCK_SECOND); // Wait 1 second
        }
    }
}
```

### Available APIs

See `contiki-sys.rs` for the complete API. Highlights:

**Timers:**
- `etimer_set()`, `etimer_expired()`, `etimer_reset()`
- `clock_time()`, `clock_seconds()`, `clock_wait()`
- Type-safe `ETimer` wrapper

**LEDs:**
- `leds_on()`, `leds_off()`, `leds_toggle()`, `leds_get()`
- Constants: `LEDS_GREEN`, `LEDS_RED`, `LEDS_BLUE`, `LEDS_ALL`

**Random Numbers:**
- `random_rand()`, `random_init()`
- `Random::rand_range()` helper

**GPIO:**
- `gpio_hal_arch_write_pin()`, `gpio_hal_arch_read_pin()`
- `gpio_hal_arch_set_pin()`, `gpio_hal_arch_clear_pin()`

**I/O:**
- `printf()`, `puts()`, `putchar()`

**Data Structures:**
- `StaticBuffer<N>` - Fixed-size buffers without heap allocation

## Development Workflow

### Testing

```bash
# Run all tests (native platform only)
make rust-test

# Run library tests only
make rust-test-lib
```

### Size Monitoring

```bash
# Show individual module sizes
make rust-size

# Show total ROM/RAM usage
make rust-size-report
```

Example output:
```
=== Total Rust Code Size ===
Total text (code):  394 bytes
Total data (initialized): 0 bytes
Total bss (uninitialized): 0 bytes
Total ROM usage: 394 bytes
Total RAM usage: 0 bytes
```

### Size Optimization

See **`SIZE_GUIDE.md`** in this directory for:
- Feature cost table (ROM/RAM per construct)
- Before/after optimization examples
- Best practices for embedded Rust
- Common pitfalls and solutions

## Supported Platforms

| Platform | Target | Status |
|----------|--------|--------|
| Native (Linux/macOS) | Auto-detected | Supported |
| ARM Cortex-M3 (zoul, cc2538dk) | thumbv7m-none-eabi | Supported |
| ARM Cortex-M4F (nrf52840) | thumbv7em-none-eabihf | Supported |
| MSP430 (sky, z1) | msp430-none-elf | Experimental |

Targets are installed automatically via `rustup` when needed.

## Examples

### Complete Examples

**`examples/rust-hello-world/`** - Comprehensive example demonstrating:
- FFI between C and Rust
- Static buffers
- Random number generation
- Data processing
- Unit testing
- All available APIs

### Common Patterns

#### Static Variables (No Heap)

```rust
static mut COUNTER: u32 = 0;

#[no_mangle]
pub extern "C" fn increment() -> u32 {
    unsafe {
        COUNTER += 1;
        COUNTER
    }
}
```

#### Fixed-Size Buffers

```rust
static mut BUFFER: [u8; 128] = [0; 128];

#[no_mangle]
pub extern "C" fn store_data(data: u8, index: usize) -> bool {
    unsafe {
        if index < 128 {
            BUFFER[index] = data;
            true
        } else {
            false
        }
    }
}
```

#### Safe Error Handling

```rust
#[no_mangle]
pub extern "C" fn divide(a: i32, b: i32, result: *mut i32) -> bool {
    if b == 0 || result.is_null() {
        return false; // Error
    }

    unsafe {
        *result = a / b;
    }
    true // Success
}
```

## Best Practices

### DO

- **Use static memory** - No heap allocation needed
- **Add unit tests** - `#[cfg(test)]` modules compile on native only
- **Monitor code size** - Use `make rust-size-report` regularly
- **Read SIZE_GUIDE.md** - Learn optimization techniques
- **Validate FFI inputs** - Check for null pointers, bounds, etc.

### DON'T

- **Avoid format macros** - `format!()` pulls in ~2 KB of code
- **Avoid Vec/String** - Use static arrays or `StaticBuffer<N>`
- **Avoid complex iterators** - Simple loops are smaller
- **Don't use debug formatting** - `{:?}` adds significant size

## Advanced Features

### Optional Allocator

Enable heap allocation if needed (adds ~100 bytes):

```toml
# In your Cargo.toml
[dependencies.contiki-sys]
features = ["allocator"]
```

### Custom Panic Handler

Provide detailed panic info for debugging:

```rust
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    unsafe {
        if let Some(location) = info.location() {
            printf(c_str!("PANIC at %s:%u\n"),
                   location.file().as_ptr(),
                   location.line());
        }
    }
    loop {}
}
```

## Troubleshooting

### "Target not found" error

The build system automatically installs targets. If you get this error:
```bash
rustup target add thumbv7m-none-eabi  # For ARM Cortex-M3
```

### Linker errors about missing symbols

Make sure you have a `#[panic_handler]` in your Rust code:
```rust
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
```

### Code size too large

Run `make rust-size-report` and see `SIZE_GUIDE.md` for optimization tips.

## Documentation

- **`SIZE_GUIDE.md`** - Comprehensive code size optimization guide
- **`examples/rust-hello-world/README.md`** - Complete example documentation
- **`contiki-sys.rs`** - API reference with inline documentation

## Getting Help

- **Example:** Start with `examples/rust-hello-world/`
- **Size optimization:** Read `SIZE_GUIDE.md`
- **API reference:** See `contiki-sys.rs`
- **Contiki-NG docs:** https://docs.contiki-ng.org/

## Contributing

Rust support is actively maintained. Contributions welcome for:
- Additional FFI bindings
- Platform support improvements
- Documentation enhancements
- Example applications
