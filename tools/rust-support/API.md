# Contiki-NG Rust Support Library API Reference

**Version:** 1.0
**Module:** `contiki-sys`
**Target:** `no_std` embedded environments

## Overview

The `contiki-sys` library provides safe Rust bindings for Contiki-NG, an operating system for IoT devices. It offers:

- **FFI bindings** to Contiki-NG C APIs
- **Safe wrapper functions** that hide unsafe operations
- **Type-safe abstractions** for common operations
- **Zero-cost abstractions** suitable for embedded systems
- **Macros** for ergonomic process development

---

## Table of Contents

1. [Core Types](#core-types)
2. [Process Management](#process-management)
3. [Timer APIs](#timer-apis)
4. [Clock APIs](#clock-apis)
5. [I/O Functions](#io-functions)
6. [LED Control](#led-control)
7. [Random Number Generation](#random-number-generation)
8. [Utility Types](#utility-types)
9. [Macros](#macros)
10. [Complete Examples](#complete-examples)

---

## Core Types

### Process Types

```rust
pub type process_event_t = u8;
pub type process_data_t = *mut c_void;
pub type c_int = i32;
pub type c_uint = u32;
pub type c_char = i8;
```

### Clock Types

```rust
pub type clock_time_t = c_uint;
```

Represents clock ticks. Use `clock_second()` to convert to/from seconds.

### Timer Structures

#### `timer`
```rust
#[repr(C)]
pub struct timer {
    pub start: clock_time_t,
    pub interval: clock_time_t,
}
```

Basic timer structure tracking start time and interval.

#### `etimer` (Event Timer)
```rust
#[repr(C)]
pub struct etimer {
    pub timer: timer,
    pub next: *mut etimer,
    pub p: *mut process,
}
```

Event timer that posts events when it expires. Initialize as:

```rust
static mut TIMER: etimer = etimer {
    timer: timer {
        start: 0,
        interval: 0,
    },
    next: core::ptr::null_mut(),
    p: core::ptr::null_mut(),
};
```

---

## Process Management

### Process Events

Standard Contiki-NG process events:

```rust
pub const PROCESS_EVENT_NONE: process_event_t = 0x80;
pub const PROCESS_EVENT_INIT: process_event_t = 0x81;      // Process initialization
pub const PROCESS_EVENT_POLL: process_event_t = 0x82;      // Process poll request
pub const PROCESS_EVENT_EXIT: process_event_t = 0x83;      // Process exit
pub const PROCESS_EVENT_TIMER: process_event_t = 0x88;     // Timer expired
pub const PROCESS_EVENT_MAX: process_event_t = 0x8a;
```

### Protothread States

Return values for process handlers:

```rust
pub const PT_WAITING: c_int = 0;    // Waiting for event
pub const PT_YIELDED: c_int = 1;    // Yielded, continue processing
pub const PT_EXITED: c_int = 2;     // Process exited
pub const PT_ENDED: c_int = 3;      // Process ended
```

### Process Handler Signature

```rust
pub extern "C" fn handler(
    ev: process_event_t,
    data: process_data_t
) -> c_int
```

**Returns:**
- `PT_YIELDED` - Continue processing events
- `PT_ENDED` - Terminate process

### RustProcess Trait

High-level trait for creating stateful processes:

```rust
pub trait RustProcess {
    fn init(&mut self);
    fn handle_event(&mut self, ev: process_event_t, data: process_data_t) -> bool;
}
```

**Example:**
```rust
struct MyProcess {
    counter: u32,
}

impl MyProcess {
    const fn new() -> Self {
        Self { counter: 0 }
    }
}

impl RustProcess for MyProcess {
    fn init(&mut self) {
        print(c_str!("Process initialized\n"));
    }

    fn handle_event(&mut self, ev: process_event_t, _data: process_data_t) -> bool {
        match ev {
            PROCESS_EVENT_TIMER => {
                self.counter += 1;
                true  // Continue
            }
            _ => true
        }
    }
}

rust_process!(my_handler, MyProcess);
```

---

## Timer APIs

### High-Level Timer Functions (Recommended)

These safe wrappers hide unsafe operations:

#### `timer_set`
```rust
pub fn timer_set(timer: &mut etimer, interval: clock_time_t)
```

Start a timer that will fire after `interval` clock ticks.

**Example:**
```rust
// Fire after 2 seconds
unsafe {
    timer_set(&mut TIMER, clock_second() * 2);
}
```

#### `timer_expired`
```rust
pub fn timer_expired(timer: &mut etimer) -> bool
```

Check if a timer has expired. Returns `true` if expired.

**Example:**
```rust
unsafe {
    if timer_expired(&mut TIMER) {
        // Timer fired, handle event
    }
}
```

#### `timer_reset`
```rust
pub fn timer_reset(timer: &mut etimer)
```

Reset timer to its original interval, starting from now.

**Example:**
```rust
unsafe {
    timer_reset(&mut TIMER);  // Restart with same interval
}
```

### Type-Safe ETimer Wrapper

For safer timer management:

```rust
pub struct ETimer(*mut etimer);

impl ETimer {
    pub unsafe fn new(timer: *mut etimer) -> Self;
    pub fn set(&mut self, interval: clock_time_t);
    pub fn expired(&self) -> bool;
    pub fn reset(&mut self);
    pub fn restart(&mut self);
    pub fn stop(&mut self);
    pub fn expiration_time(&self) -> clock_time_t;
    pub fn start_time(&self) -> clock_time_t;
}
```

**Example:**
```rust
static mut TIMER: etimer = /* ... */;

unsafe {
    let mut timer = ETimer::new(&mut TIMER);
    timer.set(clock_second() * 5);

    // Later...
    if timer.expired() {
        timer.reset();
    }
}
```

### Low-Level Timer FFI

Direct C bindings (use wrappers instead when possible):

```rust
extern "C" {
    pub fn etimer_set(et: *mut etimer, interval: clock_time_t);
    pub fn etimer_reset(et: *mut etimer);
    pub fn etimer_restart(et: *mut etimer);
    pub fn etimer_stop(et: *mut etimer);
    pub fn etimer_expiration_time(et: *mut etimer) -> clock_time_t;
    pub fn etimer_start_time(et: *mut etimer) -> clock_time_t;
}
```

---

## Clock APIs

### High-Level Clock Wrapper

```rust
pub struct Clock;

impl Clock {
    pub fn time() -> clock_time_t;        // Current clock ticks
    pub fn seconds() -> c_uint;           // Seconds since boot
    pub fn wait(t: clock_time_t);         // Blocking wait
}
```

**Example:**
```rust
let now = Clock::time();
let uptime = Clock::seconds();
Clock::wait(clock_second());  // Wait 1 second
```

### Core Clock Functions

#### `clock_second`
```rust
pub fn clock_second() -> clock_time_t
```

Returns the number of clock ticks per second (platform-dependent).

**Example:**
```rust
let ticks_per_second = clock_second();
let five_seconds = clock_second() * 5;
```

#### Low-Level Clock FFI

```rust
extern "C" {
    pub fn clock_time() -> clock_time_t;
    pub fn clock_seconds() -> c_uint;
    pub fn clock_wait(t: clock_time_t);
}
```

---

## I/O Functions

### High-Level Print Functions (Recommended)

#### `print`
```rust
pub fn print(msg: *const c_char)
```

Print a C string to console. Use with `c_str!` macro.

**Example:**
```rust
print(c_str!("Hello from Rust!\n"));
```

#### `print_u32`
```rust
pub fn print_u32(format: *const c_char, value: u32)
```

Print a formatted message with a u32 value.

**Example:**
```rust
print_u32(c_str!("Counter: %lu\n"), 42);
print_u32(c_str!("Value: %u\n"), my_var);
```

### Low-Level I/O FFI

```rust
extern "C" {
    pub fn printf(format: *const c_char, ...) -> c_int;
    pub fn puts(s: *const c_char) -> c_int;
    pub fn putchar(c: c_int) -> c_int;
}
```

---

## LED Control

### Type-Safe LED Wrapper

```rust
pub struct Leds;

impl Leds {
    pub fn on(leds: u8);       // Turn on specific LEDs
    pub fn off(leds: u8);      // Turn off specific LEDs
    pub fn toggle(leds: u8);   // Toggle specific LEDs
    pub fn get() -> u8;        // Get current LED state
}
```

### LED Constants

```rust
pub const LEDS_GREEN: u8 = 1;
pub const LEDS_YELLOW: u8 = 2;
pub const LEDS_RED: u8 = 4;
pub const LEDS_BLUE: u8 = 8;
pub const LEDS_ALL: u8 = 15;
```

**Example:**
```rust
Leds::on(LEDS_GREEN);                    // Turn on green LED
Leds::toggle(LEDS_RED | LEDS_BLUE);      // Toggle red and blue
Leds::off(LEDS_ALL);                     // Turn off all LEDs

let state = Leds::get();                 // Read current state
```

---

## Random Number Generation

### Type-Safe Random Wrapper

```rust
pub struct Random;

impl Random {
    pub fn init(seed: c_uint);              // Initialize RNG
    pub fn rand() -> c_uint;                 // Generate random number
    pub fn rand_range(max: c_uint) -> c_uint; // Random in [0, max)
}
```

**Example:**
```rust
Random::init(42);                    // Seed RNG
let value = Random::rand();          // Random u32
let dice = Random::rand_range(6) + 1; // Random 1-6
```

### Low-Level Random FFI

```rust
extern "C" {
    pub fn random_init(seed: c_uint);
    pub fn random_rand() -> c_uint;
}
```

---

## Utility Types

### StaticBuffer

Fixed-size buffer with compile-time size (zero heap allocation):

```rust
pub struct StaticBuffer<const N: usize> {
    data: [u8; N],
    len: usize,
}

impl<const N: usize> StaticBuffer<N> {
    pub const fn new() -> Self;
    pub fn push(&mut self, byte: u8) -> Result<(), ()>;
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn is_full(&self) -> bool;
    pub const fn capacity(&self) -> usize;
    pub fn clear(&mut self);
    pub fn as_slice(&self) -> &[u8];
    pub fn as_mut_slice(&mut self) -> &mut [u8];
    pub fn as_ptr(&self) -> *const u8;
}
```

**Example:**
```rust
let mut buffer = StaticBuffer::<64>::new();
buffer.push(b'H').unwrap();
buffer.push(b'i').unwrap();

print_cstr(buffer.as_slice());
```

---

## Macros

### `c_str!`

Create a null-terminated C string in static memory (`.rodata`).

**Signature:**
```rust
macro_rules! c_str {
    ($s:expr) => { ... }
}
```

**Example:**
```rust
print(c_str!("Hello, World!\n"));
print_u32(c_str!("Value: %u\n"), 42);
```

**Benefits:**
- Zero stack usage
- Stored in read-only memory
- Automatic null-termination

### `rust_process!`

Generate process handler boilerplate for `RustProcess` trait.

**Signature:**
```rust
macro_rules! rust_process {
    ($name:ident, $state_type:ty) => { ... }
}
```

**Example:**
```rust
struct MyProcess { counter: u32 }

impl MyProcess {
    const fn new() -> Self { Self { counter: 0 } }
}

impl RustProcess for MyProcess {
    fn init(&mut self) { /* ... */ }
    fn handle_event(&mut self, ev: process_event_t, data: process_data_t) -> bool {
        true
    }
}

rust_process!(my_process_handler, MyProcess);
```

### Protothread Macros

```rust
PROCESS_BEGIN!()                      // Start process
PROCESS_END!()                        // End process
PROCESS_WAIT_EVENT!()                 // Wait for event
PROCESS_WAIT_EVENT_UNTIL!($cond)      // Wait until condition
```

---

## Complete Examples

### Example 1: Simple Timer Process

```rust
#![no_std]
#![no_main]

#[path = "../../../tools/rust-support/contiki-sys.rs"]
mod contiki_sys;

use contiki_sys::*;

static mut TIMER: etimer = etimer {
    timer: timer { start: 0, interval: 0 },
    next: core::ptr::null_mut(),
    p: core::ptr::null_mut(),
};

static mut COUNTER: u32 = 0;

#[no_mangle]
pub extern "C" fn my_handler(ev: process_event_t, _data: process_data_t) -> c_int {
    match ev {
        PROCESS_EVENT_INIT => {
            print(c_str!("Timer process started\n"));
            unsafe {
                timer_set(&mut TIMER, clock_second() * 2);
            }
            PT_YIELDED
        }

        PROCESS_EVENT_TIMER => {
            unsafe {
                if timer_expired(&mut TIMER) {
                    COUNTER += 1;
                    print_u32(c_str!("Tick %lu\n"), COUNTER);

                    if COUNTER >= 10 {
                        print(c_str!("Done!\n"));
                        return PT_ENDED;
                    }

                    timer_reset(&mut TIMER);
                }
            }
            PT_YIELDED
        }

        _ => PT_YIELDED,
    }
}
```

### Example 2: LED Blinker

```rust
#[no_mangle]
pub extern "C" fn blink_handler(ev: process_event_t, _data: process_data_t) -> c_int {
    match ev {
        PROCESS_EVENT_INIT => {
            unsafe {
                timer_set(&mut TIMER, clock_second());
            }
            PT_YIELDED
        }

        PROCESS_EVENT_TIMER => {
            unsafe {
                if timer_expired(&mut TIMER) {
                    Leds::toggle(LEDS_GREEN);
                    timer_reset(&mut TIMER);
                }
            }
            PT_YIELDED
        }

        _ => PT_YIELDED,
    }
}
```

### Example 3: Using RustProcess Trait

```rust
struct SensorProcess {
    sample_count: u32,
    timer: etimer,
}

impl SensorProcess {
    const fn new() -> Self {
        Self {
            sample_count: 0,
            timer: etimer {
                timer: timer { start: 0, interval: 0 },
                next: core::ptr::null_mut(),
                p: core::ptr::null_mut(),
            },
        }
    }
}

impl RustProcess for SensorProcess {
    fn init(&mut self) {
        print(c_str!("Sensor process initialized\n"));
        unsafe {
            timer_set(&mut self.timer, clock_second() * 5);
        }
    }

    fn handle_event(&mut self, ev: process_event_t, _data: process_data_t) -> bool {
        match ev {
            PROCESS_EVENT_TIMER => {
                unsafe {
                    if timer_expired(&mut self.timer) {
                        self.sample_count += 1;
                        print_u32(c_str!("Sample %lu\n"), self.sample_count);
                        timer_reset(&mut self.timer);
                    }
                }
                true
            }
            _ => true,
        }
    }
}

rust_process!(sensor_handler, SensorProcess);
```

### Example 4: Random Number Generation

```rust
#[no_mangle]
pub extern "C" fn random_handler(ev: process_event_t, _data: process_data_t) -> c_int {
    match ev {
        PROCESS_EVENT_INIT => {
            let seed = Clock::time();
            Random::init(seed);

            for _ in 0..5 {
                let value = Random::rand_range(100);
                print_u32(c_str!("Random: %u\n"), value);
            }

            PT_ENDED
        }
        _ => PT_YIELDED,
    }
}
```

---

## Safety Considerations

### When to Use `unsafe`

1. **Accessing `static mut` variables** - Required by Rust
2. **Calling FFI functions** - Only if using low-level bindings

### When `unsafe` is NOT Required

- Using high-level wrappers: `print()`, `print_u32()`, `timer_set()`, etc.
- Using type-safe structs: `Leds`, `Clock`, `Random`, `ETimer`
- Creating C strings with `c_str!` macro

### Safety Guarantees in Contiki-NG

The Rust wrappers are safe because:
- **Single-threaded execution** - No concurrent access
- **Event-driven model** - Sequential event processing
- **No interrupts modifying state** - Unless explicitly designed

Document these invariants with `// SAFETY:` comments when using `unsafe`.

---

## Platform Support

Tested on:
- **Native** (Linux/macOS) - For development and testing
- **CC2538DK** - Texas Instruments ARM Cortex-M3
- **Zoul** - Zolertia IoT platform
- **nRF52840** - Nordic Semiconductor ARM Cortex-M4

---

## Building with Rust

Add to your example's `Makefile`:

```makefile
# Enable Rust support
RUST_SUPPORT = 1
include $(CONTIKI)/tools/rust-support/Makefile.rust

# Your Rust source files
RUST_SOURCES = hello_world_process.rs
```

Build as usual:
```bash
make TARGET=native
make TARGET=cc2538dk
```

---

## Additional Resources

- **Contiki-NG Documentation:** https://docs.contiki-ng.org/
- **Rust Embedded Book:** https://docs.rust-embedded.org/book/
- **Example Code:** `examples/rust/hello-world/`

---

## License

Same as Contiki-NG (3-clause BSD license)
