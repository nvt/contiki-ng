# Contiki-NG Rust Support Library API Reference

**Version:** 2.0
**Module:** `contiki-sys`
**Target:** `no_std` embedded environments

## Overview

The `contiki-sys` library provides safe Rust bindings for Contiki-NG, an operating system for IoT devices. It offers:

- **FFI bindings** to Contiki-NG C APIs
- **Safe wrapper functions** that hide unsafe operations
- **Type-safe abstractions** for common operations
- **Zero-cost abstractions** suitable for embedded systems
- **Result-based error handling** for robust applications
- **Comprehensive networking support** (UDP, RPL, TSCH)
- **Energy monitoring** and power management
- **Storage APIs** for persistent data
- **Macros** for ergonomic process development

---

## Table of Contents

1. [Core Types](#core-types)
2. [Error Handling](#error-handling)
3. [Process Management](#process-management)
4. [Timer APIs](#timer-apis)
5. [Clock APIs](#clock-apis)
6. [I/O Functions](#io-functions)
7. [LED Control](#led-control)
8. [Random Number Generation](#random-number-generation)
9. [Networking APIs](#networking-apis)
10. [Sensor APIs](#sensor-apis)
11. [Energy Monitoring (Energest)](#energy-monitoring-energest)
12. [Logging APIs](#logging-apis)
13. [Packet Buffer (Packetbuf)](#packet-buffer-packetbuf)
14. [TSCH (Time-Slotted Channel Hopping)](#tsch-time-slotted-channel-hopping)
15. [Storage (CFS)](#storage-cfs)
16. [Utility Types](#utility-types)
17. [Macros](#macros)
18. [Complete Examples](#complete-examples)

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

---

## Error Handling

### Result Type

```rust
pub type Result<T> = core::result::Result<T, Error>;
```

All fallible operations return `Result<T>` for robust error handling.

### Error Type

```rust
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidParameter,
    BufferOverflow,
    NotAvailable,
    OperationFailed,
    NullPointer,
    TimerError,
    ProcessError,
    NetworkError,
}
```

Each error variant includes a descriptive string accessible via `error.as_str()`.

**Example:**
```rust
match conn.register(8765, None, 0, Some(callback)) {
    Ok(()) => print(c_str!("Success\n")),
    Err(e) => {
        print(c_str!("Error: "));
        print(c_str!(e.as_str()));
        print(c_str!("\n"));
    }
}
```

---

## Process Management

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

## Networking APIs

### Simple UDP

Type-safe wrapper for UDP networking with IPv6 support.

#### IPv6 Address Type

```rust
#[repr(C)]
pub union uip_ipaddr_t {
    pub u8: [u8; 16],
    pub u16: [u16; 8],
}

impl uip_ipaddr_t {
    pub fn from_bytes(bytes: [u8; 16]) -> Self;
    pub fn as_bytes(&self) -> &[u8; 16];
    pub fn is_null(&self) -> bool;
}
```

#### SimpleUdpConnection

```rust
pub struct SimpleUdpConnection {
    pub inner: simple_udp_connection,
    pub registered: bool,
}

impl SimpleUdpConnection {
    pub fn new() -> Self;

    pub fn register(
        &mut self,
        local_port: u16,
        remote_addr: Option<&uip_ipaddr_t>,
        remote_port: u16,
        receive_callback: simple_udp_callback
    ) -> Result<()>;

    pub fn send(&mut self, data: &[u8]) -> Result<()>;
    pub fn send_to(&mut self, data: &[u8], to: &uip_ipaddr_t) -> Result<()>;
    pub fn send_to_port(&mut self, data: &[u8], to: &uip_ipaddr_t, to_port: u16) -> Result<()>;
}
```

**Example:**
```rust
static mut UDP_CONN: simple_udp_connection = /* ... */;

unsafe extern "C" fn udp_rx_callback(
    c: *mut simple_udp_connection,
    sender_addr: *const uip_ipaddr_t,
    sender_port: u16,
    receiver_addr: *const uip_ipaddr_t,
    receiver_port: u16,
    data: *const u8,
    datalen: u16,
) {
    // Handle received packet
}

// In process init:
let mut conn = SimpleUdpConnection::new();
conn.register(8765, None, 0, Some(udp_rx_callback))?;

// Send data
conn.send(b"Hello, World!")?;
```

### RPL Routing

Routing Protocol for Low-Power and Lossy Networks.

#### RplDagRoot

```rust
pub struct RplDagRoot;

impl RplDagRoot {
    pub fn set_prefix(prefix: Option<&uip_ipaddr_t>, iid: Option<&uip_ipaddr_t>);
    pub fn start() -> Result<()>;
    pub fn is_root() -> bool;
}
```

#### Rpl

```rust
pub struct Rpl;

impl Rpl {
    pub fn get_global_address() -> Result<&'static uip_ipaddr_t>;
    pub fn is_reachable() -> bool;
    pub fn set_leaf_only(leaf_only: bool);
}
```

**Example:**
```rust
// Configure as DAG root
RplDagRoot::set_prefix(Some(&prefix), Some(&iid));
RplDagRoot::start()?;

// Check if we're the root
if RplDagRoot::is_root() {
    print(c_str!("I am the DAG root\n"));
}

// Get global IPv6 address
if let Ok(addr) = Rpl::get_global_address() {
    print(c_str!("My address: "));
    Log::ip6addr_compact(addr);
    print(c_str!("\n"));
}
```

---

## Sensor APIs

### Sensor

Generic sensor interface for reading hardware sensors.

```rust
pub struct Sensor {
    inner: *const sensors_sensor,
}

impl Sensor {
    pub fn find(type_name: *const c_char) -> Result<Self>;
    pub fn activate(&self) -> Result<()>;
    pub fn deactivate(&self) -> Result<()>;
    pub fn value(&self, type_: c_int) -> Result<c_int>;
    pub fn status(&self, type_: c_int) -> Result<c_int>;
}
```

**Example:**
```rust
// Find temperature sensor
let sensor = Sensor::find(c_str!("temp"))?;
sensor.activate()?;

// Read value
let temp = sensor.value(0)?;
print_u32(c_str!("Temperature: %d\n"), temp as u32);

sensor.deactivate()?;
```

### Button HAL

Hardware abstraction for buttons with event support.

```rust
pub struct ButtonHal;

impl ButtonHal {
    pub fn init();
    pub fn get_by_index(index: u8) -> Option<&'static button_hal_button>;
    pub fn get_by_id(id: *const c_char) -> Option<&'static button_hal_button>;
}
```

**Button Events:**
```rust
pub static button_hal_press_event: process_event_t;
pub static button_hal_release_event: process_event_t;
pub static button_hal_periodic_event: process_event_t;
```

**Example:**
```rust
ButtonHal::init();

// In event handler
match ev {
    ev if ev == unsafe { button_hal_press_event } => {
        print(c_str!("Button pressed!\n"));
    }
    _ => {}
}
```

---

## Energy Monitoring (Energest)

Track power consumption across different device states.

### Energest

```rust
pub struct Energest;

impl Energest {
    pub fn init();
    pub fn flush();
    pub fn type_time(type_: energest_type_t) -> u64;
    pub fn type_set(type_: energest_type_t, value: u64);
    pub fn on(type_: energest_type_t);
    pub fn off(type_: energest_type_t);
    pub fn switch(type_off: energest_type_t, type_on: energest_type_t);
    pub fn get_total_time() -> u64;
    pub fn percentage(type_: energest_type_t) -> f32;
    pub fn snapshot() -> [u64; 5];
    pub fn reset_all();
}
```

### Energy Types

```rust
pub enum energest_type_t {
    CPU = 0,
    LPM = 1,         // Low-Power Mode
    DEEP_LPM = 2,    // Deep Low-Power Mode
    TRANSMIT = 3,    // Radio transmit
    LISTEN = 4,      // Radio receive/listen
    MAX = 5,
}
```

**Example:**
```rust
use energest_type_t::*;

Energest::init();

// Track transmission time
Energest::on(TRANSMIT);
// ... do transmission ...
Energest::off(TRANSMIT);

// Get statistics
let tx_time = Energest::type_time(TRANSMIT);
let tx_percent = Energest::percentage(TRANSMIT);

print_u32(c_str!("TX time: %lu ticks\n"), tx_time as u32);

// Get all measurements at once
let snapshot = Energest::snapshot();
print_u32(c_str!("CPU: %lu\n"), snapshot[0] as u32);
```

---

## Logging APIs

Structured logging with multiple levels and specialized formatting.

### Log Levels

```rust
pub const LOG_LEVEL_NONE: c_int = 0;
pub const LOG_LEVEL_ERR: c_int = 1;
pub const LOG_LEVEL_WARN: c_int = 2;
pub const LOG_LEVEL_INFO: c_int = 3;
pub const LOG_LEVEL_DBG: c_int = 4;
```

### Log

```rust
pub struct Log;

impl Log {
    pub fn lladdr(lladdr: &linkaddr_t);
    pub fn lladdr_compact(lladdr: &linkaddr_t);
    pub fn ip6addr(ipaddr: &uip_ipaddr_t);
    pub fn ip6addr_compact(ipaddr: &uip_ipaddr_t);
    pub unsafe fn ip6addr_to_buffer(buf: &mut [u8], ipaddr: &uip_ipaddr_t) -> Result<usize>;
    pub fn bytes(data: &[u8]);
    pub fn string(text: &[u8]);
    pub fn set_level(module: *const c_char, level: c_int);
    pub fn get_level(module: *const c_char) -> c_int;
    pub fn level_to_str(level: c_int) -> *const c_char;
}
```

**Example:**
```rust
// Log addresses
let mac_addr = linkaddr_t::from_bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
Log::lladdr_compact(&mac_addr);

// Log IPv6 address
if let Ok(addr) = Rpl::get_global_address() {
    Log::ip6addr_compact(addr);
}

// Log hex dump
let packet = [0xCA, 0xFE, 0xBA, 0xBE];
Log::bytes(&packet);

// Configure logging
Log::set_level(c_str!("rpl"), LOG_LEVEL_DBG);
```

---

## Packet Buffer (Packetbuf)

Safe packet buffer management for MAC-layer operations.

### Packetbuf

```rust
pub struct Packetbuf;

impl Packetbuf {
    pub fn clear();
    pub fn data_mut() -> &'static mut [u8];
    pub fn data() -> &'static [u8];
    pub fn header() -> &'static [u8];
    pub fn data_len() -> usize;
    pub fn header_len() -> usize;
    pub fn total_len() -> usize;
    pub fn remaining_len() -> usize;
    pub fn set_data_len(len: usize);
    pub fn copy_from(data: &[u8]) -> Result<usize>;
    pub fn copy_to(buf: &mut [u8]) -> Result<usize>;
    pub fn hdr_alloc(size: usize) -> Result<()>;
    pub fn hdr_reduce(size: usize) -> Result<()>;
    pub fn set_attr(attr_type: u8, value: u16);
    pub fn attr(attr_type: u8) -> u16;
    pub fn set_addr(addr_type: u8, addr: &linkaddr_t);
    pub fn addr(addr_type: u8) -> Option<&'static linkaddr_t>;
    pub fn is_broadcast() -> bool;
    pub fn clear_attrs();
}
```

### Packet Attributes

```rust
pub const PACKETBUF_ATTR_CHANNEL: u8 = 1;
pub const PACKETBUF_ATTR_NETWORK_ID: u8 = 2;
pub const PACKETBUF_ATTR_LINK_QUALITY: u8 = 3;
pub const PACKETBUF_ATTR_RSSI: u8 = 4;
pub const PACKETBUF_ATTR_MAX_MAC_TRANSMISSIONS: u8 = 5;
pub const PACKETBUF_ADDR_SENDER: u8 = 12;
pub const PACKETBUF_ADDR_RECEIVER: u8 = 13;
```

**Example:**
```rust
// Prepare a packet
Packetbuf::clear();
Packetbuf::copy_from(b"Hello, World!")?;

// Add header
Packetbuf::hdr_alloc(10)?;

// Set attributes
Packetbuf::set_attr(PACKETBUF_ATTR_CHANNEL, 26);

// Set addresses
let sender = linkaddr_t::from_bytes([0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00]);
Packetbuf::set_addr(PACKETBUF_ADDR_SENDER, &sender);

// Check broadcast
if Packetbuf::is_broadcast() {
    print(c_str!("Broadcast packet\n"));
}
```

---

## TSCH (Time-Slotted Channel Hopping)

IEEE 802.15.4e TSCH MAC protocol for scheduled communication.

### Tsch

```rust
pub struct Tsch;

impl Tsch {
    pub fn set_join_priority(priority: u8);
    pub fn set_eb_period(period: u32);
    pub fn set_ka_timeout(timeout: u32);
    pub fn set_coordinator(enable: bool);
    pub fn set_pan_secured(enable: bool);
    pub fn schedule_keepalive(immediate: bool);
    pub fn get_network_uptime_ticks() -> u64;
    pub fn disassociate();
    pub fn is_coordinator() -> bool;
    pub fn is_associated() -> bool;
    pub fn is_pan_secured() -> bool;
}
```

### Link Types and Options

```rust
pub enum link_type {
    LINK_TYPE_NORMAL = 0,
    LINK_TYPE_ADVERTISING = 1,
    LINK_TYPE_ADVERTISING_ONLY = 2,
}

pub const LINK_OPTION_TX: u8 = 1 << 0;
pub const LINK_OPTION_RX: u8 = 1 << 1;
pub const LINK_OPTION_SHARED: u8 = 1 << 2;
pub const LINK_OPTION_TIMEKEEPING: u8 = 1 << 3;
```

**Example:**
```rust
// Configure as coordinator
Tsch::set_coordinator(true);
Tsch::set_join_priority(0x10);
Tsch::set_eb_period(clock_second() * 4);

// Check status
if Tsch::is_coordinator() {
    print(c_str!("TSCH Coordinator ready\n"));
}

if Tsch::is_associated() {
    let uptime = Tsch::get_network_uptime_ticks();
    print_u32(c_str!("Network uptime: %lu\n"), uptime as u32);
}
```

---

## Storage (CFS)

Coffee File System API for persistent storage.

### CfsFile

```rust
pub struct CfsFile {
    fd: c_int,
}

impl CfsFile {
    pub fn open(name: *const c_char, flags: c_int) -> Result<Self>;
    pub fn read(&self, buf: &mut [u8]) -> Result<usize>;
    pub fn write(&self, data: &[u8]) -> Result<usize>;
    pub fn seek(&self, offset: isize, whence: c_int) -> Result<isize>;
    pub fn close(self);
    pub fn as_raw_fd(&self) -> c_int;
}

impl Drop for CfsFile {
    fn drop(&mut self);  // Auto-closes file
}
```

### Cfs Utilities

```rust
pub struct Cfs;

impl Cfs {
    pub fn remove(name: *const c_char) -> Result<()>;
    pub fn opendir(name: *const c_char) -> Result<cfs_dir>;
    pub fn readdir(dir: &mut cfs_dir) -> Option<cfs_dirent>;
    pub fn closedir(dir: cfs_dir);
}
```

### File Flags and Seek Modes

```rust
pub const CFS_READ: c_int = 1;
pub const CFS_WRITE: c_int = 2;
pub const CFS_APPEND: c_int = 4;

pub const CFS_SEEK_SET: c_int = 0;
pub const CFS_SEEK_CUR: c_int = 1;
pub const CFS_SEEK_END: c_int = 2;
```

**Example:**
```rust
// Write to a file
{
    let file = CfsFile::open(c_str!("data.txt"), CFS_WRITE)?;
    file.write(b"Hello, World!")?;
    // File automatically closed when dropped
}

// Read from a file
{
    let file = CfsFile::open(c_str!("data.txt"), CFS_READ)?;
    let mut buf = [0u8; 64];
    let n = file.read(&mut buf)?;
    print_u32(c_str!("Read %u bytes\n"), n as u32);
}

// List directory
let mut dir = Cfs::opendir(c_str!("/"))?;
while let Some(entry) = Cfs::readdir(&mut dir) {
    print(c_str!("File: "));
    print(c_str!(entry.name_str()));
    print_u32(c_str!(" Size: %d\n"), entry.size() as u32);
}
Cfs::closedir(dir);

// Remove file
Cfs::remove(c_str!("old_data.txt"))?;
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
