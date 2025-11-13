//! FFI bindings for Contiki-NG core APIs
//! This module provides safe Rust wrappers around Contiki-NG C APIs

#![no_std]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use core::ffi::{c_char, c_void, c_int, c_uint};

// Re-export c_char for use in macros
pub use core::ffi::c_char;

// Process types
#[repr(C)]
pub struct process {
    pub next: *mut process,
    pub name: *const c_char,
    pub thread: Option<unsafe extern "C" fn(*mut pt, process_event_t, *mut c_void) -> c_int>,
    pub pt: pt,
    pub state: u8,
    pub needspoll: u8,
}

#[repr(C)]
pub struct pt {
    pub lc: lc_t,
}

pub type lc_t = u16;
pub type process_event_t = u8;
pub type process_data_t = *mut c_void;

// Clock types
pub type clock_time_t = c_uint;

// External C functions
extern "C" {
    // Process functions
    pub fn process_start(p: *mut process, data: process_data_t);
    pub fn process_exit(p: *mut process);
    pub fn process_post(p: *mut process, ev: process_event_t, data: process_data_t) -> c_int;
    pub fn process_post_synch(p: *mut process, ev: process_event_t, data: process_data_t);
    pub fn process_poll(p: *mut process);

    // Clock functions
    pub fn clock_time() -> clock_time_t;
    pub fn clock_seconds() -> c_uint;
    pub fn clock_wait(t: clock_time_t);

    // Timer functions
    pub fn etimer_set(et: *mut etimer, interval: clock_time_t);
    pub fn etimer_reset(et: *mut etimer);
    pub fn etimer_restart(et: *mut etimer);
    pub fn etimer_adjust(et: *mut etimer, timediff: c_int);
    pub fn etimer_expired(et: *mut etimer) -> c_int;
    pub fn etimer_expiration_time(et: *mut etimer) -> clock_time_t;
    pub fn etimer_start_time(et: *mut etimer) -> clock_time_t;
    pub fn etimer_stop(et: *mut etimer);

    // Print functions (for debugging)
    pub fn printf(format: *const c_char, ...) -> c_int;
    pub fn puts(s: *const c_char) -> c_int;
    pub fn putchar(c: c_int) -> c_int;

    // GPIO functions (for platforms with GPIO HAL)
    pub fn gpio_hal_arch_write_pin(pin: u8, value: u8);
    pub fn gpio_hal_arch_read_pin(pin: u8) -> u8;
    pub fn gpio_hal_arch_set_pin(pin: u8);
    pub fn gpio_hal_arch_clear_pin(pin: u8);
    pub fn gpio_hal_arch_toggle_pin(pin: u8);

    // Random number generation
    pub fn random_init(seed: c_uint);
    pub fn random_rand() -> c_uint;

    // Memory management (memb - static memory blocks)
    pub fn memb_numfree(m: *const c_void) -> c_int;

    // LED functions (commonly used in IoT)
    pub fn leds_on(leds: u8);
    pub fn leds_off(leds: u8);
    pub fn leds_toggle(leds: u8);
    pub fn leds_get() -> u8;
}

// Timer structures
#[repr(C)]
pub struct timer {
    pub start: clock_time_t,
    pub interval: clock_time_t,
}

#[repr(C)]
pub struct etimer {
    pub timer: timer,
    pub next: *mut etimer,
    pub p: *mut process,
}

// Process macros helpers
pub const PROCESS_EVENT_NONE: process_event_t = 0x80;
pub const PROCESS_EVENT_INIT: process_event_t = 0x81;
pub const PROCESS_EVENT_POLL: process_event_t = 0x82;
pub const PROCESS_EVENT_EXIT: process_event_t = 0x83;
pub const PROCESS_EVENT_SERVICE_REMOVED: process_event_t = 0x84;
pub const PROCESS_EVENT_CONTINUE: process_event_t = 0x85;
pub const PROCESS_EVENT_MSG: process_event_t = 0x86;
pub const PROCESS_EVENT_EXITED: process_event_t = 0x87;
pub const PROCESS_EVENT_TIMER: process_event_t = 0x88;
pub const PROCESS_EVENT_COM: process_event_t = 0x89;
pub const PROCESS_EVENT_MAX: process_event_t = 0x8a;

// Protothread states
pub const PT_WAITING: c_int = 0;
pub const PT_YIELDED: c_int = 1;
pub const PT_EXITED: c_int = 2;
pub const PT_ENDED: c_int = 3;

// LED constants (platform-dependent, these are common values)
pub const LEDS_GREEN: u8 = 1;
pub const LEDS_YELLOW: u8 = 2;
pub const LEDS_RED: u8 = 4;
pub const LEDS_BLUE: u8 = 8;
pub const LEDS_ALL: u8 = 15;

// Clock constant (typically defined by platform, 128 is common)
// Note: Applications should use CLOCK_SECOND from their platform config
extern "C" {
    pub static CLOCK_SECOND: clock_time_t;
}

// Helper macros for Rust

/// Create a null-terminated C string stored in static memory (.rodata)
/// This is more efficient than creating strings on the stack, especially
/// for embedded systems with limited RAM.
///
/// # Example
/// ```
/// unsafe {
///     printf(c_str!("Hello from Rust!\n"));
/// }
/// ```
#[macro_export]
macro_rules! c_str {
    ($s:expr) => {{
        // Store the string in static memory to avoid stack usage
        static S: &[u8] = concat!($s, "\0").as_bytes();
        S.as_ptr() as *const $crate::c_char
    }};
}

#[macro_export]
macro_rules! PROCESS_BEGIN {
    () => {
        {
            let mut PT_YIELD_FLAG: u8 = 1;
            if PT_YIELD_FLAG != 0 {
                return $crate::PT_YIELDED;
            }
        }
    };
}

#[macro_export]
macro_rules! PROCESS_END {
    () => {
        return $crate::PT_ENDED;
    };
}

#[macro_export]
macro_rules! PROCESS_WAIT_EVENT {
    () => {
        {
            return $crate::PT_YIELDED;
        }
    };
}

#[macro_export]
macro_rules! PROCESS_WAIT_EVENT_UNTIL {
    ($cond:expr) => {
        {
            if !($cond) {
                return $crate::PT_YIELDED;
            }
        }
    };
}

// Safe wrapper functions
pub unsafe fn print_cstr(s: &[u8]) {
    if let Some(nul_pos) = s.iter().position(|&c| c == 0) {
        puts(s[..=nul_pos].as_ptr() as *const c_char);
    }
}

// Type-safe wrappers for core APIs

/// Safe wrapper around etimer
pub struct ETimer(*mut etimer);

impl ETimer {
    /// Create a new ETimer wrapper from a raw pointer
    /// # Safety
    /// The pointer must be valid and point to an initialized etimer struct
    pub unsafe fn new(timer: *mut etimer) -> Self {
        ETimer(timer)
    }

    /// Set the timer to expire after the given interval
    pub fn set(&mut self, interval: clock_time_t) {
        unsafe { etimer_set(self.0, interval) }
    }

    /// Check if the timer has expired
    pub fn expired(&self) -> bool {
        unsafe { etimer_expired(self.0) != 0 }
    }

    /// Reset the timer to its original interval
    pub fn reset(&mut self) {
        unsafe { etimer_reset(self.0) }
    }

    /// Restart the timer from the current time
    pub fn restart(&mut self) {
        unsafe { etimer_restart(self.0) }
    }

    /// Stop the timer
    pub fn stop(&mut self) {
        unsafe { etimer_stop(self.0) }
    }

    /// Get the expiration time
    pub fn expiration_time(&self) -> clock_time_t {
        unsafe { etimer_expiration_time(self.0) }
    }

    /// Get the start time
    pub fn start_time(&self) -> clock_time_t {
        unsafe { etimer_start_time(self.0) }
    }
}

/// Safe LED control wrapper
pub struct Leds;

impl Leds {
    /// Turn on specific LEDs
    pub fn on(leds: u8) {
        unsafe { leds_on(leds) }
    }

    /// Turn off specific LEDs
    pub fn off(leds: u8) {
        unsafe { leds_off(leds) }
    }

    /// Toggle specific LEDs
    pub fn toggle(leds: u8) {
        unsafe { leds_toggle(leds) }
    }

    /// Get current LED state
    pub fn get() -> u8 {
        unsafe { leds_get() }
    }
}

/// Safe random number generator wrapper
pub struct Random;

impl Random {
    /// Initialize the random number generator with a seed
    pub fn init(seed: c_uint) {
        unsafe { random_init(seed) }
    }

    /// Generate a random number
    pub fn rand() -> c_uint {
        unsafe { random_rand() }
    }

    /// Generate a random number in the range [0, max)
    pub fn rand_range(max: c_uint) -> c_uint {
        if max == 0 {
            return 0;
        }
        unsafe { random_rand() % max }
    }
}

/// Safe clock functions wrapper
pub struct Clock;

impl Clock {
    /// Get the current clock time
    pub fn time() -> clock_time_t {
        unsafe { clock_time() }
    }

    /// Get the current time in seconds since boot
    pub fn seconds() -> c_uint {
        unsafe { clock_seconds() }
    }

    /// Wait for a specified time
    pub fn wait(t: clock_time_t) {
        unsafe { clock_wait(t) }
    }
}

/// Static buffer with compile-time size (zero runtime overhead)
/// Useful for embedded systems where heap allocation is not available
pub struct StaticBuffer<const N: usize> {
    data: [u8; N],
    len: usize,
}

impl<const N: usize> StaticBuffer<N> {
    /// Create a new empty static buffer
    pub const fn new() -> Self {
        Self {
            data: [0; N],
            len: 0,
        }
    }

    /// Push a byte to the buffer
    /// Returns Ok(()) on success, Err(()) if buffer is full
    pub fn push(&mut self, byte: u8) -> Result<(), ()> {
        if self.len < N {
            self.data[self.len] = byte;
            self.len += 1;
            Ok(())
        } else {
            Err(())
        }
    }

    /// Get the current length
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Check if buffer is full
    pub fn is_full(&self) -> bool {
        self.len == N
    }

    /// Get the buffer capacity
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// Get a slice of the current data
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Get a mutable slice of the current data
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }

    /// Get the raw data pointer (useful for FFI)
    pub fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }
}

// Panic handler for no_std
#[cfg(not(target_os = "none"))]
use core::panic::PanicInfo;

#[cfg(not(target_os = "none"))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // In embedded context, just halt
    loop {}
}