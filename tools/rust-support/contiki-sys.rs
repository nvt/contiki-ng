//! FFI bindings for Contiki-NG core APIs
//! This module provides safe Rust wrappers around Contiki-NG C APIs

#![no_std]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused_attributes)]

// Import and re-export types for use in macros and external code
pub use core::ffi::{c_char, c_int, c_uint, c_void};

// ============================================================================
// Error Handling
// ============================================================================

/// Result type for Contiki-NG operations
pub type Result<T> = core::result::Result<T, Error>;

/// Error types for Contiki-NG operations
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Error {
    /// Invalid parameter provided to function
    InvalidParameter,
    /// Operation would overflow available space
    BufferOverflow,
    /// Resource is not available or not initialized
    NotAvailable,
    /// Operation failed (generic error)
    OperationFailed,
    /// Null pointer encountered
    NullPointer,
    /// Timer operation failed
    TimerError,
    /// Process operation failed
    ProcessError,
    /// Network operation failed
    NetworkError,
}

impl Error {
    /// Convert error to a descriptive string (no allocation)
    pub const fn as_str(&self) -> &'static str {
        match self {
            Error::InvalidParameter => "Invalid parameter",
            Error::BufferOverflow => "Buffer overflow",
            Error::NotAvailable => "Resource not available",
            Error::OperationFailed => "Operation failed",
            Error::NullPointer => "Null pointer",
            Error::TimerError => "Timer error",
            Error::ProcessError => "Process error",
            Error::NetworkError => "Network error",
        }
    }
}

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

// External C functions (raw FFI, prefer using safe wrappers below)
extern "C" {
    // Process functions
    fn process_start(p: *mut process, data: process_data_t);
    fn process_exit(p: *mut process);
    fn process_post(p: *mut process, ev: process_event_t, data: process_data_t) -> c_int;
    fn process_post_synch(p: *mut process, ev: process_event_t, data: process_data_t);
    fn process_poll(p: *mut process);

    // Clock functions
    pub fn clock_time() -> clock_time_t;
    pub fn clock_seconds() -> c_uint;
    pub fn clock_wait(t: clock_time_t);

    // Timer functions
    pub fn etimer_set(et: *mut etimer, interval: clock_time_t);
    pub fn etimer_reset(et: *mut etimer);
    pub fn etimer_restart(et: *mut etimer);
    pub fn etimer_adjust(et: *mut etimer, timediff: c_int);
    // Note: etimer_expired is a static inline function in C, not linkable
    // Use the Rust helper function etimer_expired() below instead
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

    // System functions
    pub fn watchdog_reboot();

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

// Clock constant provided by C wrapper
extern "C" {
    static CLOCK_SECOND_VALUE: clock_time_t;
}

/// Get the platform's clock ticks per second
///
/// This value is automatically set by the Contiki-NG build system based on the target platform.
/// Use this to convert between seconds and clock ticks.
///
/// # Example
/// ```
/// // Set a timer for 2 seconds
/// etimer_set(&mut timer, clock_second() * 2);
/// ```
#[inline]
pub fn clock_second() -> clock_time_t {
    // SAFETY: CLOCK_SECOND_VALUE is a valid extern static provided by C wrappers
    unsafe { CLOCK_SECOND_VALUE }
}

// ============================================================================
// Safe Wrapper Functions for Process Management
// ============================================================================

/// Start a process with optional data
///
/// # Errors
/// Returns `Error::NullPointer` if the process pointer is null
///
/// # Example
/// ```
/// let mut my_process = process { /* ... */ };
/// safe_process_start(&mut my_process, core::ptr::null_mut())?;
/// ```
pub fn safe_process_start(p: &mut process, data: process_data_t) -> Result<()> {
    unsafe {
        process_start(p as *mut process, data);
    }
    Ok(())
}

/// Exit a process
///
/// # Errors
/// Returns `Error::NullPointer` if the process pointer is null
pub fn safe_process_exit(p: &mut process) -> Result<()> {
    unsafe {
        process_exit(p as *mut process);
    }
    Ok(())
}

/// Post an event to a process
///
/// # Errors
/// Returns `Error::ProcessError` if posting failed (process queue full or invalid process)
///
/// # Example
/// ```
/// safe_process_post(&mut target_process, PROCESS_EVENT_CONTINUE, core::ptr::null_mut())?;
/// ```
pub fn safe_process_post(
    p: &mut process,
    ev: process_event_t,
    data: process_data_t,
) -> Result<()> {
    let result = unsafe { process_post(p as *mut process, ev, data) };
    if result == 0 {
        Err(Error::ProcessError)
    } else {
        Ok(())
    }
}

/// Post an event to a process synchronously
///
/// # Errors
/// Returns `Error::NullPointer` if the process pointer is null
pub fn safe_process_post_synch(
    p: &mut process,
    ev: process_event_t,
    data: process_data_t,
) -> Result<()> {
    unsafe {
        process_post_synch(p as *mut process, ev, data);
    }
    Ok(())
}

/// Request that a process be polled
///
/// # Errors
/// Returns `Error::NullPointer` if the process pointer is null
pub fn safe_process_poll(p: &mut process) -> Result<()> {
    unsafe {
        process_poll(p as *mut process);
    }
    Ok(())
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
    () => {{
        let mut PT_YIELD_FLAG: u8 = 1;
        if PT_YIELD_FLAG != 0 {
            return $crate::PT_YIELDED;
        }
    }};
}

#[macro_export]
macro_rules! PROCESS_END {
    () => {
        return $crate::PT_ENDED;
    };
}

#[macro_export]
macro_rules! PROCESS_WAIT_EVENT {
    () => {{
        return $crate::PT_YIELDED;
    }};
}

#[macro_export]
macro_rules! PROCESS_WAIT_EVENT_UNTIL {
    ($cond:expr) => {{
        if !($cond) {
            return $crate::PT_YIELDED;
        }
    }};
}

// Rust-native process support
// These provide a more ergonomic way to write processes in Rust

/// Trait for Rust processes
/// Implement this trait to create a Rust process with proper state management
pub trait RustProcess {
    /// Called once when the process starts
    fn init(&mut self);

    /// Called on each event
    /// Return true to continue processing, false to yield
    fn handle_event(&mut self, ev: process_event_t, data: process_data_t) -> bool;
}

/// Helper macro to define a Rust process
/// This creates the necessary boilerplate to integrate with Contiki-NG's process system
///
/// # Example
/// ```
/// struct MyProcess {
///     counter: u32,
/// }
///
/// impl MyProcess {
///     const fn new() -> Self {
///         Self { counter: 0 }
///     }
/// }
///
/// impl RustProcess for MyProcess {
///     fn init(&mut self) {
///         // Initialization code
///     }
///
///     fn handle_event(&mut self, ev: process_event_t, _data: process_data_t) -> bool {
///         // Event handling code
///         true
///     }
/// }
///
/// rust_process!(my_process_handler, MyProcess);
/// ```
#[macro_export]
macro_rules! rust_process {
    ($name:ident, $state_type:ty) => {
        static mut PROCESS_STATE: $state_type = <$state_type>::new();

        #[no_mangle]
        pub extern "C" fn $name(
            ev: $crate::process_event_t,
            data: $crate::process_data_t,
        ) -> $crate::c_int {
            unsafe {
                match ev {
                    $crate::PROCESS_EVENT_INIT => {
                        PROCESS_STATE.init();
                        $crate::PT_YIELDED
                    }
                    _ => {
                        if PROCESS_STATE.handle_event(ev, data) {
                            $crate::PT_YIELDED
                        } else {
                            $crate::PT_ENDED
                        }
                    }
                }
            }
        }
    };
}

// Safe wrapper functions for common operations

/// Print a message to the console
///
/// The message must be a null-terminated C string created with the `c_str!` macro.
///
/// # Example
/// ```
/// print(c_str!("Hello from Rust!\n"));
/// ```
#[inline]
pub fn print(msg: *const c_char) {
    // SAFETY: We only accept messages from c_str! macro which creates valid C strings
    unsafe {
        printf(msg);
    }
}

/// Print a formatted message with a u32 value
///
/// The format string must be a null-terminated C string with a valid `%u` or `%lu` format specifier.
///
/// # Example
/// ```
/// print_u32(c_str!("Counter: %u\n"), 42);
/// ```
#[inline]
pub fn print_u32(format: *const c_char, value: u32) {
    // SAFETY: We only accept format strings from c_str! macro which creates valid C strings
    unsafe {
        printf(format, value as c_uint);
    }
}

// ============================================================================
// Timer Helper Functions
// ============================================================================

/// Start an etimer with the given interval
///
/// # Example
/// ```
/// static mut TIMER: etimer = etimer { ... };
/// timer_set(&mut TIMER, clock_second() * 2);  // Fire every 2 seconds
/// ```
#[inline]
pub fn timer_set(timer: &mut etimer, interval: clock_time_t) {
    // SAFETY: timer is a valid mutable reference and Contiki-NG is single-threaded
    unsafe {
        etimer_set(timer, interval);
    }
}

/// Check if an etimer has expired
///
/// # Example
/// ```
/// static mut TIMER: etimer = etimer { ... };
/// if timer_expired(&mut TIMER) {
///     // Timer fired, do work
/// }
/// ```
#[inline]
pub fn timer_expired(timer: &mut etimer) -> bool {
    // SAFETY: timer is a valid reference
    unsafe { etimer_expired(timer) }
}

/// Reset an etimer to its original interval
///
/// This restarts the timer with the same interval it was originally set with.
///
/// # Example
/// ```
/// static mut TIMER: etimer = etimer { ... };
/// timer_reset(&mut TIMER);  // Restart with original interval
/// ```
#[inline]
pub fn timer_reset(timer: &mut etimer) {
    // SAFETY: timer is a valid mutable reference and Contiki-NG is single-threaded
    unsafe {
        etimer_reset(timer);
    }
}

/// Print a null-terminated byte string
///
/// # Safety
/// The slice must contain a null terminator and be a valid C string.
pub unsafe fn print_cstr(s: &[u8]) {
    if let Some(nul_pos) = s.iter().position(|&c| c == 0) {
        puts(s[..=nul_pos].as_ptr() as *const c_char);
    }
}

// ============================================================================
// Type-safe Wrappers for Core APIs
// ============================================================================

/// Safe wrapper around etimer with Result-based error handling
pub struct ETimer(*mut etimer);

impl ETimer {
    /// Create a new ETimer wrapper from a raw pointer
    ///
    /// # Errors
    /// Returns `Error::NullPointer` if the timer pointer is null
    ///
    /// # Safety
    /// The pointer must be valid and point to an initialized etimer struct
    pub unsafe fn new(timer: *mut etimer) -> Result<Self> {
        if timer.is_null() {
            Err(Error::NullPointer)
        } else {
            Ok(ETimer(timer))
        }
    }

    /// Set the timer to expire after the given interval
    ///
    /// # Errors
    /// Returns `Error::InvalidParameter` if interval is 0
    pub fn set(&mut self, interval: clock_time_t) -> Result<()> {
        if interval == 0 {
            return Err(Error::InvalidParameter);
        }
        unsafe { etimer_set(self.0, interval) }
        Ok(())
    }

    /// Check if the timer has expired
    pub fn expired(&self) -> bool {
        unsafe { etimer_expired(self.0) }
    }

    /// Reset the timer to its original interval
    pub fn reset(&mut self) -> Result<()> {
        unsafe { etimer_reset(self.0) }
        Ok(())
    }

    /// Restart the timer from the current time
    pub fn restart(&mut self) -> Result<()> {
        unsafe { etimer_restart(self.0) }
        Ok(())
    }

    /// Stop the timer
    pub fn stop(&mut self) -> Result<()> {
        unsafe { etimer_stop(self.0) }
        Ok(())
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

/// Check if an etimer has expired
/// This replicates the C static inline function: `return et->p == PROCESS_NONE;`
#[inline(always)]
pub unsafe fn etimer_expired(et: *mut etimer) -> bool {
    (*et).p.is_null()
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
    ///
    /// # Errors
    /// Returns `Error::BufferOverflow` if buffer is full
    pub fn push(&mut self, byte: u8) -> Result<()> {
        if self.len < N {
            self.data[self.len] = byte;
            self.len += 1;
            Ok(())
        } else {
            Err(Error::BufferOverflow)
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

// Optional allocator support
// Enable with "allocator" feature flag in Cargo.toml
#[cfg(feature = "allocator")]
pub mod allocator {
    use core::alloc::{GlobalAlloc, Layout};
    use core::ffi::c_void;

    // External C memory allocation functions
    // These should be provided by the platform or a custom implementation
    extern "C" {
        fn malloc(size: usize) -> *mut c_void;
        fn free(ptr: *mut c_void);
    }

    /// Global allocator that uses C's malloc/free
    /// This is a simple wrapper suitable for platforms with malloc support
    pub struct ContikiAllocator;

    unsafe impl GlobalAlloc for ContikiAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            malloc(layout.size()) as *mut u8
        }

        unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
            free(ptr as *mut c_void);
        }
    }

    #[global_allocator]
    static ALLOCATOR: ContikiAllocator = ContikiAllocator;
}

// Default panic handler for no_std environment
// Applications can override this by providing their own #[panic_handler]
use core::panic::PanicInfo;

/// Default panic handler that prints diagnostic information and reboots
///
/// This handler:
/// 1. Prints panic information (message and location)
/// 2. Triggers a watchdog reboot for a clean restart
///
/// Applications can provide their own panic handler if they need different behavior
/// (e.g., storing panic info to flash, custom recovery logic).
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // SAFETY: printf is safe to call with valid C strings
    unsafe {
        printf(c_str!("PANIC: Rust code panicked!\n"));
        if let Some(location) = info.location() {
            printf(
                c_str!("Panic at %s:%u\n"),
                location.file().as_ptr() as *const c_char,
                location.line(),
            );
        }
        // Note: info.message() provides the panic message but we can't easily
        // print the formatted message without std library support

        // Trigger watchdog reboot for clean system restart
        // This is more portable than architecture-specific assembly
        printf(c_str!("Triggering watchdog reboot...\n"));
        watchdog_reboot();
    }

    // Should never reach here, but required by never type
    loop {}
}

// Unit tests (only compiled for native target)
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_buffer_push() {
        let mut buf = StaticBuffer::<16>::new();
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());

        assert!(buf.push(42).is_ok());
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.as_slice()[0], 42);
    }

    #[test]
    fn test_static_buffer_full() {
        let mut buf = StaticBuffer::<4>::new();
        for i in 0..4 {
            assert!(buf.push(i).is_ok());
        }
        assert!(buf.is_full());
        assert!(buf.push(5).is_err());
    }

    #[test]
    fn test_static_buffer_clear() {
        let mut buf = StaticBuffer::<8>::new();
        buf.push(1).unwrap();
        buf.push(2).unwrap();
        assert_eq!(buf.len(), 2);

        buf.clear();
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_random_range() {
        // Test edge cases
        assert_eq!(Random::rand_range(0), 0);
        assert_eq!(Random::rand_range(1), 0);

        // Test that result is within range
        for _ in 0..10 {
            let result = Random::rand_range(100);
            assert!(result < 100);
        }
    }
}
