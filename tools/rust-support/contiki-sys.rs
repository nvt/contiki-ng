//! Contiki-NG Rust Bindings
//!
//! This module provides safe Rust wrappers around Contiki-NG C APIs, organized
//! into logical modules:
//!
//! - [`error`] - Error types and Result
//! - [`ffi`] - Raw FFI declarations (internal use)
//! - [`core`] - Process, timer, and clock primitives
//! - [`hal`] - Hardware abstraction (LEDs, GPIO, sensors)
//! - [`net`] - Networking (UDP, IPv6, RPL, TSCH)
//! - [`storage`] - File system (CFS)
//! - [`debug`] - Debugging and profiling (logging, energest)
//! - [`async_support`] - Async/await runtime
//! - [`prelude`] - Convenient re-exports

#![no_std]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

// Re-export core FFI types for use in macros
pub use ::core::ffi::{c_char, c_int, c_uint, c_void};

// =============================================================================
// Error Module
// =============================================================================

pub mod error {
    //! Error types for Contiki-NG operations

    /// Result type for Contiki-NG operations
    pub type Result<T> = ::core::result::Result<T, Error>;

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
}

pub use error::{Error, Result};

// =============================================================================
// FFI Module (Internal)
// =============================================================================

pub mod ffi {
    //! Raw FFI bindings to Contiki-NG C functions.
    //!
    //! **Note:** Prefer using the safe wrappers in other modules.
    //! These are exposed for advanced use cases only.

    use super::*;
    use crate::sys::{clock_time_t, etimer, process, process_data_t, process_event_t};
    use crate::debug::{energest_type_t, packetbuf_addr, packetbuf_attr, packetbuf_attr_t};
    use crate::hal::{button_hal_button, sensors_sensor};
    use crate::net::{
        linkaddr_t, rpl_prefix_t, simple_udp_callback, simple_udp_connection, uip_ipaddr_t,
    };
    use crate::storage::{cfs_dir, cfs_dirent, cfs_offset_t};

    extern "C" {
        // Process functions
        pub fn process_start(p: *mut process, data: process_data_t);
        pub fn process_exit(p: *mut process);
        pub fn process_post(
            p: *mut process,
            ev: process_event_t,
            data: process_data_t,
        ) -> c_int;
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
        pub fn etimer_expiration_time(et: *mut etimer) -> clock_time_t;
        pub fn etimer_start_time(et: *mut etimer) -> clock_time_t;
        pub fn etimer_stop(et: *mut etimer);

        // Print functions
        pub fn printf(format: *const c_char, ...) -> c_int;
        pub fn puts(s: *const c_char) -> c_int;
        pub fn putchar(c: c_int) -> c_int;

        // GPIO functions
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
        pub fn memb_numfree(m: *const c_void) -> c_int;

        // LED functions
        pub fn leds_on(leds: u8);
        pub fn leds_off(leds: u8);
        pub fn leds_toggle(leds: u8);
        pub fn leds_get() -> u8;

        // Sensor functions
        pub fn sensors_find(type_: *const c_char) -> *const sensors_sensor;
        pub fn sensors_first() -> *const sensors_sensor;
        pub fn sensors_next(s: *const sensors_sensor) -> *const sensors_sensor;
        pub fn sensors_changed(s: *const sensors_sensor);
        pub static sensors_event: process_event_t;

        // Button HAL functions
        pub fn button_hal_get_by_index(index: u8) -> *mut button_hal_button;
        pub fn button_hal_get_by_id(unique_id: u8) -> *mut button_hal_button;
        pub fn button_hal_init();
        pub static button_hal_press_event: process_event_t;
        pub static button_hal_release_event: process_event_t;
        pub static button_hal_periodic_event: process_event_t;

        // Energest functions
        pub fn energest_init();
        pub fn energest_flush();
        pub fn energest_type_time(type_: energest_type_t) -> u64;
        pub fn energest_type_set(type_: energest_type_t, value: u64);
        pub fn energest_on(type_: energest_type_t);
        pub fn energest_off(type_: energest_type_t);
        pub fn energest_switch(type_off: energest_type_t, type_on: energest_type_t);
        pub fn energest_get_total_time() -> u64;
        pub static mut energest_total_time: [u64; 5];

        // Logging functions
        pub fn log_lladdr(lladdr: *const linkaddr_t);
        pub fn log_lladdr_compact(lladdr: *const linkaddr_t);
        pub fn log_6addr(ipaddr: *const uip_ipaddr_t);
        pub fn log_6addr_compact(ipaddr: *const uip_ipaddr_t);
        pub fn log_6addr_compact_snprint(
            buf: *mut c_char,
            size: usize,
            ipaddr: *const uip_ipaddr_t,
        ) -> c_int;
        pub fn log_bytes(data: *const c_void, length: usize);
        pub fn log_string(text: *const c_char, length: usize);
        pub fn log_set_level(module: *const c_char, level: c_int);
        pub fn log_get_level(module: *const c_char) -> c_int;
        pub fn log_level_to_str(level: c_int) -> *const c_char;

        // Packetbuf functions
        pub fn packetbuf_clear();
        pub fn packetbuf_dataptr() -> *mut c_void;
        pub fn packetbuf_hdrptr() -> *mut c_void;
        pub fn packetbuf_hdrlen() -> u8;
        pub fn packetbuf_datalen() -> u16;
        pub fn packetbuf_totlen() -> u16;
        pub fn packetbuf_remaininglen() -> u16;
        pub fn packetbuf_set_datalen(len: u16);
        pub fn packetbuf_copyfrom(from: *const c_void, len: u16) -> c_int;
        pub fn packetbuf_copyto(to: *mut c_void) -> c_int;
        pub fn packetbuf_hdralloc(size: c_int) -> c_int;
        pub fn packetbuf_hdrreduce(size: c_int) -> c_int;
        pub fn packetbuf_set_attr(type_: u8, val: packetbuf_attr_t);
        pub fn packetbuf_attr(type_: u8) -> packetbuf_attr_t;
        pub fn packetbuf_set_addr(type_: u8, addr: *const linkaddr_t);
        pub fn packetbuf_addr(type_: u8) -> *const linkaddr_t;
        pub fn packetbuf_holds_broadcast() -> bool;
        pub fn packetbuf_attr_clear();
        pub fn packetbuf_attr_copyto(attrs: *mut packetbuf_attr, addrs: *mut packetbuf_addr);
        pub fn packetbuf_attr_copyfrom(attrs: *const packetbuf_attr, addrs: *const packetbuf_addr);

        // TSCH functions
        pub fn tsch_set_join_priority(jp: u8);
        pub fn tsch_set_eb_period(period: u32);
        pub fn tsch_set_ka_timeout(timeout: u32);
        pub fn tsch_set_coordinator(enable: c_int);
        pub fn tsch_set_pan_secured(enable: c_int);
        pub fn tsch_schedule_keepalive(immediate: c_int);
        pub fn tsch_get_network_uptime_ticks() -> u64;
        pub fn tsch_disassociate();
        pub static tsch_is_coordinator: c_int;
        pub static tsch_is_associated: c_int;
        pub static tsch_is_pan_secured: c_int;

        // CFS functions
        pub fn cfs_open(name: *const c_char, flags: c_int) -> c_int;
        pub fn cfs_close(fd: c_int);
        pub fn cfs_read(fd: c_int, buf: *mut c_void, len: c_uint) -> c_int;
        pub fn cfs_write(fd: c_int, buf: *const c_void, len: c_uint) -> c_int;
        pub fn cfs_seek(fd: c_int, offset: cfs_offset_t, whence: c_int) -> cfs_offset_t;
        pub fn cfs_remove(name: *const c_char) -> c_int;
        pub fn cfs_opendir(dirp: *mut cfs_dir, name: *const c_char) -> c_int;
        pub fn cfs_readdir(dirp: *mut cfs_dir, dirent: *mut cfs_dirent) -> c_int;
        pub fn cfs_closedir(dirp: *mut cfs_dir);

        // RPL functions
        pub fn rpl_dag_root_set_prefix(prefix: *mut uip_ipaddr_t, iid: *mut uip_ipaddr_t);
        pub fn rpl_dag_root_start() -> c_int;
        pub fn rpl_dag_root_is_root() -> c_int;
        pub fn rpl_dag_root_print_links(str: *const c_char);
        pub fn rpl_set_prefix(prefix: *mut rpl_prefix_t) -> c_int;
        pub fn rpl_set_prefix_from_addr(addr: *mut uip_ipaddr_t, len: c_uint, flags: u8) -> c_int;
        pub fn rpl_reset_prefix(last_prefix: *mut rpl_prefix_t);
        pub fn rpl_get_global_address() -> *const uip_ipaddr_t;
        pub fn rpl_is_reachable() -> c_int;
        pub fn rpl_refresh_routes(str: *const c_char);
        pub fn rpl_set_leaf_only(value: u8);
        pub fn rpl_get_leaf_only() -> u8;
        pub fn rpl_link_callback(addr: *const linkaddr_t, status: c_int, numtx: c_int);

        // Simple UDP functions
        pub fn simple_udp_init();
        pub fn simple_udp_register(
            c: *mut simple_udp_connection,
            local_port: u16,
            remote_addr: *mut uip_ipaddr_t,
            remote_port: u16,
            receive_callback: simple_udp_callback,
        ) -> c_int;
        pub fn simple_udp_send(
            c: *mut simple_udp_connection,
            data: *const c_void,
            datalen: u16,
        ) -> c_int;
        pub fn simple_udp_sendto(
            c: *mut simple_udp_connection,
            data: *const c_void,
            datalen: u16,
            to: *const uip_ipaddr_t,
        ) -> c_int;
        pub fn simple_udp_sendto_port(
            c: *mut simple_udp_connection,
            data: *const c_void,
            datalen: u16,
            to: *const uip_ipaddr_t,
            to_port: u16,
        ) -> c_int;

        // Clock constant
        pub static CLOCK_SECOND_VALUE: clock_time_t;
    }
}

// =============================================================================
// Sys Module (Core OS Primitives)
// =============================================================================

pub mod sys {
    //! Core OS primitives: processes, timers, and clock.

    use super::*;

    // -------------------------------------------------------------------------
    // Types
    // -------------------------------------------------------------------------

    /// Clock time type (platform-dependent tick count)
    pub type clock_time_t = c_uint;

    /// Process event type
    pub type process_event_t = u8;

    /// Process data pointer type
    pub type process_data_t = *mut c_void;

    /// Local continuation type for protothreads
    pub type lc_t = u16;

    /// Protothread state
    #[repr(C)]
    pub struct pt {
        pub lc: lc_t,
    }

    /// Process structure
    #[repr(C)]
    pub struct process {
        pub next: *mut process,
        pub name: *const c_char,
        pub thread: Option<unsafe extern "C" fn(*mut pt, process_event_t, *mut c_void) -> c_int>,
        pub pt: pt,
        pub state: u8,
        pub needspoll: u8,
    }

    /// Timer structure
    #[repr(C)]
    pub struct timer {
        pub start: clock_time_t,
        pub interval: clock_time_t,
    }

    /// Event timer structure
    #[repr(C)]
    pub struct etimer {
        pub timer: timer,
        pub next: *mut etimer,
        pub p: *mut process,
    }

    // -------------------------------------------------------------------------
    // Process Event Constants
    // -------------------------------------------------------------------------

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

    // -------------------------------------------------------------------------
    // Protothread States
    // -------------------------------------------------------------------------

    pub const PT_WAITING: c_int = 0;
    pub const PT_YIELDED: c_int = 1;
    pub const PT_EXITED: c_int = 2;
    pub const PT_ENDED: c_int = 3;

    // -------------------------------------------------------------------------
    // Clock Functions
    // -------------------------------------------------------------------------

    /// Get the platform's clock ticks per second
    #[inline]
    pub fn clock_second() -> clock_time_t {
        unsafe { ffi::CLOCK_SECOND_VALUE }
    }

    /// Safe clock functions wrapper
    pub struct Clock;

    impl Clock {
        /// Get the current clock time in ticks
        pub fn time() -> clock_time_t {
            unsafe { ffi::clock_time() }
        }

        /// Get the current time in seconds since boot
        pub fn seconds() -> c_uint {
            unsafe { ffi::clock_seconds() }
        }

        /// Blocking wait for a specified time
        pub fn wait(t: clock_time_t) {
            unsafe { ffi::clock_wait(t) }
        }
    }

    // -------------------------------------------------------------------------
    // Process Functions
    // -------------------------------------------------------------------------

    /// Start a process with optional data
    pub fn safe_process_start(p: &mut process, data: process_data_t) {
        unsafe { ffi::process_start(p as *mut process, data) }
    }

    /// Exit a process
    pub fn safe_process_exit(p: &mut process) {
        unsafe { ffi::process_exit(p as *mut process) }
    }

    /// Post an event to a process
    ///
    /// # Errors
    /// Returns `Error::ProcessError` if posting failed
    pub fn safe_process_post(
        p: &mut process,
        ev: process_event_t,
        data: process_data_t,
    ) -> Result<()> {
        let result = unsafe { ffi::process_post(p as *mut process, ev, data) };
        if result == 0 {
            Err(Error::ProcessError)
        } else {
            Ok(())
        }
    }

    /// Post an event to a process synchronously
    pub fn safe_process_post_synch(p: &mut process, ev: process_event_t, data: process_data_t) {
        unsafe { ffi::process_post_synch(p as *mut process, ev, data) }
    }

    /// Request that a process be polled
    pub fn safe_process_poll(p: &mut process) {
        unsafe { ffi::process_poll(p as *mut process) }
    }

    // -------------------------------------------------------------------------
    // Timer Functions
    // -------------------------------------------------------------------------

    /// Check if an etimer has expired
    #[inline(always)]
    pub unsafe fn etimer_expired(et: *mut etimer) -> bool {
        (*et).p.is_null()
    }

    /// Start an etimer with the given interval
    #[inline]
    pub fn timer_set(timer: &mut etimer, interval: clock_time_t) {
        unsafe { ffi::etimer_set(timer, interval) }
    }

    /// Check if an etimer has expired
    #[inline]
    pub fn timer_expired(timer: &mut etimer) -> bool {
        unsafe { etimer_expired(timer) }
    }

    /// Reset an etimer to its original interval
    #[inline]
    pub fn timer_reset(timer: &mut etimer) {
        unsafe { ffi::etimer_reset(timer) }
    }

    // -------------------------------------------------------------------------
    // Traits
    // -------------------------------------------------------------------------

    /// Trait for Rust processes
    pub trait RustProcess {
        /// Called once when the process starts
        fn init(&mut self);

        /// Called on each event. Return true to continue, false to end.
        fn handle_event(&mut self, ev: process_event_t, data: process_data_t) -> bool;
    }

    // -------------------------------------------------------------------------
    // Utility Types
    // -------------------------------------------------------------------------

    /// Static buffer with compile-time size (zero runtime overhead)
    pub struct StaticBuffer<const N: usize> {
        data: [u8; N],
        len: usize,
    }

    impl<const N: usize> StaticBuffer<N> {
        /// Create a new empty static buffer
        pub const fn new() -> Self {
            Self { data: [0; N], len: 0 }
        }

        /// Push a byte to the buffer
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

        /// Get the raw data pointer
        pub fn as_ptr(&self) -> *const u8 {
            self.data.as_ptr()
        }
    }
}

pub use sys::{
    clock_second, etimer, process, process_data_t, process_event_t, pt, timer,
    timer_expired, timer_reset, timer_set, Clock, RustProcess, StaticBuffer,
    clock_time_t, lc_t,
    safe_process_exit, safe_process_poll, safe_process_post, safe_process_post_synch,
    safe_process_start,
    PROCESS_EVENT_COM, PROCESS_EVENT_CONTINUE, PROCESS_EVENT_EXIT, PROCESS_EVENT_EXITED,
    PROCESS_EVENT_INIT, PROCESS_EVENT_MAX, PROCESS_EVENT_MSG, PROCESS_EVENT_NONE,
    PROCESS_EVENT_POLL, PROCESS_EVENT_SERVICE_REMOVED, PROCESS_EVENT_TIMER,
    PT_ENDED, PT_EXITED, PT_WAITING, PT_YIELDED,
};

// =============================================================================
// HAL Module
// =============================================================================

pub mod hal {
    //! Hardware abstraction: LEDs, GPIO, sensors, random number generation.

    use super::*;

    // -------------------------------------------------------------------------
    // LED Constants and Wrapper
    // -------------------------------------------------------------------------

    pub const LEDS_GREEN: u8 = 1;
    pub const LEDS_YELLOW: u8 = 2;
    pub const LEDS_RED: u8 = 4;
    pub const LEDS_BLUE: u8 = 8;
    pub const LEDS_ALL: u8 = 15;

    /// Safe LED control wrapper
    pub struct Leds;

    impl Leds {
        /// Turn on specific LEDs
        pub fn on(leds: u8) {
            unsafe { ffi::leds_on(leds) }
        }

        /// Turn off specific LEDs
        pub fn off(leds: u8) {
            unsafe { ffi::leds_off(leds) }
        }

        /// Toggle specific LEDs
        pub fn toggle(leds: u8) {
            unsafe { ffi::leds_toggle(leds) }
        }

        /// Get current LED state
        pub fn get() -> u8 {
            unsafe { ffi::leds_get() }
        }
    }

    // -------------------------------------------------------------------------
    // Random Number Generation
    // -------------------------------------------------------------------------

    /// Safe random number generator wrapper
    pub struct Random;

    impl Random {
        /// Initialize with a seed
        pub fn init(seed: c_uint) {
            unsafe { ffi::random_init(seed) }
        }

        /// Generate a random number
        pub fn rand() -> c_uint {
            unsafe { ffi::random_rand() }
        }

        /// Generate a random number in the range [0, max)
        pub fn rand_range(max: c_uint) -> c_uint {
            if max == 0 { return 0; }
            unsafe { ffi::random_rand() % max }
        }
    }

    // -------------------------------------------------------------------------
    // GPIO
    // -------------------------------------------------------------------------

    /// GPIO pin control
    pub struct Gpio;

    impl Gpio {
        /// Write a value to a GPIO pin
        pub fn write_pin(pin: u8, value: u8) {
            unsafe { ffi::gpio_hal_arch_write_pin(pin, value) }
        }

        /// Read a GPIO pin value
        pub fn read_pin(pin: u8) -> u8 {
            unsafe { ffi::gpio_hal_arch_read_pin(pin) }
        }

        /// Set a GPIO pin high
        pub fn set_pin(pin: u8) {
            unsafe { ffi::gpio_hal_arch_set_pin(pin) }
        }

        /// Clear a GPIO pin (set low)
        pub fn clear_pin(pin: u8) {
            unsafe { ffi::gpio_hal_arch_clear_pin(pin) }
        }

        /// Toggle a GPIO pin
        pub fn toggle_pin(pin: u8) {
            unsafe { ffi::gpio_hal_arch_toggle_pin(pin) }
        }
    }

    // -------------------------------------------------------------------------
    // Sensor Types and Wrappers
    // -------------------------------------------------------------------------

    pub const SENSORS_HW_INIT: c_int = 128;
    pub const SENSORS_ACTIVE: c_int = 129;
    pub const SENSORS_READY: c_int = 130;

    pub const BUTTON_HAL_EVENT_PRESS: c_int = 0;
    pub const BUTTON_HAL_EVENT_RELEASE: c_int = 1;
    pub const BUTTON_HAL_EVENT_PERIODIC: c_int = 2;

    /// Sensor structure
    #[repr(C)]
    pub struct sensors_sensor {
        pub type_: *const c_char,
        pub value: Option<unsafe extern "C" fn(type_: c_int) -> c_int>,
        pub configure: Option<unsafe extern "C" fn(type_: c_int, value: c_int) -> c_int>,
        pub status: Option<unsafe extern "C" fn(type_: c_int) -> c_int>,
    }

    /// Button HAL button structure
    #[repr(C)]
    pub struct button_hal_button {
        pub next: *mut button_hal_button,
        pub unique_id: u8,
        pub press_duration_event: process_event_t,
        pub negative_logic: u8,
        pub pin: u8,
        pub pull: u8,
    }

    /// Sensor wrapper
    pub struct Sensor {
        sensor: *const sensors_sensor,
    }

    impl Sensor {
        /// Find a sensor by type name
        pub fn find(type_name: *const c_char) -> Option<Self> {
            let sensor = unsafe { ffi::sensors_find(type_name) };
            if sensor.is_null() {
                None
            } else {
                Some(Self { sensor })
            }
        }

        /// Get the first registered sensor
        pub fn first() -> Option<Self> {
            let sensor = unsafe { ffi::sensors_first() };
            if sensor.is_null() {
                None
            } else {
                Some(Self { sensor })
            }
        }

        /// Get the next sensor in the list
        pub fn next(&self) -> Option<Self> {
            let sensor = unsafe { ffi::sensors_next(self.sensor) };
            if sensor.is_null() {
                None
            } else {
                Some(Self { sensor })
            }
        }

        /// Read a sensor value
        pub fn value(&self, type_: c_int) -> Option<c_int> {
            unsafe {
                if let Some(value_fn) = (*self.sensor).value {
                    Some(value_fn(type_))
                } else {
                    None
                }
            }
        }

        /// Configure the sensor
        pub fn configure(&self, type_: c_int, value: c_int) -> Option<c_int> {
            unsafe {
                if let Some(configure_fn) = (*self.sensor).configure {
                    Some(configure_fn(type_, value))
                } else {
                    None
                }
            }
        }

        /// Get sensor status
        pub fn status(&self, type_: c_int) -> Option<c_int> {
            unsafe {
                if let Some(status_fn) = (*self.sensor).status {
                    Some(status_fn(type_))
                } else {
                    None
                }
            }
        }
    }

    /// Button HAL wrapper
    pub struct Button {
        button: *mut button_hal_button,
    }

    impl Button {
        /// Initialize button HAL
        pub fn init() {
            unsafe { ffi::button_hal_init() }
        }

        /// Get button by index
        pub fn by_index(index: u8) -> Option<Self> {
            let button = unsafe { ffi::button_hal_get_by_index(index) };
            if button.is_null() {
                None
            } else {
                Some(Self { button })
            }
        }

        /// Get button by unique ID
        pub fn by_id(id: u8) -> Option<Self> {
            let button = unsafe { ffi::button_hal_get_by_id(id) };
            if button.is_null() {
                None
            } else {
                Some(Self { button })
            }
        }

        /// Get the button's unique ID
        pub fn unique_id(&self) -> u8 {
            unsafe { (*self.button).unique_id }
        }

        /// Get the button's pin
        pub fn pin(&self) -> u8 {
            unsafe { (*self.button).pin }
        }
    }
}

pub use hal::{
    button_hal_button, sensors_sensor, Button, Gpio, Leds, Random, Sensor,
    BUTTON_HAL_EVENT_PERIODIC, BUTTON_HAL_EVENT_PRESS, BUTTON_HAL_EVENT_RELEASE,
    LEDS_ALL, LEDS_BLUE, LEDS_GREEN, LEDS_RED, LEDS_YELLOW,
    SENSORS_ACTIVE, SENSORS_HW_INIT, SENSORS_READY,
};

// =============================================================================
// Net Module
// =============================================================================

pub mod net {
    //! Networking: UDP, IPv6, RPL routing, TSCH, packet buffers.

    use super::*;

    // -------------------------------------------------------------------------
    // Address Types
    // -------------------------------------------------------------------------

    /// Link-layer address (MAC address)
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct linkaddr_t {
        pub u8: [u8; 8],
    }

    impl linkaddr_t {
        pub const fn from_bytes(bytes: [u8; 8]) -> Self {
            Self { u8: bytes }
        }

        pub const fn null() -> Self {
            Self { u8: [0; 8] }
        }

        pub fn as_bytes(&self) -> &[u8; 8] {
            &self.u8
        }

        pub fn is_null(&self) -> bool {
            self.u8.iter().all(|&b| b == 0)
        }
    }

    /// IPv6 address (128 bits)
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub union uip_ip6addr_t {
        pub u8: [u8; 16],
        pub u16: [u16; 8],
    }

    pub type uip_ipaddr_t = uip_ip6addr_t;

    impl uip_ip6addr_t {
        pub const fn from_bytes(bytes: [u8; 16]) -> Self {
            Self { u8: bytes }
        }

        pub const fn zero() -> Self {
            Self { u8: [0; 16] }
        }

        pub fn as_bytes(&self) -> &[u8; 16] {
            unsafe { &self.u8 }
        }

        pub fn is_zero(&self) -> bool {
            unsafe { self.u8.iter().all(|&b| b == 0) }
        }
    }

    // -------------------------------------------------------------------------
    // UDP Types and Wrappers
    // -------------------------------------------------------------------------

    /// Forward declaration for UDP connection
    #[repr(C)]
    pub struct uip_udp_conn {
        _private: [u8; 0],
    }

    /// Simple UDP callback function type
    pub type simple_udp_callback = Option<
        unsafe extern "C" fn(
            c: *mut simple_udp_connection,
            source_addr: *const uip_ipaddr_t,
            source_port: u16,
            dest_addr: *const uip_ipaddr_t,
            dest_port: u16,
            data: *const u8,
            datalen: u16,
        ),
    >;

    /// Simple UDP connection structure
    #[repr(C)]
    pub struct simple_udp_connection {
        pub next: *mut simple_udp_connection,
        pub remote_addr: uip_ipaddr_t,
        pub remote_port: u16,
        pub local_port: u16,
        pub receive_callback: simple_udp_callback,
        pub udp_conn: *mut uip_udp_conn,
        pub client_process: *mut process,
    }

    /// Safe wrapper around simple_udp_connection
    pub struct SimpleUdpConnection {
        pub inner: simple_udp_connection,
        pub registered: bool,
    }

    impl SimpleUdpConnection {
        /// Create a new unregistered UDP connection
        pub const fn new() -> Self {
            Self {
                inner: simple_udp_connection {
                    next: ::core::ptr::null_mut(),
                    remote_addr: uip_ip6addr_t { u8: [0; 16] },
                    remote_port: 0,
                    local_port: 0,
                    receive_callback: None,
                    udp_conn: ::core::ptr::null_mut(),
                    client_process: ::core::ptr::null_mut(),
                },
                registered: false,
            }
        }

        /// Initialize the simple-udp module
        pub fn init() {
            unsafe { ffi::simple_udp_init() }
        }

        /// Register the UDP connection
        pub fn register(
            &mut self,
            local_port: u16,
            remote_addr: Option<&uip_ipaddr_t>,
            remote_port: u16,
            receive_callback: simple_udp_callback,
        ) -> Result<()> {
            let remote_addr_ptr = match remote_addr {
                Some(addr) => addr as *const _ as *mut uip_ipaddr_t,
                None => ::core::ptr::null_mut(),
            };

            let result = unsafe {
                ffi::simple_udp_register(
                    &mut self.inner as *mut simple_udp_connection,
                    local_port,
                    remote_addr_ptr,
                    remote_port,
                    receive_callback,
                )
            };

            if result == 0 {
                Err(Error::NetworkError)
            } else {
                self.registered = true;
                Ok(())
            }
        }

        /// Send data to the registered remote address
        pub fn send(&mut self, data: &[u8]) -> Result<()> {
            if !self.registered {
                return Err(Error::NotAvailable);
            }
            unsafe {
                ffi::simple_udp_send(
                    &mut self.inner as *mut simple_udp_connection,
                    data.as_ptr() as *const c_void,
                    data.len() as u16,
                )
            };
            Ok(())
        }

        /// Send data to a specific IP address
        pub fn send_to(&mut self, data: &[u8], to: &uip_ipaddr_t) -> Result<()> {
            if !self.registered {
                return Err(Error::NotAvailable);
            }
            unsafe {
                ffi::simple_udp_sendto(
                    &mut self.inner as *mut simple_udp_connection,
                    data.as_ptr() as *const c_void,
                    data.len() as u16,
                    to as *const uip_ipaddr_t,
                )
            };
            Ok(())
        }

        /// Send data to a specific IP address and port
        pub fn send_to_port(&mut self, data: &[u8], to: &uip_ipaddr_t, to_port: u16) -> Result<()> {
            if !self.registered {
                return Err(Error::NotAvailable);
            }
            unsafe {
                ffi::simple_udp_sendto_port(
                    &mut self.inner as *mut simple_udp_connection,
                    data.as_ptr() as *const c_void,
                    data.len() as u16,
                    to as *const uip_ipaddr_t,
                    to_port,
                )
            };
            Ok(())
        }

        pub fn is_registered(&self) -> bool {
            self.registered
        }

        pub fn local_port(&self) -> u16 {
            self.inner.local_port
        }

        pub fn remote_port(&self) -> u16 {
            self.inner.remote_port
        }

        pub fn remote_addr(&self) -> &uip_ipaddr_t {
            &self.inner.remote_addr
        }
    }

    // -------------------------------------------------------------------------
    // RPL Types and Wrappers
    // -------------------------------------------------------------------------

    /// RPL prefix structure
    #[repr(C)]
    pub struct rpl_prefix_t {
        pub prefix: uip_ipaddr_t,
        pub length: u8,
        pub flags: u8,
    }

    /// RPL DAG root operations
    pub struct RplDagRoot;

    impl RplDagRoot {
        /// Set the DAG root prefix
        pub fn set_prefix(prefix: &mut uip_ipaddr_t, iid: &mut uip_ipaddr_t) {
            unsafe { ffi::rpl_dag_root_set_prefix(prefix, iid) }
        }

        /// Start operating as DAG root
        pub fn start() -> Result<()> {
            let result = unsafe { ffi::rpl_dag_root_start() };
            if result == 0 {
                Err(Error::OperationFailed)
            } else {
                Ok(())
            }
        }

        /// Check if this node is the DAG root
        pub fn is_root() -> bool {
            unsafe { ffi::rpl_dag_root_is_root() != 0 }
        }
    }

    /// RPL routing operations
    pub struct Rpl;

    impl Rpl {
        /// Check if the network is reachable
        pub fn is_reachable() -> bool {
            unsafe { ffi::rpl_is_reachable() != 0 }
        }

        /// Get the global IPv6 address
        pub fn get_global_address() -> Option<&'static uip_ipaddr_t> {
            let addr = unsafe { ffi::rpl_get_global_address() };
            if addr.is_null() {
                None
            } else {
                Some(unsafe { &*addr })
            }
        }

        /// Set leaf-only mode
        pub fn set_leaf_only(value: bool) {
            unsafe { ffi::rpl_set_leaf_only(if value { 1 } else { 0 }) }
        }

        /// Get leaf-only mode
        pub fn get_leaf_only() -> bool {
            unsafe { ffi::rpl_get_leaf_only() != 0 }
        }
    }

    // -------------------------------------------------------------------------
    // TSCH Types and Wrappers
    // -------------------------------------------------------------------------

    /// TSCH link types
    #[repr(C)]
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub enum link_type {
        LINK_TYPE_NORMAL = 0,
        LINK_TYPE_ADVERTISING = 1,
        LINK_TYPE_ADVERTISING_ONLY = 2,
    }

    pub const LINK_OPTION_TX: u8 = 1 << 0;
    pub const LINK_OPTION_RX: u8 = 1 << 1;
    pub const LINK_OPTION_SHARED: u8 = 1 << 2;
    pub const LINK_OPTION_TIMEKEEPING: u8 = 1 << 3;

    /// TSCH operations
    pub struct Tsch;

    impl Tsch {
        /// Set join priority
        pub fn set_join_priority(jp: u8) {
            unsafe { ffi::tsch_set_join_priority(jp) }
        }

        /// Set enhanced beacon period
        pub fn set_eb_period(period: u32) {
            unsafe { ffi::tsch_set_eb_period(period) }
        }

        /// Set keepalive timeout
        pub fn set_ka_timeout(timeout: u32) {
            unsafe { ffi::tsch_set_ka_timeout(timeout) }
        }

        /// Set coordinator mode
        pub fn set_coordinator(enable: bool) {
            unsafe { ffi::tsch_set_coordinator(if enable { 1 } else { 0 }) }
        }

        /// Check if this node is a coordinator
        pub fn is_coordinator() -> bool {
            unsafe { ffi::tsch_is_coordinator != 0 }
        }

        /// Check if associated with a network
        pub fn is_associated() -> bool {
            unsafe { ffi::tsch_is_associated != 0 }
        }

        /// Get network uptime in ticks
        pub fn get_network_uptime_ticks() -> u64 {
            unsafe { ffi::tsch_get_network_uptime_ticks() }
        }

        /// Disassociate from the network
        pub fn disassociate() {
            unsafe { ffi::tsch_disassociate() }
        }
    }
}

pub use net::{
    linkaddr_t, link_type, rpl_prefix_t, simple_udp_callback, simple_udp_connection,
    uip_ip6addr_t, uip_ipaddr_t, uip_udp_conn,
    Rpl, RplDagRoot, SimpleUdpConnection, Tsch,
    LINK_OPTION_RX, LINK_OPTION_SHARED, LINK_OPTION_TIMEKEEPING, LINK_OPTION_TX,
};

// =============================================================================
// Storage Module
// =============================================================================

pub mod storage {
    //! File system: CFS (Contiki File System).

    use super::*;

    // -------------------------------------------------------------------------
    // Types
    // -------------------------------------------------------------------------

    pub type cfs_offset_t = c_int;

    /// Directory handle
    #[repr(C)]
    pub struct cfs_dir {
        pub state: [u8; 32],
    }

    /// Directory entry
    #[repr(C)]
    pub struct cfs_dirent {
        pub name: [u8; 32],
        pub size: cfs_offset_t,
    }

    impl cfs_dirent {
        /// Get the file name as a string slice
        pub fn name_str(&self) -> Option<&str> {
            let nul_pos = self.name.iter().position(|&c| c == 0)?;
            ::core::str::from_utf8(&self.name[..nul_pos]).ok()
        }
    }

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    pub const CFS_READ: c_int = 1;
    pub const CFS_WRITE: c_int = 2;
    pub const CFS_APPEND: c_int = 4;

    pub const CFS_SEEK_SET: c_int = 0;
    pub const CFS_SEEK_CUR: c_int = 1;
    pub const CFS_SEEK_END: c_int = 2;

    // -------------------------------------------------------------------------
    // File Wrapper
    // -------------------------------------------------------------------------

    /// Safe wrapper around CFS file operations
    pub struct CfsFile {
        fd: c_int,
    }

    impl CfsFile {
        /// Open a file
        pub fn open(name: *const c_char, flags: c_int) -> Result<Self> {
            let fd = unsafe { ffi::cfs_open(name, flags) };
            if fd < 0 {
                Err(Error::OperationFailed)
            } else {
                Ok(Self { fd })
            }
        }

        /// Read from the file
        pub fn read(&self, buf: &mut [u8]) -> Result<usize> {
            let result = unsafe {
                ffi::cfs_read(self.fd, buf.as_mut_ptr() as *mut c_void, buf.len() as c_uint)
            };
            if result < 0 {
                Err(Error::OperationFailed)
            } else {
                Ok(result as usize)
            }
        }

        /// Write to the file
        pub fn write(&self, buf: &[u8]) -> Result<usize> {
            let result = unsafe {
                ffi::cfs_write(self.fd, buf.as_ptr() as *const c_void, buf.len() as c_uint)
            };
            if result < 0 {
                Err(Error::OperationFailed)
            } else {
                Ok(result as usize)
            }
        }

        /// Seek within the file
        pub fn seek(&self, offset: cfs_offset_t, whence: c_int) -> Result<cfs_offset_t> {
            let result = unsafe { ffi::cfs_seek(self.fd, offset, whence) };
            if result < 0 {
                Err(Error::OperationFailed)
            } else {
                Ok(result)
            }
        }

        /// Get the file descriptor
        pub fn fd(&self) -> c_int {
            self.fd
        }
    }

    impl Drop for CfsFile {
        fn drop(&mut self) {
            unsafe { ffi::cfs_close(self.fd) }
        }
    }

    /// CFS static operations
    pub struct Cfs;

    impl Cfs {
        /// Remove a file
        pub fn remove(name: *const c_char) -> Result<()> {
            let result = unsafe { ffi::cfs_remove(name) };
            if result < 0 {
                Err(Error::OperationFailed)
            } else {
                Ok(())
            }
        }
    }
}

pub use storage::{cfs_dir, cfs_dirent, cfs_offset_t, Cfs, CfsFile, CFS_APPEND, CFS_READ, CFS_SEEK_CUR, CFS_SEEK_END, CFS_SEEK_SET, CFS_WRITE};

// =============================================================================
// Debug Module
// =============================================================================

pub mod debug {
    //! Debugging and profiling: logging, energy estimation, packet buffers.

    use super::*;

    // -------------------------------------------------------------------------
    // Energest Types and Wrappers
    // -------------------------------------------------------------------------

    /// Energy estimation types
    #[repr(C)]
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub enum energest_type_t {
        CPU = 0,
        LPM = 1,
        DEEP_LPM = 2,
        TRANSMIT = 3,
        LISTEN = 4,
        MAX = 5,
    }

    pub type energest_time_t = u64;

    /// Energy estimation wrapper
    pub struct Energest;

    impl Energest {
        pub fn init() {
            unsafe { ffi::energest_init() }
        }

        pub fn flush() {
            unsafe { ffi::energest_flush() }
        }

        pub fn type_time(type_: energest_type_t) -> u64 {
            unsafe { ffi::energest_type_time(type_) }
        }

        pub fn type_set(type_: energest_type_t, value: u64) {
            unsafe { ffi::energest_type_set(type_, value) }
        }

        pub fn on(type_: energest_type_t) {
            unsafe { ffi::energest_on(type_) }
        }

        pub fn off(type_: energest_type_t) {
            unsafe { ffi::energest_off(type_) }
        }

        pub fn switch(type_off: energest_type_t, type_on: energest_type_t) {
            unsafe { ffi::energest_switch(type_off, type_on) }
        }

        pub fn get_total_time() -> u64 {
            unsafe { ffi::energest_get_total_time() }
        }
    }

    // -------------------------------------------------------------------------
    // Logging Constants and Wrapper
    // -------------------------------------------------------------------------

    pub const LOG_LEVEL_NONE: c_int = 0;
    pub const LOG_LEVEL_ERR: c_int = 1;
    pub const LOG_LEVEL_WARN: c_int = 2;
    pub const LOG_LEVEL_INFO: c_int = 3;
    pub const LOG_LEVEL_DBG: c_int = 4;

    /// Logging wrapper
    pub struct Log;

    impl Log {
        pub fn set_level(module: *const c_char, level: c_int) {
            unsafe { ffi::log_set_level(module, level) }
        }

        pub fn get_level(module: *const c_char) -> c_int {
            unsafe { ffi::log_get_level(module) }
        }

        pub fn lladdr(addr: &linkaddr_t) {
            unsafe { ffi::log_lladdr(addr) }
        }

        pub fn ipaddr(addr: &uip_ipaddr_t) {
            unsafe { ffi::log_6addr(addr) }
        }

        pub fn bytes(data: &[u8]) {
            unsafe { ffi::log_bytes(data.as_ptr() as *const c_void, data.len()) }
        }
    }

    // -------------------------------------------------------------------------
    // Packetbuf Types and Wrapper
    // -------------------------------------------------------------------------

    pub type packetbuf_attr_t = u16;

    #[repr(C)]
    pub struct packetbuf_attr {
        pub val: packetbuf_attr_t,
    }

    #[repr(C)]
    pub struct packetbuf_addr {
        pub addr: linkaddr_t,
    }

    pub const PACKETBUF_ATTR_NONE: u8 = 0;
    pub const PACKETBUF_ATTR_CHANNEL: u8 = 1;
    pub const PACKETBUF_ATTR_NETWORK_ID: u8 = 2;
    pub const PACKETBUF_ATTR_LINK_QUALITY: u8 = 3;
    pub const PACKETBUF_ATTR_RSSI: u8 = 4;
    pub const PACKETBUF_ATTR_MAX_MAC_TRANSMISSIONS: u8 = 5;
    pub const PACKETBUF_ATTR_MAC_SEQNO: u8 = 6;
    pub const PACKETBUF_ATTR_MAC_ACK: u8 = 7;
    pub const PACKETBUF_ATTR_MAC_METADATA: u8 = 8;
    pub const PACKETBUF_ATTR_MAC_NO_SRC_ADDR: u8 = 9;
    pub const PACKETBUF_ATTR_MAC_NO_DEST_ADDR: u8 = 10;
    pub const PACKETBUF_ATTR_FRAME_TYPE: u8 = 11;
    pub const PACKETBUF_ADDR_SENDER: u8 = 12;
    pub const PACKETBUF_ADDR_RECEIVER: u8 = 13;

    /// Packet buffer wrapper
    pub struct Packetbuf;

    impl Packetbuf {
        pub fn clear() {
            unsafe { ffi::packetbuf_clear() }
        }

        pub fn datalen() -> u16 {
            unsafe { ffi::packetbuf_datalen() }
        }

        pub fn totlen() -> u16 {
            unsafe { ffi::packetbuf_totlen() }
        }

        pub fn set_datalen(len: u16) {
            unsafe { ffi::packetbuf_set_datalen(len) }
        }

        pub fn holds_broadcast() -> bool {
            unsafe { ffi::packetbuf_holds_broadcast() }
        }

        pub fn attr_clear() {
            unsafe { ffi::packetbuf_attr_clear() }
        }

        pub fn set_attr(type_: u8, val: packetbuf_attr_t) {
            unsafe { ffi::packetbuf_set_attr(type_, val) }
        }

        pub fn attr(type_: u8) -> packetbuf_attr_t {
            unsafe { ffi::packetbuf_attr(type_) }
        }
    }
}

pub use debug::{
    energest_type_t, energest_time_t, packetbuf_addr, packetbuf_attr, packetbuf_attr_t,
    Energest, Log, Packetbuf,
    LOG_LEVEL_DBG, LOG_LEVEL_ERR, LOG_LEVEL_INFO, LOG_LEVEL_NONE, LOG_LEVEL_WARN,
    PACKETBUF_ADDR_RECEIVER, PACKETBUF_ADDR_SENDER, PACKETBUF_ATTR_CHANNEL,
    PACKETBUF_ATTR_FRAME_TYPE, PACKETBUF_ATTR_LINK_QUALITY, PACKETBUF_ATTR_MAC_ACK,
    PACKETBUF_ATTR_MAC_METADATA, PACKETBUF_ATTR_MAC_NO_DEST_ADDR, PACKETBUF_ATTR_MAC_NO_SRC_ADDR,
    PACKETBUF_ATTR_MAC_SEQNO, PACKETBUF_ATTR_MAX_MAC_TRANSMISSIONS, PACKETBUF_ATTR_NETWORK_ID,
    PACKETBUF_ATTR_NONE, PACKETBUF_ATTR_RSSI,
};

// =============================================================================
// Async Support Module
// =============================================================================

pub mod async_support {
    //! Async/await runtime for Contiki-NG processes.
    //!
    //! This module provides async/await support on top of Contiki-NG's event-driven
    //! process model.

    use super::*;
    use ::core::cell::UnsafeCell;
    use ::core::future::Future;
    use ::core::pin::Pin;
    use ::core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    // -------------------------------------------------------------------------
    // Noop Waker (for Contiki-NG's event-driven model)
    // -------------------------------------------------------------------------

    unsafe fn noop_clone(_: *const ()) -> RawWaker {
        noop_raw_waker()
    }
    unsafe fn noop_wake(_: *const ()) {}
    unsafe fn noop_wake_by_ref(_: *const ()) {}
    unsafe fn noop_drop(_: *const ()) {}

    const NOOP_WAKER_VTABLE: RawWakerVTable =
        RawWakerVTable::new(noop_clone, noop_wake, noop_wake_by_ref, noop_drop);

    const fn noop_raw_waker() -> RawWaker {
        RawWaker::new(::core::ptr::null(), &NOOP_WAKER_VTABLE)
    }

    /// Create a no-op waker for polling futures in Contiki-NG's event-driven model.
    /// Since Contiki uses process_poll() for wakeups, the waker itself does nothing.
    pub fn noop_waker() -> Waker {
        unsafe { Waker::from_raw(noop_raw_waker()) }
    }

    // -------------------------------------------------------------------------
    // Safe Cell (for static variables)
    // -------------------------------------------------------------------------

    /// A safe cell for static variables in Contiki-NG's single-threaded environment.
    ///
    /// This provides safe access to mutable static state without explicit unsafe blocks
    /// in user code. Safety is guaranteed by Contiki-NG's cooperative, single-threaded
    /// execution model.
    ///
    /// # Example
    /// ```ignore
    /// static COUNTER: SafeCell<u32> = SafeCell::new(0);
    ///
    /// fn increment() -> u32 {
    ///     let val = COUNTER.get() + 1;
    ///     COUNTER.set(val);
    ///     val
    /// }
    /// ```
    pub struct SafeCell<T> {
        inner: UnsafeCell<T>,
    }

    // SAFETY: Contiki-NG is single-threaded, so no concurrent access is possible
    unsafe impl<T> Sync for SafeCell<T> {}

    impl<T: Copy> SafeCell<T> {
        /// Create a new SafeCell with the given initial value
        pub const fn new(value: T) -> Self {
            Self {
                inner: UnsafeCell::new(value),
            }
        }

        /// Get the current value
        pub fn get(&self) -> T {
            // SAFETY: Single-threaded execution in Contiki-NG
            unsafe { *self.inner.get() }
        }

        /// Set a new value
        pub fn set(&self, value: T) {
            // SAFETY: Single-threaded execution in Contiki-NG
            unsafe { *self.inner.get() = value }
        }
    }

    impl<T: Copy + core::ops::AddAssign> SafeCell<T> {
        /// Add to the current value
        pub fn add(&self, value: T) {
            // SAFETY: Single-threaded execution in Contiki-NG
            unsafe { *self.inner.get() += value }
        }
    }

    impl SafeCell<u32> {
        /// Increment and return the new value
        pub fn increment(&self) -> u32 {
            // SAFETY: Single-threaded execution in Contiki-NG
            unsafe {
                let ptr = self.inner.get();
                *ptr += 1;
                *ptr
            }
        }
    }

    impl SafeCell<bool> {
        /// Set to true
        pub fn set_true(&self) {
            self.set(true)
        }

        /// Set to false
        pub fn set_false(&self) {
            self.set(false)
        }

        /// Check if true
        pub fn is_true(&self) -> bool {
            self.get()
        }
    }

    // -------------------------------------------------------------------------
    // Safe Timer
    // -------------------------------------------------------------------------

    /// Thread-safe timer for static context
    pub struct SafeTimer {
        inner: UnsafeCell<etimer>,
    }

    unsafe impl Sync for SafeTimer {}

    impl SafeTimer {
        /// Create a new timer (const, for static initialization)
        pub const fn new() -> Self {
            Self {
                inner: UnsafeCell::new(etimer {
                    timer: timer { start: 0, interval: 0 },
                    next: ::core::ptr::null_mut(),
                    p: ::core::ptr::null_mut(),
                }),
            }
        }

        /// Set timer interval
        pub fn set(&self, interval: clock_time_t) {
            unsafe { ffi::etimer_set(self.inner.get(), interval) }
        }

        /// Check if expired
        pub fn expired(&self) -> bool {
            unsafe { sys::etimer_expired(self.inner.get()) }
        }

        /// Reset timer
        pub fn reset(&self) {
            unsafe { ffi::etimer_reset(self.inner.get()) }
        }

        /// Create a delay future for seconds
        pub fn delay_seconds(&self, seconds: u32) -> AsyncTimer {
            AsyncTimer {
                timer: self.inner.get(),
                interval: unsafe { ffi::CLOCK_SECOND_VALUE } * seconds,
                started: false,
            }
        }

        /// Create a delay future for milliseconds
        pub fn delay_ms(&self, ms: u32) -> AsyncTimer {
            let ticks = (unsafe { ffi::CLOCK_SECOND_VALUE } * ms) / 1000;
            AsyncTimer {
                timer: self.inner.get(),
                interval: ticks,
                started: false,
            }
        }

        /// Create a delay future with specific tick interval
        pub fn delay_ticks(&self, ticks: clock_time_t) -> AsyncTimer {
            AsyncTimer {
                timer: self.inner.get(),
                interval: ticks,
                started: false,
            }
        }

        /// Get raw pointer for advanced usage
        pub unsafe fn as_ptr(&self) -> *mut etimer {
            self.inner.get()
        }
    }

    // -------------------------------------------------------------------------
    // Async Timer Future
    // -------------------------------------------------------------------------

    /// Future that completes when a timer expires
    pub struct AsyncTimer {
        timer: *mut etimer,
        interval: clock_time_t,
        started: bool,
    }

    impl AsyncTimer {
        /// Create a new async timer
        pub unsafe fn new(timer: *mut etimer, interval: clock_time_t) -> Self {
            Self { timer, interval, started: false }
        }

        /// Create a timer for seconds
        pub unsafe fn delay_seconds(timer: *mut etimer, seconds: u32) -> Self {
            Self::new(timer, ffi::CLOCK_SECOND_VALUE * seconds)
        }

        /// Create a timer for milliseconds
        pub unsafe fn delay_ms(timer: *mut etimer, ms: u32) -> Self {
            let ticks = (ffi::CLOCK_SECOND_VALUE * ms) / 1000;
            Self::new(timer, ticks)
        }
    }

    impl Future for AsyncTimer {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            unsafe {
                if !self.started {
                    ffi::etimer_set(self.timer, self.interval);
                    self.started = true;
                    Poll::Pending
                } else if sys::etimer_expired(self.timer) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Async Executor
    // -------------------------------------------------------------------------

    /// Minimal async executor for Contiki-NG
    pub struct AsyncExecutor;

    impl AsyncExecutor {
        /// Create a dummy waker (Contiki uses event-driven polling)
        pub fn dummy_waker() -> Waker {
            unsafe { Waker::from_raw(Self::dummy_raw_waker()) }
        }

        fn dummy_raw_waker() -> RawWaker {
            fn no_op(_: *const ()) {}
            fn clone(_: *const ()) -> RawWaker {
                AsyncExecutor::dummy_raw_waker()
            }
            static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
            RawWaker::new(::core::ptr::null(), &VTABLE)
        }
    }

    // -------------------------------------------------------------------------
    // Async UDP
    // -------------------------------------------------------------------------

    /// Received UDP packet
    pub struct UdpPacket {
        pub data: [u8; 128],
        pub len: usize,
        pub sender_addr: uip_ipaddr_t,
        pub sender_port: u16,
    }

    impl UdpPacket {
        pub const fn new() -> Self {
            Self {
                data: [0; 128],
                len: 0,
                sender_addr: uip_ip6addr_t { u8: [0; 16] },
                sender_port: 0,
            }
        }
    }

    /// Async UDP wrapper
    pub struct AsyncUdp {
        conn: *mut simple_udp_connection,
        pending_packet: Option<UdpPacket>,
    }

    impl AsyncUdp {
        /// Create a new async UDP wrapper
        pub fn new(conn: &mut simple_udp_connection) -> Self {
            Self {
                conn: conn as *mut simple_udp_connection,
                pending_packet: None,
            }
        }

        /// Notify that a packet was received (call from callback)
        pub fn notify_rx(&mut self, data: &[u8], sender_addr: *const uip_ipaddr_t, sender_port: u16) {
            let mut packet = UdpPacket::new();
            let len = data.len().min(128);
            packet.data[..len].copy_from_slice(&data[..len]);
            packet.len = len;
            packet.sender_addr = unsafe { *sender_addr };
            packet.sender_port = sender_port;
            self.pending_packet = Some(packet);
        }

        /// Receive a packet asynchronously (Future-based)
        pub fn recv(&mut self) -> AsyncUdpRecv<'_> {
            AsyncUdpRecv { udp: self }
        }

        /// Try to receive a packet without blocking (non-Future API)
        /// Returns Some(packet) if a packet is available, None otherwise
        pub fn try_recv(&mut self) -> Option<UdpPacket> {
            self.pending_packet.take()
        }

        /// Check if a packet is pending without consuming it
        pub fn has_pending(&self) -> bool {
            self.pending_packet.is_some()
        }

        /// Send data (not actually async, but fits the pattern)
        pub fn send(&mut self, data: &[u8], to: &uip_ipaddr_t, to_port: u16) {
            unsafe {
                ffi::simple_udp_sendto_port(
                    self.conn,
                    data.as_ptr() as *const c_void,
                    data.len() as u16,
                    to,
                    to_port,
                );
            }
        }
    }

    /// Future for receiving UDP packets
    pub struct AsyncUdpRecv<'a> {
        udp: &'a mut AsyncUdp,
    }

    impl<'a> Future for AsyncUdpRecv<'a> {
        type Output = UdpPacket;

        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            if let Some(packet) = self.udp.pending_packet.take() {
                Poll::Ready(packet)
            } else {
                Poll::Pending
            }
        }
    }
}

pub use async_support::{AsyncExecutor, AsyncTimer, AsyncUdp, AsyncUdpRecv, noop_waker, SafeCell, SafeTimer, UdpPacket};

// =============================================================================
// Macros
// =============================================================================

/// Create a null-terminated C string in static memory
#[macro_export]
macro_rules! c_str {
    ($s:expr) => {{
        static S: &[u8] = concat!($s, "\0").as_bytes();
        S.as_ptr() as *const $crate::c_char
    }};
}

/// Create a SafeTimer in static context
#[macro_export]
macro_rules! safe_timer {
    ($name:ident) => {
        static $name: $crate::async_support::SafeTimer = $crate::async_support::SafeTimer::new();
    };
}

/// Define a Rust process handler
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

// =============================================================================
// Print Helpers
// =============================================================================

/// Print a message to the console
#[inline]
pub fn print(msg: *const c_char) {
    unsafe { ffi::printf(msg); }
}

/// Print a formatted message with a u32 value
#[inline]
pub fn print_u32(format: *const c_char, value: u32) {
    unsafe { ffi::printf(format, value as c_uint); }
}

/// Print a null-terminated byte string
pub unsafe fn print_cstr(s: &[u8]) {
    if let Some(nul_pos) = s.iter().position(|&c| c == 0) {
        ffi::puts(s[..=nul_pos].as_ptr() as *const c_char);
    }
}

// =============================================================================
// Prelude
// =============================================================================

pub mod prelude {
    //! Convenient re-exports for common usage.
    //!
    //! ```rust
    //! use contiki_sys::prelude::*;
    //! ```

    pub use super::error::{Error, Result};
    pub use super::sys::{
        clock_second, clock_time_t, etimer, process, process_data_t, process_event_t,
        timer, timer_expired, timer_reset, timer_set, Clock, RustProcess, StaticBuffer,
        PROCESS_EVENT_INIT, PROCESS_EVENT_POLL, PROCESS_EVENT_TIMER,
        PT_ENDED, PT_WAITING, PT_YIELDED,
    };
    pub use super::hal::{Leds, Random, LEDS_ALL, LEDS_GREEN, LEDS_RED};
    pub use super::net::{linkaddr_t, uip_ipaddr_t, SimpleUdpConnection};
    pub use super::async_support::{AsyncExecutor, AsyncTimer, SafeTimer};
    pub use super::{print, print_u32};
    pub use super::{c_char, c_int, c_uint, c_void};
    // Note: c_str! and safe_timer! macros are automatically exported at crate root via #[macro_export]
}

// =============================================================================
// Panic Handler
// =============================================================================

use ::core::panic::PanicInfo;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    unsafe {
        ffi::printf(c_str!("PANIC: Rust code panicked!\n"));
        if let Some(location) = info.location() {
            ffi::printf(
                c_str!("Panic at %s:%u\n"),
                location.file().as_ptr() as *const c_char,
                location.line(),
            );
        }
        ffi::printf(c_str!("Triggering watchdog reboot...\n"));
        ffi::watchdog_reboot();
    }
    loop {}
}

// =============================================================================
// Optional Allocator
// =============================================================================

#[cfg(feature = "allocator")]
pub mod allocator {
    use ::core::alloc::{GlobalAlloc, Layout};
    use ::core::ffi::c_void;

    extern "C" {
        fn malloc(size: usize) -> *mut c_void;
        fn free(ptr: *mut c_void);
    }

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

// =============================================================================
// Tests
// =============================================================================

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
        assert_eq!(Random::rand_range(0), 0);
        assert_eq!(Random::rand_range(1), 0);

        for _ in 0..10 {
            let result = Random::rand_range(100);
            assert!(result < 100);
        }
    }
}
