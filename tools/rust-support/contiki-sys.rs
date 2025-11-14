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

// ============================================================================
// Sensor Types
// ============================================================================

/// Sensor configuration constants
pub const SENSORS_HW_INIT: c_int = 128;
pub const SENSORS_ACTIVE: c_int = 129;
pub const SENSORS_READY: c_int = 130;

/// Sensor value types (platform-specific but commonly used)
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

// ============================================================================
// Energest (Energy Estimation) Types
// ============================================================================

/// Energy estimation types for tracking power consumption
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

// ============================================================================
// Logging Types and Constants
// ============================================================================

/// Log level constants
pub const LOG_LEVEL_NONE: c_int = 0;  // No log
pub const LOG_LEVEL_ERR: c_int = 1;   // Errors
pub const LOG_LEVEL_WARN: c_int = 2;  // Warnings
pub const LOG_LEVEL_INFO: c_int = 3;  // Basic info
pub const LOG_LEVEL_DBG: c_int = 4;   // Detailed debug

// ============================================================================
// Packetbuf Types and Constants
// ============================================================================

/// Packetbuf attribute type
pub type packetbuf_attr_t = u16;

/// Packetbuf attribute structure
#[repr(C)]
pub struct packetbuf_attr {
    pub val: packetbuf_attr_t,
}

/// Packetbuf address structure
#[repr(C)]
pub struct packetbuf_addr {
    pub addr: linkaddr_t,
}

/// Packetbuf attribute/address types
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

// ============================================================================
// TSCH (Time-Slotted Channel Hopping) Types
// ============================================================================

/// TSCH link types
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum link_type {
    LINK_TYPE_NORMAL = 0,
    LINK_TYPE_ADVERTISING = 1,
    LINK_TYPE_ADVERTISING_ONLY = 2,
}

/// TSCH link options (bit flags)
pub const LINK_OPTION_TX: u8 = 1 << 0;
pub const LINK_OPTION_RX: u8 = 1 << 1;
pub const LINK_OPTION_SHARED: u8 = 1 << 2;
pub const LINK_OPTION_TIMEKEEPING: u8 = 1 << 3;

// ============================================================================
// CFS (Coffee File System) Types and Constants
// ============================================================================

/// File offset type
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

/// File open flags
pub const CFS_READ: c_int = 1;
pub const CFS_WRITE: c_int = 2;
pub const CFS_APPEND: c_int = 4;

/// Seek modes
pub const CFS_SEEK_SET: c_int = 0;
pub const CFS_SEEK_CUR: c_int = 1;
pub const CFS_SEEK_END: c_int = 2;

// ============================================================================
// RPL Routing Types
// ============================================================================

/// RPL prefix structure
#[repr(C)]
pub struct rpl_prefix_t {
    pub prefix: uip_ipaddr_t,
    pub length: u8,
    pub flags: u8,
}

/// Link address structure (MAC layer)
#[repr(C)]
#[derive(Copy, Clone)]
pub struct linkaddr_t {
    pub u8: [u8; 8],  // Typical size, may vary by platform
}

impl linkaddr_t {
    /// Create a new link address from bytes
    pub const fn from_bytes(bytes: [u8; 8]) -> Self {
        Self { u8: bytes }
    }

    /// Create a null (all zeros) link address
    pub const fn null() -> Self {
        Self { u8: [0; 8] }
    }

    /// Get address as bytes
    pub fn as_bytes(&self) -> &[u8; 8] {
        &self.u8
    }

    /// Check if address is null (all zeros)
    pub fn is_null(&self) -> bool {
        self.u8.iter().all(|&b| b == 0)
    }
}

// ============================================================================
// Networking Types
// ============================================================================

/// IPv6 address (128 bits)
#[repr(C)]
#[derive(Copy, Clone)]
pub union uip_ip6addr_t {
    pub u8: [u8; 16],
    pub u16: [u16; 8],
}

pub type uip_ipaddr_t = uip_ip6addr_t;

impl uip_ip6addr_t {
    /// Create a new IPv6 address from bytes
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self { u8: bytes }
    }

    /// Create an all-zeros IPv6 address
    pub const fn zero() -> Self {
        Self { u8: [0; 16] }
    }

    /// Get the address as bytes
    pub fn as_bytes(&self) -> &[u8; 16] {
        unsafe { &self.u8 }
    }

    /// Check if address is all zeros
    pub fn is_zero(&self) -> bool {
        unsafe { self.u8.iter().all(|&b| b == 0) }
    }
}

// Forward declaration for UDP connection struct
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

// External C functions (raw FFI, prefer using safe wrappers below)
extern "C" {
    // Process functions
    fn process_start(p: *mut process, data: process_data_t);
    fn process_exit(p: *mut process);
    fn process_post(p: *mut process, ev: process_event_t, data: process_data_t) -> c_int;
    fn process_post_synch(p: *mut process, ev: process_event_t, data: process_data_t);
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

    // Energest (energy estimation) functions
    pub fn energest_init();
    pub fn energest_flush();
    pub fn energest_type_time(type_: energest_type_t) -> u64;
    pub fn energest_type_set(type_: energest_type_t, value: u64);
    pub fn energest_on(type_: energest_type_t);
    pub fn energest_off(type_: energest_type_t);
    pub fn energest_switch(type_off: energest_type_t, type_on: energest_type_t);
    pub fn energest_get_total_time() -> u64;
    pub static mut energest_total_time: [u64; 5];  // ENERGEST_TYPE_MAX = 5

    // Logging functions
    pub fn log_lladdr(lladdr: *const linkaddr_t);
    pub fn log_lladdr_compact(lladdr: *const linkaddr_t);
    pub fn log_6addr(ipaddr: *const uip_ipaddr_t);
    pub fn log_6addr_compact(ipaddr: *const uip_ipaddr_t);
    pub fn log_6addr_compact_snprint(buf: *mut c_char, size: usize, ipaddr: *const uip_ipaddr_t) -> c_int;
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

    // TSCH state variables
    pub static tsch_is_coordinator: c_int;
    pub static tsch_is_associated: c_int;
    pub static tsch_is_pan_secured: c_int;

    // CFS (Coffee File System) functions
    pub fn cfs_open(name: *const c_char, flags: c_int) -> c_int;
    pub fn cfs_close(fd: c_int);
    pub fn cfs_read(fd: c_int, buf: *mut c_void, len: c_uint) -> c_int;
    pub fn cfs_write(fd: c_int, buf: *const c_void, len: c_uint) -> c_int;
    pub fn cfs_seek(fd: c_int, offset: cfs_offset_t, whence: c_int) -> cfs_offset_t;
    pub fn cfs_remove(name: *const c_char) -> c_int;
    pub fn cfs_opendir(dirp: *mut cfs_dir, name: *const c_char) -> c_int;
    pub fn cfs_readdir(dirp: *mut cfs_dir, dirent: *mut cfs_dirent) -> c_int;
    pub fn cfs_closedir(dirp: *mut cfs_dir);

    // RPL routing functions
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

    // Networking functions (simple-udp)
    pub fn simple_udp_init();
    pub fn simple_udp_register(
        c: *mut simple_udp_connection,
        local_port: u16,
        remote_addr: *mut uip_ipaddr_t,
        remote_port: u16,
        receive_callback: simple_udp_callback,
    ) -> c_int;
    pub fn simple_udp_send(c: *mut simple_udp_connection, data: *const c_void, datalen: u16) -> c_int;
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

// ============================================================================
// Energest (Energy Estimation) API Wrappers
// ============================================================================

/// Safe wrapper for energy estimation tracking
pub struct Energest;

impl Energest {
    /// Initialize the energy estimation module
    ///
    /// Should be called once at system startup
    ///
    /// # Example
    /// ```
    /// Energest::init();
    /// ```
    pub fn init() {
        unsafe { energest_init() }
    }

    /// Flush current energy measurements
    ///
    /// This updates all active energy counters to include
    /// time up to the current moment
    pub fn flush() {
        unsafe { energest_flush() }
    }

    /// Get total time spent in a particular energy state
    ///
    /// # Parameters
    /// - `type_`: The energy state to query
    ///
    /// # Returns
    /// Time in platform-specific ticks (usually rtimer ticks)
    ///
    /// # Example
    /// ```
    /// use energest_type_t::*;
    /// let cpu_time = Energest::type_time(CPU);
    /// let tx_time = Energest::type_time(TRANSMIT);
    /// ```
    pub fn type_time(type_: energest_type_t) -> u64 {
        unsafe { energest_type_time(type_) }
    }

    /// Set the total time for an energy state
    ///
    /// Typically used for resetting counters
    ///
    /// # Parameters
    /// - `type_`: The energy state to set
    /// - `value`: The value to set (in ticks)
    pub fn type_set(type_: energest_type_t, value: u64) {
        unsafe { energest_type_set(type_, value) }
    }

    /// Turn on energy tracking for a state
    ///
    /// # Parameters
    /// - `type_`: The energy state to start tracking
    ///
    /// # Example
    /// ```
    /// use energest_type_t::*;
    /// Energest::on(TRANSMIT);  // Start tracking TX time
    /// // ... perform transmission ...
    /// Energest::off(TRANSMIT);  // Stop tracking
    /// ```
    pub fn on(type_: energest_type_t) {
        unsafe { energest_on(type_) }
    }

    /// Turn off energy tracking for a state
    ///
    /// # Parameters
    /// - `type_`: The energy state to stop tracking
    pub fn off(type_: energest_type_t) {
        unsafe { energest_off(type_) }
    }

    /// Atomically switch from one energy state to another
    ///
    /// More efficient than calling off() then on() separately
    ///
    /// # Parameters
    /// - `type_off`: The energy state to turn off
    /// - `type_on`: The energy state to turn on
    ///
    /// # Example
    /// ```
    /// use energest_type_t::*;
    /// // Switch from listen to transmit
    /// Energest::switch(LISTEN, TRANSMIT);
    /// ```
    pub fn switch(type_off: energest_type_t, type_on: energest_type_t) {
        unsafe { energest_switch(type_off, type_on) }
    }

    /// Get the total system uptime
    ///
    /// # Returns
    /// Total time in platform ticks since energest_init()
    pub fn get_total_time() -> u64 {
        unsafe { energest_get_total_time() }
    }

    /// Calculate energy usage percentage for a state
    ///
    /// # Parameters
    /// - `type_`: The energy state to calculate percentage for
    ///
    /// # Returns
    /// Percentage (0.0 to 100.0) of time spent in this state
    ///
    /// # Example
    /// ```
    /// use energest_type_t::*;
    /// let cpu_percent = Energest::percentage(CPU);
    /// let tx_percent = Energest::percentage(TRANSMIT);
    /// ```
    pub fn percentage(type_: energest_type_t) -> f32 {
        let total = Self::get_total_time();
        if total == 0 {
            return 0.0;
        }
        let type_time = Self::type_time(type_);
        (type_time as f32 / total as f32) * 100.0
    }

    /// Reset all energy counters to zero
    ///
    /// # Example
    /// ```
    /// Energest::reset_all();  // Start fresh measurement period
    /// ```
    pub fn reset_all() {
        use energest_type_t::*;
        Self::type_set(CPU, 0);
        Self::type_set(LPM, 0);
        Self::type_set(DEEP_LPM, 0);
        Self::type_set(TRANSMIT, 0);
        Self::type_set(LISTEN, 0);
    }

    /// Get a snapshot of all energy measurements
    ///
    /// # Returns
    /// Array of measurements for all energy types
    ///
    /// # Example
    /// ```
    /// let snapshot = Energest::snapshot();
    /// println!("CPU: {}, TX: {}", snapshot[0], snapshot[3]);
    /// ```
    pub fn snapshot() -> [u64; 5] {
        Self::flush();
        unsafe { energest_total_time }
    }
}

// ============================================================================
// Logging API Wrappers
// ============================================================================

/// Safe wrapper for logging functions
pub struct Log;

impl Log {
    /// Log a link-layer address (MAC address)
    ///
    /// # Parameters
    /// - `lladdr`: The link-layer address to log
    ///
    /// # Example
    /// ```
    /// let addr = linkaddr_t::from_bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
    /// Log::lladdr(&addr);  // Logs full address
    /// ```
    pub fn lladdr(lladdr: &linkaddr_t) {
        unsafe { log_lladdr(lladdr as *const linkaddr_t) }
    }

    /// Log a link-layer address in compact format
    ///
    /// # Parameters
    /// - `lladdr`: The link-layer address to log
    pub fn lladdr_compact(lladdr: &linkaddr_t) {
        unsafe { log_lladdr_compact(lladdr as *const linkaddr_t) }
    }

    /// Log an IPv6 address
    ///
    /// # Parameters
    /// - `ipaddr`: The IPv6 address to log
    ///
    /// # Example
    /// ```
    /// use contiki_sys::*;
    /// let addr = get_ipv6_address();
    /// Log::ip6addr(&addr);
    /// ```
    pub fn ip6addr(ipaddr: &uip_ipaddr_t) {
        unsafe { log_6addr(ipaddr as *const uip_ipaddr_t) }
    }

    /// Log an IPv6 address in compact format
    ///
    /// # Parameters
    /// - `ipaddr`: The IPv6 address to log
    pub fn ip6addr_compact(ipaddr: &uip_ipaddr_t) {
        unsafe { log_6addr_compact(ipaddr as *const uip_ipaddr_t) }
    }

    /// Format an IPv6 address to a buffer in compact format
    ///
    /// # Parameters
    /// - `buf`: Output buffer (must have space for at least `size` bytes)
    /// - `ipaddr`: The IPv6 address to format
    ///
    /// # Returns
    /// Number of characters written (excluding null terminator)
    ///
    /// # Safety
    /// The buffer must have at least `size` bytes of valid memory
    pub unsafe fn ip6addr_to_buffer(buf: &mut [u8], ipaddr: &uip_ipaddr_t) -> Result<usize> {
        if buf.is_empty() {
            return Err(Error::InvalidParameter);
        }

        let written = log_6addr_compact_snprint(
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            ipaddr as *const uip_ipaddr_t,
        );

        if written < 0 {
            Err(Error::OperationFailed)
        } else {
            Ok(written as usize)
        }
    }

    /// Log a byte array as hex values
    ///
    /// # Parameters
    /// - `data`: The byte array to log
    ///
    /// # Example
    /// ```
    /// let packet = [0xCA, 0xFE, 0xBA, 0xBE];
    /// Log::bytes(&packet);  // Logs as hex: CA FE BA BE
    /// ```
    pub fn bytes(data: &[u8]) {
        if !data.is_empty() {
            unsafe {
                log_bytes(
                    data.as_ptr() as *const c_void,
                    data.len(),
                )
            }
        }
    }

    /// Log a string (may not be null-terminated)
    ///
    /// # Parameters
    /// - `text`: The string to log
    ///
    /// # Example
    /// ```
    /// Log::string(b"Hello, World!");
    /// ```
    pub fn string(text: &[u8]) {
        if !text.is_empty() {
            unsafe {
                log_string(
                    text.as_ptr() as *const c_char,
                    text.len(),
                )
            }
        }
    }

    /// Set the log level for a module at runtime
    ///
    /// # Parameters
    /// - `module`: Module name (null-terminated C string)
    /// - `level`: New log level (use LOG_LEVEL_* constants)
    ///
    /// # Example
    /// ```
    /// use contiki_sys::*;
    /// Log::set_level(c_str!("rpl"), LOG_LEVEL_DBG);
    /// ```
    pub fn set_level(module: *const c_char, level: c_int) {
        unsafe { log_set_level(module, level) }
    }

    /// Get the current log level for a module
    ///
    /// # Parameters
    /// - `module`: Module name (null-terminated C string)
    ///
    /// # Returns
    /// Current log level (LOG_LEVEL_* constant)
    pub fn get_level(module: *const c_char) -> c_int {
        unsafe { log_get_level(module) }
    }

    /// Convert a log level to a string description
    ///
    /// # Parameters
    /// - `level`: Log level (LOG_LEVEL_* constant)
    ///
    /// # Returns
    /// Pointer to static string describing the level
    ///
    /// # Safety
    /// The returned pointer points to static memory and is always valid
    pub fn level_to_str(level: c_int) -> *const c_char {
        unsafe { log_level_to_str(level) }
    }
}

// ============================================================================
// Packetbuf API Wrappers
// ============================================================================

/// Safe wrapper for packet buffer operations
pub struct Packetbuf;

impl Packetbuf {
    /// Clear and reset the packet buffer
    ///
    /// This should be called before preparing a new packet
    ///
    /// # Example
    /// ```
    /// Packetbuf::clear();
    /// Packetbuf::copy_from(b"Hello");
    /// ```
    pub fn clear() {
        unsafe { packetbuf_clear() }
    }

    /// Get a mutable slice to the data portion of the packet buffer
    ///
    /// # Returns
    /// Mutable slice to the packet data, or empty slice if no data
    ///
    /// # Safety
    /// The returned slice is valid until the next packetbuf operation
    pub fn data_mut() -> &'static mut [u8] {
        unsafe {
            let ptr = packetbuf_dataptr() as *mut u8;
            let len = packetbuf_datalen() as usize;
            if ptr.is_null() || len == 0 {
                &mut []
            } else {
                core::slice::from_raw_parts_mut(ptr, len)
            }
        }
    }

    /// Get an immutable slice to the data portion of the packet buffer
    ///
    /// # Returns
    /// Immutable slice to the packet data
    pub fn data() -> &'static [u8] {
        unsafe {
            let ptr = packetbuf_dataptr() as *const u8;
            let len = packetbuf_datalen() as usize;
            if ptr.is_null() || len == 0 {
                &[]
            } else {
                core::slice::from_raw_parts(ptr, len)
            }
        }
    }

    /// Get a slice to the header portion of the packet buffer
    ///
    /// # Returns
    /// Immutable slice to the packet header
    pub fn header() -> &'static [u8] {
        unsafe {
            let ptr = packetbuf_hdrptr() as *const u8;
            let len = packetbuf_hdrlen() as usize;
            if ptr.is_null() || len == 0 {
                &[]
            } else {
                core::slice::from_raw_parts(ptr, len)
            }
        }
    }

    /// Get the length of the data in the packet buffer
    pub fn data_len() -> usize {
        unsafe { packetbuf_datalen() as usize }
    }

    /// Get the length of the header in the packet buffer
    pub fn header_len() -> usize {
        unsafe { packetbuf_hdrlen() as usize }
    }

    /// Get the total length (header + data) in the packet buffer
    pub fn total_len() -> usize {
        unsafe { packetbuf_totlen() as usize }
    }

    /// Get the remaining space in the packet buffer
    pub fn remaining_len() -> usize {
        unsafe { packetbuf_remaininglen() as usize }
    }

    /// Set the length of the data in the packet buffer
    ///
    /// # Parameters
    /// - `len`: New data length
    ///
    /// # Safety
    /// The caller must ensure that `len` doesn't exceed the available buffer space
    pub fn set_data_len(len: usize) {
        unsafe { packetbuf_set_datalen(len as u16) }
    }

    /// Copy data from a slice into the packet buffer
    ///
    /// # Parameters
    /// - `data`: The data to copy
    ///
    /// # Returns
    /// Number of bytes copied (may be less than requested if buffer is full)
    ///
    /// # Example
    /// ```
    /// Packetbuf::clear();
    /// let copied = Packetbuf::copy_from(b"Hello, World!");
    /// ```
    pub fn copy_from(data: &[u8]) -> Result<usize> {
        unsafe {
            let result = packetbuf_copyfrom(
                data.as_ptr() as *const c_void,
                data.len() as u16,
            );
            if result < 0 {
                Err(Error::OperationFailed)
            } else {
                Ok(result as usize)
            }
        }
    }

    /// Copy the entire packet buffer to an external buffer
    ///
    /// # Parameters
    /// - `buf`: Destination buffer (must be at least PACKETBUF_SIZE bytes)
    ///
    /// # Returns
    /// Number of bytes copied
    pub fn copy_to(buf: &mut [u8]) -> Result<usize> {
        unsafe {
            let result = packetbuf_copyto(buf.as_mut_ptr() as *mut c_void);
            if result < 0 {
                Err(Error::OperationFailed)
            } else {
                Ok(result as usize)
            }
        }
    }

    /// Extend the header for outbound packets
    ///
    /// # Parameters
    /// - `size`: Number of bytes to allocate in header
    ///
    /// # Returns
    /// Ok(()) if successful, Err if insufficient space
    ///
    /// # Example
    /// ```
    /// Packetbuf::clear();
    /// Packetbuf::copy_from(b"payload");
    /// Packetbuf::hdr_alloc(10)?;  // Allocate 10 bytes for header
    /// ```
    pub fn hdr_alloc(size: usize) -> Result<()> {
        unsafe {
            let result = packetbuf_hdralloc(size as c_int);
            if result != 0 {
                Ok(())
            } else {
                Err(Error::BufferOverflow)
            }
        }
    }

    /// Reduce the header for incoming packets
    ///
    /// Removes bytes from the beginning of the header, typically
    /// used when processing received packets
    ///
    /// # Parameters
    /// - `size`: Number of bytes to remove from header
    ///
    /// # Returns
    /// Ok(()) if successful, Err if insufficient header space
    pub fn hdr_reduce(size: usize) -> Result<()> {
        unsafe {
            let result = packetbuf_hdrreduce(size as c_int);
            if result != 0 {
                Ok(())
            } else {
                Err(Error::InvalidParameter)
            }
        }
    }

    /// Set a packet attribute
    ///
    /// # Parameters
    /// - `attr_type`: Attribute type (use PACKETBUF_ATTR_* constants)
    /// - `value`: Attribute value
    ///
    /// # Example
    /// ```
    /// use contiki_sys::*;
    /// Packetbuf::set_attr(PACKETBUF_ATTR_CHANNEL, 26);
    /// ```
    pub fn set_attr(attr_type: u8, value: u16) {
        unsafe { packetbuf_set_attr(attr_type, value) }
    }

    /// Get a packet attribute
    ///
    /// # Parameters
    /// - `attr_type`: Attribute type (use PACKETBUF_ATTR_* constants)
    ///
    /// # Returns
    /// Attribute value
    pub fn attr(attr_type: u8) -> u16 {
        unsafe { packetbuf_attr(attr_type) }
    }

    /// Set a packet address (sender or receiver)
    ///
    /// # Parameters
    /// - `addr_type`: Address type (PACKETBUF_ADDR_SENDER or PACKETBUF_ADDR_RECEIVER)
    /// - `addr`: The link-layer address
    ///
    /// # Example
    /// ```
    /// use contiki_sys::*;
    /// let sender = linkaddr_t::from_bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
    /// Packetbuf::set_addr(PACKETBUF_ADDR_SENDER, &sender);
    /// ```
    pub fn set_addr(addr_type: u8, addr: &linkaddr_t) {
        unsafe { packetbuf_set_addr(addr_type, addr as *const linkaddr_t) }
    }

    /// Get a packet address (sender or receiver)
    ///
    /// # Parameters
    /// - `addr_type`: Address type (PACKETBUF_ADDR_SENDER or PACKETBUF_ADDR_RECEIVER)
    ///
    /// # Returns
    /// Reference to the address, or None if not set
    pub fn addr(addr_type: u8) -> Option<&'static linkaddr_t> {
        unsafe {
            let ptr = packetbuf_addr(addr_type);
            if ptr.is_null() {
                None
            } else {
                Some(&*ptr)
            }
        }
    }

    /// Check if the current packet is a broadcast
    ///
    /// # Returns
    /// true if the packet is addressed to the broadcast address
    pub fn is_broadcast() -> bool {
        unsafe { packetbuf_holds_broadcast() }
    }

    /// Clear all packet attributes
    pub fn clear_attrs() {
        unsafe { packetbuf_attr_clear() }
    }
}

// ============================================================================
// TSCH (Time-Slotted Channel Hopping) API Wrappers
// ============================================================================

/// Safe wrapper for TSCH operations
pub struct Tsch;

impl Tsch {
    /// Set the TSCH join priority
    ///
    /// Lower values indicate higher priority. Default is typically 0xFF.
    ///
    /// # Parameters
    /// - `priority`: Join priority value (0-255)
    ///
    /// # Example
    /// ```
    /// use contiki_sys::*;
    /// Tsch::set_join_priority(0x10);  // Set medium priority
    /// ```
    pub fn set_join_priority(priority: u8) {
        unsafe { tsch_set_join_priority(priority) }
    }

    /// Set the period for sending Enhanced Beacons (EBs)
    ///
    /// # Parameters
    /// - `period`: Period in clock ticks (set to 0 to stop sending EBs)
    ///
    /// Note: If RPL is used, this will be automatically reset by RPL
    /// when the DIO period changes.
    pub fn set_eb_period(period: u32) {
        unsafe { tsch_set_eb_period(period) }
    }

    /// Set the keep-alive timeout
    ///
    /// After this timeout, a node sends a unicast keep-alive to its time source
    ///
    /// # Parameters
    /// - `timeout`: Timeout in clock ticks (set to 0 to stop sending keep-alives)
    pub fn set_ka_timeout(timeout: u32) {
        unsafe { tsch_set_ka_timeout(timeout) }
    }

    /// Set the node as PAN coordinator
    ///
    /// # Parameters
    /// - `enable`: true to be coordinator, false to be a regular node
    ///
    /// # Example
    /// ```
    /// use contiki_sys::*;
    /// Tsch::set_coordinator(true);  // Become coordinator
    /// ```
    pub fn set_coordinator(enable: bool) {
        unsafe { tsch_set_coordinator(if enable { 1 } else { 0 }) }
    }

    /// Enable or disable link-layer security for the PAN
    ///
    /// # Parameters
    /// - `enable`: true to enable security, false to disable
    ///
    /// Note: Requires compilation with LLSEC802154_ENABLED set
    pub fn set_pan_secured(enable: bool) {
        unsafe { tsch_set_pan_secured(if enable { 1 } else { 0 }) }
    }

    /// Schedule a keep-alive transmission
    ///
    /// # Parameters
    /// - `immediate`: true to send immediately, false to schedule using current timeout
    pub fn schedule_keepalive(immediate: bool) {
        unsafe { tsch_schedule_keepalive(if immediate { 1 } else { 0 }) }
    }

    /// Get the network uptime in clock ticks
    ///
    /// # Returns
    /// Network uptime in ticks, or u64::MAX if not part of a TSCH network
    ///
    /// # Example
    /// ```
    /// use contiki_sys::*;
    /// let uptime = Tsch::get_network_uptime_ticks();
    /// if uptime != u64::MAX {
    ///     print(c_str!("Network uptime: "));
    ///     print_u32(c_str!("%llu"), uptime as u32);
    ///     print(c_str!(" ticks\n"));
    /// }
    /// ```
    pub fn get_network_uptime_ticks() -> u64 {
        unsafe {
            let uptime = tsch_get_network_uptime_ticks();
            // The C function returns -1 (cast to u64) if not in a network
            uptime
        }
    }

    /// Leave the TSCH network
    ///
    /// Disassociates from the current TSCH network
    pub fn disassociate() {
        unsafe { tsch_disassociate() }
    }

    /// Check if this node is the coordinator
    ///
    /// # Returns
    /// true if this node is the PAN coordinator
    pub fn is_coordinator() -> bool {
        unsafe { tsch_is_coordinator != 0 }
    }

    /// Check if this node is associated with a TSCH network
    ///
    /// # Returns
    /// true if associated with a network
    pub fn is_associated() -> bool {
        unsafe { tsch_is_associated != 0 }
    }

    /// Check if the PAN is running with link-layer security
    ///
    /// # Returns
    /// true if security is enabled
    pub fn is_pan_secured() -> bool {
        unsafe { tsch_is_pan_secured != 0 }
    }
}

// ============================================================================
// CFS (Coffee File System) API Wrappers
// ============================================================================

/// Safe wrapper for CFS file operations
pub struct CfsFile {
    fd: c_int,
}

impl CfsFile {
    /// Open a file
    ///
    /// # Parameters
    /// - `name`: File name (null-terminated C string)
    /// - `flags`: Open flags (CFS_READ, CFS_WRITE, CFS_APPEND)
    ///
    /// # Returns
    /// File handle on success, or error
    ///
    /// # Example
    /// ```
    /// use contiki_sys::*;
    /// let file = CfsFile::open(c_str!("data.txt"), CFS_WRITE)?;
    /// file.write(b"Hello, World!")?;
    /// file.close();
    /// ```
    pub fn open(name: *const c_char, flags: c_int) -> Result<Self> {
        unsafe {
            let fd = cfs_open(name, flags);
            if fd < 0 {
                Err(Error::OperationFailed)
            } else {
                Ok(CfsFile { fd })
            }
        }
    }

    /// Read data from the file
    ///
    /// # Parameters
    /// - `buf`: Buffer to read into
    ///
    /// # Returns
    /// Number of bytes read, or error
    pub fn read(&self, buf: &mut [u8]) -> Result<usize> {
        unsafe {
            let result = cfs_read(
                self.fd,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as c_uint,
            );
            if result < 0 {
                Err(Error::OperationFailed)
            } else {
                Ok(result as usize)
            }
        }
    }

    /// Write data to the file
    ///
    /// # Parameters
    /// - `data`: Data to write
    ///
    /// # Returns
    /// Number of bytes written, or error
    pub fn write(&self, data: &[u8]) -> Result<usize> {
        unsafe {
            let result = cfs_write(
                self.fd,
                data.as_ptr() as *const c_void,
                data.len() as c_uint,
            );
            if result < 0 {
                Err(Error::OperationFailed)
            } else {
                Ok(result as usize)
            }
        }
    }

    /// Seek to a position in the file
    ///
    /// # Parameters
    /// - `offset`: Offset value
    /// - `whence`: Seek mode (CFS_SEEK_SET, CFS_SEEK_CUR, CFS_SEEK_END)
    ///
    /// # Returns
    /// New file position, or error
    pub fn seek(&self, offset: isize, whence: c_int) -> Result<isize> {
        unsafe {
            let result = cfs_seek(self.fd, offset as cfs_offset_t, whence);
            if result < 0 {
                Err(Error::OperationFailed)
            } else {
                Ok(result as isize)
            }
        }
    }

    /// Close the file
    ///
    /// This consumes the file handle to prevent use-after-close
    pub fn close(self) {
        unsafe { cfs_close(self.fd) }
        // fd is dropped automatically
    }

    /// Get the raw file descriptor
    ///
    /// For advanced use cases that need direct access to the FD
    pub fn as_raw_fd(&self) -> c_int {
        self.fd
    }
}

// Implement Drop to auto-close files
impl Drop for CfsFile {
    fn drop(&mut self) {
        unsafe { cfs_close(self.fd) }
    }
}

/// CFS utility functions
pub struct Cfs;

impl Cfs {
    /// Remove a file
    ///
    /// # Parameters
    /// - `name`: File name (null-terminated C string)
    ///
    /// # Returns
    /// Ok(()) on success, error if file couldn't be removed
    ///
    /// # Example
    /// ```
    /// use contiki_sys::*;
    /// Cfs::remove(c_str!("old_data.txt"))?;
    /// ```
    pub fn remove(name: *const c_char) -> Result<()> {
        unsafe {
            let result = cfs_remove(name);
            if result < 0 {
                Err(Error::OperationFailed)
            } else {
                Ok(())
            }
        }
    }

    /// Open a directory for reading
    ///
    /// # Parameters
    /// - `name`: Directory name (null-terminated C string)
    ///
    /// # Returns
    /// Directory handle on success, or error
    ///
    /// # Example
    /// ```
    /// use contiki_sys::*;
    /// let mut dir = Cfs::opendir(c_str!("/"))?;
    /// while let Some(entry) = Cfs::readdir(&mut dir) {
    ///     // Process directory entry
    /// }
    /// Cfs::closedir(dir);
    /// ```
    pub fn opendir(name: *const c_char) -> Result<cfs_dir> {
        unsafe {
            let mut dir = core::mem::zeroed::<cfs_dir>();
            let result = cfs_opendir(&mut dir as *mut cfs_dir, name);
            if result < 0 {
                Err(Error::OperationFailed)
            } else {
                Ok(dir)
            }
        }
    }

    /// Read a directory entry
    ///
    /// # Parameters
    /// - `dir`: Directory handle from opendir()
    ///
    /// # Returns
    /// Some(dirent) if entry was read, None if no more entries
    pub fn readdir(dir: &mut cfs_dir) -> Option<cfs_dirent> {
        unsafe {
            let mut dirent = core::mem::zeroed::<cfs_dirent>();
            let result = cfs_readdir(dir as *mut cfs_dir, &mut dirent as *mut cfs_dirent);
            if result < 0 {
                None
            } else {
                Some(dirent)
            }
        }
    }

    /// Close a directory
    ///
    /// # Parameters
    /// - `dir`: Directory handle to close
    pub fn closedir(mut dir: cfs_dir) {
        unsafe { cfs_closedir(&mut dir as *mut cfs_dir) }
    }
}

impl cfs_dirent {
    /// Get the file/directory name as a Rust string slice
    ///
    /// Returns the name up to the first null byte or the end of the buffer
    pub fn name_str(&self) -> &str {
        // Find the null terminator
        let len = self.name.iter()
            .position(|&c| c == 0)
            .unwrap_or(self.name.len());

        // Convert to string, replacing invalid UTF-8 with replacement char
        core::str::from_utf8(&self.name[..len])
            .unwrap_or("<invalid>")
    }

    /// Get the file size
    pub fn size(&self) -> isize {
        self.size as isize
    }
}

// ============================================================================
// Sensor API Wrappers
// ============================================================================

/// Safe wrapper around a Contiki sensor
pub struct Sensor {
    inner: *const sensors_sensor,
}

impl Sensor {
    /// Find a sensor by type name
    ///
    /// # Errors
    /// Returns `Error::NotAvailable` if sensor not found
    ///
    /// # Example
    /// ```
    /// let button = Sensor::find(c_str!("button"))?;
    /// ```
    pub fn find(type_name: *const c_char) -> Result<Self> {
        let sensor = unsafe { sensors_find(type_name) };
        if sensor.is_null() {
            Err(Error::NotAvailable)
        } else {
            Ok(Self { inner: sensor })
        }
    }

    /// Get the first sensor in the system
    ///
    /// # Errors
    /// Returns `Error::NotAvailable` if no sensors available
    pub fn first() -> Result<Self> {
        let sensor = unsafe { sensors_first() };
        if sensor.is_null() {
            Err(Error::NotAvailable)
        } else {
            Ok(Self { inner: sensor })
        }
    }

    /// Get the next sensor in the list
    ///
    /// # Errors
    /// Returns `Error::NotAvailable` if no more sensors
    pub fn next(&self) -> Result<Self> {
        let sensor = unsafe { sensors_next(self.inner) };
        if sensor.is_null() {
            Err(Error::NotAvailable)
        } else {
            Ok(Self { inner: sensor })
        }
    }

    /// Activate the sensor
    ///
    /// # Errors
    /// Returns `Error::OperationFailed` if activation failed
    pub fn activate(&self) -> Result<()> {
        let result = unsafe {
            if let Some(configure) = (*self.inner).configure {
                configure(SENSORS_ACTIVE, 1)
            } else {
                return Err(Error::NotAvailable);
            }
        };
        if result == 0 {
            Err(Error::OperationFailed)
        } else {
            Ok(())
        }
    }

    /// Deactivate the sensor
    ///
    /// # Errors
    /// Returns `Error::OperationFailed` if deactivation failed
    pub fn deactivate(&self) -> Result<()> {
        let result = unsafe {
            if let Some(configure) = (*self.inner).configure {
                configure(SENSORS_ACTIVE, 0)
            } else {
                return Err(Error::NotAvailable);
            }
        };
        if result == 0 {
            Err(Error::OperationFailed)
        } else {
            Ok(())
        }
    }

    /// Read a value from the sensor
    ///
    /// # Errors
    /// Returns `Error::NotAvailable` if sensor has no value function
    ///
    /// # Example
    /// ```
    /// let temp_value = sensor.value(0)?;
    /// ```
    pub fn value(&self, type_: c_int) -> Result<c_int> {
        unsafe {
            if let Some(value_fn) = (*self.inner).value {
                Ok(value_fn(type_))
            } else {
                Err(Error::NotAvailable)
            }
        }
    }

    /// Check if sensor is ready
    ///
    /// # Errors
    /// Returns `Error::NotAvailable` if sensor has no status function
    pub fn is_ready(&self) -> Result<bool> {
        unsafe {
            if let Some(status_fn) = (*self.inner).status {
                Ok(status_fn(SENSORS_READY) != 0)
            } else {
                Err(Error::NotAvailable)
            }
        }
    }

    /// Get the sensor type name
    pub fn type_name(&self) -> &str {
        unsafe {
            let type_ptr = (*self.inner).type_;
            if type_ptr.is_null() {
                return "unknown";
            }
            // Find string length
            let mut len = 0;
            while *type_ptr.add(len) != 0 {
                len += 1;
            }
            let bytes = core::slice::from_raw_parts(type_ptr as *const u8, len);
            core::str::from_utf8(bytes).unwrap_or("unknown")
        }
    }

    /// Notify the system that sensor value has changed
    pub fn changed(&self) {
        unsafe { sensors_changed(self.inner) }
    }
}

/// Safe wrapper around button HAL
pub struct Button {
    inner: *mut button_hal_button,
}

impl Button {
    /// Initialize the button HAL (call once at startup)
    pub fn init() {
        unsafe { button_hal_init() }
    }

    /// Get a button by its index
    ///
    /// # Errors
    /// Returns `Error::NotAvailable` if button not found
    ///
    /// # Example
    /// ```
    /// let button0 = Button::get_by_index(0)?;
    /// ```
    pub fn get_by_index(index: u8) -> Result<Self> {
        let button = unsafe { button_hal_get_by_index(index) };
        if button.is_null() {
            Err(Error::NotAvailable)
        } else {
            Ok(Self { inner: button })
        }
    }

    /// Get a button by its unique ID
    ///
    /// # Errors
    /// Returns `Error::NotAvailable` if button not found
    pub fn get_by_id(unique_id: u8) -> Result<Self> {
        let button = unsafe { button_hal_get_by_id(unique_id) };
        if button.is_null() {
            Err(Error::NotAvailable)
        } else {
            Ok(Self { inner: button })
        }
    }

    /// Get the button's unique ID
    pub fn unique_id(&self) -> u8 {
        unsafe { (*self.inner).unique_id }
    }

    /// Get the button's GPIO pin
    pub fn pin(&self) -> u8 {
        unsafe { (*self.inner).pin }
    }

    /// Check if button uses negative logic (pressed = low)
    pub fn is_negative_logic(&self) -> bool {
        unsafe { (*self.inner).negative_logic != 0 }
    }
}

// ============================================================================
// RPL Routing API Wrappers
// ============================================================================

/// Safe wrapper for RPL DAG root operations
pub struct RplDagRoot;

impl RplDagRoot {
    /// Set the prefix for the DAG root
    ///
    /// # Parameters
    /// - `prefix`: The IPv6 prefix (None for default)
    /// - `iid`: The interface identifier (None to auto-generate)
    ///
    /// # Example
    /// ```
    /// let prefix = uip_ip6addr_t::from_bytes([/* prefix bytes */]);
    /// RplDagRoot::set_prefix(Some(&prefix), None);
    /// ```
    pub fn set_prefix(prefix: Option<&uip_ipaddr_t>, iid: Option<&uip_ipaddr_t>) {
        let prefix_ptr = prefix.map_or(core::ptr::null_mut(), |p| p as *const _ as *mut _);
        let iid_ptr = iid.map_or(core::ptr::null_mut(), |i| i as *const _ as *mut _);
        unsafe {
            rpl_dag_root_set_prefix(prefix_ptr, iid_ptr);
        }
    }

    /// Start the DAG as root
    ///
    /// # Errors
    /// Returns `Error::OperationFailed` if DAG root start failed
    ///
    /// # Example
    /// ```
    /// RplDagRoot::set_prefix(None, None);
    /// RplDagRoot::start()?;
    /// ```
    pub fn start() -> Result<()> {
        let result = unsafe { rpl_dag_root_start() };
        if result < 0 {
            Err(Error::OperationFailed)
        } else {
            Ok(())
        }
    }

    /// Check if this node is the DAG root
    pub fn is_root() -> bool {
        unsafe { rpl_dag_root_is_root() != 0 }
    }

    /// Print all routing links for debugging
    ///
    /// # Example
    /// ```
    /// RplDagRoot::print_links(c_str!("Current links"));
    /// ```
    pub fn print_links(description: *const c_char) {
        unsafe {
            rpl_dag_root_print_links(description);
        }
    }
}

/// Safe wrapper for RPL operations
pub struct Rpl;

impl Rpl {
    /// Set RPL prefix from a prefix structure
    ///
    /// # Errors
    /// Returns `Error::OperationFailed` if prefix setting failed
    pub fn set_prefix(prefix: &mut rpl_prefix_t) -> Result<()> {
        let result = unsafe { rpl_set_prefix(prefix as *mut rpl_prefix_t) };
        if result == 0 {
            Err(Error::OperationFailed)
        } else {
            Ok(())
        }
    }

    /// Set RPL prefix from an IPv6 address
    ///
    /// # Parameters
    /// - `addr`: The prefix address
    /// - `len`: Prefix length in bits
    /// - `flags`: DIO prefix flags
    ///
    /// # Errors
    /// Returns `Error::OperationFailed` if prefix setting failed
    ///
    /// # Example
    /// ```
    /// let mut prefix = uip_ip6addr_t::from_bytes([/* bytes */]);
    /// Rpl::set_prefix_from_addr(&mut prefix, 64, 0)?;
    /// ```
    pub fn set_prefix_from_addr(addr: &mut uip_ipaddr_t, len: u32, flags: u8) -> Result<()> {
        let result = unsafe {
            rpl_set_prefix_from_addr(addr as *mut uip_ipaddr_t, len as c_uint, flags)
        };
        if result == 0 {
            Err(Error::OperationFailed)
        } else {
            Ok(())
        }
    }

    /// Reset/remove the current prefix
    pub fn reset_prefix(last_prefix: &mut rpl_prefix_t) {
        unsafe {
            rpl_reset_prefix(last_prefix as *mut rpl_prefix_t);
        }
    }

    /// Get the node's global IPv6 address
    ///
    /// # Errors
    /// Returns `Error::NotAvailable` if no global address is available
    ///
    /// # Example
    /// ```
    /// let global_addr = Rpl::get_global_address()?;
    /// ```
    pub fn get_global_address() -> Result<&'static uip_ipaddr_t> {
        let addr = unsafe { rpl_get_global_address() };
        if addr.is_null() {
            Err(Error::NotAvailable)
        } else {
            Ok(unsafe { &*addr })
        }
    }

    /// Check if the node is reachable (has downward route)
    pub fn is_reachable() -> bool {
        unsafe { rpl_is_reachable() != 0 }
    }

    /// Trigger a route refresh via DTSN increment
    ///
    /// # Example
    /// ```
    /// Rpl::refresh_routes(c_str!("topology change"));
    /// ```
    pub fn refresh_routes(reason: *const c_char) {
        unsafe {
            rpl_refresh_routes(reason);
        }
    }

    /// Set whether this node acts only as a leaf (doesn't forward)
    ///
    /// # Parameters
    /// - `leaf_only`: true to enable leaf-only mode, false to disable
    ///
    /// # Example
    /// ```
    /// Rpl::set_leaf_only(true);  // Act as leaf only
    /// ```
    pub fn set_leaf_only(leaf_only: bool) {
        unsafe {
            rpl_set_leaf_only(if leaf_only { 1 } else { 0 });
        }
    }

    /// Check if leaf-only mode is enabled
    pub fn is_leaf_only() -> bool {
        unsafe { rpl_get_leaf_only() != 0 }
    }

    /// Notify RPL of a link-layer transmission result
    ///
    /// This should be called by MAC layers after transmission attempts
    ///
    /// # Parameters
    /// - `addr`: Link-layer address of destination
    /// - `status`: Transmission status
    /// - `numtx`: Number of transmission attempts
    pub fn link_callback(addr: &linkaddr_t, status: i32, numtx: i32) {
        unsafe {
            rpl_link_callback(addr as *const linkaddr_t, status as c_int, numtx as c_int);
        }
    }
}

// ============================================================================
// Networking API Wrappers (Simple UDP)
// ============================================================================

/// Safe wrapper around simple_udp_connection with Result-based error handling
pub struct SimpleUdpConnection {
    pub inner: simple_udp_connection,
    pub registered: bool,
}

impl SimpleUdpConnection {
    /// Create a new unregistered UDP connection
    pub const fn new() -> Self {
        Self {
            inner: simple_udp_connection {
                next: core::ptr::null_mut(),
                remote_addr: uip_ip6addr_t { u8: [0; 16] },
                remote_port: 0,
                local_port: 0,
                receive_callback: None,
                udp_conn: core::ptr::null_mut(),
                client_process: core::ptr::null_mut(),
            },
            registered: false,
        }
    }

    /// Initialize the simple-udp module (call once at startup)
    pub fn init() {
        unsafe { simple_udp_init() }
    }

    /// Register the UDP connection with local and remote ports
    ///
    /// # Parameters
    /// - `local_port`: Local UDP port (0 for ephemeral port)
    /// - `remote_addr`: Remote IP address (None to accept from any address)
    /// - `remote_port`: Remote UDP port (0 if using None for remote_addr)
    /// - `receive_callback`: Function to call when packets arrive
    ///
    /// # Errors
    /// Returns `Error::NetworkError` if registration failed (no UDP connection available)
    ///
    /// # Example
    /// ```
    /// let mut conn = SimpleUdpConnection::new();
    /// conn.register(1234, None, 0, Some(my_callback))?;
    /// ```
    pub fn register(
        &mut self,
        local_port: u16,
        remote_addr: Option<&uip_ipaddr_t>,
        remote_port: u16,
        receive_callback: simple_udp_callback,
    ) -> Result<()> {
        let remote_addr_ptr = match remote_addr {
            Some(addr) => addr as *const _ as *mut uip_ipaddr_t,
            None => core::ptr::null_mut(),
        };

        let result = unsafe {
            simple_udp_register(
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
    ///
    /// # Errors
    /// Returns `Error::NotAvailable` if not registered
    /// Returns `Error::NetworkError` if send failed
    ///
    /// # Example
    /// ```
    /// conn.send(b"Hello, world!")?;
    /// ```
    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        if !self.registered {
            return Err(Error::NotAvailable);
        }

        // Note: simple_udp_send always returns 0 (void-like function)
        // It doesn't actually indicate success/failure
        unsafe {
            simple_udp_send(
                &mut self.inner as *mut simple_udp_connection,
                data.as_ptr() as *const c_void,
                data.len() as u16,
            )
        };

        Ok(())
    }

    /// Send data to a specific IP address
    ///
    /// # Errors
    /// Returns `Error::NotAvailable` if not registered
    /// Returns `Error::NetworkError` if send failed
    ///
    /// # Example
    /// ```
    /// let dest_addr = uip_ip6addr_t::from_bytes([/* IPv6 bytes */]);
    /// conn.send_to(b"Hello!", &dest_addr)?;
    /// ```
    pub fn send_to(&mut self, data: &[u8], to: &uip_ipaddr_t) -> Result<()> {
        if !self.registered {
            return Err(Error::NotAvailable);
        }

        // Note: simple_udp_sendto always returns 0 (void-like function)
        // It doesn't actually indicate success/failure
        unsafe {
            simple_udp_sendto(
                &mut self.inner as *mut simple_udp_connection,
                data.as_ptr() as *const c_void,
                data.len() as u16,
                to as *const uip_ipaddr_t,
            )
        };

        Ok(())
    }

    /// Send data to a specific IP address and port
    ///
    /// # Errors
    /// Returns `Error::NotAvailable` if not registered
    /// Returns `Error::NetworkError` if send failed
    ///
    /// # Example
    /// ```
    /// let dest_addr = uip_ip6addr_t::from_bytes([/* IPv6 bytes */]);
    /// conn.send_to_port(b"Hello!", &dest_addr, 5678)?;
    /// ```
    pub fn send_to_port(&mut self, data: &[u8], to: &uip_ipaddr_t, to_port: u16) -> Result<()> {
        if !self.registered {
            return Err(Error::NotAvailable);
        }

        // Note: simple_udp_sendto_port always returns 0 (void-like function)
        // It doesn't actually indicate success/failure
        unsafe {
            simple_udp_sendto_port(
                &mut self.inner as *mut simple_udp_connection,
                data.as_ptr() as *const c_void,
                data.len() as u16,
                to as *const uip_ipaddr_t,
                to_port,
            )
        };

        Ok(())
    }

    /// Check if the connection is registered
    pub fn is_registered(&self) -> bool {
        self.registered
    }

    /// Get the local port
    pub fn local_port(&self) -> u16 {
        self.inner.local_port
    }

    /// Get the remote port
    pub fn remote_port(&self) -> u16 {
        self.inner.remote_port
    }

    /// Get a reference to the remote address
    pub fn remote_addr(&self) -> &uip_ipaddr_t {
        &self.inner.remote_addr
    }
}

// ============================================================================
// Async Runtime for Contiki-NG Processes
// ============================================================================

/// Async runtime support for Contiki-NG processes
///
/// This module provides async/await support on top of Contiki-NG's event-driven
/// process model. It allows writing process logic using async/await syntax while
/// integrating seamlessly with the underlying protothread system.
///
/// # Example
///
/// ```rust
/// use contiki_sys::*;
///
/// async fn my_async_process() {
///     loop {
///         AsyncTimer::delay_seconds(5).await;
///         print(c_str!("Tick!\n"));
///     }
/// }
/// ```
pub mod async_support {
    use super::*;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use core::cell::UnsafeCell;

    // ========================================================================
    // Safe Timer Wrapper
    // ========================================================================

    /// Thread-safe timer that can be used from static context
    ///
    /// This wrapper encapsulates all unsafe timer operations, providing
    /// a safe API that can be used without unsafe blocks.
    ///
    /// # Example
    /// ```rust
    /// static TIMER: SafeTimer = SafeTimer::new();
    ///
    /// // In process - no unsafe needed!
    /// TIMER.delay_seconds(2).await;
    /// ```
    pub struct SafeTimer {
        inner: UnsafeCell<etimer>,
    }

    unsafe impl Sync for SafeTimer {}

    impl SafeTimer {
        /// Create a new timer (const, for static initialization)
        pub const fn new() -> Self {
            Self {
                inner: UnsafeCell::new(etimer {
                    timer: timer {
                        start: 0,
                        interval: 0,
                    },
                    next: core::ptr::null_mut(),
                    p: core::ptr::null_mut(),
                }),
            }
        }

        /// Set timer interval
        pub fn set(&self, interval: clock_time_t) {
            unsafe {
                etimer_set(self.inner.get(), interval);
            }
        }

        /// Check if expired
        pub fn expired(&self) -> bool {
            unsafe {
                etimer_expired(self.inner.get())
            }
        }

        /// Reset timer
        pub fn reset(&self) {
            unsafe {
                etimer_reset(self.inner.get());
            }
        }

        /// Create a delay future for the specified number of seconds
        ///
        /// # Example
        /// ```rust
        /// TIMER.delay_seconds(2).await;  // Wait 2 seconds
        /// ```
        pub fn delay_seconds(&self, seconds: u32) -> AsyncTimer {
            AsyncTimer {
                timer: self.inner.get(),
                interval: unsafe { clock_second() } * seconds,
                started: false,
            }
        }

        /// Create a delay future for the specified number of milliseconds
        ///
        /// # Example
        /// ```rust
        /// TIMER.delay_ms(500).await;  // Wait 500ms
        /// ```
        pub fn delay_ms(&self, ms: u32) -> AsyncTimer {
            let ticks = (unsafe { clock_second() } * ms) / 1000;
            AsyncTimer {
                timer: self.inner.get(),
                interval: ticks,
                started: false,
            }
        }

        /// Create a delay future with a specific tick interval
        pub fn delay_ticks(&self, ticks: clock_time_t) -> AsyncTimer {
            AsyncTimer {
                timer: self.inner.get(),
                interval: ticks,
                started: false,
            }
        }

        /// Get raw pointer (for advanced usage)
        ///
        /// # Safety
        /// Caller must ensure no aliasing or data races
        pub unsafe fn as_ptr(&self) -> *mut etimer {
            self.inner.get()
        }
    }

    // ========================================================================
    // Async Timer
    // ========================================================================

    /// Future that completes when a timer expires
    ///
    /// This integrates with Contiki-NG's etimer system to provide
    /// async timer support.
    pub struct AsyncTimer {
        timer: *mut etimer,
        interval: clock_time_t,
        started: bool,
    }

    impl AsyncTimer {
        /// Create a new async timer with the given interval
        ///
        /// # Parameters
        /// - `timer`: Pointer to static etimer structure
        /// - `interval`: Timer interval in clock ticks
        ///
        /// # Safety
        /// The timer pointer must point to a valid, static etimer
        ///
        /// # Example
        /// ```rust
        /// static mut TIMER: etimer = /* ... */;
        /// let fut = unsafe { AsyncTimer::new(&mut TIMER, clock_second() * 5) };
        /// fut.await;
        /// ```
        pub unsafe fn new(timer: *mut etimer, interval: clock_time_t) -> Self {
            Self {
                timer,
                interval,
                started: false,
            }
        }

        /// Create a timer that delays for the specified number of seconds
        ///
        /// # Parameters
        /// - `timer`: Pointer to static etimer structure
        /// - `seconds`: Number of seconds to delay
        ///
        /// # Safety
        /// The timer pointer must point to a valid, static etimer
        pub unsafe fn delay_seconds(timer: *mut etimer, seconds: u32) -> Self {
            Self::new(timer, clock_second() * seconds)
        }

        /// Create a timer that delays for the specified number of milliseconds
        ///
        /// # Parameters
        /// - `timer`: Pointer to static etimer structure
        /// - `ms`: Number of milliseconds to delay
        ///
        /// # Safety
        /// The timer pointer must point to a valid, static etimer
        pub unsafe fn delay_ms(timer: *mut etimer, ms: u32) -> Self {
            let ticks = (clock_second() * ms) / 1000;
            Self::new(timer, ticks)
        }
    }

    impl Future for AsyncTimer {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            unsafe {
                if !self.started {
                    // Start the timer on first poll
                    etimer_set(self.timer, self.interval);
                    self.started = true;
                    Poll::Pending
                } else {
                    // Check if timer has expired
                    if etimer_expired(self.timer) {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                }
            }
        }
    }

    // ========================================================================
    // Async Event
    // ========================================================================

    /// Future that completes when a specific event occurs
    pub struct AsyncEvent {
        expected_event: process_event_t,
        received_event: Option<process_event_t>,
    }

    impl AsyncEvent {
        /// Create a future that waits for a specific event
        ///
        /// # Parameters
        /// - `event`: The event to wait for
        ///
        /// # Example
        /// ```rust
        /// AsyncEvent::new(button_hal_press_event).await;
        /// print(c_str!("Button pressed!\n"));
        /// ```
        pub fn new(event: process_event_t) -> Self {
            Self {
                expected_event: event,
                received_event: None,
            }
        }

        /// Update this future with a received event
        ///
        /// Call this from your process event handler to notify
        /// the future about incoming events.
        pub fn notify(&mut self, event: process_event_t) {
            self.received_event = Some(event);
        }
    }

    impl Future for AsyncEvent {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            if let Some(event) = self.received_event {
                if event == self.expected_event {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            } else {
                Poll::Pending
            }
        }
    }

    // ========================================================================
    // Async Process Executor
    // ========================================================================

    /// Simple executor for async processes
    ///
    /// This provides a minimal async runtime that integrates with
    /// Contiki-NG's event system.
    pub struct AsyncExecutor;

    impl AsyncExecutor {
        /// Create a dummy waker (Contiki-NG handles scheduling via events)
        pub fn dummy_waker() -> Waker {
            unsafe fn clone(_: *const ()) -> RawWaker {
                dummy_raw_waker()
            }
            unsafe fn wake(_: *const ()) {}
            unsafe fn wake_by_ref(_: *const ()) {}
            unsafe fn drop(_: *const ()) {}

            fn dummy_raw_waker() -> RawWaker {
                RawWaker::new(
                    core::ptr::null(),
                    &RawWakerVTable::new(clone, wake, wake_by_ref, drop),
                )
            }

            unsafe { Waker::from_raw(dummy_raw_waker()) }
        }

        /// Poll a future once
        ///
        /// Returns true if the future is ready, false if still pending
        pub fn poll_once<F>(future: Pin<&mut F>) -> bool
        where
            F: Future<Output = ()>,
        {
            let waker = Self::dummy_waker();
            let mut context = Context::from_waker(&waker);

            match future.poll(&mut context) {
                Poll::Ready(()) => true,
                Poll::Pending => false,
            }
        }
    }

    // ========================================================================
    // Static Future Storage
    // ========================================================================

    use core::mem::{self, MaybeUninit};
    use core::marker::PhantomData;
    use core::ptr;

    /// Fixed-size storage for futures without heap allocation
    ///
    /// This allows storing `async fn` futures in static memory by providing
    /// a fixed-size buffer. The buffer must be large enough to hold the
    /// future's state machine.
    ///
    /// # Example
    /// ```rust
    /// static mut FUTURE: StaticFuture<(), 512> = StaticFuture::new();
    ///
    /// async fn my_process() {
    ///     for i in 0..10 {
    ///         AsyncTimer::delay_seconds(&mut TIMER, 2).await;
    ///         print_u32(c_str!("Counter: %u\n"), i);
    ///     }
    /// }
    ///
    /// // In PROCESS_EVENT_INIT:
    /// unsafe { FUTURE.init(my_process()); }
    ///
    /// // Later, to poll:
    /// let pinned = unsafe { FUTURE.as_pin_mut().unwrap() };
    /// match pinned.poll(&mut context) {
    ///     Poll::Ready(()) => { /* done */ },
    ///     Poll::Pending => { /* wait */ },
    /// }
    /// ```
    pub struct StaticFuture<T, const SIZE: usize> {
        storage: MaybeUninit<[u8; SIZE]>,
        initialized: bool,
        _phantom: PhantomData<T>,
    }

    impl<T, const SIZE: usize> StaticFuture<T, SIZE> {
        /// Create a new uninitialized static future
        pub const fn new() -> Self {
            Self {
                storage: MaybeUninit::uninit(),
                initialized: false,
                _phantom: PhantomData,
            }
        }

        /// Initialize the future with an async function
        ///
        /// # Safety
        /// - Must only be called once
        /// - The future F must fit in SIZE bytes
        /// - Must call drop() before re-initializing
        pub unsafe fn init<F>(&mut self, future: F)
        where
            F: Future<Output = T>,
        {
            assert!(
                mem::size_of::<F>() <= SIZE,
                "Future size {} exceeds buffer size {}",
                mem::size_of::<F>(),
                SIZE
            );

            // Write the future to storage
            let ptr = self.storage.as_mut_ptr() as *mut F;
            ptr::write(ptr, future);
            self.initialized = true;
        }

        /// Get a pinned mutable reference to the future
        ///
        /// # Safety
        /// - Future must be initialized
        /// - Must not move the future after pinning
        pub unsafe fn as_pin_mut<F>(&mut self) -> Option<Pin<&mut F>>
        where
            F: Future<Output = T>,
        {
            if !self.initialized {
                return None;
            }

            let ptr = self.storage.as_mut_ptr() as *mut F;
            Some(Pin::new_unchecked(&mut *ptr))
        }

        /// Check if the future is initialized
        pub fn is_initialized(&self) -> bool {
            self.initialized
        }

        /// Drop the stored future
        ///
        /// # Safety
        /// - Future must be initialized with type F
        pub unsafe fn drop_future<F>(&mut self)
        where
            F: Future<Output = T>,
        {
            if self.initialized {
                let ptr = self.storage.as_mut_ptr() as *mut F;
                ptr::drop_in_place(ptr);
                self.initialized = false;
            }
        }
    }

    // ========================================================================
    // Async UDP Support
    // ========================================================================

    /// Async UDP connection
    ///
    /// Wraps SimpleUdpConnection with async recv/send capabilities
    pub struct AsyncUdp {
        conn: *mut simple_udp_connection,
        rx_ready: bool,
        rx_data: Option<UdpPacket>,
    }

    /// Received UDP packet data
    pub struct UdpPacket {
        pub data: StaticBuffer<256>,
        pub sender_addr: uip_ipaddr_t,
        pub sender_port: u16,
    }

    impl AsyncUdp {
        /// Create a new AsyncUdp wrapper
        ///
        /// # Safety
        /// The connection pointer must be valid and properly registered
        pub unsafe fn new(conn: *mut simple_udp_connection) -> Self {
            Self {
                conn,
                rx_ready: false,
                rx_data: None,
            }
        }

        /// Signal that data has been received (called from callback)
        ///
        /// # Safety
        /// Must be called from the UDP receive callback
        pub unsafe fn notify_rx(
            &mut self,
            data: &[u8],
            sender_addr: *const uip_ipaddr_t,
            sender_port: u16,
        ) {
            let mut buf = StaticBuffer::<256>::new();
            for &byte in data {
                let _ = buf.push(byte);
            }

            self.rx_data = Some(UdpPacket {
                data: buf,
                sender_addr: *sender_addr,
                sender_port,
            });
            self.rx_ready = true;
        }

        /// Async receive - waits for a packet
        pub fn recv(&mut self) -> AsyncUdpRecv<'_> {
            AsyncUdpRecv { udp: self }
        }

        /// Async send - sends a packet
        pub async fn send(&mut self, data: &[u8]) -> Result<()> {
            unsafe {
                simple_udp_send(
                    self.conn,
                    data.as_ptr() as *const core::ffi::c_void,
                    data.len() as u16,
                )
            };
            Ok(())
        }

        /// Async send to specific address and port
        pub async fn send_to(
            &mut self,
            data: &[u8],
            addr: *const uip_ipaddr_t,
            port: u16,
        ) -> Result<()> {
            unsafe {
                simple_udp_sendto_port(self.conn, data.as_ptr() as *const core::ffi::c_void, data.len() as u16, addr, port)
            };
            Ok(())
        }
    }

    /// Future for receiving UDP data
    pub struct AsyncUdpRecv<'a> {
        udp: &'a mut AsyncUdp,
    }

    impl<'a> Future for AsyncUdpRecv<'a> {
        type Output = UdpPacket;

        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.udp.rx_ready {
                self.udp.rx_ready = false;
                if let Some(packet) = self.udp.rx_data.take() {
                    Poll::Ready(packet)
                } else {
                    Poll::Pending
                }
            } else {
                Poll::Pending
            }
        }
    }

}

// NOTE: StaticFuture provides heap-free storage for async fn futures.
// AsyncUdp provides async networking capabilities.
// See examples for usage patterns.

/// Macro to create a safe timer (recommended)
///
/// This creates a static SafeTimer that can be used without unsafe blocks.
///
/// # Example
///
/// ```rust
/// safe_timer!(TIMER);
///
/// // Use without unsafe!
/// TIMER.delay_seconds(2).await;
/// ```
#[macro_export]
macro_rules! safe_timer {
    ($name:ident) => {
        static $name: $crate::async_support::SafeTimer = $crate::async_support::SafeTimer::new();
    };
}

/// Macro to create a timer for async use (legacy)
///
/// This creates a static etimer that can be used with AsyncTimer.
/// Note: Consider using `safe_timer!` instead for better safety.
///
/// # Example
///
/// ```rust
/// async_timer!(MY_TIMER);
///
/// async fn my_task() {
///     unsafe { AsyncTimer::delay_seconds(&mut MY_TIMER, 5).await; }
/// }
/// ```
#[macro_export]
macro_rules! async_timer {
    ($name:ident) => {
        static mut $name: $crate::etimer = $crate::etimer {
            timer: $crate::timer {
                start: 0,
                interval: 0,
            },
            next: core::ptr::null_mut(),
            p: core::ptr::null_mut(),
        };
    };
}

/// Macro to create an async process handler using StaticFuture
///
/// This generates a process event handler that stores an async function
/// in a StaticFuture and polls it on events.
///
/// # Example
///
/// ```rust
/// async_timer!(TIMER);
///
/// async fn my_async_process() {
///     for i in 0..10 {
///         unsafe { AsyncTimer::delay_seconds(&mut TIMER, 2).await; }
///         print_u32(c_str!("Counter: %u\n"), i);
///     }
/// }
///
/// async_fn_process!(my_handler, my_async_process, 512);
/// ```
#[macro_export]
macro_rules! async_fn_process {
    ($handler_name:ident, $async_fn:ident, $size:expr) => {
        mod __async_process_impl {
            use super::*;
            use core::mem::MaybeUninit;
            use core::pin::Pin;
            use core::task::{Context, Poll};

            // Wrapper to hold the future with its concrete type
            pub struct FutureHolder {
                storage: MaybeUninit<[u8; $size]>,
                initialized: bool,
            }

            impl FutureHolder {
                pub const fn new() -> Self {
                    Self {
                        storage: MaybeUninit::uninit(),
                        initialized: false,
                    }
                }

                pub unsafe fn init_and_poll(&mut self, waker: &core::task::Waker) -> (bool, Poll<()>) {
                    // Create the future - type is inferred here
                    let mut future = $async_fn();

                    // Check size
                    assert!(
                        core::mem::size_of_val(&future) <= $size,
                        "Future size {} exceeds buffer size {}",
                        core::mem::size_of_val(&future),
                        $size
                    );

                    // Poll it once before storing
                    let pinned = Pin::new_unchecked(&mut future);
                    let mut context = Context::from_waker(waker);
                    let result = pinned.poll(&mut context);

                    // If still pending, store it
                    if matches!(result, Poll::Pending) {
                        core::ptr::write(self.storage.as_mut_ptr() as *mut _, future);
                        self.initialized = true;
                    }

                    (matches!(result, Poll::Pending), result)
                }

                pub unsafe fn poll(&mut self, waker: &core::task::Waker) -> Poll<()> {
                    if !self.initialized {
                        return Poll::Ready(());
                    }

                    // Reconstruct the future reference from storage
                    // This works because we stored it with the exact same type
                    let future_ptr = self.storage.as_mut_ptr() as *mut _;
                    let future = &mut *future_ptr;

                    // Create a helper function to poll with proper type inference
                    fn poll_helper<F: core::future::Future<Output = ()>>(
                        future: &mut F,
                        waker: &core::task::Waker,
                    ) -> Poll<()> {
                        let pinned = unsafe { Pin::new_unchecked(future) };
                        let mut context = Context::from_waker(waker);
                        pinned.poll(&mut context)
                    }

                    poll_helper(future, waker)
                }
            }
        }

        static mut __FUTURE_HOLDER: __async_process_impl::FutureHolder =
            __async_process_impl::FutureHolder::new();

        #[no_mangle]
        pub extern "C" fn $handler_name(
            ev: $crate::process_event_t,
            _data: $crate::process_data_t,
        ) -> $crate::c_int {
            use $crate::async_support::AsyncExecutor;
            use core::task::Poll;

            unsafe {
                match ev {
                    $crate::PROCESS_EVENT_INIT => {
                        let waker = AsyncExecutor::dummy_waker();
                        let (pending, _) = __FUTURE_HOLDER.init_and_poll(&waker);

                        if pending {
                            $crate::PT_WAITING
                        } else {
                            $crate::PT_ENDED
                        }
                    }
                    _ => {
                        let waker = AsyncExecutor::dummy_waker();
                        match __FUTURE_HOLDER.poll(&waker) {
                            Poll::Ready(()) => $crate::PT_ENDED,
                            Poll::Pending => $crate::PT_WAITING,
                        }
                    }
                }
            }
        }
    };
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
