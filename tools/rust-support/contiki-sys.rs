//! FFI bindings for Contiki-NG core APIs
//! This module provides safe Rust wrappers around Contiki-NG C APIs

#![no_std]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use core::ffi::{c_char, c_void, c_int, c_uint};

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

// Helper macros for Rust
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

// Panic handler for no_std
#[cfg(not(target_os = "none"))]
use core::panic::PanicInfo;

#[cfg(not(target_os = "none"))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // In embedded context, just halt
    loop {}
}