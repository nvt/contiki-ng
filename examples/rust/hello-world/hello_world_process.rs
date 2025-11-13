//! Minimal Rust Hello World Process for Contiki-NG
//!
//! Timer-based demo that counts from 1 to 10.
//! See README.md for architecture overview, FFI patterns, and building instructions.

#![no_std]
#![no_main]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(static_mut_refs)]

#[path = "../../../tools/rust-support/contiki-sys.rs"]
mod contiki_sys;

use contiki_sys::*;

// ============================================================================
// Process State
// ============================================================================
// Static variables maintain state across events. Safe due to single-threaded execution.

/// Event timer - set during PROCESS_EVENT_INIT
#[no_mangle]
#[used]
static mut TIMER: etimer = etimer {
    timer: timer {
        start: 0,
        interval: 0,
    },
    next: core::ptr::null_mut(),
    p: core::ptr::null_mut(),
};

/// Counter - increments from 0 to 10, then process terminates
#[no_mangle]
#[used]
static mut COUNTER: u32 = 0;

// ============================================================================
// Helper Functions
// ============================================================================

#[inline]
fn init_counter() {
    // SAFETY: Single-threaded execution - no data races
    unsafe {
        COUNTER = 0;
    }
}

#[inline]
fn increment_counter() -> u32 {
    // SAFETY: Single-threaded execution - no data races
    unsafe {
        COUNTER += 1;
        COUNTER
    }
}

// ============================================================================
// Main Process Handler
// ============================================================================

/// Event handler called by C code. Returns PT_YIELDED to continue or PT_ENDED to terminate.
#[no_mangle]
pub extern "C" fn rust_hello_world_handler(ev: process_event_t, _data: process_data_t) -> c_int {
    match ev {
        PROCESS_EVENT_INIT => {
            print(c_str!("Hello from Rust using contiki-sys!\n"));
            print(c_str!("Starting timer-based execution...\n"));
            init_counter();
            // SAFETY: Single-threaded execution - no concurrent access to TIMER
            unsafe {
                timer_set(&mut TIMER, clock_second() * 2);
            }
            PT_YIELDED
        }

        PROCESS_EVENT_TIMER => {
            // SAFETY: Single-threaded execution - no concurrent access to TIMER
            let expired = unsafe { timer_expired(&mut TIMER) };
            if expired {
                let counter = increment_counter();
                print_u32(c_str!("Hello from Rust! Counter: %lu\n"), counter);

                if counter >= 10 {
                    print(c_str!("Rust process completed!\n"));
                    return PT_ENDED;
                }

                // SAFETY: Single-threaded execution - no concurrent access to TIMER
                unsafe {
                    timer_reset(&mut TIMER);
                }
            }
            PT_YIELDED
        }

        _ => PT_YIELDED,
    }
}
