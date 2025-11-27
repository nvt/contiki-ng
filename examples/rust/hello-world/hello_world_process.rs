//! Minimal Rust Hello World Process for Contiki-NG
//!
//! Timer-based demo that counts from 1 to 10.
//! Uses SafeTimer and SafeCell to eliminate unsafe blocks in user code.

#![no_std]
#![no_main]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#[path = "../../../tools/rust-support/contiki-sys.rs"]
mod contiki_sys;

use contiki_sys::*;

// ============================================================================
// Process State - Safe static variables
// ============================================================================

/// Event timer using safe wrapper
safe_timer!(TIMER);

/// Counter using safe cell (no unsafe needed to access)
static COUNTER: SafeCell<u32> = SafeCell::new(0);

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
            COUNTER.set(0);
            TIMER.set(clock_second() * 2);
            PT_YIELDED
        }

        PROCESS_EVENT_TIMER => {
            if TIMER.expired() {
                let count = COUNTER.increment();
                print_u32(c_str!("Hello from Rust! Counter: %lu\n"), count);

                if count >= 10 {
                    print(c_str!("Rust process completed!\n"));
                    return PT_ENDED;
                }

                TIMER.reset();
            }
            PT_YIELDED
        }

        _ => PT_YIELDED,
    }
}
