//! Safe Async Hello World
//!
//! This example demonstrates:
//! - SafeTimer (no unsafe in user code!)
//! - Clean, readable async patterns
//! - Proper encapsulation
//! - Idiomatic Rust style

#![no_std]
#![no_main]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(static_mut_refs)]

#[path = "../../../tools/rust-support/contiki-sys.rs"]
mod contiki_sys;

use contiki_sys::*;
use contiki_sys::async_support::*;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

// ============================================================================
// Static State - Safe and Clean!
// ============================================================================

// ✅ No unsafe, no mut, just a safe timer!
safe_timer!(TIMER);

// ============================================================================
// Async Counter Future - Much Simpler!
// ============================================================================

/// Counts from 1 to max with delays
struct CounterFuture {
    count: u32,
    max_count: u32,
    timer_future: Option<AsyncTimer>,
}

impl CounterFuture {
    fn new(max_count: u32) -> Self {
        Self {
            count: 0,
            max_count,
            timer_future: None,
        }
    }
}

impl Future for CounterFuture {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            // Check if we're done
            if self.count >= self.max_count {
                return Poll::Ready(());
            }

            // Create timer future if needed
            if self.timer_future.is_none() {
                if self.count == 0 {
                    print(c_str!("Hello from Safe Async Rust!\n"));
                    print(c_str!("Starting safe async execution...\n"));
                }

                // ✅ No unsafe! Clean and safe!
                self.timer_future = Some(TIMER.delay_seconds(2));
            }

            // Poll the timer
            if let Some(ref mut timer_fut) = self.timer_future {
                match Pin::new(timer_fut).poll(cx) {
                    Poll::Ready(()) => {
                        // Timer expired
                        self.count += 1;
                        print_u32(c_str!("Safe async count: %lu\n"), self.count);

                        // Reset for next iteration
                        self.timer_future = None;
                        continue;
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
    }
}

// ============================================================================
// Process State
// ============================================================================

#[no_mangle]
#[used]
static mut FUTURE: Option<CounterFuture> = None;

// ============================================================================
// Process Handler
// ============================================================================

#[no_mangle]
pub extern "C" fn rust_async_hello_handler(
    ev: process_event_t,
    _data: process_data_t,
) -> c_int {
    unsafe {
        match ev {
            PROCESS_EVENT_INIT => {
                print(c_str!("Initializing safe async process...\n"));

                // Create future - no unsafe needed!
                FUTURE = Some(CounterFuture::new(10));

                // Poll once to initialize
                if let Some(ref mut future) = FUTURE {
                    let waker = AsyncExecutor::dummy_waker();
                    let mut context = Context::from_waker(&waker);

                    match Pin::new(future).poll(&mut context) {
                        Poll::Ready(()) => return PT_ENDED,
                        Poll::Pending => {}
                    }
                }

                PT_WAITING
            }

            _ => {
                // Poll the future
                if let Some(ref mut future) = FUTURE {
                    let waker = AsyncExecutor::dummy_waker();
                    let mut context = Context::from_waker(&waker);

                    match Pin::new(future).poll(&mut context) {
                        Poll::Ready(()) => {
                            print(c_str!("Safe async process completed!\n"));
                            PT_ENDED
                        }
                        Poll::Pending => PT_WAITING,
                    }
                } else {
                    PT_ENDED
                }
            }
        }
    }
}
