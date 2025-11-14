//! Future-based Hello World Process for Contiki-NG
//!
//! Demonstrates Future-based programming built on top of Contiki-NG's
//! event-driven process model and protothreads.
//!
//! This example shows:
//! - Manual Future implementation (what async/await does under the hood)
//! - AsyncTimer as a building block
//! - Integration with Contiki-NG's event system
//! - Zero heap allocation, works in no_std
//!
//! Note: This is a manual state machine approach. Full async/await syntax
//! requires additional infrastructure not shown here.

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
// Static State
// ============================================================================

/// Event timer
async_timer!(TIMER);

/// Counter Future - manually implemented state machine
struct CounterFuture {
    timer: *mut etimer,
    count: u32,
    max_count: u32,
    timer_future: Option<AsyncTimer>,
}

impl CounterFuture {
    fn new(timer: *mut etimer, max_count: u32) -> Self {
        Self {
            timer,
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
            // If we've reached max count, we're done
            if self.count >= self.max_count {
                return Poll::Ready(());
            }

            // If we don't have a timer future, create one
            if self.timer_future.is_none() {
                if self.count == 0 {
                    print(c_str!("Hello from Future-based Rust!\n"));
                    print(c_str!("Starting future-based execution...\n"));
                }

                self.timer_future = Some(unsafe { AsyncTimer::delay_seconds(self.timer, 2) });
            }

            // Poll the timer future
            if let Some(ref mut timer_fut) = self.timer_future {
                match Pin::new(timer_fut).poll(cx) {
                    Poll::Ready(()) => {
                        // Timer expired, increment counter and print
                        self.count += 1;
                        print_u32(c_str!("Future Hello! Counter: %lu\n"), self.count);

                        // Reset timer future for next iteration
                        self.timer_future = None;

                        // Continue loop to check if we're done or need another delay
                        continue;
                    }
                    Poll::Pending => {
                        // Timer not ready yet
                        return Poll::Pending;
                    }
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

/// Main process event handler
#[no_mangle]
pub extern "C" fn rust_async_hello_handler(
    ev: process_event_t,
    _data: process_data_t,
) -> c_int {
    unsafe {
        match ev {
            PROCESS_EVENT_INIT => {
                print(c_str!("Initializing future-based process...\n"));

                // Create the counter future
                FUTURE = Some(CounterFuture::new(&mut TIMER, 10));

                // Poll the future once to start the timer
                if let Some(ref mut future) = FUTURE {
                    let waker = AsyncExecutor::dummy_waker();
                    let mut context = Context::from_waker(&waker);

                    match Pin::new(future).poll(&mut context) {
                        Poll::Ready(()) => {
                            print(c_str!("Completed immediately!\n"));
                            return PT_ENDED;
                        }
                        Poll::Pending => {
                            print(c_str!("Started, waiting for events...\n"));
                        }
                    }
                }

                PT_WAITING
            }

            _ => {
                // Poll the future
                if let Some(ref mut future) = FUTURE {
                    // Create a no-op waker (Contiki-NG handles scheduling)
                    let waker = AsyncExecutor::dummy_waker();
                    let mut context = Context::from_waker(&waker);

                    match Pin::new(future).poll(&mut context) {
                        Poll::Ready(()) => {
                            print(c_str!("Future-based process completed!\n"));
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
