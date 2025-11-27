//! Safe Async Hello World
//!
//! This example demonstrates:
//! - SafeTimer (no unsafe in user code for timer!)
//! - SafeCell for state management
//! - Clean, readable async patterns
//! - Minimal unsafe code

#![no_std]
#![no_main]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#[path = "../../../tools/rust-support/contiki-sys.rs"]
mod contiki_sys;

use contiki_sys::*;
use contiki_sys::async_support::*;
use core::cell::UnsafeCell;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

// ============================================================================
// Static State - Safe wrappers
// ============================================================================

safe_timer!(TIMER);

// ============================================================================
// Async Counter Future
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
            if self.count >= self.max_count {
                return Poll::Ready(());
            }

            if self.timer_future.is_none() {
                if self.count == 0 {
                    print(c_str!("Hello from Safe Async Rust!\n"));
                    print(c_str!("Starting safe async execution...\n"));
                }
                self.timer_future = Some(TIMER.delay_seconds(2));
            }

            if let Some(ref mut timer_fut) = self.timer_future {
                match Pin::new(timer_fut).poll(cx) {
                    Poll::Ready(()) => {
                        self.count += 1;
                        print_u32(c_str!("Safe async count: %lu\n"), self.count);
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
// Safe Future Storage
// ============================================================================

/// Safe wrapper for the future state
struct SafeFuture {
    inner: UnsafeCell<Option<CounterFuture>>,
}

unsafe impl Sync for SafeFuture {}

impl SafeFuture {
    const fn new() -> Self {
        Self { inner: UnsafeCell::new(None) }
    }

    fn init(&self, future: CounterFuture) {
        unsafe { *self.inner.get() = Some(future) }
    }

    fn poll(&self, cx: &mut Context<'_>) -> Poll<()> {
        unsafe {
            if let Some(ref mut future) = *self.inner.get() {
                Pin::new(future).poll(cx)
            } else {
                Poll::Ready(())
            }
        }
    }
}

static FUTURE: SafeFuture = SafeFuture::new();

// ============================================================================
// Process Handler
// ============================================================================

#[no_mangle]
pub extern "C" fn rust_async_hello_handler(
    ev: process_event_t,
    _data: process_data_t,
) -> c_int {
    match ev {
        PROCESS_EVENT_INIT => {
            print(c_str!("Initializing safe async process...\n"));

            FUTURE.init(CounterFuture::new(10));

            // Poll once to initialize
            let waker = noop_waker();
            let mut context = Context::from_waker(&waker);

            match FUTURE.poll(&mut context) {
                Poll::Ready(()) => PT_ENDED,
                Poll::Pending => PT_WAITING,
            }
        }

        _ => {
            let waker = noop_waker();
            let mut context = Context::from_waker(&waker);

            match FUTURE.poll(&mut context) {
                Poll::Ready(()) => {
                    print(c_str!("Safe async process completed!\n"));
                    PT_ENDED
                }
                Poll::Pending => PT_WAITING,
            }
        }
    }
}
