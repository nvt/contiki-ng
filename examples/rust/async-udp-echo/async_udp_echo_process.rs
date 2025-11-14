//! Async UDP Echo Server Example
//!
//! This example demonstrates true async UDP networking in Rust for Contiki-NG.
//! It uses AsyncUdp with a manually-implemented Future to handle packets asynchronously.
//!
//! Architecture:
//! - UDP callback stores packets in AsyncUdp via notify_rx()
//! - UdpEchoFuture awaits packets using AsyncUdp::recv()
//! - Future processes packets and echoes them back
//! - Manual state machine implements the async loop
//!
//! This demonstrates:
//! - Async packet reception with Future pattern
//! - Bridging C callbacks with async Rust
//! - Manual Future implementation for no_std
//! - Event-driven async execution in Contiki-NG

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
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

// ============================================================================
// Noop Waker (for Contiki-NG event-driven model)
// ============================================================================

unsafe fn noop_clone(_: *const ()) -> RawWaker {
    noop_raw_waker()
}

unsafe fn noop_wake(_: *const ()) {}

unsafe fn noop_wake_by_ref(_: *const ()) {}

unsafe fn noop_drop(_: *const ()) {}

const NOOP_WAKER_VTABLE: RawWakerVTable =
    RawWakerVTable::new(noop_clone, noop_wake, noop_wake_by_ref, noop_drop);

const fn noop_raw_waker() -> RawWaker {
    RawWaker::new(core::ptr::null(), &NOOP_WAKER_VTABLE)
}

fn noop_waker() -> Waker {
    unsafe { Waker::from_raw(noop_raw_waker()) }
}

// ============================================================================
// Static State
// ============================================================================

const UDP_PORT: u16 = 8765;

/// Track initialization state
static mut INITIALIZED: bool = false;

/// UDP connection structure
#[no_mangle]
#[used]
static mut UDP_CONN: simple_udp_connection = simple_udp_connection {
    next: core::ptr::null_mut(),
    remote_addr: uip_ip6addr_t { u8: [0; 16] },
    remote_port: 0,
    local_port: 0,
    receive_callback: None,
    udp_conn: core::ptr::null_mut(),
    client_process: core::ptr::null_mut(),
};

/// Async UDP wrapper for async packet reception
#[no_mangle]
#[used]
static mut ASYNC_UDP: Option<AsyncUdp> = None;

/// Process pointer (needed to wake up the process from callback)
#[no_mangle]
#[used]
static mut PROCESS_PTR: *mut process = core::ptr::null_mut();

// ============================================================================
// UDP Callback
// ============================================================================

/// Called when UDP data is received
#[no_mangle]
pub unsafe extern "C" fn udp_rx_callback(
    _c: *mut simple_udp_connection,
    sender_addr: *const uip_ipaddr_t,
    sender_port: u16,
    _receiver_addr: *const uip_ipaddr_t,
    _receiver_port: u16,
    data: *const u8,
    datalen: u16,
) {
    // Create data slice safely
    let data_slice = if datalen > 0 && !data.is_null() {
        core::slice::from_raw_parts(data, datalen as usize)
    } else {
        &[]
    };

    // Store packet in async UDP for async processing
    if let Some(ref mut async_udp) = ASYNC_UDP {
        async_udp.notify_rx(data_slice, sender_addr, sender_port);
    }

    // Wake the process to handle the packet asynchronously
    if !PROCESS_PTR.is_null() {
        process_poll(PROCESS_PTR);
    }
}


// ============================================================================
// Async UDP Echo Future
// ============================================================================

/// Future that implements async UDP echo
/// This implements a simple loop: await packet -> echo back -> repeat
struct UdpEchoFuture;

impl UdpEchoFuture {
    fn new() -> Self {
        Self
    }
}

impl Future for UdpEchoFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        unsafe {
            // Check if we have a packet ready
            if let Some(ref mut async_udp) = ASYNC_UDP {
                // Create and immediately poll the recv future
                let mut recv_future = async_udp.recv();

                match Pin::new(&mut recv_future).poll(cx) {
                    Poll::Ready(packet) => {
                        // Got a packet! Print and echo it back
                        print(c_str!("Async received "));
                        print_u32(c_str!("%u"), packet.data.len() as u32);
                        print(c_str!(" bytes from port "));
                        print_u32(c_str!("%u\n"), packet.sender_port as u32);

                        // Echo back the packet
                        simple_udp_sendto_port(
                            &mut UDP_CONN as *mut simple_udp_connection,
                            packet.data.as_slice().as_ptr() as *const core::ffi::c_void,
                            packet.data.len() as u16,
                            &packet.sender_addr,
                            packet.sender_port,
                        );

                        print(c_str!("Async echoed back\n"));

                        // Keep the future alive - always return Pending
                        // Wake immediately to check for more packets
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Poll::Pending => {
                        // No packet available, wait for next event
                        Poll::Pending
                    }
                }
            } else {
                // No AsyncUdp available (shouldn't happen)
                Poll::Pending
            }
        }
    }
}

/// Static storage for the main future
#[no_mangle]
#[used]
static mut ECHO_FUTURE: Option<UdpEchoFuture> = None;

// ============================================================================
// Process Handler
// ============================================================================

// External C function to get process pointer
extern "C" {
    fn rust_get_process_ptr() -> *mut process;
}

/// Main process event handler
#[no_mangle]
pub extern "C" fn rust_async_udp_echo_handler(
    ev: process_event_t,
    _data: process_data_t,
) -> c_int {
    unsafe {
        match ev {
            PROCESS_EVENT_INIT => {
                print(c_str!("Async UDP Echo Server starting...\n"));

                // Get process pointer from C side
                PROCESS_PTR = rust_get_process_ptr();

                // Register UDP connection DIRECTLY on the static UDP_CONN
                // This is critical - we must register the static, not a temporary!
                let result = simple_udp_register(
                    &mut UDP_CONN as *mut simple_udp_connection,
                    UDP_PORT,
                    core::ptr::null_mut(),
                    0,
                    Some(udp_rx_callback),
                );

                if result != 0 {
                    print(c_str!("UDP server listening on port "));
                    print_u32(c_str!("%u"), UDP_PORT as u32);
                    print(c_str!("\n"));

                    INITIALIZED = true;

                    // Initialize AsyncUdp wrapper
                    ASYNC_UDP = Some(AsyncUdp::new(&mut UDP_CONN));

                    // Create the async echo future
                    ECHO_FUTURE = Some(UdpEchoFuture::new());

                    print(c_str!("Async echo loop ready\n"));
                    print(c_str!("Send UDP packets to this node on port "));
                    print_u32(c_str!("%u"), UDP_PORT as u32);
                    print(c_str!(" and they will be echoed back asynchronously\n"));

                    PT_WAITING
                } else {
                    print(c_str!("Failed to register UDP connection\n"));
                    PT_ENDED
                }
            }

            _ => {
                // Poll the async future on every event
                if INITIALIZED {
                    if let Some(ref mut future) = ECHO_FUTURE {
                        // Create a minimal waker for the async context
                        let waker = noop_waker();
                        let mut context = Context::from_waker(&waker);

                        // Poll the future
                        match Pin::new(future).poll(&mut context) {
                            Poll::Ready(()) => {
                                // Future completed (shouldn't happen - it loops forever)
                                print(c_str!("Echo future completed unexpectedly\n"));
                                PT_ENDED
                            }
                            Poll::Pending => PT_WAITING,
                        }
                    } else {
                        PT_WAITING
                    }
                } else {
                    PT_ENDED
                }
            }
        }
    }
}
