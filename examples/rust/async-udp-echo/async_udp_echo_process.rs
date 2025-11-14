//! Async UDP Echo Server
//!
//! This example demonstrates AsyncUdp for async networking.
//! It uses a manual Future implementation to handle UDP packets.
//!
//! This shows:
//! - AsyncUdp for async packet reception
//! - Manual Future state machine (reliable, no_std friendly)
//! - Integration with Contiki-NG's UDP callbacks

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

const UDP_PORT: u16 = 8765;

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

/// Async UDP wrapper
#[no_mangle]
#[used]
static mut ASYNC_UDP: Option<AsyncUdp> = None;

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
    // Notify the async UDP handler
    if let Some(ref mut async_udp) = ASYNC_UDP {
        let data_slice = if datalen > 0 && !data.is_null() {
            core::slice::from_raw_parts(data, datalen as usize)
        } else {
            &[]
        };

        async_udp.notify_rx(data_slice, sender_addr, sender_port);
    }
}

// ============================================================================
// Async Echo Future
// ============================================================================

/// Future that handles UDP echo in an async manner
struct UdpEchoFuture {
    initialized: bool,
    recv_future: Option<AsyncUdpRecv<'static>>,
}

impl UdpEchoFuture {
    fn new() -> Self {
        Self {
            initialized: false,
            recv_future: None,
        }
    }
}

impl Future for UdpEchoFuture {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        unsafe {
            // Initialize on first poll
            if !self.initialized {
                print(c_str!("Async UDP Echo Server starting...\n"));

                // Initialize UDP connection
                let mut conn = SimpleUdpConnection::new();

                match conn.register(UDP_PORT, None, 0, Some(udp_rx_callback)) {
                    Ok(()) => {
                        print(c_str!("Listening on port "));
                        print_u32(c_str!("%u\n"), UDP_PORT as u32);

                        // Set up async UDP
                        ASYNC_UDP = Some(AsyncUdp::new(&mut UDP_CONN as *mut simple_udp_connection));
                        UDP_CONN = conn.inner;

                        self.initialized = true;
                        print(c_str!("Ready to echo packets!\n"));
                    }
                    Err(_) => {
                        print(c_str!("Failed to register UDP connection!\n"));
                        return Poll::Ready(());
                    }
                }
            }

            // Main echo loop
            loop {
                // If we don't have a receive future, create one
                if self.recv_future.is_none() {
                    if let Some(ref mut async_udp) = ASYNC_UDP {
                        self.recv_future = Some(async_udp.recv());
                    } else {
                        return Poll::Ready(());
                    }
                }

                // Poll the receive future
                if let Some(ref mut recv_fut) = self.recv_future {
                    match Pin::new(recv_fut).poll(cx) {
                        Poll::Ready(packet) => {
                            // Got a packet! Echo it back
                            print(c_str!("Received "));
                            print_u32(c_str!("%u"), packet.data.len() as u32);
                            print(c_str!(" bytes from port "));
                            print_u32(c_str!("%u\n"), packet.sender_port as u32);

                            // Echo back using simple_udp directly (async send not needed for this)
                            simple_udp_sendto_port(
                                &mut UDP_CONN as *mut simple_udp_connection,
                                packet.data.as_slice().as_ptr() as *const core::ffi::c_void,
                                packet.data.len() as u16,
                                &packet.sender_addr as *const uip_ipaddr_t,
                                packet.sender_port,
                            );

                            print(c_str!("Echoed packet back\n"));

                            // Reset for next receive
                            self.recv_future = None;

                            // Continue loop to start next receive
                            continue;
                        }
                        Poll::Pending => {
                            // Waiting for packet
                            return Poll::Pending;
                        }
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
static mut FUTURE: Option<UdpEchoFuture> = None;

// ============================================================================
// Process Handler
// ============================================================================

/// Main process event handler
#[no_mangle]
pub extern "C" fn rust_async_udp_echo_handler(
    ev: process_event_t,
    _data: process_data_t,
) -> c_int {
    unsafe {
        match ev {
            PROCESS_EVENT_INIT => {
                // Create the future
                FUTURE = Some(UdpEchoFuture::new());

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
                        Poll::Ready(()) => PT_ENDED,
                        Poll::Pending => PT_WAITING,
                    }
                } else {
                    PT_ENDED
                }
            }
        }
    }
}
