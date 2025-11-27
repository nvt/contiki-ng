//! Async UDP Echo Server Example
//!
//! This example demonstrates async-style UDP networking in Rust for Contiki-NG.
//! It shows how to use AsyncUdp to decouple packet reception (in callback) from
//! packet processing (in process handler).
//!
//! Key difference from udp-echo:
//! - udp-echo: processes packets directly in the callback
//! - async-udp-echo: callback stores packets, handler processes them
//!
//! This pattern is useful when packet processing is complex or needs
//! access to state that shouldn't be accessed from interrupt context.

#![no_std]
#![no_main]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(static_mut_refs)]

#[path = "../../../tools/rust-support/contiki-sys.rs"]
mod contiki_sys;

use contiki_sys::*;
use contiki_sys::ffi;

// ============================================================================
// Static State
// ============================================================================

const UDP_PORT: u16 = 8765;

/// UDP connection structure
static mut UDP_CONN: simple_udp_connection = simple_udp_connection {
    next: core::ptr::null_mut(),
    remote_addr: uip_ip6addr_t { u8: [0; 16] },
    remote_port: 0,
    local_port: 0,
    receive_callback: None,
    udp_conn: core::ptr::null_mut(),
    client_process: core::ptr::null_mut(),
};

/// Async UDP wrapper for decoupled packet handling
static mut ASYNC_UDP: Option<AsyncUdp> = None;

/// Process pointer (needed to wake process from callback)
static mut PROCESS_PTR: *mut process = core::ptr::null_mut();

// ============================================================================
// UDP Callback
// ============================================================================

/// Called when UDP data is received - stores packet for async processing
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
    let data_slice = if datalen > 0 && !data.is_null() {
        core::slice::from_raw_parts(data, datalen as usize)
    } else {
        &[]
    };

    // Store packet for processing in the handler
    if let Some(ref mut async_udp) = ASYNC_UDP {
        async_udp.notify_rx(data_slice, sender_addr, sender_port);
    }

    // Wake the process to handle the packet
    if !PROCESS_PTR.is_null() {
        ffi::process_poll(PROCESS_PTR);
    }
}

// ============================================================================
// Process Handler
// ============================================================================

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

                PROCESS_PTR = rust_get_process_ptr();

                let result = ffi::simple_udp_register(
                    &mut UDP_CONN,
                    UDP_PORT,
                    core::ptr::null_mut(),
                    0,
                    Some(udp_rx_callback),
                );

                if result != 0 {
                    ASYNC_UDP = Some(AsyncUdp::new(&mut UDP_CONN));

                    print(c_str!("Listening on port "));
                    print_u32(c_str!("%u\n"), UDP_PORT as u32);
                    PT_WAITING
                } else {
                    print(c_str!("Failed to register UDP\n"));
                    PT_ENDED
                }
            }

            _ => {
                // Process any pending packet
                if let Some(ref mut async_udp) = ASYNC_UDP {
                    if let Some(packet) = async_udp.try_recv() {
                        print(c_str!("Received "));
                        print_u32(c_str!("%u"), packet.len as u32);
                        print(c_str!(" bytes from port "));
                        print_u32(c_str!("%u\n"), packet.sender_port as u32);

                        // Echo back
                        async_udp.send(
                            &packet.data[..packet.len],
                            &packet.sender_addr,
                            packet.sender_port,
                        );

                        print(c_str!("Echoed back\n"));
                    }
                }
                PT_WAITING
            }
        }
    }
}
