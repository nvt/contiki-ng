//! UDP Echo Server Example
//!
//! This example demonstrates:
//! - Using the SimpleUdpConnection API with Result-based error handling
//! - IPv6 networking in Rust
//! - Proper callback handling
//! - Error reporting

#![no_std]
#![no_main]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(static_mut_refs)]

#[path = "../../../tools/rust-support/contiki-sys.rs"]
mod contiki_sys;

use contiki_sys::*;

// ============================================================================
// Static State
// ============================================================================

/// UDP connection - must be static for C callback access
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

/// Track initialization state
#[no_mangle]
#[used]
static mut INITIALIZED: bool = false;

const UDP_PORT: u16 = 8765;

// ============================================================================
// UDP Callback
// ============================================================================

/// Callback function called when UDP data is received
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
    // Print received data
    print(c_str!("Received "));
    print_u32(c_str!("%u"), datalen as u32);
    print(c_str!(" bytes from port "));
    print_u32(c_str!("%u"), sender_port as u32);
    print(c_str!("\n"));

    // Echo the data back using raw FFI (simpler in callback context)

    // Create data slice safely
    let data_slice = if datalen > 0 && !data.is_null() {
        core::slice::from_raw_parts(data, datalen as usize)
    } else {
        &[]
    };

    // Send echo response using raw FFI (simpler in callback context)
    let result = simple_udp_sendto_port(
        &mut UDP_CONN as *mut simple_udp_connection,
        data_slice.as_ptr() as *const core::ffi::c_void,
        datalen,
        sender_addr,
        sender_port,
    );

    if result == 0 {
        print(c_str!("Error sending echo\n"));
    } else {
        print(c_str!("Echoed data back\n"));
    }
}

// ============================================================================
// Process Handler
// ============================================================================

/// Main process event handler
#[no_mangle]
pub extern "C" fn rust_udp_echo_handler(
    ev: process_event_t,
    _data: process_data_t,
) -> c_int {
    match ev {
        PROCESS_EVENT_INIT => {
            print(c_str!("UDP Echo Server Starting...\n"));

            // Create and register UDP connection with error handling
            // Note: simple-udp doesn't require explicit initialization
            let mut conn = SimpleUdpConnection::new();

            match conn.register(
                UDP_PORT,
                None,  // Accept from any address
                0,     // No specific remote port
                Some(udp_rx_callback),
            ) {
                Ok(()) => {
                    print(c_str!("UDP server listening on port "));
                    print_u32(c_str!("%u"), UDP_PORT as u32);
                    print(c_str!("\n"));

                    // Save the registered connection
                    unsafe {
                        UDP_CONN = conn.inner;
                        INITIALIZED = true;
                    }
                }
                Err(_e) => {
                    print(c_str!("Failed to register UDP connection\n"));
                    return PT_ENDED;
                }
            }

            print(c_str!("Send UDP packets to this node on port "));
            print_u32(c_str!("%u"), UDP_PORT as u32);
            print(c_str!(" and they will be echoed back\n"));

            PT_YIELDED
        }

        _ => PT_YIELDED,
    }
}
