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
use core::cell::UnsafeCell;

// ============================================================================
// Static State
// ============================================================================

const UDP_PORT: u16 = 8765;

/// UDP connection structure (must be static for C callback)
static mut UDP_CONN: simple_udp_connection = simple_udp_connection {
    next: core::ptr::null_mut(),
    remote_addr: uip_ip6addr_t { u8: [0; 16] },
    remote_port: 0,
    local_port: 0,
    receive_callback: None,
    udp_conn: core::ptr::null_mut(),
    client_process: core::ptr::null_mut(),
};

/// Safe wrapper for AsyncUdp state
struct SafeAsyncUdp {
    inner: UnsafeCell<Option<AsyncUdp>>,
}

unsafe impl Sync for SafeAsyncUdp {}

impl SafeAsyncUdp {
    const fn new() -> Self {
        Self { inner: UnsafeCell::new(None) }
    }

    fn init(&self, conn: &mut simple_udp_connection) {
        unsafe { *self.inner.get() = Some(AsyncUdp::new(conn)) }
    }

    fn with<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&mut AsyncUdp) -> R,
    {
        unsafe {
            if let Some(ref mut udp) = *self.inner.get() {
                Some(f(udp))
            } else {
                None
            }
        }
    }
}

static ASYNC_UDP: SafeAsyncUdp = SafeAsyncUdp::new();

/// Process pointer using SafeCell
static PROCESS_PTR: SafeCell<*mut process> = SafeCell::new(core::ptr::null_mut());

// ============================================================================
// UDP Callback
// ============================================================================

/// Called when UDP data is received - stores packet for async processing.
/// Note: This must be unsafe extern "C" as it's called from C code.
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
    ASYNC_UDP.with(|udp| udp.notify_rx(data_slice, sender_addr, sender_port));

    // Wake the process to handle the packet
    let ptr = PROCESS_PTR.get();
    if !ptr.is_null() {
        ffi::process_poll(ptr);
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
    match ev {
        PROCESS_EVENT_INIT => {
            print(c_str!("Async UDP Echo Server starting...\n"));

            // Store process pointer for callback wakeup
            PROCESS_PTR.set(unsafe { rust_get_process_ptr() });

            // Register UDP connection
            let result = unsafe {
                ffi::simple_udp_register(
                    &mut UDP_CONN,
                    UDP_PORT,
                    core::ptr::null_mut(),
                    0,
                    Some(udp_rx_callback),
                )
            };

            if result != 0 {
                // Initialize AsyncUdp wrapper
                unsafe { ASYNC_UDP.init(&mut UDP_CONN) };

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
            ASYNC_UDP.with(|async_udp| {
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
            });
            PT_WAITING
        }
    }
}
