//! Rust module for Contiki-NG Hello World example
//! This demonstrates how to write Rust code that can be called from Contiki-NG C code

#![no_std]
#![no_main]

use core::ffi::c_char;
use core::panic::PanicInfo;

// External C functions from Contiki-NG
extern "C" {
    fn printf(format: *const c_char, ...) -> i32;
    fn clock_seconds() -> u32;
}

// Helper macro for printing C strings
macro_rules! c_str {
    ($s:expr) => {
        concat!($s, "\0").as_ptr() as *const c_char
    };
}

/// Print "Hello, World!" from Rust
#[no_mangle]
pub extern "C" fn rust_hello_world() {
    unsafe {
        printf(c_str!("Hello from Rust!\n"));
        printf(c_str!("This message is printed from a Rust function.\n"));
    }
}

/// Calculate Fibonacci number
/// This demonstrates a pure Rust computation
#[no_mangle]
pub extern "C" fn rust_calculate_fibonacci(n: u32) -> u32 {
    match n {
        0 => 0,
        1 => 1,
        _ => {
            let mut a = 0u32;
            let mut b = 1u32;
            for _ in 2..=n {
                let temp = a.saturating_add(b);
                a = b;
                b = temp;
            }
            b
        }
    }
}

/// Print system information
/// This demonstrates calling back into Contiki-NG from Rust
#[no_mangle]
pub extern "C" fn rust_print_system_info() {
    unsafe {
        printf(c_str!("=== System Information (from Rust) ===\n"));
        
        // Get current clock time
        let seconds = clock_seconds();
        printf(c_str!("System uptime: %lu seconds\n"), seconds as u32);
        
        // Print Rust compiler information
        printf(c_str!("Rust compiler: rustc (embedded build)\n"));
        
        // Print target architecture
        #[cfg(target_arch = "arm")]
        printf(c_str!("Target architecture: ARM\n"));
        
        #[cfg(target_arch = "msp430")]
        printf(c_str!("Target architecture: MSP430\n"));
        
        #[cfg(target_arch = "x86_64")]
        printf(c_str!("Target architecture: x86_64 (native)\n"));
        
        #[cfg(target_arch = "x86")]
        printf(c_str!("Target architecture: x86 (native)\n"));
        
        printf(c_str!("=====================================\n"));
    }
}

/// Custom panic handler for no_std environment
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe {
        printf(c_str!("PANIC: Rust code panicked!\n"));
        
        // Try to print panic location if available
        if let Some(location) = _info.location() {
            printf(c_str!("Panic at %s:%u\n"), 
                   location.file().as_ptr() as *const c_char,
                   location.line());
        }
    }
    
    // Halt execution
    loop {
        // In embedded systems, we typically just loop forever on panic
        // Some platforms might have a specific halt instruction
        #[cfg(target_arch = "arm")]
        unsafe {
            core::arch::asm!("wfi"); // Wait for interrupt
        }
    }
}

/// Required by Rust compiler for certain targets
#[no_mangle]
pub extern "C" fn __aeabi_unwind_cpp_pr0() {
    // This is a dummy implementation for ARM EABI
    // Required for some ARM targets even with panic=abort
}

#[no_mangle]
pub extern "C" fn __aeabi_unwind_cpp_pr1() {
    // This is a dummy implementation for ARM EABI
    // Required for some ARM targets even with panic=abort
}
