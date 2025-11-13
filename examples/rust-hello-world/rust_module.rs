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

// Import the c_str! macro from contiki-sys if available via external linkage
// Note: In a more complete setup, you would add contiki-sys as a dependency
// For now, we provide a local version that stores strings in .rodata
macro_rules! c_str {
    ($s:expr) => {{
        static S: &[u8] = concat!($s, "\0").as_bytes();
        S.as_ptr() as *const c_char
    }};
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

/// Demonstrate static buffer usage (zero-cost abstraction)
/// This shows how to use StaticBuffer for safe fixed-size buffers
#[no_mangle]
pub extern "C" fn rust_demo_static_buffer() -> u32 {
    // Define a fixed-size buffer - no heap allocation!
    struct BufferContainer {
        data: [u8; 32],
        len: usize,
    }

    static mut BUFFER: BufferContainer = BufferContainer {
        data: [0; 32],
        len: 0,
    };

    unsafe {
        printf(c_str!("\n=== Static Buffer Demo ===\n"));

        // Add some data
        BUFFER.len = 0;
        for i in 0..10 {
            if BUFFER.len < 32 {
                // Use get_unchecked_mut to avoid bounds check
                *BUFFER.data.get_unchecked_mut(BUFFER.len) = i * 2;
                BUFFER.len += 1;
            }
        }

        printf(c_str!("Buffer filled with %u items\n"), BUFFER.len as u32);
        if BUFFER.len > 0 {
            printf(c_str!("First item: %u, Last item: %u\n"),
                   *BUFFER.data.get_unchecked(0) as u32,
                   *BUFFER.data.get_unchecked(BUFFER.len - 1) as u32);
        }

        BUFFER.len as u32
    }
}

/// Generate a random number in a range
/// This demonstrates the safe random API
#[no_mangle]
pub extern "C" fn rust_random_range(max: u32) -> u32 {
    extern "C" {
        fn random_rand() -> u32;
    }

    if max == 0 {
        return 0;
    }

    unsafe { random_rand() % max }
}

/// Demonstrate data processing with zero-cost abstractions
/// This shows how Rust's type safety doesn't add runtime overhead
#[no_mangle]
pub extern "C" fn rust_process_sensor_data(data: *const i16, len: u32) -> i16 {
    if data.is_null() || len == 0 {
        return -1;
    }

    unsafe {
        let readings = core::slice::from_raw_parts(data, len as usize);

        let mut sum: i32 = 0;
        let mut count: i32 = 0;

        // Filter out invalid readings and compute average
        for &reading in readings {
            if reading >= 0 && reading <= 1000 {
                sum += reading as i32;
                count += 1;
            }
        }

        if count == 0 {
            return -1;
        }

        // Manual division to avoid panic on divide-by-zero
        // (count is guaranteed > 0 here, but use wrapping_div to be explicit)
        (sum.wrapping_div(count)) as i16
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

// Note: ARM EABI unwinding functions (__aeabi_unwind_cpp_pr0/1) are now
// provided by rust-runtime.c, avoiding duplication across Rust modules

// Unit tests (run with: cargo test or make rust-test)
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fibonacci_base_cases() {
        assert_eq!(rust_calculate_fibonacci(0), 0);
        assert_eq!(rust_calculate_fibonacci(1), 1);
    }

    #[test]
    fn test_fibonacci_sequence() {
        assert_eq!(rust_calculate_fibonacci(2), 1);
        assert_eq!(rust_calculate_fibonacci(3), 2);
        assert_eq!(rust_calculate_fibonacci(4), 3);
        assert_eq!(rust_calculate_fibonacci(5), 5);
        assert_eq!(rust_calculate_fibonacci(6), 8);
        assert_eq!(rust_calculate_fibonacci(10), 55);
    }

    #[test]
    fn test_fibonacci_saturation() {
        // Test that large values don't overflow (thanks to saturating_add)
        let result = rust_calculate_fibonacci(50);
        assert!(result > 0); // Should saturate, not wrap to 0
    }

    #[test]
    fn test_static_buffer_demo() {
        // Test that the demo function returns expected value
        let result = rust_demo_static_buffer();
        assert_eq!(result, 10); // Should have 10 items
    }

    #[test]
    fn test_random_range() {
        // Test edge cases
        assert_eq!(rust_random_range(0), 0);
        assert_eq!(rust_random_range(1), 0);

        // Test that result is within bounds
        for _ in 0..10 {
            let result = rust_random_range(100);
            assert!(result < 100);
        }
    }

    #[test]
    fn test_process_sensor_data() {
        // Test with valid data
        let data: [i16; 5] = [100, 200, 300, 400, 500];
        let avg = rust_process_sensor_data(data.as_ptr(), 5);
        assert_eq!(avg, 300);

        // Test with mixed valid/invalid data
        let data2: [i16; 5] = [100, -1, 200, 2000, 300];
        let avg2 = rust_process_sensor_data(data2.as_ptr(), 5);
        assert_eq!(avg2, 200); // Average of 100, 200, 300

        // Test with all invalid data
        let data3: [i16; 3] = [-1, -2, 2000];
        let avg3 = rust_process_sensor_data(data3.as_ptr(), 3);
        assert_eq!(avg3, -1); // Should return -1 for no valid data

        // Test with null pointer
        let avg4 = rust_process_sensor_data(core::ptr::null(), 5);
        assert_eq!(avg4, -1);

        // Test with zero length
        let avg5 = rust_process_sensor_data(data.as_ptr(), 0);
        assert_eq!(avg5, -1);
    }
}
