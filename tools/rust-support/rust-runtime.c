/*
 * Rust runtime support functions for Contiki-NG
 *
 * This file provides minimal runtime support for Rust code compiled
 * for embedded targets. These functions are required by the Rust
 * compiler toolchain but can be implemented as no-ops for embedded
 * systems with panic=abort.
 */

/*
 * ARM EABI unwinding functions
 *
 * These are required by some ARM targets even when using panic=abort.
 * They are part of the ARM EABI specification for C++ exception handling,
 * but Rust's panic=abort means they will never be called.
 *
 * Providing empty implementations satisfies the linker without adding
 * any runtime overhead.
 */
#ifdef __arm__

void __aeabi_unwind_cpp_pr0(void) {
  /* No-op: unwinding is disabled with panic=abort */
}

void __aeabi_unwind_cpp_pr1(void) {
  /* No-op: unwinding is disabled with panic=abort */
}

#endif /* __arm__ */

/*
 * Rust's panic handler integration
 *
 * When Rust code panics with panic=abort, execution will halt.
 * On embedded systems, this typically means entering an infinite loop
 * or triggering a hardware reset, depending on the platform configuration.
 *
 * The panic handler itself is implemented in Rust (see contiki-sys.rs)
 * to allow for platform-specific panic behavior and debug output.
 */
