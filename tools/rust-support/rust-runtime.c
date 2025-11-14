/*
 * Rust runtime support functions for Contiki-NG
 *
 * This file provides minimal runtime support for Rust code compiled
 * for embedded targets. These functions are required by the Rust
 * compiler toolchain but can be implemented as no-ops for embedded
 * systems with panic=abort.
 */

#include "sys/clock.h"

/*
 * Export CLOCK_SECOND as a variable for Rust FFI
 *
 * Rust cannot directly use C macros, so we export CLOCK_SECOND
 * as a constant variable that Rust code can link against.
 */
const unsigned int CLOCK_SECOND_VALUE = CLOCK_SECOND;

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

/*
 * Slice index failure handler
 *
 * Called when slice bounds checking fails. With panic=abort, this will
 * halt execution immediately.
 *
 * Note: The symbol name uses Rust's name mangling format. The actual
 * function name is core::slice::index::slice_index_fail but mangled
 * for the linker.
 */
void _ZN4core5slice5index16slice_index_fail17hfe436548ecebea33E(
    unsigned long index,
    unsigned long len
) __attribute__((noreturn));

void _ZN4core5slice5index16slice_index_fail17hfe436548ecebea33E(
    unsigned long index,
    unsigned long len
) {
  /* Halt execution - index out of bounds */
  (void)index;
  (void)len;

  while(1) {
    /* Infinite loop - execution will not continue */
  }

  __builtin_unreachable();
}
