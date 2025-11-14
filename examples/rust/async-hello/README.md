# Safe Async Hello World

This example demonstrates how to write clean, safe async Rust code for Contiki-NG with **zero unsafe in user code**.

## Overview

The example counts from 1 to 10 with 2-second delays between each count, showcasing:
- **SafeTimer** - No unsafe blocks needed for timer operations
- **Async/await patterns** - Clean Future-based programming
- **Zero raw pointers** - All complexity hidden in safe wrappers
- **Idiomatic Rust** - Follows Rust best practices

## Code Structure

### Safe Timer Declaration

```rust
// ✅ Safe static timer - no mut, no unsafe!
safe_timer!(TIMER);
```

### Future Implementation

```rust
struct CounterFuture {
    count: u32,
    max_count: u32,
    timer_future: Option<AsyncTimer>,
}

impl Future for CounterFuture {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        loop {
            if self.count >= self.max_count {
                return Poll::Ready(());
            }

            if self.timer_future.is_none() {
                // ✅ No unsafe! Clean and safe!
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
```

## How SafeTimer Works

The `SafeTimer` type encapsulates all unsafe operations:

```rust
pub struct SafeTimer {
    inner: UnsafeCell<etimer>,
}

unsafe impl Sync for SafeTimer {}

impl SafeTimer {
    pub const fn new() -> Self { /* ... */ }

    pub fn delay_seconds(&self, seconds: u32) -> AsyncTimer {
        // Unsafe is hidden inside the wrapper
        AsyncTimer {
            timer: self.inner.get(),
            interval: clock_second() * seconds,
            started: false,
        }
    }

    pub fn delay_ms(&self, ms: u32) -> AsyncTimer {
        let ticks = (clock_second() * ms) / 1000;
        AsyncTimer {
            timer: self.inner.get(),
            interval: ticks,
            started: false,
        }
    }
}
```

### Benefits

| Aspect | Benefit |
|--------|---------|
| **Safety** | All unsafe code is in the audited wrapper |
| **Simplicity** | No raw pointers or unsafe blocks in user code |
| **Readability** | Clear, sequential async logic |
| **Type safety** | Compile-time guarantees |

## Building and Running

```bash
# Build for native platform
make TARGET=native

# Run
./build/native/async-hello.native
```

Expected output:
```
Initializing safe async process...
Hello from Safe Async Rust!
Starting safe async execution...
Safe async count: 1
Safe async count: 2
Safe async count: 3
...
Safe async count: 10
Safe async process completed!
```

## Key Concepts

### No Unsafe in User Code

The example achieves complete safety by:
1. Using `SafeTimer` instead of `static mut etimer`
2. Accessing timers through safe wrapper methods
3. No raw pointer manipulation
4. All safety concerns handled by the wrapper

### Async Execution

The Future pattern allows for:
- Non-blocking delays
- Event-driven execution
- Multiple concurrent operations
- Clean control flow

### Integration with Contiki-NG

The Rust code integrates seamlessly with Contiki-NG:
- Uses the standard process model
- Compatible with event system
- Works with existing timers
- No runtime overhead

## See Also

- `../COMPARISON.md` - Detailed analysis of SafeTimer benefits
- `/home/nvt/contiki-ng/RUST-EXAMPLES-IMPROVEMENTS.md` - Full improvement roadmap
- `../async-udp-echo/` - Async UDP networking example
- `../udp-echo/` - Non-async UDP example
- `../hello-world/` - Basic Rust example

## Future Improvements

The SafeTimer pattern can be extended to other Contiki-NG resources:

1. **UdpSocket** - Safe UDP wrapper (no unsafe for networking)
2. **ProcessContext** - Encapsulated resource management
3. **contiki_process!** macro - Less boilerplate
4. **Type-safe events** - ProcessEvent enum instead of raw integers

See `/home/nvt/contiki-ng/RUST-EXAMPLES-IMPROVEMENTS.md` for the complete roadmap.
