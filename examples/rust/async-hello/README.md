# Async Hello World Example

This example demonstrates **async/await support** for Contiki-NG processes written in Rust. It shows how to write asynchronous code that integrates seamlessly with Contiki-NG's event-driven architecture.

## Features Demonstrated

- **Async/await syntax**: Write sequential-looking code that's actually event-driven
- **AsyncTimer**: Non-blocking delays using Contiki-NG's etimer system
- **Zero-cost abstractions**: No heap allocation, no threading overhead
- **Process integration**: Async code works naturally with Contiki-NG processes
- **Macro-based setup**: Simple async_process! macro handles boilerplate

## How It Works

### Traditional Event-Driven Approach

Without async support, you'd write code like this:

```rust
fn handler(ev: process_event_t, _data: process_data_t) -> c_int {
    match ev {
        PROCESS_EVENT_INIT => {
            unsafe { timer_set(&mut TIMER, clock_second() * 2); }
            PT_WAITING
        }
        PROCESS_EVENT_TIMER => {
            if unsafe { timer_expired(&mut TIMER) } {
                unsafe { COUNTER += 1; }
                print_u32(c_str!("Counter: %lu\n"), unsafe { COUNTER });
                unsafe { timer_reset(&mut TIMER); }
            }
            PT_WAITING
        }
        _ => PT_WAITING
    }
}
```

This requires:
- Manual state management across events
- Event type checking
- Timer expiration polling
- State scattered across the function

### Async/Await Approach

With async support, the same logic becomes:

```rust
async fn async_hello_process() {
    for i in 1..=10 {
        AsyncTimer::delay_seconds(&mut TIMER, 2).await;
        print_u32(c_str!("Counter: %lu\n"), i);
    }
}

async_process!(handler_name, async_hello_process);
```

Benefits:
- **Sequential code flow**: Write code that reads top-to-bottom
- **Automatic state management**: Compiler handles state across .await points
- **Clean logic**: No event matching, just async functions
- **Familiar syntax**: Standard Rust async/await

## Architecture

### The Async Runtime

The async runtime is built on three core components:

1. **AsyncTimer** - Future that completes when a timer expires
2. **AsyncEvent** - Future that waits for specific process events
3. **AsyncExecutor** - Minimal executor that polls futures

### Integration with Contiki-NG

The async runtime leverages Contiki-NG's existing event system:

```
User Async Code
    ↓
  .await
    ↓
Future::poll() → returns Poll::Pending
    ↓
Process returns PT_WAITING
    ↓
Contiki-NG scheduler
    ↓
Event arrives (timer, etc)
    ↓
Process receives event
    ↓
Future::poll() → returns Poll::Ready
    ↓
Async code continues
```

Key insight: **Async doesn't replace Contiki-NG's scheduler** - it builds on top of it. When an async function `.await`s:

1. The Future is polled
2. If not ready, the process returns `PT_WAITING` to Contiki-NG
3. Contiki-NG schedules the process when events arrive
4. The Future is polled again
5. If ready, execution continues

### Memory Model

The async runtime is designed for embedded systems:

- **No heap allocation** (when using static futures)
- **No threading** - everything is event-driven
- **Single task** - one future per process
- **Stack-based** - futures live in process static state

## Building

```bash
make TARGET=native
```

For embedded targets:
```bash
make TARGET=zoul
```

## Running

### Native Platform

```bash
./build/native/async-hello.native
```

Expected output:
```
Hello from Async Rust!
Starting async timer-based execution...
Async Hello! Counter: 1
Async Hello! Counter: 2
Async Hello! Counter: 3
...
Async Hello! Counter: 10
Async Rust process completed!
```

Each message appears after a 2-second delay.

## Code Structure

### async-hello.c
Minimal C wrapper that:
- Registers the process with Contiki-NG
- Delegates to Rust implementation

### async_hello_process.rs
Rust implementation showing:
- `async_timer!` macro for declaring timers
- `async fn` for process logic
- `AsyncTimer::delay_seconds()` for delays
- `async_process!` macro for wiring everything together

## Key APIs

### Declaring Async Timers

```rust
async_timer!(TIMER_NAME);
```

This creates a static `etimer` that can be used with `AsyncTimer`.

### AsyncTimer

```rust
// Delay by seconds
AsyncTimer::delay_seconds(&mut TIMER, 5).await;

// Delay by milliseconds
AsyncTimer::delay_ms(&mut TIMER, 500).await;

// Create with specific interval
let timer_future = AsyncTimer::new(&mut TIMER, CLOCK_SECOND * 3);
timer_future.await;
```

### AsyncEvent

```rust
// Wait for a specific event
let event_future = AsyncEvent::new();
// ... store event_future somewhere ...
// Later, when event arrives:
event_future.notify(event_type);
event_future.await;  // Completes when event arrives
```

### async_process! Macro

```rust
async_process!(handler_function_name, async_function);
```

This macro generates:
- Static state storage for the async future
- Process event handler
- Initialization logic
- Event-to-poll translation

## Writing Your Own Async Process

1. **Declare any needed timers**:
```rust
async_timer!(MY_TIMER);
```

2. **Write your async logic**:
```rust
async fn my_process_logic() {
    print(c_str!("Starting...\n"));

    // Async delay
    AsyncTimer::delay_seconds(&mut MY_TIMER, 5).await;

    print(c_str!("After 5 seconds\n"));

    // Can have loops
    loop {
        AsyncTimer::delay_ms(&mut MY_TIMER, 1000).await;
        print(c_str!("Tick!\n"));
    }
}
```

3. **Wire it up with the macro**:
```rust
async_process!(rust_my_handler, my_process_logic);
```

4. **Create C wrapper**:
```c
extern int rust_my_handler(process_event_t ev, process_data_t data);

PROCESS(my_process, "My Async Process");
AUTOSTART_PROCESSES(&my_process);

PROCESS_THREAD(my_process, ev, data)
{
  return rust_my_handler(ev, data);
}
```

## Limitations

Current limitations of the async support:

1. **Single future per process**: Each process can run one async function
2. **No concurrent futures**: Can't await multiple futures at once (no select/join)
3. **No async I/O**: Only timers and events, no async networking yet
4. **No cancellation**: Async functions run to completion
5. **Static allocation**: Futures must be stored in static variables

## Future Enhancements

Potential improvements to the async runtime:

- **Async networking**: AsyncUdp, AsyncCoAP futures
- **Async sensors**: Read sensor data with .await
- **Future combinators**: select!, join! macros for multiple futures
- **Async iterators**: Stream-based APIs
- **Better error handling**: Result types in async context
- **Wake-up optimization**: Only poll on relevant events

## Learning Points

1. **Async is state machines**: The compiler transforms async functions into state machines
2. **Events drive polling**: Contiki-NG events trigger future polling
3. **No threads needed**: Async provides concurrency without parallelism
4. **Zero cost**: Compiled code is as efficient as hand-written event handlers
5. **Sequential thinking**: Async lets you think sequentially even in event-driven code

## Comparison with Traditional Code

| Aspect | Event-Driven | Async/Await |
|--------|--------------|-------------|
| Code flow | Event matching | Sequential |
| State management | Manual static vars | Automatic |
| Readability | Scattered logic | Linear flow |
| Complexity | Grows with states | Stays manageable |
| Performance | Optimal | Optimal (zero-cost) |
| Memory | Static vars | Static state machine |

## Advanced Example: Multiple Operations

```rust
async fn complex_process() {
    // Startup sequence
    print(c_str!("Initializing...\n"));
    AsyncTimer::delay_ms(&mut TIMER1, 500).await;
    print(c_str!("Ready!\n"));

    // Main loop with multiple delays
    for i in 0..5 {
        print_u32(c_str!("Iteration %lu\n"), i);

        // Short delay
        AsyncTimer::delay_seconds(&mut TIMER1, 1).await;
        print(c_str!("  Step 1\n"));

        // Another delay
        AsyncTimer::delay_seconds(&mut TIMER1, 2).await;
        print(c_str!("  Step 2\n"));
    }

    print(c_str!("Done!\n"));
}
```

This would be much more complex in traditional event-driven style!

## See Also

- `examples/rust/hello-world` - Traditional event-driven approach
- `examples/rust/udp-echo` - UDP networking in Rust
- `tools/rust-support/API.md` - Complete Rust API documentation
- Rust async book: https://rust-lang.github.io/async-book/
