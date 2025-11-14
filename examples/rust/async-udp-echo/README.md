# Async UDP Echo Server

This example demonstrates the **improved async support** for Contiki-NG with real `async fn` syntax and async networking!

## What's New

Compared to the `async-hello` example (manual Future implementation), this example showcases:

1. **Real `async fn` syntax** - Write natural async code without manual state machines
2. **AsyncUdp** - Async UDP networking with `.await`
3. **StaticFuture** - Heap-free storage for async functions
4. **async_fn_process! macro** - One-line process handler generation

## Features Demonstrated

- **async/await** - Clean sequential code flow
- **AsyncUdp::recv()** - Async packet reception
- **AsyncUdp::send_to()** - Async packet sending
- **No heap allocation** - Works in embedded no_std
- **Event-driven** - Integrates with Contiki-NG's scheduler

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

Terminal 1 (server):
```bash
./build/native/async-udp-echo.native
```

Terminal 2 (client):
```bash
echo "Hello async Rust!" | nc -u -6 ::1 8765
```

### Expected Output

Server:
```
Async UDP Echo Server starting...
Listening on port 8765
Ready to echo packets!
Received 18 bytes from port 54321
Echoed packet back
```

Client:
```
Hello async Rust!
```

## Code Comparison

### Old Way (Manual Future Implementation)

```rust
// Define state machine struct
struct CounterFuture {
    timer: *mut etimer,
    count: u32,
    timer_future: Option<AsyncTimer>,
}

// Implement Future trait manually
impl Future for CounterFuture {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        loop {
            if self.timer_future.is_none() {
                self.timer_future = Some(AsyncTimer::delay_seconds(self.timer, 2));
            }

            if let Some(ref mut timer_fut) = self.timer_future {
                match Pin::new(timer_fut).poll(cx) {
                    Poll::Ready(()) => {
                        self.count += 1;
                        self.timer_future = None;
                        continue;
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
    }
}

// Manual event handler with 50+ lines of boilerplate...
```

### New Way (async fn with async_fn_process!)

```rust
async fn async_udp_echo_server() {
    // Setup
    let mut conn = SimpleUdpConnection::new();
    conn.register(8765, None, 0, Some(callback)).unwrap();

    // Main loop
    loop {
        let packet = async_udp.recv().await;  // Just .await!
        async_udp.send_to(&packet.data, &packet.sender_addr, packet.sender_port).await;
    }
}

// One-line process handler generation!
async_fn_process!(rust_async_udp_echo_handler, async_udp_echo_server, 1024);
```

**Result**: ~80% less code, infinitely more readable!

## How It Works

### 1. StaticFuture Storage

`StaticFuture<T, SIZE>` provides fixed-size storage for async functions:

```rust
static mut FUTURE: StaticFuture<(), 1024> = StaticFuture::new();

// Initialize with an async function
unsafe { FUTURE.init(my_async_fn()); }

// Poll the future
let pinned = unsafe { FUTURE.as_pin_mut().unwrap() };
match pinned.poll(&mut context) {
    Poll::Ready(()) => { /* done */ },
    Poll::Pending => { /* continue */ },
}
```

The `SIZE` parameter must be large enough to hold the async state machine. The compiler will panic at runtime if the future is too large.

### 2. AsyncUdp Networking

`AsyncUdp` wraps `SimpleUdpConnection` with async capabilities:

```rust
// Create wrapper
let mut async_udp = unsafe { AsyncUdp::new(&mut UDP_CONN) };

// Async receive
let packet = async_udp.recv().await;

// Async send
async_udp.send(data).await?;
async_udp.send_to(data, &addr, port).await?;
```

The UDP callback calls `notify_rx()` to wake the async receive:

```rust
#[no_mangle]
pub unsafe extern "C" fn udp_rx_callback(...) {
    if let Some(ref mut async_udp) = ASYNC_UDP {
        async_udp.notify_rx(data_slice, sender_addr, sender_port);
    }
}
```

### 3. async_fn_process! Macro

This macro generates all the boilerplate:

```rust
async_fn_process!(handler_name, async_function, buffer_size);
```

It creates:
- `StaticFuture` storage
- Process event handler
- Initialization code
- Polling logic

## Choosing Buffer Size

The `SIZE` parameter in `async_fn_process!` must accommodate the async state machine:

```rust
async_fn_process!(handler, my_fn, 512);   // 512 bytes for state machine
```

**Guidelines:**
- Simple loops with timers: 256-512 bytes
- Network operations: 512-1024 bytes
- Complex state: 1024-2048 bytes

If too small, you'll get a runtime panic:
```
panicked at 'Future size 768 exceeds buffer size 512'
```

## Architecture

The async support is built in layers:

```
         async fn my_process()
                 ↓
         Rust async/await
                 ↓
      StaticFuture<(), SIZE>
                 ↓
    AsyncTimer / AsyncUdp Futures
                 ↓
       AsyncExecutor (polls)
                 ↓
    Contiki-NG event scheduler
```

Key points:
- **No threads** - Everything is event-driven
- **No heap** - Static storage only
- **Zero-cost** - Compiled to efficient state machines
- **Composable** - Mix async and sync code freely

## API Reference

### async_fn_process! Macro

```rust
async_fn_process!(handler_name, async_function, buffer_size);
```

**Parameters:**
- `handler_name`: Name of generated C-compatible handler function
- `async_function`: Name of async fn to run (must take no arguments)
- `buffer_size`: Size in bytes for future storage (const expression)

**Generated:**
- Static `StaticFuture<(), buffer_size>`
- Event handler function with name `handler_name`
- Initialization and polling logic

### StaticFuture

```rust
pub struct StaticFuture<T, const SIZE: usize>
```

**Methods:**
- `new()` - Create uninitialized storage (const fn)
- `init<F>(future: F)` - Initialize with async function
- `as_pin_mut<F>()` - Get pinned mutable reference for polling
- `is_initialized()` - Check if future is stored
- `drop_future<F>()` - Explicitly drop the stored future

### AsyncUdp

```rust
pub struct AsyncUdp
```

**Methods:**
- `new(conn: *mut simple_udp_connection)` - Create wrapper
- `recv() -> impl Future<Output = UdpPacket>` - Async receive
- `send(data: &[u8]) -> impl Future<Output = Result<()>>` - Async send
- `send_to(data: &[u8], addr: *const uip_ipaddr_t, port: u16) -> impl Future<Output = Result<()>>` - Async send to address
- `notify_rx(data: &[u8], sender_addr: *const uip_ipaddr_t, sender_port: u16)` - Signal received data (call from callback)

### UdpPacket

```rust
pub struct UdpPacket {
    pub data: StaticBuffer<256>,
    pub sender_addr: uip_ipaddr_t,
    pub sender_port: u16,
}
```

Received packet with data and sender information.

## Writing Your Own Async Process

### Step 1: Write your async function

```rust
async fn my_process() {
    // Your async code here
    loop {
        AsyncTimer::delay_seconds(&mut TIMER, 5).await;
        print(c_str!("Tick!\n"));
    }
}
```

### Step 2: Use async_fn_process! macro

```rust
async_fn_process!(my_handler, my_process, 512);
```

### Step 3: Create C wrapper

```c
extern int my_handler(process_event_t ev, process_data_t data);

PROCESS(my_proc, "My Process");
AUTOSTART_PROCESSES(&my_proc);

PROCESS_THREAD(my_proc, ev, data) {
    return my_handler(ev, data);
}
```

That's it! No manual Future implementation needed.

## Common Patterns

### Timeout Pattern

```rust
async fn operation_with_timeout() {
    // Start operation
    start_sensor();

    // Wait for result or timeout
    let result = select! {
        data = sensor.read() => Ok(data),
        _ = AsyncTimer::delay_seconds(&mut TIMER, 5) => Err(Timeout),
    };

    // Note: select! not yet implemented, but planned
}
```

### Multi-source Event Loop

```rust
async fn multi_source() {
    loop {
        select! {
            packet = udp.recv() => handle_packet(packet),
            temp = sensor.read() => handle_temp(temp),
            _ = button.wait_press() => handle_button(),
        }
    }

    // Note: select! not yet implemented, but planned
}
```

### Periodic Tasks

```rust
async fn periodic_task() {
    loop {
        // Do work
        let sensor_value = read_sensor();
        send_to_server(sensor_value).await;

        // Wait before next iteration
        AsyncTimer::delay_seconds(&mut TIMER, 60).await;
    }
}
```

## Limitations

Current limitations (planned improvements):

1. **Single future per process** - One async fn per process
2. **No select/join** - Can't wait on multiple futures simultaneously
3. **Buffer size at compile time** - Must choose SIZE upfront
4. **Manual callback wiring** - Still need C callbacks for some events
5. **Limited error handling** - No async Result propagation yet

## Future Enhancements

Planned improvements:

- **select! macro** - Wait on multiple futures
- **join! macro** - Run futures concurrently
- **AsyncSensor** - Async sensor readings
- **AsyncButton** - Async button events
- **Timeout combinators** - Easy timeout patterns
- **Better error handling** - Async Result support
- **Auto callback wiring** - Less boilerplate

## Performance

Async code has **zero runtime overhead** compared to manual state machines:

- **Same memory usage** - State machine size is identical
- **Same CPU usage** - Compiles to same instructions
- **Same latency** - No additional polling overhead
- **Better ergonomics** - Much easier to write and maintain

## Debugging Tips

### Future Too Large Error

```
panicked at 'Future size 1500 exceeds buffer size 1024'
```

**Solution**: Increase buffer size:
```rust
async_fn_process!(handler, my_fn, 2048);  // Increased from 1024
```

### Packet Not Received

Check that:
1. UDP callback is registered correctly
2. `notify_rx()` is called from callback
3. `ASYNC_UDP` is properly initialized
4. Process is returning `PT_WAITING` to stay alive

### Process Exits Immediately

Ensure you poll the future once during `PROCESS_EVENT_INIT` (the macro does this automatically).

## See Also

- `examples/rust/async-hello` - Manual Future implementation (educational)
- `examples/rust/udp-echo` - Non-async UDP echo (comparison)
- `tools/rust-support/API.md` - Complete Rust API documentation

## Learn More

**Rust async book**: https://rust-lang.github.io/async-book/

**Key concepts**:
- Futures are lazy state machines
- `.await` suspends execution until ready
- No threads - everything is cooperative
- Zero-cost abstraction - no runtime overhead
