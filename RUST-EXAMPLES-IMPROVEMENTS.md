# Rust Examples Improvements

This document outlines improvements to make Rust examples more elegant, readable, and correct.

## Problems with Current Approach

### 1. Too Much `unsafe`
- Every timer operation requires `unsafe`
- Every access to static mut requires `unsafe`
- Hard to audit safety invariants
- Violates Rust's "unsafe in small, auditable places" principle

### 2. Global Mutable State
```rust
// Current ❌
static mut TIMER: etimer = ...;
static mut COUNTER: u32 = 0;
static mut ASYNC_UDP: Option<AsyncUdp> = None;
```

Problems:
- No encapsulation
- Unclear ownership
- Hard to test
- Risk of aliasing bugs

### 3. Raw Pointers
```rust
// Current ❌
struct CounterFuture {
    timer: *mut etimer,  // Can dangle, unclear lifetime
}
```

### 4. Manual Future Boilerplate
Every async operation requires 40+ lines of state machine code.

### 5. Callback Hell
C callbacks modify global state, bypassing Rust's safety.

---

## Proposed Solutions

### Solution 1: Safe Timer Wrapper

Create a `SafeTimer` type that encapsulates unsafe operations:

```rust
/// Thread-safe timer that can be used from static context
pub struct SafeTimer {
    inner: UnsafeCell<etimer>,
}

unsafe impl Sync for SafeTimer {}

impl SafeTimer {
    /// Create a new timer (const, for static initialization)
    pub const fn new() -> Self {
        Self {
            inner: UnsafeCell::new(etimer {
                timer: timer { start: 0, interval: 0 },
                next: core::ptr::null_mut(),
                p: core::ptr::null_mut(),
            }),
        }
    }

    /// Set timer interval
    pub fn set(&self, interval: clock_time_t) {
        unsafe {
            etimer_set(self.inner.get(), interval);
        }
    }

    /// Check if expired
    pub fn expired(&self) -> bool {
        unsafe {
            etimer_expired(self.inner.get())
        }
    }

    /// Reset timer
    pub fn reset(&self) {
        unsafe {
            etimer_reset(self.inner.get());
        }
    }

    /// Get delay future
    pub fn delay(&self, ticks: clock_time_t) -> AsyncTimer {
        AsyncTimer {
            timer: self.inner.get(),
            interval: ticks,
            started: false,
        }
    }
}
```

**Usage:**
```rust
// ✅ No unsafe in user code!
static TIMER: SafeTimer = SafeTimer::new();

// In process
for i in 0..10 {
    TIMER.delay(CLOCK_SECOND * 2).await;
    print_u32(c_str!("Count: %u\n"), i);
}
```

### Solution 2: Process Context

Instead of global state, use a context object:

```rust
/// Process execution context
pub struct ProcessContext {
    timer: SafeTimer,
    // Other resources
}

impl ProcessContext {
    pub const fn new() -> Self {
        Self {
            timer: SafeTimer::new(),
        }
    }

    pub fn timer(&self) -> &SafeTimer {
        &self.timer
    }
}
```

**Usage:**
```rust
static CTX: ProcessContext = ProcessContext::new();

async fn my_process() {
    CTX.timer().delay(CLOCK_SECOND * 2).await;
}
```

### Solution 3: Safe UDP Wrapper

Encapsulate UDP connection state:

```rust
/// Safe UDP socket
pub struct UdpSocket {
    conn: UnsafeCell<simple_udp_connection>,
    async_state: UnsafeCell<Option<AsyncUdp>>,
}

unsafe impl Sync for UdpSocket {}

impl UdpSocket {
    pub const fn new() -> Self {
        Self {
            conn: UnsafeCell::new(/* ... */),
            async_state: UnsafeCell::new(None),
        }
    }

    pub fn bind(&self, port: u16) -> Result<()> {
        // Safe binding logic
    }

    pub fn recv(&self) -> UdpRecvFuture {
        UdpRecvFuture { socket: self }
    }

    pub fn send_to(&self, data: &[u8], addr: &IpAddr, port: u16) -> Result<()> {
        // Safe sending
    }

    // Internal: called from callback
    pub(crate) fn on_receive(&self, packet: UdpPacket) {
        unsafe {
            if let Some(ref mut async_state) = *self.async_state.get() {
                async_state.notify_rx(/* ... */);
            }
        }
    }
}
```

**Usage:**
```rust
static UDP: UdpSocket = UdpSocket::new();

async fn udp_echo() {
    UDP.bind(8765)?;

    loop {
        let packet = UDP.recv().await;
        UDP.send_to(&packet.data, &packet.addr, packet.port)?;
    }
}
```

### Solution 4: Macro for Process Definition

Create a macro that handles all boilerplate:

```rust
#[macro_export]
macro_rules! contiki_process {
    (
        $name:literal,
        $handler:ident,
        $body:expr
    ) => {
        // Generate C wrapper
        #[no_mangle]
        pub extern "C" fn $handler(
            ev: $crate::process_event_t,
            _data: $crate::process_data_t,
        ) -> $crate::c_int {
            static mut INITIALIZED: bool = false;

            unsafe {
                match ev {
                    $crate::PROCESS_EVENT_INIT => {
                        INITIALIZED = true;
                        $crate::PT_WAITING
                    }
                    _ if INITIALIZED => {
                        $body()
                    }
                    _ => $crate::PT_ENDED,
                }
            }
        }
    };
}
```

**Usage:**
```rust
contiki_process!(
    "My Process",
    rust_my_handler,
    || {
        // Process logic here
        PT_WAITING
    }
);
```

### Solution 5: Improved AsyncTimer

Make AsyncTimer easier to use:

```rust
impl AsyncTimer {
    /// Create timer future without unsafe
    pub fn new_safe(timer: &SafeTimer, interval: clock_time_t) -> Self {
        Self {
            timer: timer.inner.get(),
            interval,
            started: false,
        }
    }
}

// Extension trait
pub trait TimerExt {
    fn delay_seconds(&self, seconds: u32) -> AsyncTimer;
    fn delay_ms(&self, ms: u32) -> AsyncTimer;
}

impl TimerExt for SafeTimer {
    fn delay_seconds(&self, seconds: u32) -> AsyncTimer {
        AsyncTimer::new_safe(self, CLOCK_SECOND * seconds)
    }

    fn delay_ms(&self, ms: u32) -> AsyncTimer {
        AsyncTimer::new_safe(self, (CLOCK_SECOND * ms) / 1000)
    }
}
```

**Usage:**
```rust
// ✅ Clean and safe!
TIMER.delay_seconds(2).await;
TIMER.delay_ms(500).await;
```

### Solution 6: Type-Safe Events

Replace raw integers with enums:

```rust
#[repr(u32)]
pub enum ProcessEvent {
    Init = PROCESS_EVENT_INIT,
    Poll = PROCESS_EVENT_POLL,
    Timer = PROCESS_EVENT_TIMER,
    Exit = PROCESS_EVENT_EXIT,
    Continue = PROCESS_EVENT_CONTINUE,
    Custom(u8),
}

impl From<process_event_t> for ProcessEvent {
    fn from(ev: process_event_t) -> Self {
        match ev {
            PROCESS_EVENT_INIT => Self::Init,
            PROCESS_EVENT_TIMER => Self::Timer,
            // ...
            _ => Self::Custom((ev - PROCESS_EVENT_MAX) as u8),
        }
    }
}
```

**Usage:**
```rust
match ProcessEvent::from(ev) {
    ProcessEvent::Init => { /* ... */ }
    ProcessEvent::Timer => { /* ... */ }
    _ => PT_WAITING
}
```

### Solution 7: Builder Pattern for Complex Setup

```rust
pub struct ProcessBuilder {
    name: &'static str,
    has_timer: bool,
    has_udp: bool,
    udp_port: Option<u16>,
}

impl ProcessBuilder {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            has_timer: false,
            has_udp: false,
            udp_port: None,
        }
    }

    pub fn with_timer(mut self) -> Self {
        self.has_timer = true;
        self
    }

    pub fn with_udp(mut self, port: u16) -> Self {
        self.has_udp = true;
        self.udp_port = Some(port);
        self
    }

    pub fn build<F>(self, handler: F)
    where
        F: FnOnce(&ProcessContext) -> c_int,
    {
        // Generate process code
    }
}
```

**Usage:**
```rust
ProcessBuilder::new("UDP Echo")
    .with_udp(8765)
    .build(|ctx| {
        // Process logic with ctx
        PT_WAITING
    });
```

---

## Example Transformations

### Before: async-hello (Verbose, Lots of Unsafe)

```rust
async_timer!(TIMER);

struct CounterFuture {
    timer: *mut etimer,  // ❌ Raw pointer
    count: u32,
    max_count: u32,
    timer_future: Option<AsyncTimer>,
}

impl Future for CounterFuture {
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        loop {
            if self.timer_future.is_none() {
                self.timer_future = Some(unsafe {  // ❌ Unsafe
                    AsyncTimer::delay_seconds(self.timer, 2)
                });
            }
            // ... 30 more lines ...
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_async_hello_handler(...) -> c_int {
    unsafe {  // ❌ Unsafe
        match ev {
            PROCESS_EVENT_INIT => {
                FUTURE = Some(CounterFuture::new(&mut TIMER, 10));
                // Poll future...
                PT_WAITING
            }
            _ => { /* ... */ }
        }
    }
}
```

### After: async-hello (Clean, Safe, Readable)

```rust
static TIMER: SafeTimer = SafeTimer::new();  // ✅ Safe static

async fn count_to_ten() {
    for i in 1..=10 {
        TIMER.delay_seconds(2).await;  // ✅ No unsafe!
        print_u32(c_str!("Count: %u\n"), i);
    }
}

contiki_process!("Async Hello", rust_async_hello_handler, count_to_ten);
```

**Improvements:**
- 80% less code
- Zero unsafe in user code
- Clear, sequential logic
- Easy to understand

### Before: udp-echo (Global State, Callbacks)

```rust
static mut UDP_CONN: simple_udp_connection = ...;  // ❌ Global mut
static mut ASYNC_UDP: Option<AsyncUdp> = None;     // ❌ Global mut

#[no_mangle]
pub unsafe extern "C" fn udp_rx_callback(...) {  // ❌ Unsafe callback
    if let Some(ref mut async_udp) = ASYNC_UDP {
        async_udp.notify_rx(...);
    }
}

// ... 100+ lines of complex state management ...
```

### After: udp-echo (Encapsulated, Safe)

```rust
static UDP: UdpSocket = UdpSocket::new();  // ✅ Safe encapsulation

async fn udp_echo_server() {
    UDP.bind(8765).expect("Failed to bind");

    loop {
        let packet = UDP.recv().await;
        UDP.send_to(&packet.data, &packet.addr, packet.port).ok();
    }
}

contiki_process!("UDP Echo", rust_udp_echo_handler, udp_echo_server);
```

**Improvements:**
- No global mut
- No unsafe in user code
- Simple, clean async/await
- Encapsulated state

---

## Implementation Priority

### Phase 1: Core Safety Wrappers (High Priority)
1. ✅ **SafeTimer** - Eliminates most unsafe in examples
2. ✅ **UdpSocket** - Safe UDP networking
3. ✅ **ProcessContext** - Encapsulates resources

### Phase 2: Better Ergonomics (Medium Priority)
4. **contiki_process! macro** - Reduce boilerplate
5. **TimerExt trait** - Cleaner timer API
6. **ProcessEvent enum** - Type-safe events

### Phase 3: Advanced Features (Low Priority)
7. **ProcessBuilder** - Complex setup
8. **select! macro** - Multiple futures
9. **Timeout utilities**

---

## Testing Strategy

### Unit Tests
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_timer_creation() {
        let timer = SafeTimer::new();
        assert!(!timer.expired());
    }

    #[test]
    fn test_udp_socket_bind() {
        let socket = UdpSocket::new();
        assert!(socket.bind(8765).is_ok());
    }
}
```

### Integration Tests
- Test async timer delays
- Test UDP echo functionality
- Test process lifecycle

---

## Benefits Summary

| Aspect | Before | After |
|--------|--------|-------|
| **Unsafe blocks** | 20+ per example | 0 in user code |
| **Global mut** | 5+ per example | 0 (encapsulated) |
| **Raw pointers** | Everywhere | Hidden in wrappers |
| **Lines of code** | 150+ | 30-50 |
| **Readability** | Complex | Clear |
| **Safety** | Manual auditing | Compile-time checks |
| **Testability** | Difficult | Easy |

---

## Migration Path

### Step 1: Add Safe Wrappers
Add SafeTimer, UdpSocket to contiki-sys.rs without breaking existing code.

### Step 2: Create New Examples
Create "v2" versions of examples using new APIs:
- `hello-world-v2`
- `udp-echo-v2`

### Step 3: Document Patterns
Update README with best practices.

### Step 4: Deprecate Old Patterns
Mark old unsafe patterns as deprecated.

---

## Conclusion

By introducing safe wrappers, encapsulation, and better abstractions, we can make Rust examples:

✅ **More elegant** - Less boilerplate, cleaner code
✅ **More readable** - Sequential async/await style
✅ **More correct** - Type safety, no unsafe in user code
✅ **More idiomatic** - Follows Rust best practices
✅ **Easier to learn** - Clear patterns, good examples

The key insight: **Hide complexity in well-audited wrappers, expose simple, safe APIs.**
