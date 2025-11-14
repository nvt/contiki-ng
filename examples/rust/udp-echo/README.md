# UDP Echo Server Example

This example demonstrates using Contiki-NG's networking API from Rust with comprehensive error handling.

## Features Demonstrated

- **Simple UDP API**: Using the `SimpleUdpConnection` wrapper
- **Result-based error handling**: Proper error propagation and reporting
- **IPv6 networking**: Working with IPv6 addresses
- **Callbacks**: Safe FFI callback handling
- **Static memory**: No heap allocation required

## Building

```bash
make TARGET=native
```

For embedded targets (e.g., Zoul):
```bash
make TARGET=zoul WERROR=0
```

## Running

### Native Platform

Terminal 1 (server):
```bash
./build/native/udp-echo.native
```

Terminal 2 (client - send test packet):
```bash
# Using netcat or similar UDP tool
echo "Hello from client!" | nc -u -6 ::1 8765
```

### Expected Output

Server output:
```
UDP Echo Server Starting...
UDP server listening on port 8765
Send UDP packets to this node on port 8765 and they will be echoed back
Received 18 bytes from port 54321
Echoed data back
```

## Code Structure

### `udp-echo.c`
Minimal C wrapper that:
- Registers the process with Contiki-NG
- Delegates all logic to Rust

### `udp_echo_process.rs`
Rust implementation showing:
- Creating and registering UDP connections
- Handling received packets via callbacks
- Sending echo responses with error handling
- Proper Result<T, Error> usage throughout
- Keeping the process alive with PT_WAITING return values

## Error Handling Examples

The code demonstrates several error handling patterns:

1. **Registration errors**:
```rust
match conn.register(UDP_PORT, None, 0, Some(callback)) {
    Ok(()) => { /* success */ }
    Err(e) => {
        print(c_str!("Failed: "));
        print(c_str!(e.as_str()));
    }
}
```

2. **Send errors**:
```rust
if let Err(e) = conn.send_to_port(data, addr, port) {
    print(c_str!("Error sending: "));
    print(c_str!(e.as_str()));
}
```

## API Usage

### Creating a UDP Connection

```rust
let mut conn = SimpleUdpConnection::new();
```

### Registering with Callback

```rust
conn.register(
    8765,          // Local port
    None,          // Accept from any address
    0,             // Any remote port
    Some(callback) // Receive callback
)?;
```

### Sending Data

```rust
// To registered remote address
conn.send(b"Hello")?;

// To specific address
conn.send_to(b"Hello", &dest_addr)?;

// To specific address and port
conn.send_to_port(b"Hello", &dest_addr, 1234)?;
```

## Learning Points

1. **Zero-cost abstractions**: The wrapper adds no runtime overhead
2. **Type safety**: IPv6 addresses are properly typed
3. **Error propagation**: Using Result<T> for robust error handling
4. **FFI patterns**: Safe callback handling between C and Rust
5. **Static memory**: All state is static, no heap needed

## Extending This Example

Try modifying the code to:
- Parse and respond to specific commands
- Implement a simple protocol
- Add statistics tracking
- Forward packets to other nodes
- Implement multicast support
