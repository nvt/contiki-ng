# UDP Communication

This document describes UDP communication in Contiki-NG. UDP (User Datagram Protocol) is a connectionless transport protocol defined in RFC 768, providing unreliable datagram delivery for applications that prioritize low overhead over guaranteed delivery.

Contiki-NG provides three UDP APIs with different levels of abstraction: simple-udp (high-level), udp-socket (mid-level), and raw uIP (low-level).

## Architecture Overview

```
┌─────────────────────────────────────────┐
│        Application Layer                │
├─────────────────────────────────────────┤
│  simple-udp  │ udp-socket  │ Raw uIP   │  ← UDP APIs
├──────────────┴─────────────┴────────────┤
│           UDP Protocol Layer            │
│    (uip_udp_conn management)            │
├─────────────────────────────────────────┤
│         IPv6 Stack (uIP)                │
├─────────────────────────────────────────┤
│       6LoWPAN / Link Layer              │
└─────────────────────────────────────────┘
```

## API Comparison

| Feature | simple-udp | udp-socket | Raw uIP |
|---------|------------|------------|---------|
| Ease of use | Easy | Moderate | Complex |
| Memory overhead | Low | Low | Minimal |
| Callback support | Yes | Yes | Process-based |
| Multiple sends | Limited | Yes | Full control |
| Bind flexibility | Automatic | Manual | Manual |
| Use case | Simple apps | Most apps | Advanced control |
| Header file | `simple-udp.h` | `udp-socket.h` | `uip.h` |

**Recommendation:** Use simple-udp for most applications, udp-socket when you need more control over binding/connection, and raw uIP only for special requirements.

## Simple-UDP API

The simple-udp module provides the easiest way to send and receive UDP datagrams.

### Data Structures

```c
struct simple_udp_connection {
  struct simple_udp_connection *next;
  uip_ipaddr_t remote_addr;
  uint16_t remote_port, local_port;
  simple_udp_callback receive_callback;
  struct uip_udp_conn *udp_conn;
  struct process *client_process;
};
```

### API Reference

| Function | Description | Return Value |
|----------|-------------|--------------|
| `simple_udp_register()` | Register a UDP connection with callback | 1 on success, 0 on failure |
| `simple_udp_send()` | Send to the registered remote address/port | Bytes sent, or -1 on error |
| `simple_udp_sendto()` | Send to a specific IPv6 address | Bytes sent, or -1 on error |
| `simple_udp_sendto_port()` | Send to a specific address and port | Bytes sent, or -1 on error |
| `simple_udp_init()` | Initialize simple-udp module (called automatically) | void |

**Callback signature:**
```c
void callback(struct simple_udp_connection *c,
              const uip_ipaddr_t *sender_addr,
              uint16_t sender_port,
              const uip_ipaddr_t *receiver_addr,
              uint16_t receiver_port,
              const uint8_t *data,
              uint16_t datalen);
```

## UDP-Socket API

The udp-socket module provides a flexible socket-like interface with separate bind and connect operations.

### Data Structures

```c
struct udp_socket {
  udp_socket_input_callback_t input_callback;
  void *ptr;  /* Opaque pointer passed to callback */
  struct process *p;
  struct uip_udp_conn *udp_conn;
};
```

### API Reference

| Function | Description | Return Value |
|----------|-------------|--------------|
| `udp_socket_register()` | Register a UDP socket with callback | 1 on success, -1 on failure |
| `udp_socket_bind()` | Bind socket to a local port | 1 on success, -1 on failure |
| `udp_socket_connect()` | Connect to remote address/port | 1 on success, -1 on failure |
| `udp_socket_send()` | Send on connected socket | Bytes sent, or -1 on error |
| `udp_socket_sendto()` | Send to specific address/port | Bytes sent, or -1 on error |
| `udp_socket_close()` | Close the UDP socket | 1 on success, -1 on failure |

**Callback signature:**
```c
void callback(struct udp_socket *c,
              void *ptr,
              const uip_ipaddr_t *source_addr,
              uint16_t source_port,
              const uip_ipaddr_t *dest_addr,
              uint16_t dest_port,
              const uint8_t *data,
              uint16_t datalen);
```

## Raw uIP UDP API

Low-level UDP API for advanced use cases.

### Key Functions

| Function | Description |
|----------|-------------|
| `uip_udp_new()` | Create new UDP connection |
| `uip_udp_bind()` | Bind to local port |
| `uip_udp_remove()` | Remove UDP connection |
| `uip_udp_send()` | Send UDP datagram |
| `uip_udp_periodic()` | Periodic processing |

See [IPv6 Core documentation](/doc/programming/IPv6-core) for detailed uIP API information.

## Configuration Parameters

Configure these in `project-conf.h`:

| Parameter | Description | Default | Valid Range |
|-----------|-------------|---------|-------------|
| `UIP_CONF_UDP` | Enable UDP support | 1 | 0 or 1 |
| `UIP_CONF_UDP_CHECKSUMS` | Enable UDP checksums | 1 | 0 or 1 |
| `UIP_CONF_UDP_CONNS` | Maximum concurrent UDP connections | 10 | 1-255 |
| `UIP_CONF_BUFFER_SIZE` | Size of uIP packet buffer | 1280 | ≥60 bytes |

**Notes:**
- Each UDP connection consumes approximately 24 bytes of RAM
- Disabling checksums saves CPU cycles but violates RFC 768 for IPv6
- Buffer size affects maximum UDP payload (max payload = buffer - headers)
- Maximum UDP payload ≈ `UIP_BUFSIZE - UIP_IPUDPH_LEN - uip_ext_len`

**Example configuration:**
```c
/* project-conf.h */
#define UIP_CONF_UDP_CONNS 4        /* Limit to 4 connections */
#define UIP_CONF_UDP_CHECKSUMS 1     /* Always use checksums */
```

## Code Examples

### Example 1: Simple UDP Server

```c
#include "contiki.h"
#include "net/ipv6/simple-udp.h"
#include "sys/log.h"

#define LOG_MODULE "UDP-Server"
#define LOG_LEVEL LOG_LEVEL_INFO

#define UDP_PORT 5678

static struct simple_udp_connection udp_conn;

PROCESS(udp_server_process, "UDP server");
AUTOSTART_PROCESSES(&udp_server_process);

static void
udp_rx_callback(struct simple_udp_connection *c,
                const uip_ipaddr_t *sender_addr,
                uint16_t sender_port,
                const uip_ipaddr_t *receiver_addr,
                uint16_t receiver_port,
                const uint8_t *data,
                uint16_t datalen)
{
  LOG_INFO("Received %u bytes from ", datalen);
  LOG_INFO_6ADDR(sender_addr);
  LOG_INFO_(" port %u: %.*s\n", sender_port, datalen, (char *)data);

  /* Echo back to sender */
  simple_udp_sendto(&udp_conn, data, datalen, sender_addr);
}

PROCESS_THREAD(udp_server_process, ev, data)
{
  PROCESS_BEGIN();

  /* Register UDP connection (no fixed remote address) */
  simple_udp_register(&udp_conn, UDP_PORT, NULL, UDP_PORT, udp_rx_callback);

  LOG_INFO("UDP server listening on port %u\n", UDP_PORT);

  PROCESS_END();
}
```

### Example 2: Simple UDP Client

```c
#include "contiki.h"
#include "net/ipv6/simple-udp.h"
#include "net/ipv6/uip-ds6.h"
#include "sys/log.h"

#define LOG_MODULE "UDP-Client"
#define LOG_LEVEL LOG_LEVEL_INFO

#define UDP_PORT 5678
#define SEND_INTERVAL (10 * CLOCK_SECOND)

static struct simple_udp_connection udp_conn;
static struct etimer periodic_timer;

PROCESS(udp_client_process, "UDP client");
AUTOSTART_PROCESSES(&udp_client_process);

static void
udp_rx_callback(struct simple_udp_connection *c,
                const uip_ipaddr_t *sender_addr,
                uint16_t sender_port,
                const uip_ipaddr_t *receiver_addr,
                uint16_t receiver_port,
                const uint8_t *data,
                uint16_t datalen)
{
  LOG_INFO("Response: %.*s\n", datalen, (char *)data);
}

PROCESS_THREAD(udp_client_process, ev, data)
{
  static unsigned count = 0;
  static char message[32];
  uip_ipaddr_t dest_addr;

  PROCESS_BEGIN();

  /* Register UDP connection */
  simple_udp_register(&udp_conn, UDP_PORT, NULL, UDP_PORT, udp_rx_callback);

  /* Set destination address (example: fd00::1) */
  uip_ip6addr(&dest_addr, 0xfd00, 0, 0, 0, 0, 0, 0, 0x0001);

  etimer_set(&periodic_timer, SEND_INTERVAL);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));

    snprintf(message, sizeof(message), "Message %u", count++);
    LOG_INFO("Sending: %s\n", message);

    simple_udp_sendto(&udp_conn, message, strlen(message), &dest_addr);

    etimer_reset(&periodic_timer);
  }

  PROCESS_END();
}
```

### Example 3: UDP Socket with Bind

```c
#include "contiki.h"
#include "net/ipv6/udp-socket.h"
#include "sys/log.h"

#define LOG_MODULE "UDP-Socket"
#define LOG_LEVEL LOG_LEVEL_INFO

#define LOCAL_PORT 8765
#define REMOTE_PORT 8766

static struct udp_socket udp_sock;

PROCESS(udp_socket_example_process, "UDP socket example");
AUTOSTART_PROCESSES(&udp_socket_example_process);

static void
udp_rx_callback(struct udp_socket *c,
                void *ptr,
                const uip_ipaddr_t *source_addr,
                uint16_t source_port,
                const uip_ipaddr_t *dest_addr,
                uint16_t dest_port,
                const uint8_t *data,
                uint16_t datalen)
{
  LOG_INFO("Received %u bytes\n", datalen);

  /* Send response back to sender */
  udp_socket_sendto(&udp_sock, data, datalen, source_addr, source_port);
}

PROCESS_THREAD(udp_socket_example_process, ev, data)
{
  PROCESS_BEGIN();

  /* Register socket with custom pointer */
  if(udp_socket_register(&udp_sock, NULL, udp_rx_callback) < 0) {
    LOG_ERR("Failed to register UDP socket\n");
    PROCESS_EXIT();
  }

  /* Bind to local port */
  if(udp_socket_bind(&udp_sock, LOCAL_PORT) < 0) {
    LOG_ERR("Failed to bind to port %u\n", LOCAL_PORT);
    PROCESS_EXIT();
  }

  LOG_INFO("UDP socket bound to port %u\n", LOCAL_PORT);

  PROCESS_END();
}
```

### Example 4: Connected UDP Socket

```c
#include "contiki.h"
#include "net/ipv6/udp-socket.h"
#include "sys/log.h"

#define LOG_MODULE "UDP-Connected"
#define LOG_LEVEL LOG_LEVEL_INFO

#define REMOTE_PORT 7777
#define SEND_INTERVAL (5 * CLOCK_SECOND)

static struct udp_socket udp_sock;
static struct etimer send_timer;

PROCESS(udp_connected_process, "UDP connected example");
AUTOSTART_PROCESSES(&udp_connected_process);

static void
udp_rx_callback(struct udp_socket *c,
                void *ptr,
                const uip_ipaddr_t *source_addr,
                uint16_t source_port,
                const uip_ipaddr_t *dest_addr,
                uint16_t dest_port,
                const uint8_t *data,
                uint16_t datalen)
{
  LOG_INFO("Received response: %.*s\n", datalen, (char *)data);
}

PROCESS_THREAD(udp_connected_process, ev, data)
{
  static char msg[64];
  static uint16_t seq = 0;
  uip_ipaddr_t remote_addr;

  PROCESS_BEGIN();

  /* Set remote address */
  uip_ip6addr(&remote_addr, 0xfd00, 0, 0, 0, 0, 0, 0, 0x0001);

  /* Register and connect socket */
  udp_socket_register(&udp_sock, NULL, udp_rx_callback);
  udp_socket_connect(&udp_sock, &remote_addr, REMOTE_PORT);

  LOG_INFO("Connected to ");
  LOG_INFO_6ADDR(&remote_addr);
  LOG_INFO_(" port %u\n", REMOTE_PORT);

  etimer_set(&send_timer, SEND_INTERVAL);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&send_timer));

    snprintf(msg, sizeof(msg), "Sequence %u", seq++);

    /* Send on connected socket (no need to specify destination) */
    udp_socket_send(&udp_sock, msg, strlen(msg));

    etimer_reset(&send_timer);
  }

  PROCESS_END();
}
```

### Example 5: UDP Multicast Sender

```c
#include "contiki.h"
#include "net/ipv6/simple-udp.h"
#include "net/ipv6/uip-ds6.h"
#include "sys/log.h"

#define LOG_MODULE "Mcast-Send"
#define LOG_LEVEL LOG_LEVEL_INFO

#define MCAST_PORT 5000
#define SEND_INTERVAL (30 * CLOCK_SECOND)

static struct simple_udp_connection udp_conn;
static struct etimer periodic_timer;

PROCESS(mcast_sender_process, "Multicast sender");
AUTOSTART_PROCESSES(&mcast_sender_process);

PROCESS_THREAD(mcast_sender_process, ev, data)
{
  static char message[32];
  uip_ipaddr_t mcast_addr;

  PROCESS_BEGIN();

  /* Set multicast address (ff02::1 = all nodes link-local) */
  uip_create_linklocal_allnodes_mcast(&mcast_addr);

  /* Register UDP connection */
  simple_udp_register(&udp_conn, MCAST_PORT, NULL, MCAST_PORT, NULL);

  etimer_set(&periodic_timer, SEND_INTERVAL);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));

    snprintf(message, sizeof(message), "Multicast beacon");
    LOG_INFO("Sending multicast message\n");

    simple_udp_sendto(&udp_conn, message, strlen(message), &mcast_addr);

    etimer_reset(&periodic_timer);
  }

  PROCESS_END();
}
```

### Example 6: UDP Broadcast Receiver

```c
#include "contiki.h"
#include "net/ipv6/simple-udp.h"
#include "net/ipv6/uip-ds6.h"
#include "sys/log.h"

#define LOG_MODULE "Bcast-Recv"
#define LOG_LEVEL LOG_LEVEL_INFO

#define BCAST_PORT 6000

static struct simple_udp_connection udp_conn;

PROCESS(bcast_receiver_process, "Broadcast receiver");
AUTOSTART_PROCESSES(&bcast_receiver_process);

static void
udp_rx_callback(struct simple_udp_connection *c,
                const uip_ipaddr_t *sender_addr,
                uint16_t sender_port,
                const uip_ipaddr_t *receiver_addr,
                uint16_t receiver_port,
                const uint8_t *data,
                uint16_t datalen)
{
  LOG_INFO("Broadcast from ");
  LOG_INFO_6ADDR(sender_addr);
  LOG_INFO_(": %.*s\n", datalen, (char *)data);
}

PROCESS_THREAD(bcast_receiver_process, ev, data)
{
  uip_ipaddr_t mcast_addr;

  PROCESS_BEGIN();

  /* Register for all-nodes multicast (ff02::1) */
  simple_udp_register(&udp_conn, BCAST_PORT, NULL, BCAST_PORT, udp_rx_callback);

  /* Join multicast group */
  uip_create_linklocal_allnodes_mcast(&mcast_addr);
  uip_ds6_maddr_add(&mcast_addr);

  LOG_INFO("Listening for broadcasts on port %u\n", BCAST_PORT);

  PROCESS_END();
}
```

### Example 7: Request-Response Pattern

```c
#include "contiki.h"
#include "net/ipv6/simple-udp.h"
#include "sys/log.h"

#define LOG_MODULE "Req-Resp"
#define LOG_LEVEL LOG_LEVEL_INFO

#define SERVER_PORT 9000
#define REQUEST_TIMEOUT (5 * CLOCK_SECOND)

static struct simple_udp_connection udp_conn;
static struct etimer timeout_timer;
static bool waiting_for_response = false;

PROCESS(request_response_process, "Request-response");
AUTOSTART_PROCESSES(&request_response_process);

static void
udp_rx_callback(struct simple_udp_connection *c,
                const uip_ipaddr_t *sender_addr,
                uint16_t sender_port,
                const uip_ipaddr_t *receiver_addr,
                uint16_t receiver_port,
                const uint8_t *data,
                uint16_t datalen)
{
  if(waiting_for_response) {
    LOG_INFO("Response received: %.*s\n", datalen, (char *)data);
    waiting_for_response = false;
    process_post(&request_response_process, PROCESS_EVENT_CONTINUE, NULL);
  }
}

PROCESS_THREAD(request_response_process, ev, data)
{
  static char request[] = "GET_STATUS";
  uip_ipaddr_t server_addr;

  PROCESS_BEGIN();

  uip_ip6addr(&server_addr, 0xfd00, 0, 0, 0, 0, 0, 0, 0x0001);

  simple_udp_register(&udp_conn, SERVER_PORT, NULL, SERVER_PORT, udp_rx_callback);

  /* Send request */
  LOG_INFO("Sending request\n");
  simple_udp_sendto(&udp_conn, request, sizeof(request), &server_addr);

  waiting_for_response = true;
  etimer_set(&timeout_timer, REQUEST_TIMEOUT);

  PROCESS_WAIT_EVENT();

  if(ev == PROCESS_EVENT_CONTINUE) {
    LOG_INFO("Request successful\n");
  } else if(etimer_expired(&timeout_timer)) {
    LOG_WARN("Request timeout\n");
  }

  PROCESS_END();
}
```

### Example 8: Fragmented Payload Handling

```c
#include "contiki.h"
#include "net/ipv6/simple-udp.h"
#include "sys/log.h"

#define LOG_MODULE "UDP-Frag"
#define LOG_LEVEL LOG_LEVEL_INFO

#define UDP_PORT 8888
#define MAX_PAYLOAD_SIZE 1024

static struct simple_udp_connection udp_conn;

PROCESS(fragmented_udp_process, "Fragmented UDP");
AUTOSTART_PROCESSES(&fragmented_udp_process);

static void
udp_rx_callback(struct simple_udp_connection *c,
                const uip_ipaddr_t *sender_addr,
                uint16_t sender_port,
                const uip_ipaddr_t *receiver_addr,
                uint16_t receiver_port,
                const uint8_t *data,
                uint16_t datalen)
{
  LOG_INFO("Received fragment: %u bytes\n", datalen);

  /* Process payload chunk */
  /* Note: 6LoWPAN handles fragmentation/reassembly automatically */
}

PROCESS_THREAD(fragmented_udp_process, ev, data)
{
  static char large_payload[MAX_PAYLOAD_SIZE];
  uip_ipaddr_t dest_addr;

  PROCESS_BEGIN();

  simple_udp_register(&udp_conn, UDP_PORT, NULL, UDP_PORT, udp_rx_callback);

  uip_ip6addr(&dest_addr, 0xfd00, 0, 0, 0, 0, 0, 0, 0x0001);

  /* Fill payload */
  memset(large_payload, 'A', sizeof(large_payload));

  /* Send large payload (will be fragmented by 6LoWPAN if needed) */
  LOG_INFO("Sending %u bytes (may require fragmentation)\n", sizeof(large_payload));

  int result = simple_udp_sendto(&udp_conn, large_payload,
                                  sizeof(large_payload), &dest_addr);

  if(result < 0) {
    LOG_ERR("Send failed\n");
  } else {
    LOG_INFO("Send successful\n");
  }

  PROCESS_END();
}
```

## Troubleshooting

### No packets received

**Symptoms:** Callback never called, no data received

**Possible causes:**
1. **Wrong port number** - Verify sender and receiver use same port
2. **No route to destination** - Check RPL DODAG formation
3. **Connection limit reached** - Increase `UIP_CONF_UDP_CONNS`
4. **Callback not registered** - Ensure `simple_udp_register()` succeeded
5. **Process not running** - Verify process is in AUTOSTART_PROCESSES

**Debug steps:**
```c
/* Enable UDP logging */
#define LOG_CONF_LEVEL_UDP LOG_LEVEL_DBG

/* Check connection registration */
if(!simple_udp_register(&conn, port, NULL, port, callback)) {
  LOG_ERR("Registration failed - increase UIP_CONF_UDP_CONNS\n");
}

/* Verify IPv6 address is assigned */
if(!uip_ds6_get_global(ADDR_PREFERRED)) {
  LOG_WARN("No global IPv6 address assigned yet\n");
}
```

### Packets dropped

**Symptoms:** Some packets received, others lost

**Possible causes:**
1. **Buffer overflow** - Payload larger than `UIP_BUFSIZE`
2. **Queue full** - Too many packets queued at MAC layer
3. **Checksum error** - Corrupted packets (check `UIP_CONF_UDP_CHECKSUMS`)
4. **Network congestion** - TSCH slots full, increase bandwidth
5. **Callback blocking** - Callback takes too long, blocks reception

**Solutions:**
```c
/* Check payload size */
#define MAX_PAYLOAD (UIP_BUFSIZE - UIP_IPUDPH_LEN - 100)  /* Leave margin */

/* Keep callbacks fast */
static void udp_rx_callback(...) {
  /* Don't do heavy processing here - post event instead */
  process_post(&handler_process, PROCESS_EVENT_MSG, (void *)data);
}
```

### Send fails

**Symptoms:** `simple_udp_send()` returns -1

**Possible causes:**
1. **No connection** - Connection not registered
2. **Invalid destination** - NULL or uninitialized address
3. **Buffer busy** - uIP buffer in use
4. **No route** - RPL has no route to destination

**Debug:**
```c
int result = simple_udp_sendto(&conn, data, len, &dest);
if(result < 0) {
  LOG_ERR("Send failed: ");
  if(!conn.udp_conn) {
    LOG_ERR_("no connection\n");
  } else if(uip_len != 0) {
    LOG_ERR_("buffer busy\n");
  } else {
    LOG_ERR_("routing failure\n");
  }
}
```

### High memory usage

**Symptoms:** Out of memory errors

**Possible causes:**
1. **Too many connections** - Reduce `UIP_CONF_UDP_CONNS`
2. **Large buffer** - Reduce `UIP_CONF_BUFFER_SIZE` if possible
3. **Connection leaks** - Not closing udp-socket connections

**Solution:**
```c
/* Minimize connections */
#define UIP_CONF_UDP_CONNS 2  /* Only what's needed */

/* Close connections when done */
udp_socket_close(&sock);
```

### Callback context issues

**Symptoms:** Strange behavior, crashes in callback

**Possible causes:**
1. **Callback runs in interrupt** - simple-udp callbacks run in process context
2. **Stack overflow** - Callback uses too much stack
3. **Buffer reuse** - Data pointer invalidated after callback returns

**Solution:**
```c
static void udp_rx_callback(..., const uint8_t *data, uint16_t datalen) {
  /* Copy data if needed beyond callback scope */
  static uint8_t buffer[128];
  if(datalen <= sizeof(buffer)) {
    memcpy(buffer, data, datalen);
    /* Use buffer, not data */
  }
}
```

### Port conflicts

**Symptoms:** Connection registration fails

**Solution:**
```c
/* Use unique ports for each connection */
#define SENSOR_PORT 5001
#define ACTUATOR_PORT 5002
#define COMMAND_PORT 5003
```

## Best Practices

1. **Choose the right API**
   - Use simple-udp for most applications
   - Use udp-socket when you need separate bind/connect
   - Avoid raw uIP unless necessary

2. **Handle unreliability**
   ```c
   /* UDP is unreliable - implement retries if needed */
   static uint8_t retries = 0;
   #define MAX_RETRIES 3

   if(send_failed && retries < MAX_RETRIES) {
     retries++;
     simple_udp_sendto(&conn, data, len, &dest);
   }
   ```

3. **Validate input**
   ```c
   static void udp_rx_callback(..., const uint8_t *data, uint16_t datalen) {
     if(datalen < sizeof(expected_header)) {
       LOG_WARN("Packet too small\n");
       return;
     }
     /* Validate data before processing */
   }
   ```

4. **Minimize payload size**
   ```c
   /* Use compact encoding */
   struct __attribute__((packed)) sensor_msg {
     uint8_t type;
     uint16_t value;
   };  /* 3 bytes instead of 8 */
   ```

5. **Use appropriate buffer sizes**
   ```c
   /* Don't waste RAM on oversized buffers */
   #define UIP_CONF_BUFFER_SIZE 128  /* For small payloads */
   ```

6. **Implement timeouts**
   ```c
   /* Don't wait forever for responses */
   etimer_set(&timeout, 5 * CLOCK_SECOND);
   PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_POLL ||
                             etimer_expired(&timeout));
   ```

7. **Keep callbacks fast**
   ```c
   /* Offload heavy processing to main process */
   static void udp_rx_callback(...) {
     process_poll(&main_process);  /* Wake process */
   }
   ```

8. **Enable checksums**
   ```c
   /* Always use checksums for IPv6 (required by RFC) */
   #define UIP_CONF_UDP_CHECKSUMS 1
   ```

9. **Clean up resources**
   ```c
   /* Close sockets when done */
   PROCESS_EXITHANDLER(udp_socket_close(&sock));
   ```

10. **Handle multicast properly**
    ```c
    /* Join multicast group before listening */
    uip_ds6_maddr_add(&mcast_addr);
    ```

## Performance Considerations

### Throughput

UDP throughput depends on:
- **Payload size:** Larger payloads improve efficiency (less header overhead)
- **Packet rate:** Limited by TSCH timeslots or CSMA channel access
- **6LoWPAN fragmentation:** Large payloads may require fragmentation
- **Network topology:** Multi-hop routes reduce effective throughput

**Optimization:**
```c
/* Maximize payload while avoiding fragmentation */
#define OPTIMAL_PAYLOAD 60  /* Typical for 6LoWPAN with TSCH */
```

### Latency

Factors affecting latency:
- **TSCH slot scheduling:** Depends on Orchestra or manual scheduling
- **Queue depth:** Packets wait in MAC queue
- **Routing:** Multi-hop paths increase latency
- **Retransmissions:** MAC-layer retries add delay

**Typical latencies:**
- Single hop TSCH: 10-100ms
- Multi-hop TSCH: 100ms-1s per hop
- CSMA: Variable, 10-500ms

### Power Consumption

UDP transmission costs:
- **Radio on-time:** ~20mA transmit, ~18mA receive
- **CPU processing:** Minimal for UDP
- **Total per packet:** ~0.1-1mJ depending on size

**Optimization:**
```c
/* Batch sensor readings */
struct sensor_batch {
  uint16_t readings[10];
};  /* Send 10 readings at once instead of 10 separate packets */

/* Reduce transmission rate */
#define REPORT_INTERVAL (60 * CLOCK_SECOND)  /* Every 60s */
```

### Memory Usage

RAM consumption per UDP connection:
- Connection structure: ~24 bytes
- Callbacks and state: ~8-16 bytes per connection
- **Total:** ~32-40 bytes per connection

**Calculation:**
```c
/* With UIP_CONF_UDP_CONNS = 4 */
/* UDP connections: 4 × 40 = 160 bytes */
/* Plus uip_buf: 1280 bytes (shared) */
/* Total: ~1440 bytes */
```

## References

- **RFC 768** - User Datagram Protocol
- **RFC 2460** - Internet Protocol, Version 6 (IPv6) Specification
- **RFC 4944** - Transmission of IPv6 Packets over IEEE 802.15.4 Networks (6LoWPAN)
- **RFC 6282** - Compression Format for IPv6 Datagrams over IEEE 802.15.4-Based Networks (IPHC)
- [IPv6 Core Documentation](/doc/programming/IPv6-core)
- [TSCH and 6TiSCH](/doc/programming/TSCH-and-6TiSCH)
