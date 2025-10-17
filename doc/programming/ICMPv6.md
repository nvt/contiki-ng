# ICMPv6 (Internet Control Message Protocol for IPv6)

## About

ICMPv6 is an integral part of IPv6, used for error reporting, diagnostics (ping), and network management. In Contiki-NG, ICMPv6 is implemented in the `uip-icmp6` module and provides both standard protocol support and an extensible framework for custom message handlers.

For detailed protocol specifications, see [RFC 4443](https://tools.ietf.org/html/rfc4443) (ICMPv6 for IPv6).

## Architecture

```
┌──────────────────────────────────────────────────────┐
│              Applications                             │
│  (Ping, Neighbor Discovery, RPL, etc.)               │
└────────────────┬─────────────────────────────────────┘
                 │ Register handlers
┌────────────────▼─────────────────────────────────────┐
│         ICMPv6 Core (uip-icmp6.c)                    │
│  • Message dispatch                                   │
│  • Handler registration                               │
│  • Echo request/reply                                 │
│  • Error message generation                           │
└────────────────┬─────────────────────────────────────┘
                 │
┌────────────────▼─────────────────────────────────────┐
│           IPv6 Layer (uip6.c)                        │
│  Next Header = 58 (ICMP6)                            │
└──────────────────────────────────────────────────────┘
```

## Message Types

### ICMPv6 Message Categories

| Type Range | Category | Examples |
|------------|----------|----------|
| 0-127 | Error Messages | Destination Unreachable, Packet Too Big, Time Exceeded |
| 128-255 | Informational Messages | Echo Request/Reply, Router/Neighbor Discovery |

### Supported Message Types

| Type | Code | Message | Purpose |
|------|------|---------|---------|
| **Error Messages** |
| 1 | 0-4 | Destination Unreachable | Various unreachability reasons |
| 2 | 0 | Packet Too Big | MTU discovery |
| 3 | 0-1 | Time Exceeded | Hop limit or fragment timeout |
| 4 | 0-2 | Parameter Problem | Header field errors |
| **Informational Messages** |
| 128 | 0 | Echo Request | Ping request |
| 129 | 0 | Echo Reply | Ping reply |
| **Neighbor Discovery** (RFC 4861) |
| 133 | 0 | Router Solicitation | Request router information |
| 134 | 0 | Router Advertisement | Advertise router information |
| 135 | 0 | Neighbor Solicitation | Address resolution / reachability |
| 136 | 0 | Neighbor Advertisement | Response to NS |
| 137 | 0 | Redirect | Better next-hop notification |
| **RPL** (RFC 6550) |
| 155 | various | RPL Control Messages | DIS, DIO, DAO, DAO-ACK |
| **Multicast** |
| 159 | 0 | MPL Control Message | Multicast forwarding |

### Message Type Constants

```c
/* Error messages (RFC 4443) */
#define ICMP6_DST_UNREACH        1
#define ICMP6_PACKET_TOO_BIG     2
#define ICMP6_TIME_EXCEEDED      3
#define ICMP6_PARAM_PROB         4

/* Informational messages */
#define ICMP6_ECHO_REQUEST       128
#define ICMP6_ECHO_REPLY         129

/* Neighbor Discovery (RFC 4861) */
#define ICMP6_RS                 133
#define ICMP6_RA                 134
#define ICMP6_NS                 135
#define ICMP6_NA                 136
#define ICMP6_REDIRECT           137

/* Protocol-specific */
#define ICMP6_RPL                155
#define ICMP6_MPL                159
```

### Error Message Codes

**Destination Unreachable (Type 1):**
```c
#define ICMP6_DST_UNREACH_NOROUTE      0  /* No route to destination */
#define ICMP6_DST_UNREACH_ADMIN        1  /* Administratively prohibited */
#define ICMP6_DST_UNREACH_BEYONDSCOPE  2  /* Beyond scope of source address */
#define ICMP6_DST_UNREACH_ADDR         3  /* Address unreachable */
#define ICMP6_DST_UNREACH_NOPORT       4  /* Port unreachable */
```

**Time Exceeded (Type 3):**
```c
#define ICMP6_TIME_EXCEED_TRANSIT      0  /* Hop limit exceeded */
#define ICMP6_TIME_EXCEED_REASSEMBLY   1  /* Fragment reassembly time exceeded */
```

**Parameter Problem (Type 4):**
```c
#define ICMP6_PARAMPROB_HEADER         0  /* Erroneous header field */
#define ICMP6_PARAMPROB_NEXTHEADER     1  /* Unrecognized next header */
#define ICMP6_PARAMPROB_OPTION         2  /* Unrecognized IPv6 option */
```

## API Reference

### Sending ICMPv6 Messages

```c
/**
 * Send a generic ICMPv6 message
 * \param dest Destination IPv6 address
 * \param type ICMPv6 message type
 * \param code ICMPv6 message code
 * \param payload_len Length of payload in uip_buf
 */
void uip_icmp6_send(const uip_ipaddr_t *dest, int type, int code, int payload_len);

/**
 * Send an ICMPv6 error message
 * \param type Error message type (1-4)
 * \param code Error code
 * \param param 32-bit parameter (e.g., MTU, pointer to error)
 *
 * Note: The invoking packet must still be in uip_buf
 */
void uip_icmp6_error_output(uint8_t type, uint8_t code, uint32_t param);
```

### Echo (Ping) Support

```c
/* Echo reply callback function type */
typedef void (*uip_icmp6_echo_reply_callback_t)(uip_ipaddr_t *source,
                                                 uint8_t ttl,
                                                 uint8_t *data,
                                                 uint16_t datalen);

/* Notification structure */
struct uip_icmp6_echo_reply_notification {
  struct uip_icmp6_echo_reply_notification *next;
  uip_icmp6_echo_reply_callback_t callback;
};

/**
 * Register a callback for ping replies
 * \param n Notification structure (must be static/global)
 * \param c Callback function
 */
void uip_icmp6_echo_reply_callback_add(
  struct uip_icmp6_echo_reply_notification *n,
  uip_icmp6_echo_reply_callback_t c);

/**
 * Unregister a callback for ping replies
 * \param n Notification structure to remove
 */
void uip_icmp6_echo_reply_callback_rm(
  struct uip_icmp6_echo_reply_notification *n);
```

### Custom Message Handlers

```c
/* Handler function type */
typedef struct uip_icmp6_input_handler {
  struct uip_icmp6_input_handler *next;
  void (*handler)(void);
  uint8_t type;
  uint8_t icode;
} uip_icmp6_input_handler_t;

/* Handler codes */
#define UIP_ICMP6_HANDLER_CODE_ANY 0xFF  /* Handle all codes for this type */

/* Return values */
#define UIP_ICMP6_INPUT_SUCCESS    0
#define UIP_ICMP6_INPUT_ERROR      1

/**
 * Macro to define an ICMPv6 input handler
 * \param name Variable name for handler
 * \param type ICMPv6 message type to handle
 * \param code ICMPv6 code (or UIP_ICMP6_HANDLER_CODE_ANY)
 * \param func Handler function
 */
#define UIP_ICMP6_HANDLER(name, type, code, func) \
  static uip_icmp6_input_handler_t name = { NULL, func, type, code }

/**
 * Register a custom ICMPv6 message handler
 * \param handler Pointer to handler structure
 */
void uip_icmp6_register_input_handler(uip_icmp6_input_handler_t *handler);

/**
 * Dispatch incoming ICMPv6 message to registered handler
 * \param type ICMPv6 message type
 * \param icode ICMPv6 message code
 * \return UIP_ICMP6_INPUT_SUCCESS if handler found, _ERROR otherwise
 */
uint8_t uip_icmp6_input(uint8_t type, uint8_t icode);
```

### Initialization

```c
/**
 * Initialize ICMPv6 module
 * Called automatically by uip_init()
 */
void uip_icmp6_init(void);
```

## Code Examples

### Implementing Ping

```c
#include "net/ipv6/uip-icmp6.h"
#include "net/ipv6/uip-ds6.h"

static struct uip_icmp6_echo_reply_notification echo_reply_notification;
static uint16_t ping_seqno = 0;

static void
echo_reply_handler(uip_ipaddr_t *source, uint8_t ttl,
                   uint8_t *data, uint16_t datalen)
{
  LOG_INFO("Ping reply from ");
  LOG_INFO_6ADDR(source);
  LOG_INFO_(" TTL=%u len=%u\n", ttl, datalen);
}

void
send_ping(const uip_ipaddr_t *dest)
{
  uint16_t len = 4;  /* Minimum echo request payload */

  /* Fill echo request data */
  UIP_ICMP_BUF->type = ICMP6_ECHO_REQUEST;
  UIP_ICMP_BUF->icode = 0;

  /* Add sequence number */
  *((uint16_t *)UIP_ICMP_PAYLOAD) = uip_htons(ping_seqno++);

  /* Send */
  uip_icmp6_send(dest, ICMP6_ECHO_REQUEST, 0, len);

  LOG_INFO("Sent ping to ");
  LOG_INFO_6ADDR(dest);
  LOG_INFO_("\n");
}

void
ping_init(void)
{
  /* Register echo reply callback */
  uip_icmp6_echo_reply_callback_add(&echo_reply_notification,
                                     echo_reply_handler);
}
```

### Handling Destination Unreachable

```c
#include "net/ipv6/uip-icmp6.h"

void
handle_unreachable_destination(uip_ipaddr_t *dest)
{
  /* Send "No route to host" error */
  uip_icmp6_error_output(ICMP6_DST_UNREACH,
                          ICMP6_DST_UNREACH_NOROUTE,
                          0);

  LOG_WARN("Sent unreachable message for ");
  LOG_WARN_6ADDR(dest);
  LOG_WARN_("\n");
}
```

### Custom ICMPv6 Message Handler

```c
#include "net/ipv6/uip-icmp6.h"

#define ICMP6_CUSTOM_TYPE 200  /* Use experimental range */

static void
custom_icmp6_handler(void)
{
  uint8_t *data = UIP_ICMP_PAYLOAD;
  uint16_t datalen = uip_len - uip_l2_l3_icmp_hdr_len;

  LOG_INFO("Received custom ICMPv6 message, len=%u\n", datalen);

  /* Process message */
  /* ... */

  /* Must set uip_len = 0 if no response */
  uip_len = 0;
}

/* Define and register handler */
UIP_ICMP6_HANDLER(custom_handler, ICMP6_CUSTOM_TYPE,
                  UIP_ICMP6_HANDLER_CODE_ANY, custom_icmp6_handler);

void
custom_icmp6_init(void)
{
  uip_icmp6_register_input_handler(&custom_handler);
  LOG_INFO("Registered custom ICMPv6 handler for type %u\n",
           ICMP6_CUSTOM_TYPE);
}
```

### Sending Custom ICMPv6 Message

```c
void
send_custom_message(const uip_ipaddr_t *dest)
{
  uint8_t *payload = UIP_ICMP_PAYLOAD;
  uint16_t len = 10;

  /* Fill custom payload */
  memcpy(payload, "CustomData", len);

  /* Send */
  uip_icmp6_send(dest, ICMP6_CUSTOM_TYPE, 0, len);
}
```

### Error Handling in Forwarding

```c
void
forward_packet(void)
{
  /* Decrement hop limit */
  UIP_IP_BUF->ttl--;

  if(UIP_IP_BUF->ttl == 0) {
    /* Send Time Exceeded error */
    uip_icmp6_error_output(ICMP6_TIME_EXCEEDED,
                            ICMP6_TIME_EXCEED_TRANSIT,
                            0);
    LOG_WARN("Packet dropped: hop limit exceeded\n");
    return;
  }

  /* Continue forwarding */
  /* ... */
}
```

### MTU Discovery

```c
void
send_packet_too_big(uint32_t mtu)
{
  /* Send Packet Too Big error with MTU parameter */
  uip_icmp6_error_output(ICMP6_PACKET_TOO_BIG, 0, mtu);

  LOG_INFO("Sent Packet Too Big, MTU=%lu\n", (unsigned long)mtu);
}
```

## Message Format

### ICMPv6 Header

```c
struct uip_icmp_hdr {
  uint8_t type;       /* Message type */
  uint8_t icode;      /* Message code */
  uint16_t icmpchksum; /* Checksum */
  /* Followed by type-specific data */
};
```

### Error Message Format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Parameter                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    As much of invoking packet                 |
+               as possible without exceeding MTU               +
|                                                               |
```

### Echo Request/Reply Format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Identifier          |        Sequence Number        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Data ...
+-+-+-+-+-
```

## Integration with Other Protocols

### Neighbor Discovery (ND)

ICMPv6 messages 133-137 are used by the Neighbor Discovery protocol:

```c
/* ND messages automatically handled by uip-nd6.c */
#include "net/ipv6/uip-nd6.h"

/* Send Router Solicitation */
uip_nd6_rs_output();

/* Send Neighbor Solicitation */
uip_nd6_ns_output(src, dest, target);
```

See [IPv6 Neighbor Discovery](IPv6-neighbor-discovery.md) for details.

### RPL Routing

RPL uses ICMPv6 type 155 for control messages:

```c
/* RPL messages automatically handled by rpl-icmp6.c */
#include "net/routing/rpl-lite/rpl-icmp6.h"

/* RPL handlers registered at initialization */
rpl_icmp6_init();
```

See [RPL](RPL.md) for details.

### Multicast

Multicast Prot

ocol for Low-Power and Lossy Networks (MPL) uses ICMPv6 type 159:

```c
/* MPL messages handled by mcast engine */
#include "net/ipv6/multicast/uip-mcast6.h"
```

## Troubleshooting

### Common Issues

#### 1. Ping Not Working

**Symptoms:**
- Echo requests sent but no replies received

**Check:**
```c
/* Verify destination address is reachable */
if(!uip_ds6_is_addr_onlink(&dest)) {
  LOG_INFO("Destination not on-link\n");
}

/* Enable ICMPv6 logging */
#define LOG_CONF_LEVEL_ICMP6 LOG_LEVEL_DBG

/* Check if callback is registered */
uip_icmp6_echo_reply_callback_add(&notification, callback);
```

#### 2. Custom Handler Not Called

**Symptoms:**
- Custom ICMPv6 messages not processed

**Solutions:**
```c
/* Ensure handler is registered before messages arrive */
void init(void) {
  uip_icmp6_register_input_handler(&my_handler);
}

/* Verify type/code match */
UIP_ICMP6_HANDLER(my_handler, CORRECT_TYPE, CORRECT_CODE, my_func);

/* Handler must set uip_len = 0 if no response */
void my_func(void) {
  /* Process message */
  uip_len = 0;  /* Important! */
}
```

#### 3. Error Messages Not Sent

**Symptoms:**
- No ICMPv6 errors generated for invalid packets

**Reasons:**
```c
/* Error messages rate-limited by ICMPv6 */
/* Can't send error in response to:
 *  - Multicast packets
 *  - ICMPv6 error messages
 *  - Fragment with offset > 0
 */

/* Check if error sending is appropriate */
if(uip_is_addr_mcast(&UIP_IP_BUF->destipaddr)) {
  /* Don't send error for multicast */
  return;
}
```

## Best Practices

### 1. Always Register Handlers at Initialization

```c
void
module_init(void)
{
  /* Register handler before any messages arrive */
  uip_icmp6_register_input_handler(&my_handler);
}
```

### 2. Set uip_len Correctly in Handlers

```c
void
my_handler(void)
{
  if(send_response) {
    /* Prepare response in uip_buf */
    uip_len = response_length;
  } else {
    /* No response - MUST set to 0 */
    uip_len = 0;
  }
}
```

### 3. Check Message Validity

```c
void
process_icmp6_message(void)
{
  if(uip_len < uip_l2_l3_icmp_hdr_len + MIN_PAYLOAD_SIZE) {
    LOG_WARN("ICMPv6 message too short\n");
    uip_len = 0;
    return;
  }
  /* Process message */
}
```

### 4. Handle Echo Replies Properly

```c
static void
echo_reply_handler(uip_ipaddr_t *source, uint8_t ttl,
                   uint8_t *data, uint16_t datalen)
{
  /* Don't access uip_buf here - data pointer provides payload */
  /* Process data */

  /* Don't call uip_icmp6_send() from callback */
}
```

### 5. Use Appropriate Error Codes

```c
/* Choose specific error code */
if(no_route) {
  uip_icmp6_error_output(ICMP6_DST_UNREACH,
                          ICMP6_DST_UNREACH_NOROUTE, 0);
} else if(port_not_found) {
  uip_icmp6_error_output(ICMP6_DST_UNREACH,
                          ICMP6_DST_UNREACH_NOPORT, 0);
}
```

## Performance Considerations

### Memory Usage

- **ICMPv6 code**: ~2-3 KB ROM
- **Handler list**: ~20 bytes per registered handler
- **Echo reply callbacks**: ~12 bytes per callback

### Rate Limiting

ICMPv6 error messages are automatically rate-limited to prevent network flooding. The implementation follows RFC 4443 recommendations:
- Maximum 1 error per second per destination
- No errors in response to errors
- No errors for multicast packets

### Optimization Tips

1. **Disable unused handlers**:
   ```c
   /* Remove ND if using static configuration */
   #define UIP_CONF_ND6_SEND_NS 0
   #define UIP_CONF_ND6_SEND_NA 0
   ```

2. **Limit error generation** in forwarding path for performance

3. **Use UIP_ICMP6_HANDLER_CODE_ANY** to reduce handler count

## References

### RFCs and Standards
- [RFC 4443](https://tools.ietf.org/html/rfc4443) - ICMPv6 for IPv6
- [RFC 4884](https://tools.ietf.org/html/rfc4884) - Extended ICMP to Support Multi-Part Messages
- [RFC 4861](https://tools.ietf.org/html/rfc4861) - Neighbor Discovery (uses ICMPv6)
- [RFC 6550](https://tools.ietf.org/html/rfc6550) - RPL (uses ICMPv6)

### Implementation Documentation
- Source: `os/net/ipv6/uip-icmp6.c`, `os/net/ipv6/uip-icmp6.h`
- Examples: `examples/ipv6/ipv6-ping/`

### Related Documentation
- [IPv6 Core](IPv6-core.md)
- [IPv6 Neighbor Discovery](IPv6-neighbor-discovery.md)
- [RPL](RPL.md)
