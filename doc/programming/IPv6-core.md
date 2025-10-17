# IPv6 Core (uIP Stack)

## About

Contiki-NG includes uIP, a lightweight IPv6 stack designed for resource-constrained embedded devices. The uIP stack provides full IPv6 support including packet processing, address management, routing, and integration with upper-layer protocols (UDP, TCP, ICMPv6).

For detailed protocol specifications, see [RFC 8200](https://tools.ietf.org/html/rfc8200) (IPv6 Specification).

## Architecture

```
┌──────────────────────────────────────────────────────┐
│          Application Layer (CoAP, MQTT, etc.)         │
└─────────────────────┬────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────┐
│        Transport Layer (UDP/TCP) - tcpip.c           │
└─────────────────────┬────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────┐
│    Network Layer (IPv6 Core) - uip6.c                │
│  • Packet processing                                  │
│  • Address management (uip-ds6.c)                     │
│  • Neighbor Discovery (uip-nd6.c)                     │
│  • ICMPv6 (uip-icmp6.c)                               │
│  • Routing (uip-ds6-route.c)                          │
└─────────────────────┬────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────┐
│   Adaptation Layer (6LoWPAN) - sicslowpan.c          │
│  • Header compression (IPHC)                          │
│  • Fragmentation/reassembly                           │
└─────────────────────┬────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────┐
│        MAC Layer (CSMA, TSCH, etc.)                   │
└──────────────────────────────────────────────────────┘
```

### Key Components

| Component | Source File | Purpose |
|-----------|-------------|---------|
| **IPv6 Core** | `os/net/ipv6/uip6.c` | Main packet processing engine |
| **TCP/IP Interface** | `os/net/ipv6/tcpip.c` | Process-based interface to stack |
| **Data Structures** | `os/net/ipv6/uip-ds6.c` | IPv6 address/prefix/route management |
| **Neighbor Discovery** | `os/net/ipv6/uip-nd6.c` | ND protocol (RFC 4861) |
| **ICMPv6** | `os/net/ipv6/uip-icmp6.c` | ICMPv6 messages (RFC 4443) |
| **Routing** | `os/net/ipv6/uip-ds6-route.c` | Routing table management |
| **Neighbor Cache** | `os/net/ipv6/uip-ds6-nbr.c` | Neighbor cache management |
| **UDP** | `os/net/ipv6/uip-udp-packet.c` | UDP packet handling |
| **TCP** | `os/net/ipv6/tcp-socket.c` | TCP socket API |

## IPv6 Packet Buffer (uip_buf)

The core of uIP is the global packet buffer `uip_buf`, used for both incoming and outgoing packets.

### Buffer Structure

```c
/* Global packet buffer (defined in uip6.c) */
extern uint8_t uip_buf[UIP_BUFSIZE + 2];  /* +2 for 16-bit alignment */
extern uint16_t uip_len;                   /* Current packet length */

/* Buffer size */
#define UIP_BUFSIZE 1280  /* Default: IPv6 minimum MTU */
```

### Buffer Access Macros

```c
/* IPv6 header access */
#define UIP_IP_BUF  ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])

/* Protocol-specific header access */
#define UIP_ICMP_BUF    ((struct uip_icmp_hdr *)&uip_buf[uip_l2_l3_hdr_len])
#define UIP_UDP_BUF     ((struct uip_udp_hdr *)&uip_buf[uip_l2_l3_hdr_len])
#define UIP_TCP_BUF     ((struct uip_tcp_hdr *)&uip_buf[uip_l2_l3_hdr_len])

/* Payload access */
#define UIP_ICMP_PAYLOAD  ((unsigned char *)&uip_buf[uip_l2_l3_icmp_hdr_len])
#define UIP_UDP_PAYLOAD   ((unsigned char *)&uip_buf[uip_l2_l3_hdr_len + UIP_UDPH_LEN])
```

### Buffer Layout

```
┌──────────────┬──────────────┬──────────────┬────────────────┐
│ Link Layer   │ IPv6 Header  │ Next Header  │    Payload     │
│ Header (0-X) │   (40 bytes) │  (Variable)  │   (Variable)   │
└──────────────┴──────────────┴──────────────┴────────────────┘
 UIP_LLH_LEN    UIP_IPH_LEN                    uip_len
```

## Address Management (uip-ds6)

The `uip-ds6` module manages IPv6 addresses, prefixes, and related data structures.

### Address Types

| Type | Description | Configuration |
|------|-------------|---------------|
| **Link-Local** | fe80::/10 - local segment communication | Auto-configured from MAC |
| **Global** | 2000::/3 - Internet routable | From Router Advertisement or manual |
| **Multicast** | ff00::/8 - group communication | System and application-defined |
| **Anycast** | Same as unicast - nearest node | Router-specific |

### Configuration Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `UIP_CONF_BUFFER_SIZE` | 1280 | IPv6 packet buffer size (bytes) |
| `UIP_CONF_DS6_ADDR_NBU` | 2 | Number of unicast addresses per interface |
| `UIP_CONF_DS6_MADDR_NBU` | 0 | Number of additional multicast addresses |
| `UIP_CONF_DS6_PREFIX_NBU` | 2 | Number of prefixes |
| `UIP_CONF_DS6_DEFRT_NBU` | 2 | Number of default routers |
| `UIP_DS6_DEFAULT_PREFIX` | 0xfd00 | Default IPv6 prefix (ULA) |

### API Reference

#### Address Management

```c
/* Add/remove unicast address */
uip_ds6_addr_t *uip_ds6_addr_add(uip_ipaddr_t *ipaddr,
                                 unsigned long vlifetime, uint8_t type);
void uip_ds6_addr_rm(uip_ds6_addr_t *addr);

/* Lookup addresses */
uip_ds6_addr_t *uip_ds6_addr_lookup(uip_ipaddr_t *ipaddr);
uip_ds6_addr_t *uip_ds6_get_link_local(int8_t state);
uip_ds6_addr_t *uip_ds6_get_global(int8_t state);

/* Address states (RFC 4862) */
#define ADDR_TENTATIVE  0  /* Undergoing DAD */
#define ADDR_PREFERRED  1  /* Valid and preferred */
#define ADDR_DEPRECATED 2  /* Valid but deprecated */
```

#### Prefix Management

```c
/* Add/remove prefix */
uip_ds6_prefix_t *uip_ds6_prefix_add(uip_ipaddr_t *ipaddr, uint8_t length,
                                     unsigned long interval);
void uip_ds6_prefix_rm(uip_ds6_prefix_t *prefix);

/* Lookup prefix */
uip_ds6_prefix_t *uip_ds6_prefix_lookup(uip_ipaddr_t *ipaddr, uint8_t ipaddrlen);

/* Check if address is on-link */
uint8_t uip_ds6_is_addr_onlink(uip_ipaddr_t *ipaddr);

/* Get/set default prefix */
const uip_ip6addr_t *uip_ds6_default_prefix(void);
void uip_ds6_set_default_prefix(const uip_ip6addr_t *prefix);
```

#### Multicast Management

```c
/* Add/remove multicast address */
uip_ds6_maddr_t *uip_ds6_maddr_add(const uip_ipaddr_t *ipaddr);
void uip_ds6_maddr_rm(uip_ds6_maddr_t *maddr);
uip_ds6_maddr_t *uip_ds6_maddr_lookup(const uip_ipaddr_t *ipaddr);
```

#### Utility Functions

```c
/* Create IPv6 address from MAC address */
void uip_ds6_set_addr_iid(uip_ipaddr_t *ipaddr, const uip_lladdr_t *lladdr);

/* Extract MAC address from IPv6 address */
void uip_ds6_set_lladdr_from_iid(uip_lladdr_t *lladdr, const uip_ipaddr_t *ipaddr);

/* Source address selection (RFC 3484) */
void uip_ds6_select_src(uip_ipaddr_t *src, uip_ipaddr_t *dst);

/* Check if address belongs to this node */
#define uip_ds6_is_my_addr(addr)  (uip_ds6_addr_lookup(addr) != NULL)
#define uip_ds6_is_my_maddr(addr) (uip_ds6_maddr_lookup(addr) != NULL)
```

## TCP/IP Process Interface (tcpip.c)

Applications interact with the IPv6 stack through the `tcpip` process, which provides an event-driven interface.

### Events

| Event | Description |
|-------|-------------|
| `tcpip_event` | General TCP/IP event |
| `PROCESS_EVENT_POLL` | Polling request |

### API Functions

```c
/* Send UDP packet */
void tcpip_output(const uip_lladdr_t *lladdr);

/* Poll TCP/IP stack */
void tcpip_poll_udp(struct uip_udp_conn *conn);
void tcpip_poll_tcp(struct uip_conn *conn);

/* Input packet (from lower layers) */
void tcpip_input(void);
```

## Code Examples

### Setting Up IPv6 Address

```c
#include "net/ipv6/uip-ds6.h"

void
configure_ipv6_address(void)
{
  uip_ipaddr_t ipaddr;

  /* Get link-local address (auto-configured) */
  uip_ds6_addr_t *lladdr = uip_ds6_get_link_local(ADDR_PREFERRED);
  if(lladdr) {
    LOG_INFO("Link-local address: ");
    LOG_INFO_6ADDR(&lladdr->ipaddr);
    LOG_INFO_("\n");
  }

  /* Add global address manually: fd00::1 */
  uip_ip6addr(&ipaddr, 0xfd00, 0, 0, 0, 0, 0, 0, 0x0001);
  if(uip_ds6_addr_add(&ipaddr, 0, ADDR_MANUAL) == NULL) {
    LOG_ERR("Failed to add IPv6 address\n");
  } else {
    LOG_INFO("Added global address: ");
    LOG_INFO_6ADDR(&ipaddr);
    LOG_INFO_("\n");
  }
}
```

### Checking Address Availability

```c
#include "net/ipv6/uip-ds6.h"

bool
wait_for_global_address(void)
{
  /* Wait for global address to be configured */
  uip_ds6_addr_t *addr = uip_ds6_get_global(ADDR_PREFERRED);

  if(addr != NULL) {
    LOG_INFO("Global IPv6 address ready: ");
    LOG_INFO_6ADDR(&addr->ipaddr);
    LOG_INFO_("\n");
    return true;
  }

  LOG_INFO("Waiting for global IPv6 address...\n");
  return false;
}
```

### Listing All IPv6 Addresses

```c
void
print_ipv6_addresses(void)
{
  int i;
  uint8_t state;

  LOG_INFO("IPv6 addresses:\n");

  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      LOG_INFO("  ");
      LOG_INFO_6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
      LOG_INFO_(" - state: %s\n",
               state == ADDR_TENTATIVE ? "TENTATIVE" : "PREFERRED");
    }
  }
}
```

### Creating Multicast Address

```c
void
join_multicast_group(void)
{
  uip_ipaddr_t mcast_addr;

  /* Join multicast group ff02::1 (all nodes) */
  uip_create_linklocal_allnodes_mcast(&mcast_addr);

  if(uip_ds6_maddr_add(&mcast_addr) == NULL) {
    LOG_ERR("Failed to join multicast group\n");
  } else {
    LOG_INFO("Joined multicast group: ");
    LOG_INFO_6ADDR(&mcast_addr);
    LOG_INFO_("\n");
  }
}
```

### Simple UDP Server

```c
#include "net/ipv6/uip-ds6.h"
#include "net/ipv6/simple-udp.h"

static struct simple_udp_connection udp_conn;

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
  LOG_INFO_("\n");
}

PROCESS_THREAD(udp_server_process, ev, data)
{
  PROCESS_BEGIN();

  /* Wait for IPv6 address */
  PROCESS_WAIT_UNTIL(uip_ds6_get_global(ADDR_PREFERRED) != NULL);

  /* Register UDP connection on port 3000 */
  simple_udp_register(&udp_conn, 3000, NULL, 3000, udp_rx_callback);

  LOG_INFO("UDP server listening on port 3000\n");

  PROCESS_END();
}
```

## IPv6 Header Structure

```c
/* IPv6 header (40 bytes) - RFC 8200 */
struct uip_ip_hdr {
  uint8_t vtc;              /* Version (4 bits) + Traffic Class (8 bits) */
  uint8_t tcflow;           /* Traffic Class (4 bits) + Flow Label (4 bits) */
  uint16_t flow;            /* Flow Label (16 bits) */
  uint16_t len;             /* Payload Length */
  uint8_t proto, ttl;       /* Next Header, Hop Limit */
  uip_ip6addr_t srcipaddr;  /* Source Address (128 bits) */
  uip_ip6addr_t destipaddr; /* Destination Address (128 bits) */
};

/* IPv6 extension headers */
#define UIP_PROTO_HBHO     0  /* Hop-by-Hop Options */
#define UIP_PROTO_DESTO    60 /* Destination Options */
#define UIP_PROTO_ROUTING  43 /* Routing Header */
#define UIP_PROTO_FRAG     44 /* Fragment Header */
#define UIP_PROTO_NONE     59 /* No Next Header */

/* Common next headers */
#define UIP_PROTO_ICMP6    58 /* ICMPv6 */
#define UIP_PROTO_TCP      6  /* TCP */
#define UIP_PROTO_UDP      17 /* UDP */
```

## Configuration Options

### Buffer and Memory

```c
/* Buffer size - must be >= 1280 (IPv6 minimum MTU) */
#define UIP_CONF_BUFFER_SIZE 1280

/* Packet queue during address resolution */
#define UIP_CONF_IPV6_QUEUE_PKT 0

/* IPv6 consistency checks */
#define UIP_CONF_IPV6_CHECKS 1

/* Fragmentation reassembly */
#define UIP_CONF_IPV6_REASSEMBLY 0
```

### Address and Prefix Configuration

```c
/* Number of IPv6 addresses per interface */
#define UIP_CONF_DS6_ADDR_NBU 2

/* Number of prefixes */
#define UIP_CONF_DS6_PREFIX_NBU 2

/* Number of default routers */
#define UIP_CONF_DS6_DEFRT_NBU 2

/* Default prefix (ULA - Unique Local Address) */
#define UIP_DS6_DEFAULT_PREFIX 0xfd00  /* fd00::/8 */
```

### Protocol Configuration

```c
/* Enable UDP support */
#define UIP_CONF_UDP 1

/* Enable TCP support */
#define UIP_CONF_TCP 1

/* UDP connections */
#define UIP_CONF_UDP_CONNS 10

/* TCP connections */
#define UIP_CONF_TCP_CONNS 10

/* TCP listening ports */
#define UIP_CONF_MAX_LISTENPORTS 20
```

### Timing Parameters

```c
/* Hop limit (TTL) for outgoing packets */
#define UIP_CONF_TTL 64

/* TCP retransmission timeout */
#define UIP_RTO 3

/* Maximum TCP retransmissions */
#define UIP_MAXRTX 8

/* TIME_WAIT timeout (seconds) */
#define UIP_CONF_WAIT_TIMEOUT 120
```

## Packet Processing Flow

### Incoming Packets

```
1. MAC layer receives packet
   ↓
2. NETSTACK_NETWORK.input() called
   ↓
3. 6LoWPAN decompression (if applicable)
   ↓
4. uip_input() processes IPv6 header
   ↓
5. Check destination address
   ↓
6. Process extension headers
   ↓
7. Deliver to upper layer:
   - ICMPv6 → uip_icmp6_input()
   - UDP → uip_udp_packet_input()
   - TCP → uip_tcp_input()
   ↓
8. Application callback
```

### Outgoing Packets

```
1. Application calls udp_send() or tcp_send()
   ↓
2. Upper layer fills uip_buf
   ↓
3. uip_output() adds IPv6 header
   ↓
4. Source address selection
   ↓
5. Next-hop determination
   ↓
6. 6LoWPAN compression (if applicable)
   ↓
7. MAC layer transmission
```

## Troubleshooting

### Common Issues

#### 1. No Global IPv6 Address

**Symptoms:**
- Only link-local address (fe80::) available
- Cannot communicate beyond local link

**Solutions:**
```c
/* Check if router advertisements are being received */
#define UIP_CONF_ROUTER 0  /* Host mode - listen for RAs */

/* Or manually configure address */
uip_ipaddr_t ipaddr;
uip_ip6addr(&ipaddr, 0xfd00, 0, 0, 0, 0, 0, 0, 0x0001);
uip_ds6_addr_add(&ipaddr, 0, ADDR_MANUAL);
```

#### 2. Packet Buffer Too Small

**Symptoms:**
- Large packets dropped
- Fragmentation errors

**Solution:**
```c
/* Increase buffer size (must be >= 1280) */
#define UIP_CONF_BUFFER_SIZE 1500
```

#### 3. Address Table Full

**Symptoms:**
- Log: "Cannot add address"
- New addresses rejected

**Solution:**
```c
/* Increase address table size */
#define UIP_CONF_DS6_ADDR_NBU 4
```

#### 4. Routing Issues

**Symptoms:**
- Packets not reaching destination
- "No route to host" errors

**Check:**
```c
/* Enable IPv6 checks for debugging */
#define UIP_CONF_IPV6_CHECKS 1

/* Verify routing protocol is active */
MAKE_ROUTING = MAKE_ROUTING_RPL_LITE

/* Check default router */
void check_default_router(void) {
  uip_ds6_defrt_t *defrt = uip_ds6_defrt_head();
  if(defrt) {
    LOG_INFO("Default router: ");
    LOG_INFO_6ADDR(&defrt->ipaddr);
    LOG_INFO_("\n");
  } else {
    LOG_WARN("No default router\n");
  }
}
```

## Performance Considerations

### Memory Usage

**Per-interface (typical):**
- IPv6 stack code: ~15-20 KB ROM
- uip_buf: 1280 bytes RAM
- Address list: 3 addresses × ~30 bytes = ~90 bytes
- Prefix list: 3 prefixes × ~30 bytes = ~90 bytes
- Neighbor cache: Handled by nbr-table module

**Total: ~16-22 KB ROM, ~1.5 KB RAM (excluding application buffers)**

### Optimization Tips

1. **Reduce buffer size** for memory-constrained devices:
   ```c
   #define UIP_CONF_BUFFER_SIZE 1280  /* Minimum required */
   ```

2. **Limit connection tables**:
   ```c
   #define UIP_CONF_UDP_CONNS 4
   #define UIP_CONF_TCP_CONNS 2
   ```

3. **Disable unused protocols**:
   ```c
   #define UIP_CONF_TCP 0  /* Disable TCP if not needed */
   ```

4. **Use link-local addresses** when possible to avoid global address management overhead

## Best Practices

### 1. Always Wait for Address Configuration

```c
PROCESS_WAIT_UNTIL(uip_ds6_get_global(ADDR_PREFERRED) != NULL);
```

### 2. Use Link-Local for Local Communication

```c
/* More efficient than using global addresses */
uip_ds6_addr_t *lladdr = uip_ds6_get_link_local(ADDR_PREFERRED);
```

### 3. Check Address Validity Before Use

```c
if(uip_ds6_addr_lookup(&dest_addr) != NULL) {
  /* Address is valid */
}
```

### 4. Handle Address Lifetime

```c
/* Addresses can expire - periodically check */
uip_ds6_addr_t *addr = uip_ds6_get_global(ADDR_PREFERRED);
if(addr && addr->state == ADDR_DEPRECATED) {
  LOG_WARN("Address is deprecated\n");
}
```

### 5. Use Appropriate Prefix

```c
/* For local deployments, use ULA (Unique Local Address) */
#define UIP_DS6_DEFAULT_PREFIX 0xfd00  /* fd00::/8 */

/* For global connectivity, configure appropriate prefix */
```

## Integration with Other Modules

### With RPL Routing

```c
/* RPL automatically manages global addresses */
#include "net/routing/rpl-lite/rpl.h"

/* Wait for RPL to establish connectivity */
PROCESS_WAIT_UNTIL(rpl_is_reachable());
```

### With 6LoWPAN

```c
/* Enable IPHC compression */
#define SICSLOWPAN_CONF_COMPRESSION SICSLOWPAN_COMPRESSION_IPHC

/* Enable fragmentation for large packets */
#define SICSLOWPAN_CONF_FRAG 1
```

### With CoAP

```c
/* CoAP automatically uses IPv6 addresses from uip-ds6 */
#include "coap-engine.h"

/* Server listens on all configured addresses */
coap_activate_resource(&res_hello, "hello");
```

## References

### RFCs and Standards
- [RFC 8200](https://tools.ietf.org/html/rfc8200) - IPv6 Specification
- [RFC 4291](https://tools.ietf.org/html/rfc4291) - IPv6 Addressing Architecture
- [RFC 4862](https://tools.ietf.org/html/rfc4862) - IPv6 Stateless Address Autoconfiguration
- [RFC 4443](https://tools.ietf.org/html/rfc4443) - ICMPv6 for IPv6
- [RFC 4861](https://tools.ietf.org/html/rfc4861) - Neighbor Discovery for IPv6
- [RFC 6282](https://tools.ietf.org/html/rfc6282) - 6LoWPAN Header Compression

### Implementation Documentation
- IPv6 source: `os/net/ipv6/`
- uIP documentation: `doc/programming/Packet-buffers.md`
- Related: [ICMPv6](ICMPv6.md), [Neighbor Discovery](IPv6-neighbor-discovery.md)

### Related Modules
- [RPL Routing](RPL.md)
- [6LoWPAN and Fragmentation](6LoWPAN.md)
- [TSCH and 6TiSCH](TSCH-and-6TiSCH.md)
