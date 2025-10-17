# IPv6 Neighbor Discovery

## About

IPv6 Neighbor Discovery (ND) is a core IPv6 protocol that replaces ARP, ICMP router discovery, and ICMP redirect from IPv4. It provides address resolution, neighbor reachability detection, duplicate address detection, router discovery, and prefix discovery.

In Contiki-NG, ND is implemented in the `uip-nd6` module and integrates with the neighbor cache (`uip-ds6-nbr`) and routing (`uip-ds6-route`).

For detailed protocol specifications, see [RFC 4861](https://tools.ietf.org/html/rfc4861) (Neighbor Discovery for IPv6) and [RFC 6775](https://tools.ietf.org/html/rfc6775) (Neighbor Discovery Optimization for 6LoWPAN).

## Architecture

```
┌──────────────────────────────────────────────────────┐
│           Applications & Upper Layers                 │
└────────────────┬─────────────────────────────────────┘
                 │
┌────────────────▼─────────────────────────────────────┐
│        Neighbor Discovery (uip-nd6.c)                │
│  • Router Discovery (RS/RA)                           │
│  • Address Resolution (NS/NA)                         │
│  • Neighbor Unreachability Detection (NUD)            │
│  • Duplicate Address Detection (DAD)                  │
│  • Redirect handling                                  │
└────────────────┬─────────────────────────────────────┘
                 │
┌────────────────▼─────────────────────────────────────┐
│         Neighbor Cache (uip-ds6-nbr.c)               │
│  • Neighbor table                                     │
│  • Reachability state                                 │
│  • Link-layer address mapping                         │
└────────────────┬─────────────────────────────────────┘
                 │
┌────────────────▼─────────────────────────────────────┐
│      ICMPv6 Layer (Type 133-137 messages)            │
└──────────────────────────────────────────────────────┘
```

## Neighbor Discovery Messages

Neighbor Discovery uses five ICMPv6 message types:

| Message | Type | Direction | Purpose |
|---------|------|-----------|---------|
| **Router Solicitation (RS)** | 133 | Host → Multicast | Request router information |
| **Router Advertisement (RA)** | 134 | Router → Multicast/Unicast | Advertise router presence, prefixes, parameters |
| **Neighbor Solicitation (NS)** | 135 | Node → Multicast/Unicast | Address resolution, NUD, DAD |
| **Neighbor Advertisement (NA)** | 136 | Node → Unicast/Multicast | Response to NS, unsolicited announcement |
| **Redirect** | 137 | Router → Host | Better next-hop notification |

### Message Options

| Option | Code | Used In | Purpose |
|--------|------|---------|---------|
| **Source Link-Layer Address (SLLAO)** | 1 | RS, NS, RA | Sender's link-layer address |
| **Target Link-Layer Address (TLLAO)** | 2 | NA, Redirect | Target's link-layer address |
| **Prefix Information** | 3 | RA | IPv6 prefix configuration |
| **Redirected Header** | 4 | Redirect | Original packet header |
| **MTU** | 5 | RA | Link MTU |
| **RDNSS** | 25 | RA | Recursive DNS servers (RFC 6106) |

## Key Functions

### Router Solicitation

```c
/**
 * Send Router Solicitation (host → router)
 * Solicits Router Advertisements to quickly configure address
 */
void uip_nd6_rs_output(void);
```

**When to use:**
- Node boot-up to quickly discover routers
- After losing all default routers
- Periodic solicitation if no RA received

**Example:**
```c
/* Send RS to discover routers */
uip_nd6_rs_output();
LOG_INFO("Sent Router Solicitation\n");
```

### Router Advertisement

```c
#if UIP_CONF_ROUTER
/**
 * Send Router Advertisement (router → hosts)
 * \param dest Destination address (NULL for multicast)
 *
 * Advertises router presence, prefixes, and configuration
 */
void uip_nd6_ra_output(const uip_ipaddr_t *dest);
#endif
```

**When to use:**
- Periodic advertisements (every 200-600 seconds)
- Response to Router Solicitation
- Network configuration changes

**Example:**
```c
#if UIP_CONF_ROUTER
/* Send RA in response to RS */
uip_nd6_ra_output(NULL);  /* NULL = multicast */
LOG_INFO("Sent Router Advertisement\n");
#endif
```

### Neighbor Solicitation

```c
/**
 * Send Neighbor Solicitation
 * \param src Source address (NULL for automatic selection)
 * \param dest Destination (NULL for multicast, unicast for NUD)
 * \param tgt Target address being resolved
 *
 * Used for:
 * - Address Resolution: dest=NULL, resolve tgt link-layer address
 * - NUD: dest=unicast, verify tgt is still reachable
 * - DAD: src=NULL, check if tgt is already in use
 */
void uip_nd6_ns_output(const uip_ipaddr_t *src,
                       const uip_ipaddr_t *dest,
                       uip_ipaddr_t *tgt);
```

**Example - Address Resolution:**
```c
/* Resolve link-layer address for destination */
uip_ipaddr_t target;
/* ... set target ... */
uip_nd6_ns_output(NULL, NULL, &target);
LOG_INFO("Sent NS for address resolution\n");
```

**Example - Neighbor Unreachability Detection:**
```c
/* Verify neighbor is still reachable */
uip_ipaddr_t *neighbor_addr = &nbr->ipaddr;
uip_nd6_ns_output(NULL, neighbor_addr, neighbor_addr);
LOG_INFO("Sent NS for NUD\n");
```

### Neighbor Advertisement

Neighbor Advertisements are sent automatically in response to NS or can be sent unsolicited.

## Neighbor Cache Management

The neighbor cache stores information about nodes on the same link.

### Neighbor States

```c
/* Neighbor reachability states (RFC 4861) */
#define NBR_INCOMPLETE  0  /* Address resolution in progress */
#define NBR_REACHABLE   1  /* Reachability confirmed */
#define NBR_STALE       2  /* No recent confirmation */
#define NBR_DELAY       3  /* Waiting for upper-layer confirmation */
#define NBR_PROBE       4  /* Actively probing reachability */
```

### State Transitions

```
          [Address Resolution Needed]
                     ↓
              INCOMPLETE ←──────────────┐
                     ↓ (NA received)    │ (No NA)
              REACHABLE ←─────────┐     │
                     ↓ (timeout)  │     │
                 STALE             │     │
                     ↓ (traffic)  │     │
                 DELAY             │     │
                     ↓ (timeout)  │     │
                 PROBE             │     │
                     │ (NA recv'd)│     │
                     └─────────────┘     │
                     ↓ (max probes sent) │
                 [Neighbor Deleted] ─────┘
```

### Neighbor Table APIs

```c
/* Defined in uip-ds6-nbr.h */

/**
 * Add neighbor to cache
 * \param ipaddr IPv6 address
 * \param lladdr Link-layer address (can be NULL)
 * \param isrouter 1 if neighbor is a router
 * \param state Initial state
 * \return Pointer to neighbor entry, NULL on failure
 */
uip_ds6_nbr_t *uip_ds6_nbr_add(const uip_ipaddr_t *ipaddr,
                                const uip_lladdr_t *lladdr,
                                uint8_t isrouter, uint8_t state);

/**
 * Remove neighbor from cache
 * \param nbr Neighbor to remove
 */
void uip_ds6_nbr_rm(uip_ds6_nbr_t *nbr);

/**
 * Lookup neighbor by IPv6 address
 * \param ipaddr IPv6 address
 * \return Pointer to neighbor entry, NULL if not found
 */
uip_ds6_nbr_t *uip_ds6_nbr_lookup(const uip_ipaddr_t *ipaddr);

/**
 * Lookup neighbor by link-layer address
 * \param lladdr Link-layer address
 * \return Pointer to neighbor entry, NULL if not found
 */
uip_ds6_nbr_t *uip_ds6_nbr_ll_lookup(const uip_lladdr_t *lladdr);

/**
 * Get number of neighbors in cache
 * \return Number of neighbors
 */
int uip_ds6_nbr_num(void);
```

## Configuration Parameters

### Router Discovery (Host Mode)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `UIP_CONF_ND6_MAX_RTR_SOLICITATION_DELAY` | 1 sec | Max initial RS delay |
| `UIP_CONF_ND6_RTR_SOLICITATION_INTERVAL` | 4 sec | Interval between RS |
| `UIP_CONF_ND6_MAX_RTR_SOLICITATIONS` | 3 | Max RS transmissions |

### Router Advertisement (Router Mode)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `UIP_CONF_ND6_SEND_RA` | 1 | Enable/disable RA sending |
| `UIP_CONF_ND6_MAX_RA_INTERVAL` | 600 sec | Maximum interval between RAs |
| `UIP_CONF_ND6_MIN_RA_INTERVAL` | 200 sec | Minimum interval between RAs (MAX/3) |
| `UIP_CONF_ROUTER_LIFETIME` | 1800 sec | Router lifetime in RA (3 × MAX_RA_INTERVAL) |
| `UIP_CONF_ND6_MIN_DELAY_BETWEEN_RAS` | 3 sec | Min delay between any two RAs |

### Neighbor Discovery

| Parameter | Default | Description |
|-----------|---------|-------------|
| `UIP_CONF_ND6_SEND_NS` | 1 | Enable/disable NS sending |
| `UIP_CONF_ND6_SEND_NA` | 1 | Enable/disable NA sending |
| `UIP_CONF_ND6_MAX_MULTICAST_SOLICIT` | 3 | Max multicast NS for address resolution |
| `UIP_CONF_ND6_MAX_UNICAST_SOLICIT` | 3 | Max unicast NS for NUD |
| `UIP_CONF_ND6_REACHABLE_TIME` | 60000 ms | Time neighbor considered reachable |
| `UIP_CONF_ND6_RETRANS_TIMER` | 1000 ms | Time between NS retransmissions |

### Duplicate Address Detection

| Parameter | Default | Description |
|-----------|---------|-------------|
| `UIP_CONF_ND6_DEF_MAXDADNS` | 0 (802.15.4), 1 (other) | Max DAD NS transmissions |
| `UIP_ND6_DELAY_FIRST_PROBE_TIME` | 5 sec | Delay before first probe |

### Special Features

| Parameter | Default | Description |
|-----------|---------|-------------|
| `UIP_CONF_ND6_AUTOFILL_NBR_CACHE` | 0 | Auto-derive link-layer from IPv6 (non-standard) |
| `UIP_CONF_ND6_RA_RDNSS` | 0 | Include DNS servers in RA |
| `UIP_CONF_DS6_LL_NUD` | 0 | Use link-layer ACKs for NUD |

## Code Examples

### Host: Discovering Routers

```c
#include "net/ipv6/uip-ds6.h"
#include "net/ipv6/uip-nd6.h"

PROCESS_THREAD(host_process, ev, data)
{
  static struct etimer timer;

  PROCESS_BEGIN();

  /* Send initial Router Solicitation */
  uip_nd6_rs_output();
  LOG_INFO("Sent Router Solicitation\n");

  /* Wait for Router Advertisement and global address */
  etimer_set(&timer, 10 * CLOCK_SECOND);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer) ||
                            uip_ds6_get_global(ADDR_PREFERRED) != NULL);

  if(uip_ds6_get_global(ADDR_PREFERRED) != NULL) {
    LOG_INFO("Got global address from Router Advertisement\n");
  } else {
    LOG_WARN("No Router Advertisement received\n");
    /* Retry RS */
    uip_nd6_rs_output();
  }

  PROCESS_END();
}
```

### Router: Sending Advertisements

```c
#if UIP_CONF_ROUTER
#include "net/ipv6/uip-ds6.h"
#include "net/ipv6/uip-nd6.h"

static void
configure_router(void)
{
  uip_ipaddr_t ipaddr, prefix;

  /* Set router's global address */
  uip_ip6addr(&ipaddr, 0xfd00, 0, 0, 0, 0, 0, 0, 0x0001);
  uip_ds6_addr_add(&ipaddr, 0, ADDR_MANUAL);

  /* Configure prefix to advertise */
  uip_ip6addr(&prefix, 0xfd00, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_prefix_add(&prefix, 64, 1,  /* advertise=1 */
                      UIP_ND6_RA_FLAG_ONLINK | UIP_ND6_RA_FLAG_AUTONOMOUS,
                      UIP_ND6_INFINITE_LIFETIME,
                      UIP_ND6_INFINITE_LIFETIME);

  LOG_INFO("Router configured, sending RA\n");

  /* Send initial RA */
  uip_nd6_ra_output(NULL);
}

/* Periodic RA sending handled automatically by uip-ds6 */
#endif
```

### Checking Neighbor Reachability

```c
#include "net/ipv6/uip-ds6-nbr.h"

void
check_neighbor_status(const uip_ipaddr_t *ipaddr)
{
  uip_ds6_nbr_t *nbr;

  nbr = uip_ds6_nbr_lookup(ipaddr);

  if(nbr == NULL) {
    LOG_INFO("Neighbor not in cache\n");
    return;
  }

  LOG_INFO("Neighbor ");
  LOG_INFO_6ADDR(ipaddr);

  switch(uip_ds6_nbr_get_state(nbr)) {
  case NBR_INCOMPLETE:
    LOG_INFO_(" state: INCOMPLETE (resolving)\n");
    break;
  case NBR_REACHABLE:
    LOG_INFO_(" state: REACHABLE\n");
    break;
  case NBR_STALE:
    LOG_INFO_(" state: STALE (needs verification)\n");
    break;
  case NBR_DELAY:
    LOG_INFO_(" state: DELAY (waiting for confirmation)\n");
    break;
  case NBR_PROBE:
    LOG_INFO_(" state: PROBE (actively probing)\n");
    break;
  }

  /* Get link-layer address */
  const uip_lladdr_t *lladdr = uip_ds6_nbr_get_ll(nbr);
  LOG_INFO("  Link-layer address: ");
  LOG_INFO_LLADDR(lladdr);
  LOG_INFO_("\n");
}
```

### Listing All Neighbors

```c
void
print_neighbor_cache(void)
{
  uip_ds6_nbr_t *nbr;
  int count = 0;

  LOG_INFO("Neighbor Cache:\n");

  nbr = nbr_table_head(ds6_neighbors);
  while(nbr != NULL) {
    count++;
    LOG_INFO("  %d. ", count);
    LOG_INFO_6ADDR(uip_ds6_nbr_get_ipaddr(nbr));
    LOG_INFO_(" → ");
    LOG_INFO_LLADDR(uip_ds6_nbr_get_ll(nbr));
    LOG_INFO_(" [%s]\n",
             uip_ds6_nbr_get_state(nbr) == NBR_REACHABLE ? "REACHABLE" :
             uip_ds6_nbr_get_state(nbr) == NBR_STALE ? "STALE" :
             uip_ds6_nbr_get_state(nbr) == NBR_PROBE ? "PROBE" : "OTHER");
    nbr = nbr_table_next(ds6_neighbors, nbr);
  }

  if(count == 0) {
    LOG_INFO("  (empty)\n");
  }
}
```

### Manual Neighbor Entry

```c
void
add_static_neighbor(void)
{
  uip_ipaddr_t ipaddr;
  uip_lladdr_t lladdr;

  /* Neighbor IPv6 address */
  uip_ip6addr(&ipaddr, 0xfe80, 0, 0, 0, 0x0212, 0x4b00, 0x0123, 0x4567);

  /* Neighbor link-layer address (802.15.4 example) */
  lladdr.addr[0] = 0x00;
  lladdr.addr[1] = 0x12;
  lladdr.addr[2] = 0x4b;
  lladdr.addr[3] = 0x00;
  lladdr.addr[4] = 0x01;
  lladdr.addr[5] = 0x23;
  lladdr.addr[6] = 0x45;
  lladdr.addr[7] = 0x67;

  /* Add to neighbor cache as REACHABLE */
  if(uip_ds6_nbr_add(&ipaddr, &lladdr, 0, NBR_REACHABLE) == NULL) {
    LOG_ERR("Failed to add static neighbor\n");
  } else {
    LOG_INFO("Added static neighbor\n");
  }
}
```

### Detecting Link-Layer Address Changes

```c
void
handle_lladdr_change(const uip_ipaddr_t *ipaddr, const uip_lladdr_t *new_lladdr)
{
  uip_ds6_nbr_t *nbr;

  nbr = uip_ds6_nbr_lookup(ipaddr);

  if(nbr != NULL) {
    /* Update link-layer address */
    uip_ds6_nbr_t *updated = uip_ds6_nbr_add(ipaddr, new_lladdr, 0, NBR_STALE);

    if(updated) {
      LOG_INFO("Updated neighbor link-layer address\n");
    }
  }
}
```

## Special Cases

### 6LoWPAN Optimizations (RFC 6775)

For 6LoWPAN networks, several ND optimizations are available:

**Address Registration:**
- Nodes register with border router using NS/NA
- Reduces multicast overhead
- Explicit registration confirmation

**Duplicate Address Detection:**
- Typically disabled for 802.15.4 when using EUI-64
- `UIP_ND6_DEF_MAXDADNS = 0` (default for 802.15.4)

**Configuration:**
```c
/* Disable DAD for 802.15.4 */
#define UIP_CONF_ND6_DEF_MAXDADNS 0

/* Enable address registration */
#define UIP_CONF_ND6_SEND_NS 1
#define UIP_CONF_ND6_SEND_NA 1
```

### Link-Layer Address Autofill

Non-standard feature to auto-derive link-layer address from IPv6 address:

```c
/* Enable autofill (avoid ND overhead) */
#define UIP_CONF_ND6_AUTOFILL_NBR_CACHE 1
```

**Caution:** This violates RFC 4861 and assumes:
- All nodes use EUI-64 for IPv6 address
- Link-layer address can be derived from IPv6 IID
- No address privacy (RFC 4941)

### Using Link-Layer ACKs for NUD

In 802.15.4 with ACKs, use link-layer feedback for faster NUD:

```c
/* Use link-layer ACKs for reachability confirmation */
#define UIP_CONF_DS6_LL_NUD 1
```

**Benefits:**
- Faster detection of unreachable neighbors
- Reduced ICMPv6 overhead
- Works well with TSCH

## Troubleshooting

### Common Issues

#### 1. No Router Advertisements Received

**Symptoms:**
- Node stuck with only link-local address
- Repeated Router Solicitations

**Check:**
```c
/* Verify RS is being sent */
#define UIP_CONF_ND6_SEND_NS 1

/* Check router is configured to send RA */
#define UIP_CONF_ROUTER 1
#define UIP_CONF_ND6_SEND_RA 1

/* Enable debug logging */
#define LOG_CONF_LEVEL_ND6 LOG_LEVEL_DBG
```

#### 2. Address Resolution Failures

**Symptoms:**
- Cannot communicate with neighbors
- INCOMPLETE state neighbors

**Solutions:**
```c
/* Increase solicitation attempts */
#define UIP_CONF_ND6_MAX_MULTICAST_SOLICIT 5

/* Check neighbor is responding to NS */
/* Verify link-layer connectivity */
```

#### 3. Neighbor Cache Full

**Symptoms:**
- Log: "Neighbor cache full"
- Cannot add new neighbors

**Solution:**
```c
/* Increase neighbor table size (in nbr-table.h) */
#define NBR_TABLE_CONF_MAX_NEIGHBORS 20
```

#### 4. Stale Neighbors Not Updated

**Symptoms:**
- Neighbors stuck in STALE state
- Communication works but state not updated

**This is normal:** STALE state is valid for communication. NUD will run when needed.

#### 5. DAD Failures

**Symptoms:**
- Address remains in TENTATIVE state
- Duplicate address detected

**Check:**
```c
/* Verify DAD is enabled if needed */
#define UIP_CONF_ND6_DEF_MAXDADNS 1

/* Check for actual duplicate */
/* Another node may be using the same address */
```

## Performance Considerations

### Memory Usage

**Per neighbor:**
- Neighbor entry: ~40-50 bytes
- Includes IPv6 address, link-layer address, state, timers

**Code size:**
- ND implementation: ~4-6 KB ROM

**Configuration impact:**
```c
/* Minimal (host only, no DAD) */
#define UIP_CONF_ND6_DEF_MAXDADNS 0
#define UIP_CONF_ROUTER 0
/* ~4 KB ROM */

/* Full (router with DAD) */
#define UIP_CONF_ND6_DEF_MAXDADNS 1
#define UIP_CONF_ROUTER 1
#define UIP_CONF_ND6_SEND_RA 1
/* ~6 KB ROM */
```

### Optimization Tips

1. **Disable DAD** for 802.15.4 networks (EUI-64 addresses):
   ```c
   #define UIP_CONF_ND6_DEF_MAXDADNS 0
   ```

2. **Use link-layer ACKs** for NUD when available:
   ```c
   #define UIP_CONF_DS6_LL_NUD 1
   ```

3. **Reduce retransmission timers** for faster resolution:
   ```c
   #define UIP_CONF_ND6_RETRANS_TIMER 500  /* 500ms instead of 1000ms */
   ```

4. **Static neighbor entries** for known nodes:
   ```c
   /* Add at boot - avoid ND overhead */
   uip_ds6_nbr_add(&known_nbr_addr, &known_lladdr, 0, NBR_REACHABLE);
   ```

## Best Practices

### 1. Configure ND Based on Node Role

**Host:**
```c
#define UIP_CONF_ROUTER 0
#define UIP_CONF_ND6_SEND_NS 1
#define UIP_CONF_ND6_SEND_NA 1
```

**Router:**
```c
#define UIP_CONF_ROUTER 1
#define UIP_CONF_ND6_SEND_RA 1
#define UIP_CONF_ND6_SEND_NS 1
#define UIP_CONF_ND6_SEND_NA 1
```

### 2. Wait for Address Configuration

```c
/* Always wait for address before communication */
PROCESS_WAIT_UNTIL(uip_ds6_get_global(ADDR_PREFERRED) != NULL);
```

### 3. Monitor Neighbor Cache Size

```c
void check_cache_usage(void) {
  int num = uip_ds6_nbr_num();
  if(num > (NBR_TABLE_MAX_NEIGHBORS * 0.8)) {
    LOG_WARN("Neighbor cache nearly full: %d/%d\n",
             num, NBR_TABLE_MAX_NEIGHBORS);
  }
}
```

### 4. Handle Router Lifetime

```c
/* Check if default router is still valid */
uip_ds6_defrt_t *dr = uip_ds6_defrt_head();
if(dr && dr->lifetime.start + dr->lifetime.interval < clock_seconds()) {
  LOG_WARN("Default router expired\n");
  /* Send RS to discover new router */
  uip_nd6_rs_output();
}
```

### 5. Use Appropriate Timers for Network Type

**Low-power 802.15.4:**
```c
#define UIP_CONF_ND6_REACHABLE_TIME 120000  /* 2 minutes */
#define UIP_CONF_ND6_RETRANS_TIMER 2000     /* 2 seconds */
```

**Good connectivity:**
```c
#define UIP_CONF_ND6_REACHABLE_TIME 30000   /* 30 seconds */
#define UIP_CONF_ND6_RETRANS_TIMER 1000     /* 1 second */
```

## Integration with Other Protocols

### With RPL

RPL builds on top of ND for routing:
- Uses ND for neighbor cache
- ND provides link-local communication
- RPL manages routing beyond link-local

```c
#include "net/routing/rpl-lite/rpl.h"
/* ND automatically integrated */
```

### With TSCH

TSCH provides reliable link layer, enabling optimizations:
```c
/* Use link-layer ACKs for NUD */
#define UIP_CONF_DS6_LL_NUD 1

/* Longer reachable time (reliable links) */
#define UIP_CONF_ND6_REACHABLE_TIME 180000  /* 3 minutes */
```

### With 6LoWPAN

6LoWPAN compresses ND messages:
- SLLAO/TLLAO compressed when derivable
- Context-based compression
- See [RFC 6282](https://tools.ietf.org/html/rfc6282)

## References

### RFCs and Standards
- [RFC 4861](https://tools.ietf.org/html/rfc4861) - Neighbor Discovery for IPv6
- [RFC 4862](https://tools.ietf.org/html/rfc4862) - IPv6 Stateless Address Autoconfiguration (SLAAC)
- [RFC 6775](https://tools.ietf.org/html/rfc6775) - Neighbor Discovery Optimization for 6LoWPAN
- [RFC 6106](https://tools.ietf.org/html/rfc6106) - DNS Configuration in RA
- [RFC 4443](https://tools.ietf.org/html/rfc4443) - ICMPv6 (ND uses ICMPv6)

### Implementation Documentation
- Source: `os/net/ipv6/uip-nd6.c`, `os/net/ipv6/uip-ds6-nbr.c`
- Headers: `os/net/ipv6/uip-nd6.h`, `os/net/ipv6/uip-ds6-nbr.h`

### Related Documentation
- [IPv6 Core](IPv6-core.md)
- [ICMPv6](ICMPv6.md)
- [RPL](RPL.md)
- [TSCH and 6TiSCH](TSCH-and-6TiSCH.md)
