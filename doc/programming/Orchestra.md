# Orchestra

## Overview

Orchestra is an autonomous scheduling solution for TSCH (Time Slotted Channel Hopping) networks that eliminates the need for centralized schedulers or neighbor negotiation. Nodes autonomously compute their own schedules based solely on their local RPL routing state, resulting in zero scheduling overhead while maintaining low contention.

**Key benefits:**
- **Zero overhead**: No schedule negotiation messages, no centralized scheduler
- **Autonomous**: Each node computes its schedule independently using local RPL state
- **Scalable**: Works in networks of any size without modification
- **Collision-resistant**: Hash-based timeslot assignment minimizes contention
- **Out-of-box ready**: Default rules work in any RPL network

Orchestra is described and evaluated in [*Orchestra: Robust Mesh Networks Through Autonomously Scheduled TSCH*](http://www.simonduquennoy.net/papers/duquennoy15orchestra.pdf), ACM SenSys'15.

## Requirements

Orchestra requires:
- **TSCH MAC layer**: IEEE 802.15.4-2015 Time Slotted Channel Hopping
- **RPL routing**: Either RPL-Lite (non-storing mode) or RPL-Classic (storing or non-storing)
- **IPv6 networking**: Full Contiki-NG network stack

## How Orchestra Works

### Autonomous Scheduling Principle

Traditional TSCH schedulers require either:
1. **Centralized control**: A network coordinator computes and distributes schedules
2. **Negotiation**: Nodes exchange messages to agree on timeslots (e.g., 6P protocol)

Orchestra takes a radically different approach: **each node independently computes the same schedule** using globally known information (the RPL topology). Since all nodes use the same hash functions and know the RPL DAG structure, they arrive at identical schedules without any communication.

### Slotframes and Rules

Orchestra organizes time into **slotframes**—repeating sequences of timeslots. Each slotframe serves a specific traffic type:

```
Slotframe 0 (EB):         [0][1][2]...[396]  (period 397, for beacons)
Slotframe 1 (Unicast):    [0][1][2]...[16]   (period 17, for unicast)
Slotframe 2 (Common):     [0][1][2]...[30]   (period 31, for broadcast/fallback)
```

Each slotframe is governed by an **Orchestra rule** that determines:
- When a node should transmit (TX timeslot)
- When a node should listen (RX timeslot)
- Which packets use this slotframe

### Timeslot Assignment

Orchestra uses **hash functions** to map node addresses to timeslots:

```c
/* Node A transmits in timeslot = hash(A) % slotframe_period */
timeslot = hash(node_address) % slotframe_size;
```

For unicast traffic, the receiver-based approach means:
- **Sender**: Transmits in timeslot = `hash(receiver_address) % period`
- **Receiver**: Listens in timeslot = `hash(own_address) % period`

This ensures that when node A wants to send to node B:
1. A knows to transmit in B's timeslot
2. B is listening in its own timeslot
3. No coordination needed—both compute the same timeslot independently

### Example Network

Consider a simple network:
```
     [Root]
        |
      [A:42]
       / \
   [B:17] [C:99]
```

With a unicast period of 17 and hash(addr) = last_byte % 17:
- Node A listens in slot: 42 % 17 = 8
- Node B listens in slot: 17 % 17 = 0
- Node C listens in slot: 99 % 17 = 14

When A wants to send to the root, it transmits in the root's timeslot.
When the root wants to send to A, it transmits in slot 8 (A's timeslot).

## Orchestra Rules

Orchestra comes with 6 pre-built rules that can be combined to handle different traffic types and network configurations.

### Rule Reference

#### 1. EB Per Time Source (`eb_per_time_source`)

**Purpose**: Handles Enhanced Beacon (EB) transmission for network advertisements and synchronization.

**How it works:**
- Each node transmits EBs in timeslot = `hash(own_address) % EBSF_PERIOD`
- Each node listens for EBs in timeslot = `hash(time_source_address) % EBSF_PERIOD`
- Nodes follow their RPL parent's time synchronization

**Slotframe size**: 397 (default)

**Use case**: Should be included in virtually all Orchestra configurations to handle network formation and time synchronization.

**Configuration options:**
```c
/* Slotframe period for EB transmission */
#define ORCHESTRA_CONF_EBSF_PERIOD 397

/* Channel offset range for EB slots */
#define ORCHESTRA_CONF_EB_MIN_CHANNEL_OFFSET 1
#define ORCHESTRA_CONF_EB_MAX_CHANNEL_OFFSET 1
```

#### 2. Unicast Per Neighbor RPL Non-Storing (`unicast_per_neighbor_rpl_ns`)

**Purpose**: Handles unicast traffic in RPL non-storing mode (source routing).

**How it works:**
- **Receiver-based**: Each node listens in timeslot = `hash(own_address) % UNICAST_PERIOD`
- Senders transmit in the receiver's timeslot
- Dedicated RX/TX links for RPL parent and all children
- Works with source routing (RPL non-storing mode)

**Slotframe size**: 17 (default)

**Use case**: Default choice for RPL-Lite (non-storing mode) networks.

**When to use:**
- RPL non-storing mode (RPL-Lite default)
- Networks where root has sufficient memory for source routes
- Typically better for smaller networks (< 100 nodes)

#### 3. Unicast Per Neighbor RPL Storing (`unicast_per_neighbor_rpl_storing`)

**Purpose**: Handles unicast traffic in RPL storing mode.

**How it works:**
- Creates dedicated links to RPL parent and RPL children (from routing table)
- Can be sender-based or receiver-based (controlled by `ORCHESTRA_UNICAST_SENDER_BASED`)
- Uses DAO messages to track children

**Slotframe size**: 17 (default)

**Use case**: For RPL storing mode networks where nodes maintain routing tables.

**When to use:**
- RPL storing mode (RPL-Classic)
- Networks where distributing routing state is preferred
- Larger networks where root can't maintain all source routes

**Configuration:**
```c
/* Use sender-based (1) or receiver-based (0) scheduling */
#define ORCHESTRA_CONF_UNICAST_SENDER_BASED 0
```

**Note**: Sender-based only works with storing mode because it requires DAO messages to know children.

#### 4. Unicast Link-Based (`unicast_per_neighbor_link_based`)

**Purpose**: Creates unicast links based on link-layer information rather than RPL topology.

**How it works:**
- Uses pair-wise hash: `hash2(sender, receiver)` for timeslot assignment
- Creates dedicated links for any link-layer neighbor
- Independent of RPL topology

**Slotframe size**: 17 (default)

**Use case**: For non-RPL traffic or when you want schedules independent of routing topology.

**When to use:**
- Applications with significant non-RPL traffic
- Mesh networks with dynamic, non-tree topologies
- When you need schedules that persist across RPL re-convergence

#### 5. Special for Root (`special_for_root`)

**Purpose**: Provides additional capacity for the root node, which handles more traffic than other nodes.

**How it works:**
- Creates a dedicated slotframe with a shorter period for root communication
- Non-root nodes add TX slots to communicate with root
- Root adds RX slots to receive from any node

**Slotframe size**: 7 (default, shorter than regular unicast)

**Use case**: Include when the root node is a bottleneck.

**When to use:**
- Networks with significant root-directed traffic (data collection)
- Border router scenarios where root handles all external traffic
- Networks where root also performs intensive processing

**Configuration:**
```c
/* Shorter period = more capacity for root */
#define ORCHESTRA_CONF_ROOT_PERIOD 7
```

#### 6. Default Common (`default_common`)

**Purpose**: Provides a shared slotframe for broadcast traffic and unicast to nodes without dedicated links.

**How it works:**
- Single shared timeslot that all nodes can transmit/receive on
- Uses CSMA-like contention resolution
- Serves as fallback for any traffic not handled by other rules

**Slotframe size**: 31 (default)

**Use case**: Should be included in all Orchestra configurations as a fallback mechanism.

**When to use:** Always include as the last rule.

**Configuration:**
```c
/* Period for shared slotframe */
#define ORCHESTRA_CONF_COMMON_SHARED_PERIOD 31

/* Channel offset for shared slot */
#define ORCHESTRA_CONF_DEFAULT_COMMON_CHANNEL_OFFSET 0
```

## Configuration Reference

### Rule Set Selection

Define which rules to use in your `project-conf.h`:

```c
/* Default configuration for RPL non-storing mode */
#define ORCHESTRA_CONF_RULES { &eb_per_time_source, \
                               &unicast_per_neighbor_rpl_ns, \
                               &default_common }

/* Configuration for RPL storing mode */
#define ORCHESTRA_CONF_RULES { &eb_per_time_source, \
                               &unicast_per_neighbor_rpl_storing, \
                               &default_common }

/* Configuration with root optimization */
#define ORCHESTRA_CONF_RULES { &eb_per_time_source, \
                               &unicast_per_neighbor_rpl_ns, \
                               &special_for_root, \
                               &default_common }

/* Configuration for link-based scheduling */
#define ORCHESTRA_CONF_RULES { &eb_per_time_source, \
                               &unicast_per_neighbor_link_based, \
                               &default_common }
```

### Slotframe Period Configuration

Slotframe periods control the trade-off between capacity, latency, and energy:

| Parameter | Default | Description | Trade-offs |
|-----------|---------|-------------|------------|
| `ORCHESTRA_CONF_EBSF_PERIOD` | 397 | EB slotframe period | Larger = less frequent EBs = lower energy but slower join |
| `ORCHESTRA_CONF_UNICAST_PERIOD` | 17 | Unicast slotframe period | Smaller = lower latency but higher contention |
| `ORCHESTRA_CONF_COMMON_SHARED_PERIOD` | 31 | Shared slotframe period | Balance broadcast capacity vs energy |
| `ORCHESTRA_CONF_ROOT_PERIOD` | 7 | Root slotframe period | Smaller = more root capacity |

**Why prime numbers?**
The default periods (397, 31, 17, 7) are prime numbers. This minimizes collisions when multiple slotframes overlap—the least common multiple is maximized, reducing periodic collision patterns.

**Tuning guidelines:**
```c
/* Small network (< 20 nodes), optimize for latency */
#define ORCHESTRA_CONF_UNICAST_PERIOD 7
#define ORCHESTRA_CONF_COMMON_SHARED_PERIOD 13

/* Large network (> 100 nodes), optimize for capacity */
#define ORCHESTRA_CONF_UNICAST_PERIOD 31
#define ORCHESTRA_CONF_COMMON_SHARED_PERIOD 61

/* Energy-constrained, optimize for low duty cycle */
#define ORCHESTRA_CONF_EBSF_PERIOD 997      /* Less frequent EBs */
#define ORCHESTRA_CONF_UNICAST_PERIOD 37    /* Larger period */
```

### Hash Function Configuration

The hash function maps node addresses to timeslots:

```c
/* Default: use last byte of address */
#define ORCHESTRA_CONF_LINKADDR_HASH(addr) \
  ((addr != NULL) ? (addr)->u8[LINKADDR_SIZE - 1] : -1)

/* Custom: use node ID (if configured) */
#define ORCHESTRA_CONF_LINKADDR_HASH(addr) \
  ((addr != NULL) ? node_id_from_linkaddr(addr) : -1)

/* Maximum hash value */
#define ORCHESTRA_CONF_MAX_HASH 0x7fff

/* Set to 1 if hash is collision-free (e.g., using sequential node IDs) */
#define ORCHESTRA_CONF_COLLISION_FREE_HASH 0
```

For link-based rules, a pair-wise hash is used:

```c
/* Default pair-wise hash for link-based scheduling */
#define ORCHESTRA_CONF_LINKADDR_HASH2(addr1, addr2) \
  ((addr1)->u8[LINKADDR_SIZE - 1] + 264 * (addr2)->u8[LINKADDR_SIZE - 1])
```

The value 264 is chosen to ensure `hash2(A,B) != hash2(B,A)` for most slotframe sizes.

### Channel Offset Configuration

Orchestra supports multi-channel scheduling:

```c
/* Channel offset for common shared slot */
#define ORCHESTRA_CONF_DEFAULT_COMMON_CHANNEL_OFFSET 0

/* Channel offset range for unicast slots */
#define ORCHESTRA_CONF_UNICAST_MIN_CHANNEL_OFFSET 2
#define ORCHESTRA_CONF_UNICAST_MAX_CHANNEL_OFFSET \
  (sizeof(TSCH_DEFAULT_HOPPING_SEQUENCE) - 1)

/* Channel offset range for EB slots */
#define ORCHESTRA_CONF_EB_MIN_CHANNEL_OFFSET 1
#define ORCHESTRA_CONF_EB_MAX_CHANNEL_OFFSET 1
```

**Channel diversity benefits:**
- Frequency diversity improves reliability in harsh RF environments
- Parallel transmissions on different channels increase capacity
- Reduces impact of narrow-band interference

### Sender vs Receiver-Based Scheduling

For storing mode only:

```c
/* Receiver-based (default): transmit in receiver's slot */
#define ORCHESTRA_CONF_UNICAST_SENDER_BASED 0

/* Sender-based: transmit in sender's own slot */
#define ORCHESTRA_CONF_UNICAST_SENDER_BASED 1
```

**Trade-offs:**

| Approach | Pros | Cons |
|----------|------|------|
| **Receiver-based** (default) | Works with any RPL mode, simpler | Receivers must listen continuously in their slot |
| **Sender-based** | Senders control when to transmit | Only works with storing mode, requires DAO |

## Getting Started

### Step 1: Add Orchestra Module

In your application's `Makefile`:

```makefile
MODULES += os/services/orchestra
```

This automatically:
- Compiles Orchestra code
- Defines `BUILD_WITH_ORCHESTRA=1`
- Calls `orchestra_init()` from `contiki-main.c`

### Step 2: Configure Required Callbacks

Orchestra requires several TSCH and routing callbacks. Add to your `project-conf.h`:

```c
/*******************************************************/
/***************** Configure Orchestra *****************/
/*******************************************************/

/* Orchestra callbacks */
#define TSCH_CALLBACK_PACKET_READY orchestra_callback_packet_ready
#define TSCH_CALLBACK_NEW_TIME_SOURCE orchestra_callback_new_time_source
#define NETSTACK_CONF_ROUTING_NEIGHBOR_ADDED_CALLBACK orchestra_callback_child_added
#define NETSTACK_CONF_ROUTING_NEIGHBOR_REMOVED_CALLBACK orchestra_callback_child_removed

/* Orchestra requires TSCH time source to match RPL parent */
#define RPL_CALLBACK_PARENT_SWITCH tsch_rpl_callback_parent_switch

/* Enable neighbor table callbacks */
#define TSCH_CALLBACK_ROOT_NODE_UPDATED orchestra_callback_root_node_updated
#define NETSTACK_CONF_DS6_NEIGHBOR_UPDATED_CALLBACK orchestra_callback_neighbor_updated
```

### Step 3: Configure TSCH

Orchestra works with TSCH, so ensure TSCH is properly configured:

```c
/*******************************************************/
/******************* Configure TSCH ********************/
/*******************************************************/

/* IEEE 802.15.4 PANID */
#define IEEE802154_CONF_PANID 0x81a5

/* TSCH schedule length (minimal schedule, Orchestra adds slotframes) */
#define TSCH_SCHEDULE_CONF_DEFAULT_LENGTH 3

/* Enable TSCH logs (optional, for debugging) */
#define TSCH_LOG_CONF_PER_SLOT 1
```

### Step 4: Optional Orchestra Customization

Add Orchestra-specific configuration (optional):

```c
/* Select rule set (if not using default) */
#define ORCHESTRA_CONF_RULES { &eb_per_time_source, \
                               &unicast_per_neighbor_rpl_ns, \
                               &special_for_root, \
                               &default_common }

/* Adjust slotframe periods (if needed) */
#define ORCHESTRA_CONF_UNICAST_PERIOD 17
#define ORCHESTRA_CONF_COMMON_SHARED_PERIOD 31
#define ORCHESTRA_CONF_EBSF_PERIOD 397
```

### Complete Example: RPL Non-Storing with Orchestra

**project-conf.h:**

```c
#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/*******************************************************/
/******************* Configure TSCH ********************/
/*******************************************************/

/* IEEE 802.15.4 PANID */
#define IEEE802154_CONF_PANID 0x81a5

/* Do not start TSCH at init, wait for NETSTACK_MAC.on() */
#define TSCH_CONF_AUTOSTART 0

/* TSCH minimal schedule length */
#define TSCH_SCHEDULE_CONF_DEFAULT_LENGTH 3

/*******************************************************/
/***************** Configure Orchestra *****************/
/*******************************************************/

/* Orchestra callbacks */
#define TSCH_CALLBACK_PACKET_READY orchestra_callback_packet_ready
#define TSCH_CALLBACK_NEW_TIME_SOURCE orchestra_callback_new_time_source
#define NETSTACK_CONF_ROUTING_NEIGHBOR_ADDED_CALLBACK orchestra_callback_child_added
#define NETSTACK_CONF_ROUTING_NEIGHBOR_REMOVED_CALLBACK orchestra_callback_child_removed
#define RPL_CALLBACK_PARENT_SWITCH tsch_rpl_callback_parent_switch
#define TSCH_CALLBACK_ROOT_NODE_UPDATED orchestra_callback_root_node_updated
#define NETSTACK_CONF_DS6_NEIGHBOR_UPDATED_CALLBACK orchestra_callback_neighbor_updated

/* Rule set: default for RPL non-storing mode */
#define ORCHESTRA_CONF_RULES { &eb_per_time_source, \
                               &unicast_per_neighbor_rpl_ns, \
                               &special_for_root, \
                               &default_common }

/* Slotframe periods (optional tuning) */
#define ORCHESTRA_CONF_UNICAST_PERIOD 17
#define ORCHESTRA_CONF_COMMON_SHARED_PERIOD 31
#define ORCHESTRA_CONF_EBSF_PERIOD 397
#define ORCHESTRA_CONF_ROOT_PERIOD 7

/*******************************************************/
/************* Other system configuration **************/
/*******************************************************/

/* Logging levels */
#define LOG_CONF_LEVEL_RPL LOG_LEVEL_INFO
#define LOG_CONF_LEVEL_MAC LOG_LEVEL_INFO

#endif /* PROJECT_CONF_H_ */
```

**Makefile:**

```makefile
CONTIKI_PROJECT = my-app
CONTIKI = ../..

# Include Orchestra
MODULES += os/services/orchestra

# Include the Contiki-NG build system
include $(CONTIKI)/Makefile.include
```

**my-app.c:**

```c
#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "sys/log.h"

#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_INFO

PROCESS(node_process, "Orchestra Node");
AUTOSTART_PROCESSES(&node_process);

PROCESS_THREAD(node_process, ev, data)
{
  PROCESS_BEGIN();

  /* Determine if this node should be the root */
  if(node_id == 1) {
    LOG_INFO("Setting up as DAG root\n");
    NETSTACK_ROUTING.root_start();
  } else {
    LOG_INFO("Setting up as regular node\n");
  }

  /* Start TSCH (Orchestra is automatically initialized) */
  NETSTACK_MAC.on();

  LOG_INFO("Orchestra node started\n");

  PROCESS_END();
}
```

### Complete Example: RPL Storing Mode with Orchestra

For RPL storing mode, the main differences are:

**project-conf.h changes:**

```c
/* Use RPL Classic in storing mode */
#define ROUTING_CONF_RPL_CLASSIC 1
#define RPL_CONF_MOP RPL_MOP_STORING_NO_MULTICAST

/* Use storing-mode Orchestra rule */
#define ORCHESTRA_CONF_RULES { &eb_per_time_source, \
                               &unicast_per_neighbor_rpl_storing, \
                               &default_common }

/* Optional: use sender-based scheduling (storing mode only) */
#define ORCHESTRA_CONF_UNICAST_SENDER_BASED 0  /* 0=receiver-based, 1=sender-based */
```

## Rule Selection Guide

### Decision Tree

```
                    Start
                      |
              Do you use RPL?
                    /  \
                  Yes   No
                  /       \
      What RPL mode?    Use link-based
         /    \           +
    Storing  Non-storing  default_common
       |         |
       |    Use: eb_per_time_source
       |         + unicast_per_neighbor_rpl_ns
       |         + default_common
       |
  Use: eb_per_time_source
       + unicast_per_neighbor_rpl_storing
       + default_common

  Optional add-ons (for any configuration):
    - special_for_root (if root is bottleneck)
```

### Common Configurations

#### Configuration 1: Small Network, Low Latency

**Characteristics**: < 20 nodes, latency-critical application, sufficient energy budget

```c
#define ORCHESTRA_CONF_RULES { &eb_per_time_source, \
                               &unicast_per_neighbor_rpl_ns, \
                               &default_common }

#define ORCHESTRA_CONF_UNICAST_PERIOD 7      /* Short period = low latency */
#define ORCHESTRA_CONF_COMMON_SHARED_PERIOD 13
#define ORCHESTRA_CONF_EBSF_PERIOD 199       /* Faster network formation */
```

#### Configuration 2: Large Network, High Capacity

**Characteristics**: > 100 nodes, high traffic, need to minimize collisions

```c
#define ORCHESTRA_CONF_RULES { &eb_per_time_source, \
                               &unicast_per_neighbor_rpl_ns, \
                               &special_for_root, \
                               &default_common }

#define ORCHESTRA_CONF_UNICAST_PERIOD 31     /* Larger = less collision */
#define ORCHESTRA_CONF_COMMON_SHARED_PERIOD 61
#define ORCHESTRA_CONF_EBSF_PERIOD 997
#define ORCHESTRA_CONF_ROOT_PERIOD 7         /* Root needs extra capacity */
```

#### Configuration 3: Energy-Constrained Sensors

**Characteristics**: Battery-powered, infrequent transmissions, long lifetime priority

```c
#define ORCHESTRA_CONF_RULES { &eb_per_time_source, \
                               &unicast_per_neighbor_rpl_ns, \
                               &default_common }

#define ORCHESTRA_CONF_UNICAST_PERIOD 37     /* Longer period = lower duty cycle */
#define ORCHESTRA_CONF_COMMON_SHARED_PERIOD 97
#define ORCHESTRA_CONF_EBSF_PERIOD 1999      /* Very infrequent EBs */
```

#### Configuration 4: Data Collection Network

**Characteristics**: Many-to-one traffic pattern, root aggregates all data

```c
#define ORCHESTRA_CONF_RULES { &eb_per_time_source, \
                               &unicast_per_neighbor_rpl_ns, \
                               &special_for_root, \
                               &default_common }

#define ORCHESTRA_CONF_UNICAST_PERIOD 17
#define ORCHESTRA_CONF_COMMON_SHARED_PERIOD 31
#define ORCHESTRA_CONF_ROOT_PERIOD 5         /* Extra root capacity critical */
```

#### Configuration 5: RPL Storing Mode

**Characteristics**: Using RPL Classic in storing mode

```c
#define ROUTING_CONF_RPL_CLASSIC 1
#define RPL_CONF_MOP RPL_MOP_STORING_NO_MULTICAST

#define ORCHESTRA_CONF_RULES { &eb_per_time_source, \
                               &unicast_per_neighbor_rpl_storing, \
                               &default_common }

#define ORCHESTRA_CONF_UNICAST_SENDER_BASED 0  /* Receiver-based recommended */
```

## Performance Tuning

### Understanding Period Impact

The period of each slotframe directly affects:
- **Latency**: Time to wait for next transmission opportunity
- **Capacity**: Number of parallel transmissions possible
- **Energy**: Duty cycle of radio listening
- **Collision probability**: Larger periods reduce hash collisions

### Latency Calculation

Average latency for a packet = `period / 2 * slot_duration`

Example with default TSCH timings (10ms slot):
```
UNICAST_PERIOD = 17 slots
Average latency = 17 / 2 * 10ms = 85ms
Max latency = 17 * 10ms = 170ms
```

### Capacity Calculation

Theoretical capacity (packets/second per node):
```
Capacity = 1 / (period * slot_duration)

UNICAST_PERIOD = 17, slot = 10ms:
Capacity = 1 / (17 * 0.01s) = 5.88 packets/second
```

### Collision Probability

For N nodes and period P, collision probability ≈ `N / P` (assuming uniform hash distribution)

```c
/* 10 nodes, period 17: ~59% collision-free */
/* 10 nodes, period 31: ~68% collision-free */
/* 10 nodes, period 61: ~84% collision-free */
```

**Rule of thumb**: Choose period ≥ 2 × number_of_nodes for low collision rate.

### Memory Considerations

Orchestra memory usage scales with:
- **Number of neighbors**: Each unicast rule creates links per neighbor
- **Number of rules**: Each rule maintains metadata
- **Number of slotframes**: TSCH schedule memory

Typical memory usage:
```
Base Orchestra overhead: ~500 bytes
Per-neighbor overhead:   ~40 bytes
Per-slotframe overhead:  ~60 bytes
```

For a node with 5 neighbors and 3 slotframes:
```
Total ≈ 500 + (5 × 40) + (3 × 60) = 880 bytes
```

### Network Size Limits

Orchestra scales well, but practical limits exist:

| Network Size | Recommended Max Period | Notes |
|--------------|------------------------|-------|
| < 20 nodes | 17-31 | Default settings work well |
| 20-50 nodes | 31-61 | Consider larger unicast period |
| 50-100 nodes | 61-127 | Use prime numbers, add special_for_root |
| 100+ nodes | 127-257 | Carefully tune periods, monitor collisions |

### Tuning Workflow

1. **Start with defaults** and measure performance
2. **Identify bottleneck**: Latency? Throughput? Energy?
3. **Adjust relevant period**:
   - High latency → decrease unicast period
   - High collision rate → increase unicast period
   - Slow join time → decrease EB period
   - High energy consumption → increase all periods
4. **Test and iterate**

## Creating Custom Rules

### Orchestra Rule Structure

An Orchestra rule is defined by the `orchestra_rule` structure:

```c
struct orchestra_rule {
  void (* init)(uint16_t slotframe_handle);
  void (* new_time_source)(const struct tsch_neighbor *old,
                           const struct tsch_neighbor *new);
  int  (* select_packet)(uint16_t *slotframe, uint16_t *timeslot,
                         uint16_t *channel_offset);
  void (* child_added)(const linkaddr_t *addr);
  void (* child_removed)(const linkaddr_t *addr);
  void (* neighbor_updated)(const linkaddr_t *addr, uint8_t is_added);
  void (* root_node_updated)(const linkaddr_t *addr, uint8_t is_added);
  const char *const name;
  const int16_t slotframe_size;
};
```

### Callback Reference

#### init(slotframe_handle)

Called once at Orchestra initialization.

**Purpose**: Set up the slotframe and initial links.

**Parameters:**
- `slotframe_handle`: Unique identifier for this rule's slotframe

**Typical tasks:**
- Create slotframe with `tsch_schedule_add_slotframe()`
- Add initial links with `tsch_schedule_add_link()`

#### select_packet(slotframe, timeslot, channel_offset)

Called for each outgoing packet to determine if this rule should handle it.

**Purpose**: Decide if and how this rule handles the packet.

**Parameters (output):**
- `slotframe`: Set to this rule's slotframe handle
- `timeslot`: Set to the timeslot to use
- `channel_offset`: Set to channel offset (or leave as 0xffff for default)

**Returns:**
- `1` if this rule handles the packet
- `0` if this rule doesn't handle the packet (try next rule)

**Example logic:**
```c
/* Select only unicast packets to RPL neighbors */
if(packetbuf_attr(PACKETBUF_ATTR_FRAME_TYPE) == FRAME802154_DATAFRAME) {
  const linkaddr_t *dest = packetbuf_addr(PACKETBUF_ADDR_RECEIVER);
  if(is_rpl_neighbor(dest)) {
    *slotframe = my_slotframe_handle;
    *timeslot = compute_timeslot(dest);
    return 1;  /* We handle this packet */
  }
}
return 0;  /* Not for us, try next rule */
```

#### new_time_source(old, new)

Called when the TSCH time source changes (typically when RPL parent changes).

**Purpose**: Update RX links to listen to new time source's EBs.

**Parameters:**
- `old`: Previous time source (may be NULL)
- `new`: New time source (may be NULL)

**Typical tasks:**
- Remove RX links for old time source
- Add RX links for new time source

#### child_added(addr) / child_removed(addr)

Called when RPL routing adds/removes a child.

**Purpose**: Update schedule to add/remove links for the child.

**Parameters:**
- `addr`: Link-layer address of the child

**Note**: Only called for RPL children (downward routes).

#### neighbor_updated(addr, is_added)

Called when a link-layer neighbor is added or removed.

**Purpose**: Update schedule based on link-layer neighbor changes.

**Parameters:**
- `addr`: Link-layer address of the neighbor
- `is_added`: 1 if neighbor added, 0 if removed

**Note**: Called for all neighbors, not just RPL neighbors.

#### root_node_updated(addr, is_added)

Called when root node status changes in the network.

**Purpose**: Update schedule if root node changes.

**Parameters:**
- `addr`: Address of the root node
- `is_added`: 1 if root detected, 0 if root disappeared

### Custom Rule Example: Time-Based Periodic Beaconing

This example creates a custom rule that broadcasts periodic keep-alive beacons.

```c
/*
 * Custom Orchestra rule: Periodic beacon transmission
 * Each node broadcasts a beacon every 10 slotframes
 */

#include "contiki.h"
#include "orchestra.h"
#include "net/packetbuf.h"

#define BEACON_PERIOD 127  /* Prime number for collision resistance */
#define BEACON_CHANNEL_OFFSET 1

static uint16_t slotframe_handle = 0;
static struct tsch_slotframe *sf_beacon;

/* Get beacon timeslot for a node */
static uint16_t
get_beacon_timeslot(const linkaddr_t *addr)
{
  if(BEACON_PERIOD > 0) {
    return ORCHESTRA_LINKADDR_HASH(addr) % BEACON_PERIOD;
  }
  return 0xffff;
}

/* Initialize rule: create slotframe and add TX slot */
static void
init(uint16_t sf_handle)
{
  uint16_t local_timeslot;

  slotframe_handle = sf_handle;
  sf_beacon = tsch_schedule_add_slotframe(slotframe_handle, BEACON_PERIOD);

  /* Calculate our own beacon timeslot */
  local_timeslot = get_beacon_timeslot(&linkaddr_node_addr);

  /* Add broadcast TX link in our timeslot */
  tsch_schedule_add_link(sf_beacon,
                         LINK_OPTION_TX,
                         LINK_TYPE_ADVERTISING,
                         &tsch_broadcast_address,
                         local_timeslot,
                         BEACON_CHANNEL_OFFSET,
                         1);

  LOG_INFO("Beacon rule: TX in slot %u\n", local_timeslot);
}

/* When time source changes, listen to its beacons */
static void
new_time_source(const struct tsch_neighbor *old, const struct tsch_neighbor *new)
{
  uint16_t timeslot;
  static struct tsch_link *rx_link = NULL;

  /* Remove old RX link */
  if(rx_link != NULL) {
    tsch_schedule_remove_link(sf_beacon, rx_link);
    rx_link = NULL;
  }

  /* Add new RX link if we have a time source */
  if(new != NULL) {
    const linkaddr_t *addr = tsch_queue_get_nbr_address(new);
    timeslot = get_beacon_timeslot(addr);

    rx_link = tsch_schedule_add_link(sf_beacon,
                                      LINK_OPTION_RX,
                                      LINK_TYPE_ADVERTISING,
                                      &tsch_broadcast_address,
                                      timeslot,
                                      BEACON_CHANNEL_OFFSET,
                                      0);

    LOG_INFO("Beacon rule: RX in slot %u\n", timeslot);
  }
}

/* Select packets: handle broadcast beacons */
static int
select_packet(uint16_t *sf, uint16_t *ts, uint16_t *co)
{
  /* Check if this is a beacon packet (application-defined) */
  uint8_t packet_type = packetbuf_attr(PACKETBUF_ATTR_PACKET_TYPE);

  if(packet_type == PACKETBUF_ATTR_PACKET_TYPE_BEACON) {
    if(sf != NULL) {
      *sf = slotframe_handle;
    }
    if(ts != NULL) {
      *ts = get_beacon_timeslot(&linkaddr_node_addr);
    }
    /* Use channel offset from link */
    return 1;
  }

  return 0;
}

/* Define the rule */
struct orchestra_rule custom_periodic_beacon = {
  init,
  new_time_source,
  select_packet,
  NULL,  /* child_added */
  NULL,  /* child_removed */
  NULL,  /* neighbor_updated */
  NULL,  /* root_node_updated */
  "periodic beacon",
  BEACON_PERIOD,
};
```

**To use this custom rule:**

```c
/* In project-conf.h */
#define ORCHESTRA_CONF_RULES { &eb_per_time_source, \
                               &custom_periodic_beacon, \
                               &unicast_per_neighbor_rpl_ns, \
                               &default_common }
```

## Troubleshooting

### Issue: Nodes Don't Join Network

**Symptoms**: Nodes never synchronize, remain unconnected.

**Possible causes:**

1. **Missing EB rule**
   ```c
   /* WRONG: No EB rule */
   #define ORCHESTRA_CONF_RULES { &unicast_per_neighbor_rpl_ns, \
                                  &default_common }

   /* CORRECT: Include EB rule */
   #define ORCHESTRA_CONF_RULES { &eb_per_time_source, \
                                  &unicast_per_neighbor_rpl_ns, \
                                  &default_common }
   ```

2. **EB period too long**
   ```c
   /* Try shorter EB period for faster join */
   #define ORCHESTRA_CONF_EBSF_PERIOD 199  /* Instead of 397 */
   ```

3. **Missing callbacks in project-conf.h**
   - Verify all required Orchestra callbacks are defined
   - Check that `RPL_CALLBACK_PARENT_SWITCH` is set

4. **TSCH not started**
   ```c
   /* Make sure to call this in your application */
   NETSTACK_MAC.on();
   ```

**Debugging:**
```c
/* Enable Orchestra and TSCH logs */
#define LOG_CONF_LEVEL_MAC LOG_LEVEL_DBG
#define TSCH_LOG_CONF_PER_SLOT 1
```

### Issue: High Packet Loss

**Symptoms**: Many packets don't reach destination, retransmissions frequent.

**Possible causes:**

1. **Hash collisions (too many nodes for period)**
   ```c
   /* If 30 nodes with period 17, collision rate is high */
   /* Increase unicast period */
   #define ORCHESTRA_CONF_UNICAST_PERIOD 37
   ```

2. **Wrong RPL mode vs rule mismatch**
   ```c
   /* Using storing mode but non-storing rule */
   /* WRONG */
   #define RPL_CONF_MOP RPL_MOP_STORING_NO_MULTICAST
   #define ORCHESTRA_CONF_RULES { ..., &unicast_per_neighbor_rpl_ns, ... }

   /* CORRECT */
   #define RPL_CONF_MOP RPL_MOP_STORING_NO_MULTICAST
   #define ORCHESTRA_CONF_RULES { ..., &unicast_per_neighbor_rpl_storing, ... }
   ```

3. **Missing default_common rule (no fallback)**
   ```c
   /* Always include default_common as last rule */
   #define ORCHESTRA_CONF_RULES { &eb_per_time_source, \
                                  &unicast_per_neighbor_rpl_ns, \
                                  &default_common }  /* Required */
   ```

4. **Interference on channels**
   - Try different channel hopping sequence
   - Adjust channel offsets to avoid congested frequencies

**Debugging:**
```c
/* Enable TSCH statistics */
#define TSCH_STATS_CONF_ON 1

/* In your code */
struct tsch_neighbor *nbr = tsch_queue_get_nbr(dest_addr);
if(nbr != NULL) {
  LOG_INFO("Neighbor stats: tx=%u rx=%u tx_fail=%u\n",
           nbr->tx_count, nbr->rx_count, nbr->tx_fail_count);
}
```

### Issue: Root Node Bottleneck

**Symptoms**: Root can't keep up with incoming traffic, packets queued/dropped.

**Solution 1: Add special_for_root rule**
```c
#define ORCHESTRA_CONF_RULES { &eb_per_time_source, \
                               &unicast_per_neighbor_rpl_ns, \
                               &special_for_root, \
                               &default_common }
```

**Solution 2: Decrease root period**
```c
/* More frequent slots for root communication */
#define ORCHESTRA_CONF_ROOT_PERIOD 5  /* Instead of 7 */
```

**Solution 3: Increase root's queue sizes**
```c
/* In project-conf.h */
#define QUEUEBUF_CONF_NUM 16  /* Increase from default 8 */
```

### Issue: Slow Convergence After Topology Change

**Symptoms**: After node/link failure, network takes long to reconverge.

**Possible causes:**

1. **RPL timers too conservative**
   ```c
   /* Speed up RPL convergence */
   #define RPL_CONF_DIO_INTERVAL_MIN 12      /* Faster DIO (2^12 ms = ~4s) */
   #define RPL_CONF_DIO_INTERVAL_DOUBLINGS 8
   ```

2. **Unicast period too long (missed opportunities)**
   ```c
   /* Shorter period = faster detection of link failure */
   #define ORCHESTRA_CONF_UNICAST_PERIOD 11
   ```

3. **Not using keepalives**
   ```c
   /* Enable RPL link probing */
   #define RPL_CONF_PROBING_INTERVAL (60 * CLOCK_SECOND)
   ```

### Issue: High Energy Consumption

**Symptoms**: Nodes drain batteries faster than expected.

**Solutions:**

1. **Increase slotframe periods**
   ```c
   /* Longer periods = less frequent wake-ups */
   #define ORCHESTRA_CONF_UNICAST_PERIOD 37
   #define ORCHESTRA_CONF_EBSF_PERIOD 997
   ```

2. **Reduce radio duty cycle**
   ```c
   /* Minimize number of RX links */
   /* Use receiver-based (only listen in your own slot) */
   #define ORCHESTRA_CONF_UNICAST_SENDER_BASED 0
   ```

3. **Tune TSCH timing**
   ```c
   /* Shorter timeslots if possible */
   #define TSCH_CONF_DEFAULT_TIMESLOT_TIMING tsch_timing_us_15000
   ```

4. **Monitor energy consumption**
   ```c
   /* Enable Energest */
   MODULES += os/services/simple-energest
   ```

### Issue: Compilation Errors

**Error: "orchestra_callback_packet_ready undefined"**

**Solution**: Add Orchestra callbacks to project-conf.h (see Getting Started section)

**Error: "eb_per_time_source undeclared"**

**Solution**: Include Orchestra module in Makefile:
```makefile
MODULES += os/services/orchestra
```

**Error: "BUILD_WITH_ORCHESTRA undeclared"**

**Solution**: Orchestra module not included. Check Makefile.

### Verifying Orchestra is Working

**Check Orchestra initialization in logs:**
```
[INFO: Orchestra] Initializing rule EB per time source (0), size 397
[INFO: Orchestra] Initializing rule unicast per neighbor rpl ns (1), size 17
[INFO: Orchestra] Initializing rule default common (2), size 31
[INFO: Orchestra] Initialization done
```

**Check TSCH schedule:**
```c
/* In your application, print schedule */
void
print_tsch_schedule(void)
{
  struct tsch_slotframe *sf;
  struct tsch_link *link;

  sf = tsch_schedule_slotframe_head();
  while(sf != NULL) {
    LOG_INFO("Slotframe %u, size %u:\n", sf->handle, sf->size.val);

    link = list_head(sf->links_list);
    while(link != NULL) {
      LOG_INFO("  Link: timeslot=%u channel_offset=%u options=%02x\n",
               link->timeslot, link->channel_offset, link->link_options);
      link = list_item_next(link);
    }

    sf = tsch_schedule_slotframe_next(sf);
  }
}
```

**Check packet routing:**
```c
/* Enable packet tracing */
#define TSCH_CALLBACK_PACKET_READY my_packet_ready
int
my_packet_ready(void)
{
  int result = orchestra_callback_packet_ready();
  if(result >= 0) {
    LOG_INFO("Packet assigned to rule %d\n", result);
  }
  return result;
}
```

## Best Practices

### 1. Always Include EB and Default Common Rules

```c
/* WRONG: Missing essential rules */
#define ORCHESTRA_CONF_RULES { &unicast_per_neighbor_rpl_ns }

/* CORRECT: Include EB and default_common */
#define ORCHESTRA_CONF_RULES { &eb_per_time_source, \
                               &unicast_per_neighbor_rpl_ns, \
                               &default_common }
```

**Why**: EB rule is required for network formation. Default common provides fallback for any traffic not handled by specific rules.

### 2. Match Rules to RPL Mode

```c
/* RPL non-storing mode (RPL-Lite) */
#define ORCHESTRA_CONF_RULES { &eb_per_time_source, \
                               &unicast_per_neighbor_rpl_ns, \
                               &default_common }

/* RPL storing mode (RPL-Classic) */
#define ROUTING_CONF_RPL_CLASSIC 1
#define RPL_CONF_MOP RPL_MOP_STORING_NO_MULTICAST
#define ORCHESTRA_CONF_RULES { &eb_per_time_source, \
                               &unicast_per_neighbor_rpl_storing, \
                               &default_common }
```

**Why**: Wrong rule/mode combination causes missing links and packet loss.

### 3. Use Prime Number Periods

```c
/* GOOD: Prime numbers minimize collision patterns */
#define ORCHESTRA_CONF_UNICAST_PERIOD 17
#define ORCHESTRA_CONF_COMMON_SHARED_PERIOD 31
#define ORCHESTRA_CONF_EBSF_PERIOD 397

/* AVOID: Powers of 2 create periodic collision patterns */
#define ORCHESTRA_CONF_UNICAST_PERIOD 16  /* Avoid */
#define ORCHESTRA_CONF_COMMON_SHARED_PERIOD 32  /* Avoid */
```

**Why**: Prime numbers maximize the least common multiple between slotframes, reducing recurring collisions.

### 4. Size Periods Appropriately for Network

```c
/* Rule of thumb: UNICAST_PERIOD >= 2 × max_neighbors */

/* Small network (< 10 nodes) */
#define ORCHESTRA_CONF_UNICAST_PERIOD 17  /* OK */

/* Medium network (20-30 nodes) */
#define ORCHESTRA_CONF_UNICAST_PERIOD 61  /* Better */

/* Large network (> 50 nodes) */
#define ORCHESTRA_CONF_UNICAST_PERIOD 127  /* Necessary */
```

**Why**: Too-small periods cause excessive hash collisions.

### 5. Consider Root-Specific Optimization

```c
/* For data collection or border router scenarios */
#define ORCHESTRA_CONF_RULES { &eb_per_time_source, \
                               &unicast_per_neighbor_rpl_ns, \
                               &special_for_root, \
                               &default_common }

#define ORCHESTRA_CONF_ROOT_PERIOD 7  /* Short = high capacity */
```

**Why**: Root typically handles much more traffic than other nodes.

### 6. Balance Latency vs Energy vs Capacity

```c
/* Latency-optimized (short periods) */
#define ORCHESTRA_CONF_UNICAST_PERIOD 7
#define ORCHESTRA_CONF_COMMON_SHARED_PERIOD 11

/* Energy-optimized (long periods) */
#define ORCHESTRA_CONF_UNICAST_PERIOD 37
#define ORCHESTRA_CONF_COMMON_SHARED_PERIOD 97

/* Balanced (default) */
#define ORCHESTRA_CONF_UNICAST_PERIOD 17
#define ORCHESTRA_CONF_COMMON_SHARED_PERIOD 31
```

**Why**: No free lunch—shorter periods give lower latency but higher energy consumption and collision rate.

### 7. Enable Logging During Development

```c
/* Development phase: enable detailed logs */
#define LOG_CONF_LEVEL_MAC LOG_LEVEL_INFO
#define TSCH_LOG_CONF_PER_SLOT 1

/* Production: reduce log level */
#define LOG_CONF_LEVEL_MAC LOG_LEVEL_WARN
#define TSCH_LOG_CONF_PER_SLOT 0
```

**Why**: Orchestra logs help diagnose configuration issues. Disable in production to save energy and memory.

### 8. Test at Scale

```c
/* Don't just test with 2-3 nodes */
/* Test with realistic network size to reveal collision issues */
```

**Why**: Many Orchestra issues (hash collisions, capacity limits) only appear at scale.

### 9. Use Collision-Free Hash If Possible

```c
/* If using sequential node IDs (1, 2, 3, ...) */
#define ORCHESTRA_CONF_LINKADDR_HASH(addr) node_id_from_linkaddr(addr)
#define ORCHESTRA_CONF_COLLISION_FREE_HASH 1

/* Allows smaller periods without collisions */
#define ORCHESTRA_CONF_UNICAST_PERIOD 11  /* Can be smaller */
```

**Why**: Collision-free hashing eliminates scheduling conflicts, improving efficiency.

### 10. Monitor Network Health

```c
/* Periodically log statistics */
void
log_orchestra_stats(void)
{
  struct tsch_neighbor *n;

  for(n = tsch_queue_nbr_head(); n != NULL; n = tsch_queue_nbr_next(n)) {
    const linkaddr_t *addr = tsch_queue_get_nbr_address(n);
    LOG_INFO("Neighbor ");
    LOG_INFO_LLADDR(addr);
    LOG_INFO_(": tx=%u rx=%u tx_fail=%u\n",
              n->tx_count, n->rx_count, n->tx_fail_count);
  }
}
```

**Why**: Proactive monitoring helps detect and fix issues before they become critical.

## Summary

**Orchestra in a nutshell:**
- Autonomous TSCH scheduling using local RPL state
- Zero scheduling overhead (no messages, no centralized control)
- Multiple rules handle different traffic types
- Hash-based timeslot assignment prevents collisions
- Works out-of-box with sensible defaults
- Highly configurable for specific network needs

**To get started:**
1. Add `MODULES += os/services/orchestra` to Makefile
2. Configure callbacks in project-conf.h
3. Choose appropriate rule set for your RPL mode
4. Optionally tune periods for your network characteristics

**Key configuration choices:**
- **Rule set**: Match to RPL mode (storing vs non-storing)
- **Periods**: Balance latency, energy, and capacity
- **Root optimization**: Add special_for_root for data collection
- **Hash function**: Use collision-free if possible

For more information:
- [TSCH and 6TiSCH](TSCH-and-6TiSCH.md) - Understanding the TSCH MAC layer
- [RPL](RPL.md) - RPL routing protocol
- [TSCH Example Applications](TSCH-example-applications.md) - Working examples

Orchestra paper: [*Orchestra: Robust Mesh Networks Through Autonomously Scheduled TSCH*](http://www.simonduquennoy.net/papers/duquennoy15orchestra.pdf), ACM SenSys'15
