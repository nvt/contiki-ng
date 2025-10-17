# RPL

## About RPL

RPL is an IPv6 routing protocol for lossy and low-power networks specified in [RFC 6550](https://tools.ietf.org/html/rfc6550), which is implemented in Contiki-NG's IPv6 network stack. RPL builds and maintains a Destination-Oriented Directed Acyclic Graph (DODAG) topology that originates from a designated RPL root node, which typically also serves as a border router to the Internet. Routing information is disseminated through broadcast beacons aperiodically using [Trickle timers](https://tools.ietf.org/html/rfc6206). The topology is built according to a certain goal by an objective function. Such a goal can be to minimize the Estimated Transmission Count (ETX) on the path from the node to the RPL root, as is in our implementations of the two Objective Functions we support, [MRHOF](https://tools.ietf.org/html/rfc6719) and [OF0](https://tools.ietf.org/html/rfc6552).

RPL supports different directions of traffic:
* Upward routing: from any node to a root.
* Downward routing: from the root to any node.
* Any-to-any routing: where traffic flows between arbitrary pairs of nodes in the DODAG by routing upwards to their closest common ancestor (or the root in non-storing mode) in the DODAG, and then downward to the destination node.

All upward routing is handled by having each node on the path toward the root forwarding traffic through a preferred parent. Downward routing can be handled with two different types of modes: non-storing and storing mode (see below).

### Architecture Overview

```
             ┌─────────────────┐
             │   DAG Root      │  Rank: 128
             │  (Border Router)│
             └────────┬────────┘
                      │
        ┌─────────────┼─────────────┐
        │             │             │
   ┌────▼───┐    ┌───▼────┐    ┌───▼────┐
   │ Node A │    │ Node B │    │ Node C │  Rank: 256-384
   │        │    │        │    │        │
   └───┬────┘    └───┬────┘    └────┬───┘
       │             │              │
   ┌───▼────┐    ┌──▼───┐      ┌───▼────┐
   │ Node D │    │Node E│      │ Node F │  Rank: 384-512
   │        │    │      │      │        │
   └────────┘    └──────┘      └────────┘

   ↑ Upward traffic (via preferred parent)
   ↓ Downward traffic (source routing in non-storing mode)
```

### Traffic Flow

**Upward (Node D → Root):**
```
Node D → Node A (preferred parent) → Root
```

**Downward in Non-Storing Mode (Root → Node D):**
```
Root adds source route: [Root, Node A, Node D]
Root → Node A → Node D
```

**Any-to-Any (Node D → Node E):**
```
Node D → Node A → Root → Node B → Node E
```

## Implementations

Contiki-NG provides two implementations of RPL with different attributes: _RPL Classic_ and _RPL Lite_.

### RPL Classic

RPL Classic is the continuation of the original Contiki's RPL implementation: [ContikiRPL](http://www.diva-portal.org/smash/get/diva2:1042739/FULLTEXT01.pdf). This implementation was created as early as 2009, while the RPL standard was still under development. Over the years, it has gotten a lot of functionality that has been added to the RPL RFC and related RFCs, such as support for multiple instances and DODAGs, storing and non-storing mode, multicasting, and more. Hence, at the price of supporting a lot of functionality from standards and Internet drafts, the implementation has become complex and thus has gotten a large ROM footprint.

### RPL Lite

RPL Lite is Contiki-NG's default RPL implementation. It started as a major rewrite of the 2017 version of ContikiRPL, with a focus on the most important and stable functionality, as the community has experienced in many deployments and research experiments. RPL Lite removes support for storing mode in favor of non-storing mode, and removes the complexity of handling multiple instances and DODAGs. Through these changes, RPL Lite typically exhibits better performance and has a considerably smaller ROM footprint. On the flip side of these optimizations, it has a lower interoperability level with other implementations, which may use storing mode for instance.

### Comparison: RPL Lite vs RPL Classic

| Feature | RPL Lite | RPL Classic |
|---------|----------|-------------|
| **Mode of Operation** | Non-storing only | Storing, Non-storing, MOP0 |
| **Instances/DODAGs** | Single instance, single DAG | Multiple instances/DODAGs |
| **Multicast** | No | Yes (storing mode) |
| **ROM Footprint** | ~8-12 KB | ~15-20 KB |
| **RAM per Node** | ~200-300 bytes | ~300-500 bytes |
| **Complexity** | Low | High |
| **Interoperability** | Moderate (non-storing only) | High |
| **Recommended Use** | Most deployments, TSCH networks | Interoperability, storing mode required |

## Modes of Operation (MOP)

The different modes of operation refer to the different ways downward routing is done. However, they also have impact on TSCH Orchestra scheduling, on RAM usage on the nodes, and on packet sizes.

### Mode Comparison

| Aspect | Storing Mode | Non-Storing Mode | MOP0 (No Downward) |
|--------|--------------|------------------|-------------------|
| **Routing Tables** | On all nodes | Root only | None |
| **Downward Headers** | None | IPv6 SRH (large) | N/A |
| **RAM per Node** | High (~500 bytes + routes) | Low (~200 bytes) | Minimal |
| **Root RAM** | Moderate | High (full topology) | Low |
| **Packet Size** | Normal | Large (8 + 16*hops bytes) | Upward only |
| **Orchestra Support** | `unicast_per_neighbor_rpl_storing` | Receiver-based only | Receiver-based only |
| **Scalability** | Limited (memory) | Good | Best (upward only) |

### Storing Mode

For storing mode, routing tables are stored on each node, which can impose a significant memory footprint in large networks and be hard to maintain consistently, but there is on the other hand no need for potentially large source routing headers in the IPv6 packets.

RPL-Lite does not support the storing mode. To enable the storing mode, select RPL-Classic in the Makefile:

```makefile
MAKE_ROUTING = MAKE_ROUTING_RPL_CLASSIC
```

The storing mode is the default for RPL-Classic. Alternatively, it can also be explicitly enabled with:

```c
#define RPL_CONF_MOP RPL_MOP_STORING_NO_MULTICAST
```

or, if multicast routing is desired, with:

```c
#define RPL_CONF_MOP RPL_MOP_STORING_MULTICAST
```

### Non-Storing Mode

For non-storing mode, IPv6 source routing is employed, which means that nodes do not have to store routing tables for nodes below them in the DODAG. On the other hand, packets can get large if many hops are along the path, whose addresses would then need to be embedded in the source routing header. Note that packets traveling upwards are not affected - only downward packets get the extra headers!

The DODAG root node still has to store the routing table of the whole network, so its memory usage will still be high in large networks.

The Orchestra scheduler is also affected by the non-storing mode. The Orchestra rule `unicast_per_neighbor_rpl_storing` cannot be used in this mode, since it relies on routing information on each node.

To enable the non-storing mode, either select RPL-Lite (where it is the default), or use this configuration:

```c
#define RPL_CONF_MOP RPL_MOP_NON_STORING
```

**Source Routing Header Size:**
```
SRH size = 8 + (number_of_hops × 16) bytes

Example: 5-hop path = 8 + (5 × 16) = 88 bytes
```

### Mode of Operation 0 (MOP0)

This mode disables all downward routing. To enable MOP0, explicitly turn off `RPL_CONF_WITH_STORING` and `RPL_CONF_WITH_NON_STORING`:

```c
#define RPL_CONF_WITH_STORING           0
#define RPL_CONF_WITH_NON_STORING       0
#define RPL_CONF_MOP RPL_MOP_NO_DOWNWARD_ROUTES
```

MOP0 is useful for sensor-only deployments where all traffic flows to the root (e.g., monitoring applications).

## RPL Lite: Topology Formation and Configuration

We review here how RPL Lite builds a topology and the configuration parameters that matter most in this process.

### Node Lifecycle

```
BOOT → INITIALIZED → DIS → HEAR DIO → PROBING →
  PARENT SELECTED → DAO → JOINED → DAO-ACK → REACHABLE

States:
- INITIALIZED: Node starts, begins sending DIS
- JOINED: Parent selected, DAO sent
- REACHABLE: DAO-ACK received, node is fully connected
- POISONING: No valid parent, advertising infinite rank
```

### DAG Advertisement

When a node starts running as DAG root (whether it is border router or not), it will advertise the DAG with DIOs (DODAG Information Object).
DIO transmissions follow a Trickle timer (see [RFC 6206](https://tools.ietf.org/html/rfc6206) for the algorithm).

Some important configuration parameters are:
* `NETSTACK_MAX_ROUTE_ENTRIES`: the number of routing entries at the root, which must be set to at least the network size
* `RPL_CONF_SUPPORTED_OFS`: a list of Objective Functions embedded in the node, any of which can be selected at run-time
* `RPL_CONF_OF_OCP`: the Objective Function advertised by the root.
* `RPL_CONF_DIO_INTERVAL_MIN`: the minimum Trickle interval is `2^RPL_CONF_DIO_INTERVAL_MIN` milliseconds. A value of 12 for instance results in 4.096 seconds.
* `RPL_CONF_DIO_INTERVAL_DOUBLINGS`: the maximum Trickle interval is `2^(RPL_CONF_DIO_INTERVAL_MIN+RPL_CONF_DIO_INTERVAL_DOUBLINGS)` milliseconds. A value of 8 (with a min doubling interval of 12) results in a maximum period of 1048.576 seconds (about 17 minutes).
* `RPL_CONF_DIO_REDUNDANCY`: the Trickle redundancy constant, used to suppress DIO transmissions in dense networks. Disabled by default in RPL Lite (value of 0).

### Joining

Nodes willing to join a network will transmit periodic DIS (DODAG Information Solicitation) to trigger Trickle reset at neighboring nodes, and increase their chances to hear a DIO:
* `RPL_CONF_DIS_INTERVAL`: the interval at which nodes looking for a DAG or a parent will send DIS messages

Whenever hearing a DIO, the node might choose to join the DAG. The first thing needed then is to select a RPL preferred parent. Because RPL Lite focuses on reliability, nodes do not select a parent until they have a precise estimate of their link quality to the neighbor (the `link-stats` module provides a freshness indicator for that purpose). Nodes will then perform link-probing to assess their neighbors' link:
* `RPL_CONF_PROBING_SEND_FUNC`: the probing function. By default, probing is simply a unicast DIO to the target neighbor
* `RPL_CONF_PROBING_INTERVAL`: the interval at which background probing is done, in clock ticks
* `RPL_CONF_PROBING_DELAY_FUNC`: the function that calculates the next delay. By default, the delay is dynamic: if there is urgent need for probing (when the node has no usable parent), probing will happen within seconds, else, some random interval based on `RPL_CONF_PROBING_INTERVAL`
* `RPL_CONF_PROBING_SELECT_FUNC`: the function that selects the next probing target. The default function probes the urgent probing target if any, or the preferred parent if its link statistics need refresh. Otherwise, it picks at random between (1) selecting the best neighbor with non-fresh link statistics, or (2) selecting the least recently updated neighbor

### Preferred Parent Selection

After enough probing, the node will select a neighbor as preferred parent. This is according to the selected Objective Function and metric. By default, MRHOF and ETX are used. There are a number of important configuration parameters for link estimation and Objective Function:
* `LINK_STATS_CONF_INIT_ETX_FROM_RSSI`: this is part of the `link-stats` module. When set (default), nodes estimate their neighbors' link quality when first hearing from them, based on the RSSI of, e.g, an incoming DIO. For a deeper understanding of how this is calculated, as well as how link quality is later maintained, take a look at `link-stats.c`
* `RPL_MRHOF_CONF_SQUARED_ETX`: when set, MRHOF will square the link ETX before adding it to the parent rank for path cost calculation. This results in more reliable paths, as it penalizes higher link ETX. Stronger links are typically selected, at the expense of longer paths and higher churn. The feature is disabled by default, as the higher churn can result in unstable operation in networks with poor links. Check out `rpl-mrhof.c` or `rpl-of0.c` for more configuration options.

### Route Registration

Once a preferred parent is chosen, a node will then register itself through a DAO (Destination Advertisement Object). In non-storing mode (only mode in RPL lite), the DAO is sent directly to the root, using global IPv6 addresses. Upon receiving the DAO, the root will add the node to its routing state: it will store the child-parent relationship, used later for source routing. In RPL Lite, by default, DAO messages have the 'K' bit set, which means they must be acknowledged by the root:
* `RPL_CONF_DAO_RETRANSMISSION_TIMEOUT`: the delay after which nodes resend their DAO in case no DAO-ACK was received
* `RPL_CONF_DAO_MAX_RETRANSMISSIONS`: the maximum number of DAO retransmissions
* `RPL_CONF_DEFAULT_LIFETIME_UNIT`: the unit, in seconds, used for lifetime in DAO messages
* `RPL_CONF_DEFAULT_LIFETIME`: the lifetime, in lifetime units, advertised in DAO messages. The DAG root will delete the route after this lifetime expires. Nodes will resend a DAO automatically within 1-2 minutes before expiry.

After receiving a DAO-ACK, nodes know they are fully part of the network and reachable.
Only then will they start advertising DIOs in turn, and let more nodes join, forming a multi-hop mesh network.
* `RPL_CONF_DEFAULT_LEAF_ONLY`: if this is set, the node will join but only as a leaf, i.e., it will not send any DIO and will never be selected as parent

### DAG Maintenance

When a node is part of a DAG, it will constantly maintain link estimates via probing, keep its preferred parent up to date, and advertise the DAG root accordingly. RPL local repairs (reset Trickle timer, reset link statistics) are performed when needed as required in the standard. When a node undergoes a significant rank change, it will also reset its Trickle timer for quicker topology update:
* `RPL_CONF_SIGNIFICANT_CHANGE_THRESHOLD`: the rank change threshold for Trickle reset. Whenever the current rank differs form the last advertised rank by at least this threshold, the node resets its Trickle.

When a node finds no more suitable preferred parent, it will start poisoning, i.e., advertise an infinite rank to let its sub-DAG know it no longer is a valid parent. It will then leave the network after a delay:
* `RPL_CONF_DELAY_BEFORE_LEAVING`: the delay after which a node actually leaves a network, by default, 5 minutes.

During this delay, the node performs poisoning. Meanwhile, it also starts sending periodic DIS again, in hope to discover a new usable parent. If this happens, the node will directly stop poisoning and consider itself part of the DAG again. If not, it will eventually leave the DAG after the delay and send DIS until it joins a new DAG.

## Configuration Reference

### Complete Configuration Parameters

For an extensive list with defaults, see `os/net/routing/rpl-lite/rpl-conf.h`

#### Feature Toggles

| Parameter | Default | Description |
|-----------|---------|-------------|
| `RPL_CONF_MOP` | `RPL_MOP_NON_STORING` | Mode of operation |
| `RPL_CONF_WITH_NON_STORING` | 1 | Enable non-storing mode support |
| `RPL_CONF_WITH_DAO_ACK` | 1 | Enable DAO acknowledgments |
| `RPL_CONF_WITH_PROBING` | 1 | Enable link probing |
| `RPL_CONF_WITH_MC` | 0 | Enable Metric Containers |
| `RPL_CONF_DEFAULT_LEAF_ONLY` | 0 | Node joins only as leaf |
| `RPL_CONF_LOOP_ERROR_DROP` | 0 | Drop packets on loop detection |
| `RPL_CONF_GROUNDED` | 0 | Advertise grounded DAG |

#### Timing Parameters

| Parameter | Default | Description | Typical Range |
|-----------|---------|-------------|---------------|
| `RPL_CONF_DIO_INTERVAL_MIN` | 12 | Min DIO interval: 2^n ms | 8-14 (256ms-16s) |
| `RPL_CONF_DIO_INTERVAL_DOUBLINGS` | 8 | Trickle interval doublings | 6-12 |
| `RPL_CONF_DIO_REDUNDANCY` | 0 | Trickle redundancy constant | 0-10 |
| `RPL_CONF_DIS_INTERVAL` | 30 seconds | DIS transmission interval | 10-60s |
| `RPL_CONF_PROBING_INTERVAL` | 90 seconds | Link probing interval | 30-300s |
| `RPL_CONF_DAO_DELAY` | 4 seconds | DAO transmission delay | 1-10s |
| `RPL_CONF_DAO_RETRANSMISSION_TIMEOUT` | 5 seconds | DAO retransmission timeout | 3-10s |
| `RPL_CONF_DAO_MAX_RETRANSMISSIONS` | 5 | Max DAO retransmissions | 3-10 |
| `RPL_CONF_DELAY_BEFORE_LEAVING` | 5 minutes | Poisoning duration | 1-10 min |
| `RPL_CONF_DEFAULT_LIFETIME` | 30 | Route lifetime (in units) | 10-255 |
| `RPL_CONF_DEFAULT_LIFETIME_UNIT` | 60 seconds | Route lifetime unit | 30-120s |
| `RPL_CONF_DAG_LIFETIME` | 480 minutes | DAG maximum lifetime | 60-1440 min |

#### Rank and Metric Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `RPL_CONF_MIN_HOPRANKINC` | 128 (MRHOF), 256 (OF0) | Minimum rank increase per hop |
| `RPL_CONF_MAX_RANKINC` | 8 × MIN_HOPRANKINC | Maximum rank increase |
| `RPL_CONF_SIGNIFICANT_CHANGE_THRESHOLD` | 4 × MIN_HOPRANKINC | Rank change for Trickle reset |
| `LINK_STATS_CONF_INIT_ETX_FROM_RSSI` | 1 | Initialize ETX from RSSI |
| `RPL_MRHOF_CONF_SQUARED_ETX` | 0 | Square ETX in MRHOF |

#### Objective Functions

| Parameter | Default | Description |
|-----------|---------|-------------|
| `RPL_CONF_OF_OCP` | `RPL_OCP_MRHOF` | Root's objective function |
| `RPL_CONF_SUPPORTED_OFS` | `{&rpl_mrhof}` | List of supported OFs |
| `RPL_CONF_DAG_MC` | `RPL_DAG_MC_NONE` | Metric container type |

**Objective Function Options:**
- `RPL_OCP_OF0`: OF0 (RFC 6552) - hop count based
- `RPL_OCP_MRHOF`: MRHOF (RFC 6719) - ETX-based (default)

#### Function Hooks

| Parameter | Default | Description |
|-----------|---------|-------------|
| `RPL_CONF_PROBING_SEND_FUNC` | `rpl_icmp6_dio_output(addr)` | Function to send probes |
| `RPL_CONF_PROBING_SELECT_FUNC` | `get_probing_target` | Select next probing target |
| `RPL_CONF_PROBING_DELAY_FUNC` | `get_probing_delay` | Calculate probing delay |
| `RPL_CONF_VALIDATE_DIO_FUNC` | None | Validate DIO before joining |
| `RPL_CALLBACK_PARENT_SWITCH` | `tsch_rpl_callback_parent_switch` (TSCH) | Called on parent switch |
| `RPL_CALLBACK_NEW_DIO_INTERVAL` | `tsch_rpl_callback_new_dio_interval` (TSCH) | Called on DIO interval change |

#### Other Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `RPL_CONF_DEFAULT_INSTANCE` | 0 | Default RPL instance ID |
| `RPL_CONF_PREFERENCE` | 0 | DAG preference field (0-7) |
| `RPL_CONF_TRICKLE_REFRESH_DAO_ROUTES` | 4 (no DAO-ACK), 0 (with DAO-ACK) | DTSN refresh interval |
| `NETSTACK_MAX_ROUTE_ENTRIES` | Platform-dependent | Max routing entries at root |

### Configuration Examples

#### High-Reliability Network (TSCH)
```c
/* Slower convergence, more reliable */
#define RPL_CONF_DIO_INTERVAL_MIN 13          /* 8.192s */
#define RPL_CONF_DIO_INTERVAL_DOUBLINGS 10    /* Max: 8388s (~2.3 hours) */
#define RPL_CONF_PROBING_INTERVAL (120 * CLOCK_SECOND)
#define RPL_CONF_DAO_MAX_RETRANSMISSIONS 8
#define RPL_MRHOF_CONF_SQUARED_ETX 1          /* Prefer strong links */
```

#### Fast Convergence Network (Good Links)
```c
/* Faster convergence, lower overhead */
#define RPL_CONF_DIO_INTERVAL_MIN 10          /* 1.024s */
#define RPL_CONF_DIO_INTERVAL_DOUBLINGS 6     /* Max: 65s */
#define RPL_CONF_DIS_INTERVAL (10 * CLOCK_SECOND)
#define RPL_CONF_PROBING_INTERVAL (30 * CLOCK_SECOND)
#define RPL_CONF_SIGNIFICANT_CHANGE_THRESHOLD (2 * RPL_MIN_HOPRANKINC)
```

#### Battery-Powered Sensors (Upward Only)
```c
/* Minimal control traffic */
#define RPL_CONF_MOP RPL_MOP_NO_DOWNWARD_ROUTES
#define RPL_CONF_DEFAULT_LEAF_ONLY 1          /* Never become parent */
#define RPL_CONF_DIO_INTERVAL_MIN 14          /* 16.384s */
#define RPL_CONF_PROBING_INTERVAL (300 * CLOCK_SECOND)
#define RPL_CONF_WITH_DAO_ACK 0               /* Use DTSN refresh */
#define RPL_CONF_TRICKLE_REFRESH_DAO_ROUTES 6
```

#### Large Network (100+ nodes)
```c
/* Root configuration */
#define NETSTACK_MAX_ROUTE_ENTRIES 128        /* Accommodate all nodes */
#define RPL_CONF_DAO_RETRANSMISSION_TIMEOUT (10 * CLOCK_SECOND)

/* All nodes */
#define RPL_CONF_DEFAULT_LIFETIME 60          /* 60-minute routes */
#define RPL_CONF_DEFAULT_LIFETIME_UNIT 60
```

## API Reference

### DAG Root APIs

Defined in `os/net/routing/rpl-lite/rpl-dag-root.h`

| Function | Description |
|----------|-------------|
| `rpl_dag_root_set_prefix(prefix, iid)` | Set prefix before starting as root. Use NULL for defaults. |
| `rpl_dag_root_start()` | Start as DAG root. Returns 0 on success, -1 on failure. |
| `rpl_dag_root_is_root()` | Returns 1 if node is DAG root, 0 otherwise. |
| `rpl_dag_root_print_links(str)` | Print routing table (debug). |

### Regular Node APIs

Defined in `os/net/routing/rpl-lite/rpl.h`

| Function | Description |
|----------|-------------|
| `rpl_set_prefix(prefix)` | Set prefix from DIO prefix structure. |
| `rpl_set_prefix_from_addr(addr, len, flags)` | Set prefix from IPv6 address. |
| `rpl_reset_prefix(last_prefix)` | Remove current prefix. |
| `rpl_get_global_address()` | Get node's global IPv6 address. |
| `rpl_is_reachable()` | Returns 1 if node is reachable (has downward route). |
| `rpl_set_leaf_only(value)` | Set/unset leaf-only mode. |
| `rpl_get_leaf_only()` | Get leaf-only mode status. |
| `rpl_refresh_routes(str)` | Trigger route refresh via DTSN increment. |
| `rpl_link_callback(addr, status, numtx)` | Called by MAC layer after transmission. |
| `rpl_lollipop_greater_than(a, b)` | Compare lollipop counters. |

### ICMPv6 Message APIs

Defined in `os/net/routing/rpl-lite/rpl-icmp6.h`

| Function | Description |
|----------|-------------|
| `rpl_icmp6_dis_output(addr)` | Send DIS (multicast if addr is NULL). |
| `rpl_icmp6_dio_output(addr)` | Send DIO (multicast if addr is NULL). |
| `rpl_icmp6_dao_output(lifetime)` | Send DAO to root. Use lifetime=0 for No-path DAO. |
| `rpl_icmp6_dao_ack_output(dest, seq, status)` | Send DAO-ACK. |
| `rpl_icmp6_init()` | Initialize RPL ICMPv6 handlers. |

## Code Examples

### Border Router Setup

```c
#include "net/routing/rpl-lite/rpl.h"
#include "net/routing/rpl-lite/rpl-dag-root.h"
#include "net/ipv6/uip-ds6.h"

void
start_border_router(void)
{
  uip_ipaddr_t prefix;

  /* Set prefix: fd00::/64 */
  uip_ip6addr(&prefix, 0xfd00, 0, 0, 0, 0, 0, 0, 0);
  rpl_dag_root_set_prefix(&prefix, NULL);

  /* Start as DAG root */
  if(rpl_dag_root_start() < 0) {
    LOG_ERR("Failed to start as DAG root\n");
  } else {
    LOG_INFO("Started as DAG root\n");
  }
}
```

### Regular Node (Automatic Join)

```c
#include "net/routing/rpl-lite/rpl.h"

PROCESS_THREAD(rpl_node_process, ev, data)
{
  PROCESS_BEGIN();

  /* RPL joins automatically - just wait */
  PROCESS_WAIT_UNTIL(rpl_is_reachable());

  LOG_INFO("Joined RPL network\n");
  LOG_INFO("Global address: ");
  LOG_INFO_6ADDR(rpl_get_global_address());
  LOG_INFO_("\n");

  /* Application code here */

  PROCESS_END();
}
```

### Leaf-Only Mode (Battery Device)

```c
#include "net/routing/rpl-lite/rpl.h"

void
configure_battery_node(void)
{
  /* Never become parent - save energy */
  rpl_set_leaf_only(1);

  LOG_INFO("Configured as leaf-only node\n");
}
```

### Monitoring RPL State

```c
#include "net/routing/rpl-lite/rpl.h"
#include "net/routing/rpl-lite/rpl-dag.h"

void
print_rpl_status(void)
{
  if(!curr_instance.used) {
    LOG_INFO("Not part of any RPL network\n");
    return;
  }

  rpl_dag_t *dag = &curr_instance.dag;

  LOG_INFO("RPL Status:\n");
  LOG_INFO("  State: %d\n", dag->state);
  LOG_INFO("  Rank: %u\n", dag->rank);
  LOG_INFO("  DAG Rank: %u\n", DAG_RANK(dag->rank));

  if(dag->preferred_parent) {
    const linkaddr_t *addr = rpl_neighbor_get_lladdr(dag->preferred_parent);
    LOG_INFO("  Parent: ");
    LOG_INFO_LLADDR(addr);
    LOG_INFO_("\n");
    LOG_INFO("  Parent Rank: %u\n", dag->preferred_parent->rank);
  } else {
    LOG_INFO("  No preferred parent\n");
  }
}
```

### Custom Probing Function

```c
#include "net/routing/rpl-lite/rpl-icmp6.h"

void
my_probing_func(const uip_ipaddr_t *addr)
{
  /* Custom probing - e.g., piggyback on application data */
  LOG_DBG("Probing ");
  LOG_DBG_6ADDR(addr);
  LOG_DBG_("\n");

  /* Send unicast DIO as probe */
  rpl_icmp6_dio_output((uip_ipaddr_t *)addr);

  /* Or implement custom probe packet */
}

/* In project-conf.h: */
/* #define RPL_CONF_PROBING_SEND_FUNC my_probing_func */
```

### Integrating with Application (CoAP Server)

```c
#include "net/routing/rpl-lite/rpl.h"
#include "coap-engine.h"

extern coap_resource_t res_temperature;

PROCESS_THREAD(coap_sensor_process, ev, data)
{
  PROCESS_BEGIN();

  /* Wait for RPL to establish connectivity */
  PROCESS_WAIT_UNTIL(rpl_is_reachable());

  LOG_INFO("RPL connected - starting CoAP server\n");

  /* Activate CoAP resources */
  coap_activate_resource(&res_temperature, "sensors/temp");

  /* Application continues */
  while(1) {
    PROCESS_WAIT_EVENT();
  }

  PROCESS_END();
}
```

### Triggering Route Refresh

```c
void
handle_topology_change(void)
{
  if(rpl_dag_root_is_root()) {
    /* Root: increment DTSN to refresh all routes */
    rpl_refresh_routes("topology change detected");
    LOG_INFO("Triggered global route refresh\n");
  }
}
```

## ICMPv6 Messages

RPL uses four ICMPv6 message types for control traffic. For detailed packet formats, see [RFC 6550](https://tools.ietf.org/html/rfc6550).

### Message Types

| Message | Code | Direction | Purpose |
|---------|------|-----------|---------|
| **DIS** | 0x00 | Multicast/Unicast | Solicit DIO messages from neighbors |
| **DIO** | 0x01 | Multicast/Unicast | Advertise DAG information (rank, OF, etc.) |
| **DAO** | 0x02 | Unicast to root | Register route (advertise presence) |
| **DAO-ACK** | 0x03 | Unicast to node | Acknowledge DAO reception |

### DAO Status Codes

| Status Code | Meaning |
|-------------|---------|
| 0 | Unconditional accept |
| 1-127 | Accept (but with issues) |
| 128+ | Unable to accept |
| 255 | Root cannot add route |
| -1 (local) | DAO-ACK timeout |

### Message Options

See [RFC 6550 Section 6.7](https://tools.ietf.org/html/rfc6550#section-6.7) for option formats.

| Option | Code | Used In | Purpose |
|--------|------|---------|---------|
| PAD1 | 0 | All | Single-byte padding |
| PADN | 1 | All | Multi-byte padding |
| DAG Metric Container | 2 | DIO | Carry path metrics |
| Route Information | 3 | DIO | Advertise routes |
| DAG Configuration | 4 | DIO | DAG parameters (Imin, k, etc.) |
| Target | 5 | DAO | Advertised prefix |
| Transit | 6 | DAO | Parent information |
| Solicited Information | 7 | DIS | Request specific info |
| Prefix Information | 8 | DIO | IPv6 prefix |

## Objective Functions

RPL uses Objective Functions (OF) to calculate path cost and select parents. Contiki-NG supports two standard OFs.

### Comparison: MRHOF vs OF0

| Aspect | MRHOF (RFC 6719) | OF0 (RFC 6552) |
|--------|------------------|----------------|
| **Primary Metric** | ETX (link quality) | Hop count |
| **Path Selection** | Minimum ETX path | Minimum hop count |
| `MIN_HOPRANKINC` | 128 (matches ETX scale) | 256 (standard) |
| **Rank Calculation** | `parent_rank + link_ETX * 128 + 128` | `parent_rank + 256` |
| **Link Quality** | Critical | Not considered |
| **Path Length** | May be longer | Shortest |
| **Stability** | More stable (quality-aware) | Less stable |
| **Use Case** | Lossy networks, TSCH | Simple networks, good links |
| **Default** | Yes | No |

For algorithm details, see:
- MRHOF: [RFC 6719](https://tools.ietf.org/html/rfc6719)
- OF0: [RFC 6552](https://tools.ietf.org/html/rfc6552)
- Metrics: [RFC 6551](https://tools.ietf.org/html/rfc6551)

### Configuration

```c
/* Select OF for root */
#define RPL_CONF_OF_OCP RPL_OCP_MRHOF    /* or RPL_OCP_OF0 */

/* Nodes can support multiple OFs */
#define RPL_CONF_SUPPORTED_OFS {&rpl_mrhof, &rpl_of0}

/* MRHOF-specific: square ETX for stronger preference */
#define RPL_MRHOF_CONF_SQUARED_ETX 1
```

### Rank Calculation

```c
/* Simplified rank calculation (actual is in OF code) */
rank = parent_rank + link_metric + MIN_HOPRANKINC

/* MRHOF example: */
/* link ETX = 1.5 (represented as 192 with divisor 128) */
/* parent rank = 256 */
/* rank = 256 + 192 + 128 = 576 */

/* OF0 example: */
/* parent rank = 512 */
/* rank = 512 + 256 = 768 */

/* Convert rank to DAG rank (hops): */
/* dag_rank = rank / MIN_HOPRANKINC */
```

## Troubleshooting

### Common Issues and Solutions

#### 1. Network Not Forming

**Symptoms:**
- Root starts but no nodes join
- Nodes send DIS but never transition to JOINED state

**Possible Causes and Solutions:**
- **Root not advertising DIO**: Check that `rpl_dag_root_start()` returns 0
- **Nodes not hearing DIO**: Check radio configuration, transmission power
- **DIO interval too long**: Reduce `RPL_CONF_DIO_INTERVAL_MIN`
- **Check logs**: Enable RPL logging with `#define LOG_CONF_LEVEL_RPL LOG_LEVEL_DBG`

```c
/* Debug logging */
#define LOG_CONF_LEVEL_RPL LOG_LEVEL_DBG
```

#### 2. Nodes Not Joining (Stuck at DIS)

**Symptoms:**
- Nodes continuously send DIS
- State remains INITIALIZED

**Possible Causes:**
- **OF mismatch**: Node doesn't support root's OF
  ```c
  /* Ensure OF is in supported list */
  #define RPL_CONF_SUPPORTED_OFS {&rpl_mrhof, &rpl_of0}
  ```
- **No probing**: Links not fresh enough for parent selection
  ```c
  /* Reduce probing delay for urgent probing */
  #define RPL_CONF_PROBING_INTERVAL (30 * CLOCK_SECOND)
  ```
- **ETX too high**: No neighbors with acceptable link quality
  - Check `LINK_STATS_CONF_INIT_ETX_FROM_RSSI`
  - Check physical RF environment

#### 3. DAO-ACK Timeout

**Symptoms:**
- Nodes reach JOINED state but not REACHABLE
- Repeated DAO transmissions (up to max retries)
- Log: "DAO-ACK timeout"

**Possible Causes:**
- **Root unreachable**: Check multi-hop path to root
- **Root not processing DAO**: Check root has enough memory
  ```c
  #define NETSTACK_MAX_ROUTE_ENTRIES 64  /* Increase if needed */
  ```
- **Timeout too short**: Increase for multi-hop networks
  ```c
  #define RPL_CONF_DAO_RETRANSMISSION_TIMEOUT (10 * CLOCK_SECOND)
  ```
- **DAO lost in transit**: Increase max retransmissions
  ```c
  #define RPL_CONF_DAO_MAX_RETRANSMISSIONS 8
  ```

#### 4. Poor Parent Selection / Frequent Parent Switching

**Symptoms:**
- Node frequently changes preferred parent
- Suboptimal parents selected (high ETX)
- Unstable network topology

**Possible Causes:**
- **Probing too infrequent**: Links not kept fresh
  ```c
  #define RPL_CONF_PROBING_INTERVAL (60 * CLOCK_SECOND)
  ```
- **Significant change threshold too low**: Triggers unnecessary updates
  ```c
  #define RPL_CONF_SIGNIFICANT_CHANGE_THRESHOLD (8 * RPL_MIN_HOPRANKINC)
  ```
- **ETX calculation issues**: Check link-stats module
- **Bad links**: Physical environment, interference

**Solution for Stable Networks:**
```c
/* Prefer stable, strong links */
#define RPL_MRHOF_CONF_SQUARED_ETX 1
#define RPL_CONF_SIGNIFICANT_CHANGE_THRESHOLD (8 * RPL_MIN_HOPRANKINC)
```

#### 5. High Control Traffic / Battery Drain

**Symptoms:**
- Excessive DIO transmissions
- High energy consumption
- Network saturated with control packets

**Possible Causes:**
- **Trickle redundancy disabled**: All nodes transmit DIOs
  ```c
  #define RPL_CONF_DIO_REDUNDANCY 10  /* Suppress redundant DIOs */
  ```
- **DIO intervals too short**: Increase Imin/Imax
  ```c
  #define RPL_CONF_DIO_INTERVAL_MIN 13           /* 8.192s */
  #define RPL_CONF_DIO_INTERVAL_DOUBLINGS 10     /* Max: ~2.3 hours */
  ```
- **Frequent Trickle resets**: Increase significant change threshold
- **Probing too frequent**:
  ```c
  #define RPL_CONF_PROBING_INTERVAL (120 * CLOCK_SECOND)
  ```

**Solution for Battery Devices:**
```c
#define RPL_CONF_DEFAULT_LEAF_ONLY 1      /* Don't forward */
#define RPL_CONF_DIO_INTERVAL_MIN 14      /* 16s */
#define RPL_CONF_PROBING_INTERVAL (300 * CLOCK_SECOND)
```

#### 6. Routing Loops

**Symptoms:**
- Packets circulate between nodes
- High packet loss
- Log: "RPL loop detected"

**Possible Causes:**
- **Inconsistent topology**: Nodes have outdated rank information
- **Loop detection disabled**: Enable loop error handling
  ```c
  #define RPL_CONF_LOOP_ERROR_DROP 1
  ```
- **Rapid topology changes**: Network not converging

**Solutions:**
- Ensure Trickle properly configured
- Check for interference causing link quality fluctuations
- Use TSCH for more predictable link quality

#### 7. Root Memory Exhaustion (Non-Storing Mode)

**Symptoms:**
- DAO-ACK with status 255 (unable to add route)
- Root cannot track all nodes
- Log: "Routing table full"

**Solution:**
```c
/* Increase routing table size at root */
#define NETSTACK_MAX_ROUTE_ENTRIES 128  /* Match network size */
```

#### 8. Large Packet Headers (Non-Storing Mode)

**Symptoms:**
- Downward packets fail or are fragmented
- Packet loss for deep networks

**Cause:**
- Source routing header size: `8 + (hops × 16)` bytes

**Solutions:**
- Use storing mode (RPL Classic) for deep networks
- Reduce payload size to accommodate header
- Limit network depth
- Use MOP0 (upward-only) if downward traffic not needed

#### 9. Slow Network Convergence

**Symptoms:**
- Nodes take long time (minutes) to join
- Slow response to topology changes

**Solutions:**
```c
/* Faster convergence */
#define RPL_CONF_DIO_INTERVAL_MIN 10               /* 1s */
#define RPL_CONF_DIS_INTERVAL (10 * CLOCK_SECOND)
#define RPL_CONF_PROBING_INTERVAL (30 * CLOCK_SECOND)
#define RPL_CONF_SIGNIFICANT_CHANGE_THRESHOLD (2 * RPL_MIN_HOPRANKINC)
```

#### 10. TSCH Integration Issues

**Symptoms:**
- RPL forms but TSCH not synchronized
- Orchestra scheduling conflicts

**Solutions:**
- Ensure TSCH callbacks enabled (automatic with TSCH)
- Check Orchestra rules:
  ```c
  /* Use receiver-based rules with non-storing mode */
  MAKE_MAC = MAKE_MAC_TSCH
  /* In Orchestra config: */
  /* - unicast_per_neighbor_rpl_ns (non-storing) */
  /* - Not unicast_per_neighbor_rpl_storing */
  ```
- Check parent switch callback:
  ```c
  #define RPL_CALLBACK_PARENT_SWITCH tsch_rpl_callback_parent_switch
  ```

### Debug Logging

```c
/* Enable RPL debug logging */
#define LOG_CONF_LEVEL_RPL LOG_LEVEL_DBG

/* Key log events to watch for: */
/* - "Starting as DAG root" */
/* - "Joining DAG" */
/* - "Selected parent" */
/* - "DAO sent" */
/* - "DAO-ACK received" */
/* - "Now reachable" */
```

## Best Practices

### 1. Root Configuration
```c
/* Always set adequate routing table size */
#define NETSTACK_MAX_ROUTE_ENTRIES <network_size>

/* Use well-known prefix */
uip_ip6addr(&prefix, 0xfd00, 0, 0, 0, 0, 0, 0, 0);  /* fd00::/64 */
```

### 2. Leaf Devices
```c
/* Battery-powered sensors should be leaves */
#define RPL_CONF_DEFAULT_LEAF_ONLY 1
```

### 3. Network Sizing
- **Small (<10 nodes)**: Use default configuration
- **Medium (10-50 nodes)**: Increase `NETSTACK_MAX_ROUTE_ENTRIES`, tune DIO intervals
- **Large (50-100+ nodes)**: Increase route lifetime, careful tuning of all timers

### 4. Timing Configuration
- **Good links**: Shorter intervals for fast convergence
- **Lossy links**: Longer intervals, enable DIO redundancy
- **TSCH**: Longer intervals aligned with slotframe length

### 5. Objective Function Selection
- **MRHOF**: Default, best for most networks
- **OF0**: Only for simple networks with good, stable links
- **Squared ETX**: Enable for very lossy networks, disable for stability

### 6. DAO Configuration
- **Reliable networks**: Use DAO-ACK (default)
- **Lossy networks**: Consider DTSN-based refresh instead
  ```c
  #define RPL_CONF_WITH_DAO_ACK 0
  #define RPL_CONF_TRICKLE_REFRESH_DAO_ROUTES 4
  ```

### 7. Integration with TSCH
- Always use non-storing mode with TSCH
- Use Orchestra receiver-based rules
- Callbacks are automatically configured

### 8. Testing and Debugging
1. Start with root alone, verify DIO transmission
2. Add nodes one at a time initially
3. Enable debug logging during development
4. Monitor convergence time and control traffic
5. Test topology changes (node failures, additions)

### 9. Deployment Checklist
- [ ] Root configured with correct prefix
- [ ] `NETSTACK_MAX_ROUTE_ENTRIES` ≥ network size
- [ ] Objective function selected (MRHOF default)
- [ ] Timing parameters tuned for network characteristics
- [ ] Leaf nodes configured as leaf-only if appropriate
- [ ] Debug logging disabled for production
- [ ] Control traffic overhead measured and acceptable
- [ ] Convergence time tested and acceptable
- [ ] Parent switching behavior tested
- [ ] Battery lifetime projected for leaf nodes

### 10. Common Mistakes to Avoid
- Don't use storing mode Orchestra rules with non-storing mode
- Don't set DIO interval too short (wastes energy)
- Don't set DIO interval too long (slow convergence)
- Don't forget to increase `NETSTACK_MAX_ROUTE_ENTRIES` at root
- Don't disable DAO-ACK without enabling DTSN refresh
- Don't enable squared ETX in highly dynamic/lossy networks
- Don't mix RPL Lite and RPL Classic in same network (compatibility issues)

## Performance Considerations

### Memory Usage

**Per Node (RPL Lite):**
- Code (ROM): ~8-12 KB
- Data (RAM): ~200-300 bytes
- Plus neighbor table: ~50 bytes × number of neighbors

**Root (Non-Storing Mode):**
- Plus routing table: ~50-70 bytes × number of nodes

**Example: 50-node network:**
- Root: ~200 bytes + (50 × 60 bytes) = ~3.2 KB RAM
- Regular node: ~250 bytes RAM

### Control Traffic Overhead

**DIO Traffic:**
```
Average DIO rate ≈ 1 / (Imin × 2^(doublings/2))
With Imin=12 (4s), doublings=8: ≈ 1 DIO per 64 seconds per node

For N nodes: ~N/64 DIOs per second in steady state
50 nodes: ~0.78 DIOs/second
```

**Probing Traffic:**
```
Probing rate = 1 / probing_interval per node
With 90s interval: 1 probe per 90s per node

For N nodes: N/90 probes per second
50 nodes: ~0.56 probes/second
```

**DAO Traffic:**
```
DAO refresh = 1 / (lifetime × 0.5) per node
With 30-minute lifetime: ~1 DAO per 15 minutes per node

For N nodes during join: N DAOs total
For maintenance: N/(15*60) DAOs per second
50 nodes: ~0.056 DAOs/second
```

### Convergence Time

**Node Join Time:**
```
Typical: 10-60 seconds
Factors:
- DIS interval (default 30s)
- Probing required before parent selection
- DAO-ACK round-trip time

Fast config: ~10 seconds
Conservative config: ~60 seconds
```

**Network Formation Time:**
```
For N nodes: Join_time + (depth × DAO_delay)
Example: 50 nodes, depth=5: ~60s + (5 × 4s) = ~80 seconds
```

### Scalability

RPL Lite has been tested in networks up to:
- **100+ nodes**: Tested successfully in simulations and real deployments
- **Depth**: Up to 10-15 hops (limited by source routing header size in non-storing mode)
- **Density**: Up to 20-30 neighbors per node

**Limitations:**
- Non-storing mode: Root memory scales with N nodes
- Source routing header: ~16 bytes per hop (limits max hops)
- DAO traffic during mass joins: Can congest network

## Integration with Other Protocols

### TSCH and Orchestra

RPL Lite integrates seamlessly with TSCH. The Orchestra scheduler automatically adapts to RPL topology changes via callbacks.

```c
/* Callbacks are automatic when TSCH is enabled */
#define MAC_CONF_WITH_TSCH 1

/* Orchestra rules for non-storing mode: */
/* - eb_per_time_source: Minimal schedule */
/* - unicast_per_neighbor_rpl_ns: Non-storing unicast */
/* - default_common: Broadcast */
```

**Parent Switch Callback:**
When preferred parent changes, Orchestra updates the unicast schedule.

**DIO Interval Callback:**
Orchestra may adjust schedule based on network stability.

### 6LoWPAN

RPL works with 6LoWPAN header compression:
- RPL Hop-by-Hop option compressed
- Source routing headers compressed when possible
- See [RFC 6282](https://tools.ietf.org/html/rfc6282) for compression details

### Border Router

The RPL root typically acts as border router:
- Connects RPL network to external IPv6 network
- Handles prefix delegation
- May perform NAT64/DNS64 for IPv4 connectivity

See `examples/rpl-border-router/` for complete implementation.

## Advanced Topics

### Custom Objective Function

To implement a custom OF:

1. Create OF structure:
```c
static void reset(void);
static uint16_t nbr_link_metric(rpl_nbr_t *nbr);
/* ... implement all 8 callbacks ... */

const rpl_of_t my_of = {
  reset,
  nbr_link_metric,
  nbr_has_usable_link,
  nbr_is_acceptable_parent,
  nbr_path_cost,
  rank_via_nbr,
  best_parent,
  update_metric_container,
  MY_OCP  /* Define custom OCP value */
};
```

2. Add to supported OFs:
```c
#define RPL_CONF_SUPPORTED_OFS {&my_of}
```

See `os/net/routing/rpl-lite/rpl-mrhof.c` for reference implementation.

### Global Repair

Trigger network-wide topology reconstruction:
```c
/* At root: increment version number */
void
trigger_global_repair(void)
{
  if(rpl_dag_root_is_root()) {
    /* Version increment triggers global repair */
    curr_instance.dag.version++;
    rpl_reset_dio_timer();  /* Advertise new version */
  }
}
```

### Local Repair

Handle local connectivity issues:
```c
/* Triggered automatically when: */
/* - No valid parent found */
/* - Link quality degradation */
/* - Parent unreachable */

/* Manual trigger: */
rpl_local_repair("application triggered");
```

### DIO Validation Hook

Validate DIO before joining:
```c
int
my_dio_validator(rpl_dio_t *dio)
{
  /* Custom validation logic */
  if(dio->rank > MAX_ACCEPTABLE_RANK) {
    return 0;  /* Reject */
  }
  return 1;  /* Accept */
}

/* In project-conf.h: */
/* #define RPL_CONF_VALIDATE_DIO_FUNC my_dio_validator */
```

### Lollipop Counters

RPL uses lollipop counters for version numbers and DTSN. See [RFC 6550 Section 7.2](https://tools.ietf.org/html/rfc6550#section-7.2) for algorithm details.

```c
/* Compare lollipop counters */
if(rpl_lollipop_greater_than(new_version, old_version)) {
  /* new_version is newer */
}
```

## References

### RFCs and Standards
- [RFC 6550](https://tools.ietf.org/html/rfc6550) - RPL: IPv6 Routing Protocol for Low-Power and Lossy Networks
- [RFC 6206](https://tools.ietf.org/html/rfc6206) - The Trickle Algorithm
- [RFC 6719](https://tools.ietf.org/html/rfc6719) - The Minimum Rank with Hysteresis Objective Function (MRHOF)
- [RFC 6552](https://tools.ietf.org/html/rfc6552) - Objective Function Zero for RPL (OF0)
- [RFC 6551](https://tools.ietf.org/html/rfc6551) - Routing Metrics Used for Path Calculation in RPL
- [RFC 6282](https://tools.ietf.org/html/rfc6282) - Compression Format for IPv6 Datagrams over IEEE 802.15.4

### Implementation Documentation
- RPL Lite source: `os/net/routing/rpl-lite/`
- RPL Classic source: `os/net/routing/rpl-classic/`
- Configuration: `os/net/routing/rpl-lite/rpl-conf.h`
- Border router example: `examples/rpl-border-router/`

### Related Documentation
- [TSCH and 6TiSCH](TSCH-and-6TiSCH.md)
- [Orchestra](Orchestra.md)
- [Memory Management](Memory-management.md)

### Publications
- [ContikiRPL Thesis](http://www.diva-portal.org/smash/get/diva2:1042739/FULLTEXT01.pdf) - Original ContikiRPL implementation
- See [Contiki-NG publications page](https://www.contiki-ng.org/publications.html) for research papers
