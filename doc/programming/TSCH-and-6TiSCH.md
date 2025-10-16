# TSCH and 6TiSCH

## Overview

Time Slotted Channel Hopping (TSCH) is a MAC layer defined in [IEEE 802.15.4-2015][ieee802.15.4-2015] that provides industrial-grade reliability through time synchronization and channel hopping. [6TiSCH][ietf-6tisch-wg] is an IETF Working Group focused on IPv6 over TSCH, defining how to run IPv6/RPL networks over TSCH.

**Key benefits of TSCH:**
- **Deterministic latency**: Time-slotted operation provides predictable communication timing
- **High reliability**: Channel hopping provides frequency diversity, combating interference and multipath fading
- **Low power**: Nodes only wake up for scheduled slots, enabling ultra-low duty cycles
- **Scalability**: Supports large networks with thousands of nodes
- **Industrial-grade**: Proven in harsh industrial environments

This is a Contiki-NG implementation of TSCH and the 6TiSCH "minimal configuration", which defines how to run a basic RPL+TSCH network.

**Developed by:**
* Simon Duquennoy, SICS, simon.duquennoy@ri.se, github user: [simonduq](https://github.com/simonduq)
* Beshr Al Nahas, SICS (now Chalmers University), beshr@chalmers.se, github user: [beshrns](https://github.com/beshrns)
* Atis Elsts, Univ. Bristol (now EDI), atis.elsts@edi.lv, github user: [atiselsts](https://github.com/atiselsts)

**Academic publications:**
* Implementation paper: [*TSCH and 6TiSCH for Contiki-NG: Challenges, Design and Evaluation*](http://www.simonduquennoy.net/papers/duquennoy17tsch.pdf), IEEE DCOSS'17
* Orchestra scheduler: [*Orchestra: Robust Mesh Networks Through Autonomously Scheduled TSCH*](http://www.simonduquennoy.net/papers/duquennoy15orchestra.pdf), ACM SenSys'15

**Additional documentation:**
* [Orchestra autonomous scheduler](/doc/programming/Orchestra)
* [6top sub-layer for dynamic scheduling](/doc/programming/6TiSCH-6top-sub-layer)
* [TSCH tutorial](/doc/tutorials/TSCH-and-6TiSCH)
* [Switching applications to TSCH](/doc/tutorials/Switching-to-TSCH)
* [TSCH example applications](/doc/programming/TSCH-example-applications)

## TSCH Fundamentals

### What is TSCH?

TSCH (Time Slotted Channel Hopping) is a medium access control protocol that combines:

1. **Time Slotting**: Time is divided into discrete slots, with nodes synchronized to a common timescale
2. **Channel Hopping**: Each transmission uses a different frequency channel, determined by a pseudo-random sequence
3. **Scheduled Communication**: Nodes transmit only in assigned time slots, eliminating collisions

### TSCH vs CSMA

| Feature | TSCH | CSMA (e.g., ContikiMAC) |
|---------|------|--------------------------|
| **Access Method** | Scheduled, collision-free | Random access, contention-based |
| **Latency** | Deterministic, predictable | Variable, unpredictable |
| **Reliability** | High (channel hopping + no collisions) | Medium (collisions, interference) |
| **Power Consumption** | Very low (sleep between slots) | Low-medium (periodic wakeups) |
| **Scalability** | Excellent (no hidden terminal) | Limited (collisions increase with density) |
| **Setup Complexity** | Higher (synchronization required) | Lower (no synchronization) |
| **Best For** | Industrial, critical applications | General IoT, best-effort networks |

### Timeslots Explained

A **timeslot** is a fixed duration of time (typically 10ms) during which a single packet transmission occurs:

```
Timeslot structure (10ms example):

|<--------------------------- 10000 μs --------------------------->|
|                                                                   |
| TxOffset |     TX     |  AckWait  |    RX ACK   | MaxAck | Guard|
|   2120   |   (pkt)    |    800    |    (ack)    |   800  |  2200|
|          |            |           |             |        |      |
          TX           SFD          ACK          End      Next
          Start        Sent         Received      Slot
```

**Key timing elements:**
- **TxOffset**: Delay before starting transmission (2120μs)
- **Packet transmission**: Time to send the frame
- **AckWait**: Time to wait for ACK to start (800μs)
- **ACK reception**: Time to receive acknowledgment
- **MaxAck**: Maximum ACK duration (800μs)
- **RxWait (Guard time)**: Safety margin for synchronization drift (2200μs)

Nodes sleep between active timeslots, waking only for scheduled communications.

### Slotframes

A **slotframe** is a repeating sequence of timeslots. The slotframe repeats indefinitely:

```
Slotframe of length 7:

ASN: ...15 16 17 18 19 20 21 | 22 23 24 25 26 27 28 | 29 30 31...
Slot:    0  1  2  3  4  5  6 |  0  1  2  3  4  5  6 |  0  1  2...
         |<---Slotframe 1--->| |<---Slotframe 2--->| |<---...
```

**Slot assignment example:**
- Slot 0: Shared slot for broadcast/EB
- Slot 1: Node A → Node B
- Slot 2: Node C → Node D
- Slot 3: Node B → Root
- Slots 4-6: Unused (nodes sleep)

Multiple slotframes can coexist for different traffic types.

### Absolute Slot Number (ASN)

The **Absolute Slot Number (ASN)** is a global network counter incremented for each timeslot:

- **5-byte counter**: Counts from 0 to 2^40 - 1 (~34 years at 10ms slots)
- **Shared across network**: All nodes maintain synchronized ASN
- **Used for**:
  - Time synchronization
  - Channel hopping (ASN determines frequency)
  - Security (ASN part of encryption nonce)

**ASN synchronization:**
- Nodes synchronize ASN when joining via Enhanced Beacons (EBs)
- Maintained via time corrections in ACK packets
- Drift compensation keeps nodes aligned

### Channel Hopping

TSCH hops between channels following a pseudo-random sequence:

**Channel selection formula:**
```
channel = hopping_sequence[(ASN + channel_offset) % sequence_length]
```

**Example with sequence [11, 15, 20, 25, 26]:**
```
ASN=0, offset=0: channel = sequence[0 % 5] = 11
ASN=1, offset=0: channel = sequence[1 % 5] = 15
ASN=2, offset=0: channel = sequence[2 % 5] = 20
ASN=0, offset=2: channel = sequence[2 % 5] = 20
```

**Benefits:**
- **Frequency diversity**: Combats narrow-band interference
- **Multipath mitigation**: Different channels experience different fading
- **Collision avoidance**: Adjacent networks use different sequences

**Default hopping sequences:**
```c
/* 2.4 GHz: 16 IEEE 802.15.4 channels */
TSCH_HOPPING_SEQUENCE_4_4:  [11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26]

/* Sub-GHz varies by region (channels shown are examples) */
```

### Synchronization

TSCH requires tight time synchronization (±1ms typical):

**Synchronization mechanisms:**

1. **Initial synchronization**: Via Enhanced Beacon (EB) reception
   - Node receives EB with ASN
   - Calculates local time offset
   - Adjusts local clock

2. **Ongoing synchronization**: Via ACK Time Correction Information Element
   - Child sends packet to parent
   - Parent includes time correction in ACK
   - Child adjusts clock based on correction

3. **Drift compensation**:
   - Contiki-NG learns relative drift to time source
   - Compensates automatically (adaptive timesync)
   - Extends keepalive intervals once drift is learned

**Keepalive mechanism:**
- If no data to send, nodes send explicit keepalive packets
- Default keepalive timeout: 12 seconds (configurable)
- Desync threshold: 120 seconds without sync → leave network

### 6TiSCH Minimal Configuration

The **6TiSCH minimal configuration** defines a standard way to bootstrap a TSCH+RPL network:

**Components:**
1. **Minimal Schedule**: Single shared slot for all nodes
   - Emulates "always-on" behavior over TSCH
   - All nodes can transmit/receive in slot 0
   - Slotframe length: 7 slots (configurable)

2. **RPL Integration**:
   - RPL preferred parent = TSCH time source
   - RPL rank → EB join priority
   - Automatic coordination via callbacks

3. **Standard Security**:
   - Optional link-layer encryption
   - K1-K2 key pair (group key + pairwise key)
   - Nonce includes ASN for replay protection

**Minimal schedule visualization:**
```
Slotframe length 7, single shared slot:

Slot 0: [SHARED] All nodes TX/RX (with CSMA)
Slots 1-6: [IDLE] Nodes sleep
```

This provides immediate connectivity, then schedulers like Orchestra can optimize.

## Features

This implementation includes:
* **Standard IEEE 802.15.4-2015**: Frame version 2, Information Elements
* **TSCH joining procedure**: Enhanced Beacons with IEs:
  * TSCH synchronization (join priority and ASN)
  * TSCH slotframe and link (basic schedule)
  * TSCH timeslot (timeslot timing template)
  * TSCH channel hopping sequence
* **Standard TSCH operations**:
  * Link selection and slot operation
  * Synchronization with ACK/NACK time correction IE
  * TSCH queues and CSMA-CA mechanism
* **Security**: Standard TSCH and 6TiSCH security
* **6TiSCH Minimal Configuration**: TSCH-RPL interaction, minimal schedule
* **Scheduling API**: Add/remove slotframes and links programmatically
* **Per-slot logging**: Detailed logging from TSCH slot operation
* **Orchestra**: Autonomous scheduler for TSCH+RPL networks
* **Adaptive timesync**: Drift compensation mechanism

## Supported Platforms

Successfully tested on:
* Tmote Sky (`sky`)
* CC2538DK (`cc2538dk`)
* Zolertia Z1 (`z1`)
* Zolertia Zoul CC2538 (`zoul`)
* Zolertia Zoul CC1200 (`zoul`, sub-GHz, 5.8-31.5ms timeslots)
* OpenMote-CC2538 (`openmote`)
* OpenMote-B (`openmote`)
* CC2650 (`cc26x0-cc13x0` and `simplelink`)
* CC2652R1 (`simplelink`)
* CC1310 (`cc26x0-cc13x0` and `simplelink`, sub-GHz, 40ms timeslots)
* CC1312R1 (`simplelink`, sub-GHz, 40ms timeslots)
* Cooja mote (`cooja`)

**Interoperability:** Successfully tested at ETSI Plugtest events (Prague 2015, 2017) with all tested implementations.

**Platform limitations:**
* Tmote Sky: Insufficient ROM for both TSCH and RPL (choose one or reduce features)
* Other platforms may require tuning (fewer neighbors, routes, queue size) for RAM constraints

**Network layer compatibility:** TSCH can run with any network layer. For IPv6+RPL, `tsch-rpl.[ch]` handles RPL-TSCH consistency.

## Code Structure

### Frame Handling
* `os/net/mac/framer/frame802154.[ch]`: IEEE 802.15.4-2015 frame version 2
* `os/net/mac/framer/frame802154-ie.[ch]`: Information Elements (IEs)

### Core TSCH Implementation
* `os/net/mac/tsch/tsch.[ch]`: TSCH management (association, keepalive), MAC driver interface
* `tsch-slot-operation.[ch]`: Low-level slot operation (interrupt-driven), TX/RX/ACK handling
* `tsch-asn.h`: Absolute Slot Number (ASN) macros and handling
* `tsch-packet.[ch]`: Enhanced ACK (EACK) and Enhanced Beacon (EB) creation/parsing
* `tsch-queue.[ch]`: Per-neighbor queues, neighbor state, CSMA-CA
* `tsch-schedule.[ch]`: Slotframe and link handling, scheduling API
* `tsch-security.[ch]`: Frame and ACK security with ASN in nonce
* `tsch-rpl.[ch]`: TSCH+RPL integration (align time source with preferred parent)
* `tsch-log.[ch]`: Logging system with delayed messages from interrupts
* `tsch-adaptive-timesync.c`: Learn and compensate for clock drift
* `tsch-timeslot-timing.c`: Timeslot timing templates
* `tsch-const.h`: TSCH constants
* `tsch-types.h`: TSCH data types
* `tsch-conf.h`: General TSCH configuration

## Getting Started

### Basic Setup

1. **Enable TSCH in your Makefile:**
   ```makefile
   MAKE_MAC = MAKE_MAC_TSCH
   ```

2. **Configure TSCH in project-conf.h** (optional, defaults are sensible):
   ```c
   /* IEEE 802.15.4 PANID */
   #define IEEE802154_CONF_PANID 0x81a5

   /* TSCH minimal schedule length */
   #define TSCH_SCHEDULE_CONF_DEFAULT_LENGTH 7
   ```

3. **Start TSCH in your application:**
   ```c
   #include "net/netstack.h"

   /* TSCH starts automatically by default */
   /* Or manually: */
   NETSTACK_MAC.on();
   ```

### Complete Example: Simple TSCH Node

**project-conf.h:**
```c
#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* IEEE 802.15.4 PANID */
#define IEEE802154_CONF_PANID 0x81a5

/* TSCH configuration */
#define TSCH_CONF_AUTOSTART 0  /* Manual start */
#define TSCH_SCHEDULE_CONF_DEFAULT_LENGTH 7

/* Logging */
#define LOG_CONF_LEVEL_MAC LOG_LEVEL_INFO

#endif /* PROJECT_CONF_H_ */
```

**Makefile:**
```makefile
CONTIKI_PROJECT = tsch-example
CONTIKI = ../..

# Use TSCH MAC
MAKE_MAC = MAKE_MAC_TSCH

include $(CONTIKI)/Makefile.include
```

**tsch-example.c:**
```c
#include "contiki.h"
#include "net/netstack.h"
#include "net/routing/routing.h"
#include "sys/log.h"

#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_INFO

PROCESS(tsch_example_process, "TSCH Example");
AUTOSTART_PROCESSES(&tsch_example_process);

PROCESS_THREAD(tsch_example_process, ev, data)
{
  PROCESS_BEGIN();

  /* Set up as root if node ID is 1 */
  if(node_id == 1) {
    LOG_INFO("Node 1: Setting up as DAG root\n");
    NETSTACK_ROUTING.root_start();
  } else {
    LOG_INFO("Node %u: Setting up as regular node\n", node_id);
  }

  /* Start TSCH */
  LOG_INFO("Starting TSCH\n");
  NETSTACK_MAC.on();

  LOG_INFO("TSCH node started\n");

  PROCESS_END();
}
```

This creates a basic TSCH+RPL network with minimal configuration.

## Configuration Reference

### Synchronization Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `TSCH_CONF_KEEPALIVE_TIMEOUT` | 12 seconds | Max time before sending keepalive to time source |
| `TSCH_CONF_MAX_KEEPALIVE_TIMEOUT` | 60 seconds | Keepalive timeout after adaptive timesync converges |
| `TSCH_CONF_DESYNC_THRESHOLD` | 120 seconds | Max time without sync before leaving network |
| `TSCH_CONF_EB_PERIOD` | 16 seconds | Initial Enhanced Beacon period |
| `TSCH_CONF_MAX_EB_PERIOD` | 16 seconds | Maximum EB period (bounds RPL-based EB period) |
| `TSCH_CONF_RESYNC_WITH_SFD_TIMESTAMPS` | 0 | Use SFD timestamps for sync (vs busy-wait) |
| `TSCH_CONF_TIMESYNC_REMOVE_JITTER` | 0 | Remove measurement jitter from sync |
| `TSCH_CONF_BASE_DRIFT_PPM` | 0 | Compensate for known clock drift (PPM) |
| `TSCH_CONF_ADAPTIVE_TIMESYNC` | 1 | Learn and compensate for drift automatically |
| `TSCH_CONF_AUTOSELECT_TIME_SOURCE` | 0 | Auto-select time source (vs use RPL parent) |

**Example configuration:**
```c
/* Faster sync for quick network formation */
#define TSCH_CONF_EB_PERIOD (4 * CLOCK_SECOND)
#define TSCH_CONF_MAX_EB_PERIOD (8 * CLOCK_SECOND)

/* Tighter keepalive for critical applications */
#define TSCH_CONF_KEEPALIVE_TIMEOUT (6 * CLOCK_SECOND)
```

### Channel Hopping Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `TSCH_CONF_DEFAULT_HOPPING_SEQUENCE` | All 16 channels | Default hopping sequence (ID 0) |
| `TSCH_CONF_JOIN_HOPPING_SEQUENCE` | Same as default | Hopping sequence for scanning |
| `TSCH_CONF_HOPPING_SEQUENCE_MAX_LEN` | 16 | Max length of hopping sequence |

**Example - restrict to 4 channels:**
```c
/* Use only channels 15, 20, 25, 26 */
static const uint8_t my_hopping_sequence[] = {15, 20, 25, 26};
#define TSCH_CONF_DEFAULT_HOPPING_SEQUENCE my_hopping_sequence
```

### Association Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `TSCH_CONF_AUTOSTART` | 1 | Start TSCH automatically at init |
| `TSCH_CONF_MAX_JOIN_PRIORITY` | 32 | Max acceptable join priority from EB |
| `TSCH_CONF_JOIN_SECURED_ONLY` | (depends on security) | Only join secured networks |
| `TSCH_CONF_JOIN_MY_PANID_ONLY` | 1 | Only join network with matching PANID |
| `TSCH_CONF_ASSOCIATION_POLL_FREQUENCY` | 100 Hz | Radio polling frequency during scan |
| `TSCH_CONF_CHECK_TIME_AT_ASSOCIATION` | 0 | Check ASN vs uptime when joining |
| `TSCH_CONF_INIT_SCHEDULE_FROM_EB` | 1 | Initialize schedule from EB IEs |
| `TSCH_CONF_CHANNEL_SCAN_DURATION` | 1 second | Time to scan each channel |

**Example - secure network only:**
```c
/* Only join secured networks with specific PANID */
#define IEEE802154_CONF_PANID 0xABCD
#define LLSEC802154_CONF_ENABLED 1
#define TSCH_CONF_JOIN_SECURED_ONLY 1
#define TSCH_CONF_JOIN_MY_PANID_ONLY 1
```

### Enhanced Beacon (EB) Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `TSCH_PACKET_CONF_EB_WITH_TIMESLOT_TIMING` | 0 | Include timeslot timing IE in EB |
| `TSCH_PACKET_CONF_EB_WITH_HOPPING_SEQUENCE` | 0 | Include hopping sequence IE in EB |
| `TSCH_PACKET_CONF_EB_WITH_SLOTFRAME_AND_LINK` | 0 | Include schedule IE in EB |

**Note:** These IEs increase EB size. Enable only if you advertise non-default timing/hopping/schedule.

### Queue Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `QUEUEBUF_CONF_NUM` | 8 | Total queuebufs (affects TSCH queues) |
| `TSCH_CONF_DEQUEUED_ARRAY_SIZE` | (auto) | Size of dequeued packet ring buffer |
| `TSCH_CONF_MAX_INCOMING_PACKETS` | 4 | Incoming packet ring buffer size |
| `TSCH_QUEUE_CONF_NUM_PER_NEIGHBOR` | (auto) | Max packets queued per neighbor |
| `TSCH_QUEUE_CONF_MAX_NEIGHBOR_QUEUES` | NBR_TABLE max + 2 | Max number of neighbor queues |

**Example - increase capacity:**
```c
/* More buffering for high-traffic scenarios */
#define QUEUEBUF_CONF_NUM 16
#define TSCH_CONF_MAX_INCOMING_PACKETS 8
```

### Scheduling Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `TSCH_SCHEDULE_CONF_WITH_6TISCH_MINIMAL` | 1 (unless Orchestra) | Use 6TiSCH minimal schedule |
| `TSCH_SCHEDULE_CONF_DEFAULT_LENGTH` | 7 | Minimal schedule slotframe length |
| `TSCH_SCHEDULE_CONF_MAX_SLOTFRAMES` | 5 | Max number of slotframes |
| `TSCH_SCHEDULE_CONF_MAX_LINKS` | 32 | Max number of links across all slotframes |
| `TSCH_CONF_WITH_SIXTOP` | 0 | Enable 6top sub-layer |
| `TSCH_CONF_WITH_LINK_SELECTOR` | (Orchestra only) | Enable link selector feature |
| `TSCH_CONF_BURST_MAX_LEN` | 0 | Max burst length (0 = no bursts) |

**Example - custom scheduler:**
```c
/* Disable minimal schedule, use Orchestra */
#define TSCH_SCHEDULE_CONF_WITH_6TISCH_MINIMAL 0
MODULES += os/services/orchestra

/* Increase schedule capacity */
#define TSCH_SCHEDULE_CONF_MAX_SLOTFRAMES 8
#define TSCH_SCHEDULE_CONF_MAX_LINKS 64
```

### CSMA-CA Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `TSCH_CONF_MAC_MIN_BE` | 1 | Min backoff exponent |
| `TSCH_CONF_MAC_MAX_BE` | 5 | Max backoff exponent |
| `TSCH_CONF_MAC_MAX_FRAME_RETRIES` | 7 | Max retransmissions before drop |
| `TSCH_CONF_CCA_ENABLED` | 0 | Perform CCA before transmission |

**Example - more aggressive retries:**
```c
/* More retries for unreliable links */
#define TSCH_CONF_MAC_MAX_FRAME_RETRIES 15
#define TSCH_CONF_MAC_MAX_BE 7
```

### Hardware-Specific Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `TSCH_CONF_HW_FRAME_FILTERING` | 1 | Use hardware address filtering |
| `TSCH_CONF_RADIO_ON_DURING_TIMESLOT` | 0 | Keep radio on entire timeslot |
| `TSCH_CONF_DEFAULT_TIMESLOT_TIMING` | 10ms template | Default timeslot timing |
| `TSCH_CONF_DYNAMIC_TIMESLOT_TEMPLATE` | 0 | Allow runtime timing changes |
| `TSCH_CONF_RX_WAIT` | 2200 μs | Rx guard time |

**Example - always-on radio (higher power but faster):**
```c
/* Keep radio on during timeslots */
#define TSCH_CONF_RADIO_ON_DURING_TIMESLOT 1
```

### ACK Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `TSCH_PACKET_CONF_EACK_WITH_SRC_ADDR` | 0 | Include source address in ACK |
| `TSCH_PACKET_CONF_EACK_WITH_DEST_ADDR` | 1 | Include dest address in ACK |

## Timeslot Timing

### Understanding Timeslot Structure

A timeslot defines the precise timing for packet transmission, ACK reception, and synchronization. The timing must account for:

- Radio startup time
- Processing delays
- Guard time for clock drift
- Packet and ACK air time

### Default Timing Templates

Contiki-NG provides several timing templates:

**1. tsch_timeslot_timing_us_10000 (default, 2.4 GHz):**
```c
Duration: 10000 μs (10ms)
CCA offset: 1800 μs
CCA duration: 128 μs
TX offset: 2120 μs
RX offset: 1120 μs
RX ACK delay: 800 μs
TX ACK delay: 1000 μs
RX wait: 2200 μs
ACK wait: 400 μs
RX TX gap: 2000 μs
Max ACK: 800 μs
Max TX: 4256 μs
```

**2. tsch_timeslot_timing_us_15000 (sub-GHz):**
- Duration: 15000 μs (15ms)
- Longer timeslot for slower data rates

**3. Platform-specific templates:**
- CC1200 sub-GHz: 5.8ms to 31.5ms depending on data rate
- CC1310/CC1312: 40ms for long-range sub-GHz

### Custom Timing Template

To define custom timing:

```c
/* In your project-conf.h or platform code */
static const uint16_t my_timeslot_timing[] = {
  10000,  /* CCA + TX + RX  slot duration (μs) */
  1800,   /* CCA offset */
  128,    /* CCA duration */
  2120,   /* TX offset */
  1120,   /* RX offset */
  800,    /* RX ACK delay */
  1000,   /* TX ACK delay */
  2200,   /* RX wait (guard time) */
  400,    /* ACK wait */
  2000,   /* RX-TX turnaround */
  800,    /* Max ACK */
  4256,   /* Max TX */
  0       /* Timeslot timing template ID */
};

#define TSCH_CONF_DEFAULT_TIMESLOT_TIMING my_timeslot_timing
```

### Timing Calculation Example

For a 127-byte packet at 250 kbps (IEEE 802.15.4 2.4 GHz):

```
Packet air time:
- Preamble + SFD: 160 μs
- PHY header (1 byte): 32 μs
- Payload (127 bytes): 4064 μs
- Total: 4256 μs

ACK air time:
- Preamble + SFD: 160 μs
- PHY header: 32 μs
- ACK payload (~25 bytes): 800 μs
- Total: 992 μs ≈ 1000 μs

Minimum timeslot:
- TxOffset: 2120 μs
- Packet TX: 4256 μs
- AckWait: 800 μs
- ACK RX: 1000 μs
- RxWait: 2200 μs (guard)
- Total: ~10376 μs → round to 10000 μs is OK with some margin
```

## Scheduling API

The TSCH scheduling API allows programmatic creation of custom schedules.

### API Functions

**Slotframe management:**
```c
/* Create a new slotframe */
struct tsch_slotframe *
tsch_schedule_add_slotframe(uint16_t handle, uint16_t size);

/* Find slotframe by handle */
struct tsch_slotframe *
tsch_schedule_get_slotframe_by_handle(uint16_t handle);

/* Remove slotframe */
int
tsch_schedule_remove_slotframe(struct tsch_slotframe *slotframe);

/* Remove all slotframes (empty schedule) */
int
tsch_schedule_remove_all_slotframes(void);

/* Iterate slotframes */
struct tsch_slotframe *tsch_schedule_slotframe_head(void);
struct tsch_slotframe *tsch_schedule_slotframe_next(struct tsch_slotframe *sf);
```

**Link management:**
```c
/* Add link to slotframe */
struct tsch_link *
tsch_schedule_add_link(struct tsch_slotframe *slotframe,
                       uint8_t link_options,
                       enum link_type link_type,
                       const linkaddr_t *address,
                       uint16_t timeslot,
                       uint16_t channel_offset,
                       uint8_t do_remove);

/* Find link by timeslot */
struct tsch_link *
tsch_schedule_get_link_by_timeslot(struct tsch_slotframe *slotframe,
                                   uint16_t timeslot);

/* Remove link */
int
tsch_schedule_remove_link(struct tsch_slotframe *slotframe,
                          struct tsch_link *link);

/* Remove link by timeslot + channel offset */
int
tsch_schedule_remove_link_by_offsets(struct tsch_slotframe *slotframe,
                                     uint16_t timeslot,
                                     uint16_t channel_offset);
```

### Link Options

Link options are a bitfield combining:

```c
/* Link options (can be combined with |) */
#define LINK_OPTION_TX        (1 << 0)  /* Transmit link */
#define LINK_OPTION_RX        (1 << 1)  /* Receive link */
#define LINK_OPTION_SHARED    (1 << 2)  /* Shared link (with CSMA) */
#define LINK_OPTION_TIME_KEEPING (1 << 3)  /* Use for timekeeping */
```

**Common combinations:**
- `LINK_OPTION_TX | LINK_OPTION_RX`: Bidirectional dedicated link
- `LINK_OPTION_TX | LINK_OPTION_SHARED`: Transmit on shared slot
- `LINK_OPTION_RX | LINK_OPTION_SHARED`: Receive on shared slot
- `LINK_OPTION_TX | LINK_OPTION_RX | LINK_OPTION_SHARED`: Fully shared slot

### Link Types

```c
enum link_type {
  LINK_TYPE_NORMAL,              /* Regular data link */
  LINK_TYPE_ADVERTISING,         /* For Enhanced Beacons */
  LINK_TYPE_ADVERTISING_ONLY     /* EB only, no data */
};
```

### Example 1: Simple Unicast Schedule

Create a schedule with dedicated TX/RX slots for two nodes:

```c
#include "net/mac/tsch/tsch-schedule.h"
#include "net/linkaddr.h"

void
create_simple_schedule(void)
{
  struct tsch_slotframe *sf;
  linkaddr_t node_a = {{0x00, 0x12, 0x4b, 0x00, 0x14, 0xd5, 0x2b, 0x0a}};
  linkaddr_t node_b = {{0x00, 0x12, 0x4b, 0x00, 0x14, 0xd5, 0x2b, 0x0b}};

  /* Remove minimal schedule */
  tsch_schedule_remove_all_slotframes();

  /* Create slotframe of length 11 */
  sf = tsch_schedule_add_slotframe(0, 11);
  if(sf == NULL) {
    LOG_ERR("Failed to create slotframe\n");
    return;
  }

  /* Slot 0: Shared for broadcast */
  tsch_schedule_add_link(sf,
                         LINK_OPTION_TX | LINK_OPTION_RX | LINK_OPTION_SHARED,
                         LINK_TYPE_ADVERTISING,
                         &tsch_broadcast_address,
                         0, 0, 1);

  /* Slot 1: Node A → Node B */
  if(linkaddr_cmp(&linkaddr_node_addr, &node_a)) {
    /* Node A: TX link */
    tsch_schedule_add_link(sf,
                           LINK_OPTION_TX,
                           LINK_TYPE_NORMAL,
                           &node_b,
                           1, 0, 1);
  } else if(linkaddr_cmp(&linkaddr_node_addr, &node_b)) {
    /* Node B: RX link */
    tsch_schedule_add_link(sf,
                           LINK_OPTION_RX,
                           LINK_TYPE_NORMAL,
                           &node_a,
                           1, 0, 1);
  }

  /* Slot 2: Node B → Node A */
  if(linkaddr_cmp(&linkaddr_node_addr, &node_b)) {
    tsch_schedule_add_link(sf,
                           LINK_OPTION_TX,
                           LINK_TYPE_NORMAL,
                           &node_a,
                           2, 0, 1);
  } else if(linkaddr_cmp(&linkaddr_node_addr, &node_a)) {
    tsch_schedule_add_link(sf,
                           LINK_OPTION_RX,
                           LINK_TYPE_NORMAL,
                           &node_b,
                           2, 0, 1);
  }

  LOG_INFO("Created simple unicast schedule\n");
}
```

### Example 2: Multi-Channel Schedule

Use multiple channels for parallel transmissions:

```c
void
create_multichannel_schedule(void)
{
  struct tsch_slotframe *sf;

  /* Create slotframe of length 7 */
  sf = tsch_schedule_add_slotframe(0, 7);

  /* Slot 0, channel offset 0: Pair 1 communicates */
  tsch_schedule_add_link(sf,
                         LINK_OPTION_TX | LINK_OPTION_RX,
                         LINK_TYPE_NORMAL,
                         &neighbor1,
                         0,  /* timeslot */
                         0,  /* channel_offset */
                         1);

  /* Slot 0, channel offset 1: Pair 2 communicates simultaneously */
  tsch_schedule_add_link(sf,
                         LINK_OPTION_TX | LINK_OPTION_RX,
                         LINK_TYPE_NORMAL,
                         &neighbor2,
                         0,  /* same timeslot */
                         1,  /* different channel offset */
                         1);

  LOG_INFO("Created multi-channel schedule\n");
}
```

### Example 3: Dynamic Link Addition/Removal

Add and remove links at runtime:

```c
void
add_link_to_neighbor(const linkaddr_t *neighbor, uint16_t timeslot)
{
  struct tsch_slotframe *sf;
  struct tsch_link *link;

  /* Get main slotframe */
  sf = tsch_schedule_get_slotframe_by_handle(0);
  if(sf == NULL) {
    LOG_ERR("Slotframe not found\n");
    return;
  }

  /* Check if link already exists */
  link = tsch_schedule_get_link_by_timeslot(sf, timeslot);
  if(link != NULL) {
    LOG_WARN("Link already exists at timeslot %u\n", timeslot);
    return;
  }

  /* Add TX link to neighbor */
  link = tsch_schedule_add_link(sf,
                                LINK_OPTION_TX,
                                LINK_TYPE_NORMAL,
                                neighbor,
                                timeslot,
                                0,  /* channel offset 0 */
                                0); /* don't remove existing */

  if(link != NULL) {
    LOG_INFO("Added link to neighbor at slot %u\n", timeslot);
  } else {
    LOG_ERR("Failed to add link\n");
  }
}

void
remove_link_to_neighbor(uint16_t timeslot)
{
  struct tsch_slotframe *sf;
  int result;

  sf = tsch_schedule_get_slotframe_by_handle(0);
  if(sf == NULL) {
    return;
  }

  result = tsch_schedule_remove_link_by_offsets(sf, timeslot, 0);

  if(result) {
    LOG_INFO("Removed link at slot %u\n", timeslot);
  } else {
    LOG_WARN("No link found at slot %u\n", timeslot);
  }
}
```

## Security

TSCH provides link-layer security using AES-CCM encryption with 128-bit keys.

### Enabling Security

**Step 1: Enable in project-conf.h:**
```c
/* Enable link-layer security */
#define LLSEC802154_CONF_ENABLED 1

/* Only join secured networks (optional) */
#define TSCH_CONF_JOIN_SECURED_ONLY 1
```

**Step 2: Configure keys:**

By default, TSCH uses the 6TiSCH minimal security K1-K2 key pair:
- **K1**: Network-wide group key (default key)
- **K2**: Pairwise keys between nodes

Keys are configured in `os/net/mac/tsch/tsch-security.h`:

```c
/* Default key (K1) - CHANGE THIS IN PRODUCTION */
static const uint8_t default_key[16] = {
  0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};
```

**Step 3: Set keys programmatically (recommended):**

```c
#include "net/mac/tsch/tsch-security.h"
#include "net/mac/tsch/tsch.h"

void
configure_security(void)
{
  uint8_t my_network_key[16] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
  };

  /* Set default key (K1) */
  tsch_security_set_key(0, my_network_key);

  LOG_INFO("Security configured with custom key\n");
}
```

### Security Levels

TSCH supports multiple security levels (IEEE 802.15.4):

| Level | Encryption | Integrity | MIC Length |
|-------|------------|-----------|------------|
| 0 | No | No | 0 bytes |
| 1 | No | Yes | 4 bytes |
| 2 | No | Yes | 8 bytes |
| 3 | No | Yes | 16 bytes |
| 4 | Yes | No | 0 bytes |
| 5 | Yes | Yes | 4 bytes |
| 6 | Yes | Yes | 8 bytes |
| 7 | Yes | Yes | 16 bytes |

**Default level: 6** (encryption + 8-byte MIC)

Set level in frame before sending:
```c
packetbuf_set_attr(PACKETBUF_ATTR_SECURITY_LEVEL, 6);
```

### Nonce Structure

TSCH uses ASN as part of the nonce for replay protection:

```
Nonce (13 bytes):
- Source address (8 bytes)
- Frame counter / ASN (4 bytes)
- Security level (1 byte)
```

This ensures each packet is encrypted with a unique nonce, preventing replay attacks.

### Coordinator Configuration

The PAN coordinator controls whether EBs are secured:

```c
/* In coordinator code */

/* Send secured EBs (default when security enabled) */
tsch_set_pan_secured(true);

/* Send unsecured EBs (allow insecure join, then switch to secure) */
tsch_set_pan_secured(false);
```

### Node Configuration

Nodes can be configured to join only secured networks:

```c
/* Only join networks sending secured EBs */
#define TSCH_CONF_JOIN_SECURED_ONLY 1
```

### Key Management

For production deployments:

1. **Generate unique keys per deployment**
   ```c
   /* Use a cryptographically secure random number generator */
   /* NEVER use default keys in production */
   ```

2. **Consider key rotation**
   ```c
   /* Periodically update keys */
   void rotate_keys(void) {
     uint8_t new_key[16];
     generate_secure_random(new_key, 16);
     tsch_security_set_key(0, new_key);
   }
   ```

3. **Protect key storage**
   - Store keys in secure memory if available
   - Encrypt keys at rest
   - Use hardware security module (HSM) if available

### Security Best Practices

1. **Always enable security for production**
2. **Use unique keys per network**
3. **Change default keys**
4. **Monitor for security events**
   ```c
   /* Check for authentication failures */
   if(mac_status == MAC_TX_ERR_FATAL) {
     LOG_WARN("Possible security failure\n");
   }
   ```
5. **Consider secure boot and firmware authentication**

## Troubleshooting

### Issue: Nodes Don't Join Network

**Symptoms**: Nodes scan indefinitely, never receive EBs.

**Possible causes:**

1. **PANID mismatch**
   ```c
   /* Ensure same PANID on all nodes */
   #define IEEE802154_CONF_PANID 0x81a5
   ```

2. **No coordinator/root**
   - Ensure at least one node is configured as root
   ```c
   NETSTACK_ROUTING.root_start();
   ```

3. **EB period too long**
   ```c
   /* Reduce EB period for faster join */
   #define TSCH_CONF_EB_PERIOD (4 * CLOCK_SECOND)
   ```

4. **Channel mismatch**
   - Verify hopping sequences match
   - Check for interference on channels

5. **Security mismatch**
   - Secured coordinator but node has `TSCH_JOIN_SECURED_ONLY=0`
   - Keys don't match

**Debugging:**
```c
/* Enable TSCH logs */
#define LOG_CONF_LEVEL_MAC LOG_LEVEL_DBG

/* Check EB reception */
[DBG: TSCH] Received EB from <addr>, join priority <prio>
```

### Issue: Poor Synchronization

**Symptoms**: Nodes frequently desync, high retransmission rate.

**Possible causes:**

1. **High clock drift**
   ```c
   /* Reduce keepalive timeout */
   #define TSCH_CONF_KEEPALIVE_TIMEOUT (6 * CLOCK_SECOND)

   /* Ensure adaptive timesync is enabled */
   #define TSCH_CONF_ADAPTIVE_TIMESYNC 1
   ```

2. **Insufficient guard time**
   ```c
   /* Increase Rx wait time */
   #define TSCH_CONF_RX_WAIT 3000  /* μs */
   ```

3. **Platform timing issues**
   - Verify radio timing macros are correct
   - Check rtimer resolution

**Debugging:**
```c
/* Monitor drift corrections in logs */
[INFO: TSCH-LOG] ... dr 2  /* Drift correction of 2 rtimer ticks */
```

### Issue: High Packet Loss

**Symptoms**: Many retransmissions, MAC_TX_NOACK status.

**Possible causes:**

1. **Schedule conflicts**
   - Verify no overlapping TX slots
   - Check channel offsets are distinct

2. **Queue overflow**
   ```c
   /* Increase queue capacity */
   #define QUEUEBUF_CONF_NUM 16
   ```

3. **Poor link quality**
   - Check RSSI/LQI in logs
   - Adjust TX power
   - Use more channels in hopping sequence

4. **Collision in shared slots**
   ```c
   /* Reduce backoff more slowly */
   #define TSCH_CONF_MAC_MAX_BE 7
   ```

**Debugging:**
```c
/* Enable per-slot logging */
#define TSCH_LOG_CONF_PER_SLOT 1

/* Look for retry patterns */
[INFO: TSCH-LOG] ... st 2 5  /* Status 2 (NOACK), 5 attempts */
```

### Issue: Security Failures

**Symptoms**: Packets dropped, "security failure" in logs.

**Possible causes:**

1. **Key mismatch**
   - Verify all nodes have same keys
   - Check key index

2. **Replay protection triggered**
   - ASN may have rolled back (clock issue)
   - Frame counter exhausted

3. **MIC validation failure**
   - Corrupted packet
   - Wrong security level

**Debugging:**
```c
/* Check security status */
#define LLSEC802154_CONF_ENABLED 1
#define LOG_CONF_LEVEL_MAC LOG_LEVEL_DBG

/* Look for security errors */
[ERR: TSCH] Security authentication failed
```

### Issue: High Energy Consumption

**Symptoms**: Battery drains faster than expected.

**Possible causes:**

1. **Too many active slots**
   - Reduce schedule density
   - Use longer slotframes

2. **Radio stays on**
   ```c
   /* Ensure radio off between slots */
   #define TSCH_CONF_RADIO_ON_DURING_TIMESLOT 0
   ```

3. **Frequent resync**
   ```c
   /* Longer keepalive after drift compensation */
   #define TSCH_CONF_MAX_KEEPALIVE_TIMEOUT (60 * CLOCK_SECOND)
   ```

4. **Many retransmissions**
   - Improve link quality
   - Optimize schedule

**Monitoring:**
```c
/* Use Energest to measure energy consumption */
MODULES += os/services/simple-energest
```

### Issue: Schedule Not Working

**Symptoms**: Links added but no communication.

**Possible causes:**

1. **Forgot to remove minimal schedule**
   ```c
   /* When using custom schedule */
   #define TSCH_SCHEDULE_CONF_WITH_6TISCH_MINIMAL 0
   ```

2. **Link direction mismatch**
   - TX at sender, RX at receiver
   - Verify both sides configured correctly

3. **Wrong slotframe handle**
   ```c
   /* Ensure using same handle */
   struct tsch_slotframe *sf = tsch_schedule_get_slotframe_by_handle(0);
   ```

4. **Schedule not initialized**
   - Call scheduling functions after TSCH started

**Debugging:**
```c
/* Print schedule */
void
print_schedule(void)
{
  struct tsch_slotframe *sf;
  struct tsch_link *link;

  sf = tsch_schedule_slotframe_head();
  while(sf != NULL) {
    LOG_INFO("Slotframe %u, size %u:\n", sf->handle, sf->size.val);

    link = list_head(sf->links_list);
    while(link != NULL) {
      LOG_INFO("  Slot %u, ch_offset %u, options %02x\n",
               link->timeslot, link->channel_offset, link->link_options);
      link = list_item_next(link);
    }

    sf = tsch_schedule_slotframe_next(sf);
  }
}
```

## Performance Considerations

### Latency

Average latency ≈ `slotframe_length / 2 × slot_duration`

```
Example: Slotframe length 17, slot 10ms
Average latency = 17 / 2 × 10ms = 85ms
Maximum latency = 17 × 10ms = 170ms
```

**Optimization strategies:**
- Use shorter slotframes (but more collisions in shared slots)
- Assign more slots per node pair
- Use multiple slotframes for different priorities

### Throughput

Maximum throughput ≈ `(slots_per_node / slotframe_length) × max_packet_size / slot_duration`

```
Example: 1 slot per node, slotframe 17, 127-byte packets, 10ms slots
Throughput = (1/17) × 127 bytes / 10ms = 746 bytes/s ≈ 6 kbps
```

**Optimization strategies:**
- Allocate multiple slots per node
- Use shorter timeslots (if supported)
- Enable burst mode (`TSCH_BURST_MAX_LEN`)

### Memory Usage

**Static memory (approximate):**
```
TSCH core: ~2-3 KB
Per slotframe: ~60 bytes
Per link: ~40 bytes
Per neighbor queue: ~100 bytes + packets
```

**Example calculation:**
```
5 slotframes: 5 × 60 = 300 bytes
32 links: 32 × 40 = 1280 bytes
8 neighbors: 8 × 100 = 800 bytes
QUEUEBUF_NUM=16, 127-byte packets: 16 × 140 = 2240 bytes

Total: ~4.6 KB + 2-3 KB core = ~7 KB
```

### Energy Consumption

Duty cycle ≈ `(active_slots / slotframe_length) × (slot_duration / slotframe_duration)`

```
Example: 2 active slots per slotframe of 17
Duty cycle = (2/17) × 100% = 11.8%
```

**Optimization strategies:**
- Minimize number of active slots
- Use longer slotframes
- Enable adaptive timesync for longer keepalive intervals
- Use lower-power radios (sub-GHz)

## Best Practices

### 1. Always Enable Adaptive Timesync

```c
/* Default is 1, but ensure it's enabled */
#define TSCH_CONF_ADAPTIVE_TIMESYNC 1
```

**Why**: Automatically compensates for clock drift, allows longer keepalive intervals, saves energy.

### 2. Match Schedule to Traffic Pattern

```c
/* Data collection: Use Orchestra with special_for_root */
MODULES += os/services/orchestra
#define ORCHESTRA_CONF_RULES { &eb_per_time_source, \
                               &unicast_per_neighbor_rpl_ns, \
                               &special_for_root, \
                               &default_common }

/* Low-latency command/control: Short slotframe */
#define TSCH_SCHEDULE_CONF_DEFAULT_LENGTH 3

/* Low-power sensing: Long slotframe */
#define TSCH_SCHEDULE_CONF_DEFAULT_LENGTH 31
```

### 3. Tune Keepalive for Application

```c
/* Critical control system: Tight keepalive */
#define TSCH_CONF_KEEPALIVE_TIMEOUT (6 * CLOCK_SECOND)

/* Monitoring application: Relaxed keepalive */
#define TSCH_CONF_KEEPALIVE_TIMEOUT (60 * CLOCK_SECOND)
```

### 4. Use Appropriate Hopping Sequence

```c
/* Avoid congested channels */
static const uint8_t my_sequence[] = {15, 20, 25, 26};  /* Skip 11-14 */
#define TSCH_CONF_DEFAULT_HOPPING_SEQUENCE my_sequence
```

### 5. Enable Security in Production

```c
/* Always use security for production deployments */
#define LLSEC802154_CONF_ENABLED 1
#define TSCH_CONF_JOIN_SECURED_ONLY 1

/* Use unique keys */
/* NEVER use default keys */
```

### 6. Monitor Network Health

```c
/* Periodically check TSCH statistics */
void
monitor_tsch_health(void)
{
  struct tsch_neighbor *n;

  for(n = tsch_queue_nbr_head(); n != NULL; n = tsch_queue_nbr_next(n)) {
    if(n->tx_count > 0) {
      int success_rate = (100 * (n->tx_count - n->tx_fail_count)) / n->tx_count;
      LOG_INFO("Neighbor success rate: %d%%\n", success_rate);

      if(success_rate < 80) {
        LOG_WARN("Poor link quality to neighbor\n");
      }
    }
  }
}
```

### 7. Size Queues Appropriately

```c
/* Balance memory vs capacity */

/* Low memory devices */
#define QUEUEBUF_CONF_NUM 8

/* High traffic scenarios */
#define QUEUEBUF_CONF_NUM 16

/* Always ensure: QUEUEBUF_NUM >= number_of_neighbors */
```

### 8. Test at Scale

- Test with realistic network size
- Verify schedule scales
- Monitor memory usage
- Measure actual energy consumption
- Test in target RF environment

### 9. Use Minimal Schedule for Development

```c
/* During development: Use minimal schedule for simplicity */
#define TSCH_SCHEDULE_CONF_WITH_6TISCH_MINIMAL 1

/* For production: Optimize with Orchestra or custom schedule */
#define TSCH_SCHEDULE_CONF_WITH_6TISCH_MINIMAL 0
MODULES += os/services/orchestra
```

### 10. Document Your Configuration

```c
/* In project-conf.h, document why you chose each setting */

/* Keepalive set to 6s because our application requires
 * detection of node failure within 10s */
#define TSCH_CONF_KEEPALIVE_TIMEOUT (6 * CLOCK_SECOND)
```

## Per-Slot Logging

### Enabling Detailed Logs

```c
/* Enable per-slot logging */
#define TSCH_LOG_CONF_PER_SLOT 1
#define LOG_CONF_LEVEL_MAC LOG_LEVEL_INFO
```

### Log Format

All TSCH logs include slot context in `{}`:

```
[INFO: TSCH-LOG] {asn-0.24c07 link-0-7-0-0 ch-20} <event details>
                  |           |            |
                  ASN         Link info    Physical channel
```

**Link info format:** `handle-length-timeslot-channeloffset`
- `0-7-0-0`: Slotframe handle 0, length 7, timeslot 0, channel offset 0

### Reception Log

```
[INFO: TSCH-LOG] {asn-0.24c07 link-0-7-0-0 ch-20} bc-0-0 rx LL-0fcc->LL-NULL, len 35, seq 237, dr -1, edr 1
```

**Fields:**
- `bc-0-0`: Broadcast (`bc`), EB indicator (`0`), security level (`0`)
- `rx`: Reception
- `LL-0fcc->LL-NULL`: Source 0fcc, destination NULL (broadcast)
- `len 35`: Packet length
- `seq 237`: MAC sequence number
- `dr -1`: Drift correction applied (rtimer ticks)
- `edr 1`: Opposite of dr

### Transmission Log

```
[INFO: TSCH-LOG] {asn-0.306f3 link-0-7-0-0 ch-20} bc-0-0 tx LL-0fc4->LL-NULL, len 35, seq 188, st 0 1
```

**Fields:**
- `tx`: Transmission
- `st 0 1`: Status 0 (success), attempt 1

**Status codes:**
- `0`: Success (MAC_TX_OK)
- `1`: Collision (MAC_TX_COLLISION)
- `2`: No-ACK (MAC_TX_NOACK)
- `3`: Error (MAC_TX_ERR)

### Unicast Transmission Log

```
[INFO: TSCH-LOG] {asn-0.3591e link-0-7-0-0 ch-26} uc-1-0 tx LL-0fc4->LL-0fcc, len 32, seq 102, st 0 1, dr 1
```

**Fields:**
- `uc-1-0`: Unicast, data (`1`), security level (`0`)
- `LL-0fc4->LL-0fcc`: Source → destination addresses
- `dr 1`: Drift correction from ACK

### Failed Transmission Log

```
[INFO: TSCH-LOG] {asn-0.38230 link-0-7-0-0 ch-15} uc-1-0 tx LL-0fc4->LL-0084, len 32, seq 103, st 2 1
[INFO: TSCH-LOG] {asn-0.38237 link-0-7-0-0 ch-20} uc-1-0 tx LL-0fc4->LL-0084, len 32, seq 103, st 2 2
...
[INFO: TSCH-LOG] {asn-0.3856a link-0-7-0-0 ch-26} uc-1-0 tx LL-0fc4->LL-0084, len 32, seq 103, st 2 8
```

Shows 8 consecutive retransmission attempts (all failed with status 2 = NOACK), hopping through different channels.

## Porting TSCH to New Platforms

### Overview

Porting TSCH requires:
1. Radio driver features (poll mode)
2. Timing macros (radio and rtimer)
3. Platform-specific configuration

Start from an existing port: `sky`, `cc2538dk`, `zoul`, `openmote`, `cc26x0-cc13x0`.

### Required Radio Features

TSCH requires **poll mode** - a new Rx mode where:
- Radio interrupts are disabled
- TSCH polls radio for packets from interrupt at precise times
- Upper layers are never called from radio interrupt

**Capabilities checked by `tsch_init()`:**

1. **Rx mode control (`RADIO_PARAM_RX_MODE`):**
   - `RADIO_RX_MODE_ADDRESS_FILTER`: Disable address filtering
   - `RADIO_RX_MODE_AUTOACK`: Disable auto-ack
   - `RADIO_RX_MODE_POLL_MODE`: Enable poll mode

2. **Tx mode control (`RADIO_PARAM_TX_MODE`):**
   - `RADIO_TX_MODE_SEND_ON_CCA`: Disable CCA before sending

3. **Channel control:**
   - `RADIO_PARAM_CHANNEL`: Set radio channel

4. **Timestamping:**
   - `RADIO_PARAM_LAST_PACKET_TIMESTAMP`: Get SFD timestamp

5. **Optional:**
   - `RADIO_PARAM_LAST_RSSI`: Get RSSI of last packet
   - `RADIO_PARAM_LAST_LQI`: Get LQI of last packet

### Required Timing Macros

Define in platform `rtimer-arch.h` or `contiki-conf.h`:

```c
/* Rtimer conversion */
#define US_TO_RTIMERTICKS(US)  /* Convert μs to rtimer ticks */
#define RTIMERTICKS_TO_US(T)   /* Convert rtimer ticks to μs */

/* Radio timing (in rtimer ticks) */
#define RADIO_DELAY_BEFORE_TX  /* Delay from TX request to SFD sent */
#define RADIO_DELAY_BEFORE_RX  /* Delay from RX request to listening */
#define RADIO_DELAY_BEFORE_DETECT  /* Delay from SFD to receiving_packet() */

/* Air time */
#define RADIO_PHY_OVERHEAD     /* PHY header + CRC bytes (typically 3) */
#define RADIO_BYTE_AIR_TIME    /* Air time per byte in μs */

/* Optional: Custom timeslot timing */
#define TSCH_CONF_DEFAULT_TIMESLOT_TIMING my_timing_template
```

### Example: CC2538 Platform

```c
/* rtimer runs at 32768 Hz */
#define US_TO_RTIMERTICKS(US) \
  ((US) >= 0 ? (((int32_t)(US) * (RTIMER_ARCH_SECOND) + 500000) / 1000000L) : \
               (((int32_t)(US) * (RTIMER_ARCH_SECOND) - 500000) / 1000000L))

#define RTIMERTICKS_TO_US(T) \
  ((T) >= 0 ? (((int32_t)(T) * 1000000L + ((RTIMER_ARCH_SECOND) / 2)) / \
               (RTIMER_ARCH_SECOND)) : \
              (((int32_t)(T) * 1000000L - ((RTIMER_ARCH_SECOND) / 2)) / \
               (RTIMER_ARCH_SECOND)))

/* CC2538 radio timing (250 kbps, 2.4 GHz) */
#define RADIO_DELAY_BEFORE_TX US_TO_RTIMERTICKS(192)
#define RADIO_DELAY_BEFORE_RX US_TO_RTIMERTICKS(192)
#define RADIO_DELAY_BEFORE_DETECT 0

#define RADIO_PHY_OVERHEAD 3
#define RADIO_BYTE_AIR_TIME 32  /* μs, at 250 kbps */

/* Use default 10ms timeslot timing */
#define TSCH_CONF_DEFAULT_TIMESLOT_TIMING tsch_timeslot_timing_us_10000
```

### Testing Your Port

1. **Verify timing accuracy:**
   ```c
   /* Measure actual rtimer accuracy */
   rtimer_clock_t start = RTIMER_NOW();
   clock_delay_usec(10000);  /* 10ms */
   rtimer_clock_t end = RTIMER_NOW();
   int32_t elapsed_us = RTIMERTICKS_TO_US(end - start);
   printf("Expected 10000 us, measured %ld us\n", elapsed_us);
   ```

2. **Test radio poll mode:**
   - Verify packets received without interrupts
   - Check timestamps are accurate

3. **Run simple-node example:**
   - Should join network within ~1 minute
   - Verify per-slot logs show TX/RX

4. **Measure timing margins:**
   - Enable `TSCH_DEBUG_SLOT_TIMING`
   - Verify guard times are sufficient

## Additional Documentation

1. [IEEE 802.15.4-2015 Standard][ieee802.15.4-2015]
2. [IETF 6TiSCH Working Group][ietf-6tisch-wg]
3. [TSCH Implementation Paper](http://www.simonduquennoy.net/papers/duquennoy17tsch.pdf)
4. [Orchestra Paper](http://www.simonduquennoy.net/papers/duquennoy15orchestra.pdf)

[ieee802.15.4-2015]: https://standards.ieee.org/findstds/standard/802.15.4-2015.html
[ietf-6tisch-wg]: https://datatracker.ietf.org/wg/6tisch
