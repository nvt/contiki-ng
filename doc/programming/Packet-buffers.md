# Packet buffers

This page, intended for protocol developers, describes the different types of buffers used in Contiki-NG networking stack. The focus is on the 6LoWPAN stack, but all information about Packetbuf and Queuebuf also applies to NullNet.

## Buffer Architecture Overview

Contiki-NG uses three main buffer types for packet processing, each serving a specific layer in the network stack:

```
┌─────────────────────────────────────────────────────────────┐
│                      Application Layer                       │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ↓
┌─────────────────────────────────────────────────────────────┐
│                    Network Layer (uIP)                       │
│                                                               │
│  uip_buf: Static buffer (1280 bytes default)                │
│  - IPv6 datagrams with headers                               │
│  - Accessible from network layer and above                   │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ↓
┌─────────────────────────────────────────────────────────────┐
│              Adaptation Layer (6LoWPAN/NullNet)             │
│                                                               │
│  Operations: Header compression, fragmentation               │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ↓
┌─────────────────────────────────────────────────────────────┐
│                    Link Layer (MAC)                          │
│                                                               │
│  packetbuf: Global buffer (128 bytes default)               │
│  - Current packet being processed                            │
│  - Link-layer frames with attributes                         │
│  - Single global instance                                    │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ↓
┌─────────────────────────────────────────────────────────────┐
│                   MAC Queue Management                       │
│                                                               │
│  queuebuf: MEMB pool of buffers (8 buffers default)        │
│  - Packets waiting for transmission                          │
│  - Retransmission buffers                                    │
│  - Fragment storage                                          │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ↓
┌─────────────────────────────────────────────────────────────┐
│                    Physical Layer (Radio)                    │
└─────────────────────────────────────────────────────────────┘
```

### Buffer Comparison

| Buffer Type | Scope | Default Size | Storage | Access | Concurrency |
|-------------|-------|--------------|---------|--------|-------------|
| **uip_buf** | Network layer and above | 1280 bytes | Static global | Direct array access | Single packet at a time |
| **packetbuf** | Link layer and below | 128 bytes | Static global | API functions | Single packet at a time |
| **queuebuf** | Link layer | 128 bytes × N | MEMB pool (optionally CFS) | Pointer-based | Multiple packets queued |

**Key principles:**
- **uip_buf** is for complete IPv6 datagrams (network layer and above)
- **packetbuf** is for link-layer frames currently being processed
- **queuebuf** is for storing multiple link-layer frames

## Packet Flow Through the Stack

### Transmission Path

```
Application writes to uip_buf
         ↓
uIP adds IPv6 header → uip_buf
         ↓
6LoWPAN compresses headers → packetbuf
         ↓
6LoWPAN fragments (if needed) → queuebuf for each fragment
         ↓
MAC processes → packetbuf (one fragment at a time)
         ↓
MAC queues (if needed) → queuebuf
         ↓
MAC transmits → Radio
```

**Example with fragmentation:**
```
1280-byte IPv6 packet in uip_buf
  → 6LoWPAN compression (saves ~38 bytes)
  → Payload still too large for 127-byte MAC frame
  → Create 10 fragments, each stored in queuebuf
  → MAC processes fragments one by one via packetbuf
```

### Reception Path

```
Radio receives → MAC writes to packetbuf
         ↓
MAC passes to 6LoWPAN → packetbuf with attributes
         ↓
6LoWPAN decompresses → uip_buf
         ↓
6LoWPAN reassembles (if fragmented) → uses queuebuf for fragment storage
         ↓
uIP processes → uip_buf
         ↓
Application reads from uip_buf
```

## uIP Buffer

At the network layer and above, packet payloads are stored in `uip_buf`.

### Architecture

The uIP buffer is a **statically allocated** array that holds complete IPv6 datagrams including headers. It is defined in `os/net/ipv6/uip6.c`:

```c
/* Aligned buffer for 32-bit access */
typedef union {
  uint32_t u32[(UIP_BUFSIZE + 3) / 4];
  uint8_t u8[UIP_BUFSIZE];
} uip_buf_t;

extern uip_buf_t uip_aligned_buf;
#define uip_buf (uip_aligned_buf.u8)
```

**Memory layout:**
```
uip_buf (UIP_BUFSIZE = 1280 bytes default):
┌──────────────────────────────────────────────────────────┐
│ [IPv6 Header: 40] [Extension Headers] [Payload]          │
└──────────────────────────────────────────────────────────┘
 ^                   ^                  ^
 UIP_IP_BUF          uip_ext_len        uip_appdata
```

**Key macros for accessing uIP buffer:**
```c
#define UIP_IP_BUF        ((struct uip_ip_hdr *)uip_buf)
#define UIP_IP_PAYLOAD(ext) ((unsigned char *)uip_buf + UIP_IPH_LEN + (ext))
#define UIP_ICMP_BUF      ((struct uip_icmp_hdr *)UIP_IP_PAYLOAD(uip_ext_len))
#define UIP_UDP_BUF       ((struct uip_udp_hdr *)UIP_IP_PAYLOAD(uip_ext_len))
#define UIP_TCP_BUF       ((struct uip_tcp_hdr *)UIP_IP_PAYLOAD(uip_ext_len))
```

### Configuration

```c
/* In project-conf.h */

/* IPv6 buffer size (default: 1280, minimum for IPv6 compliance) */
#define UIP_CONF_BUFFER_SIZE 1280

/* For constrained devices, can reduce if no large datagrams */
#define UIP_CONF_BUFFER_SIZE 256  /* Saves 1KB RAM */
```

**Configuration guidelines:**
- **1280 bytes**: IPv6 minimum MTU, required for full IPv6 compliance
- **256-512 bytes**: Sufficient for CoAP/UDP applications with small payloads
- **2048+ bytes**: For applications requiring large datagrams (rare in IoT)

### Transmission Usage

To send data, upper-layer protocols or applications write to `uip_buf` and then trigger a transmission:

```c
void
send_udp_packet(void)
{
  /* Prepare data in uip_buf */
  uint8_t *data = uip_appdata;
  memcpy(data, "Hello, world!", 13);

  /* Send via UDP */
  uip_udp_packet_send(conn, data, 13);
  /* uIP will:
   *  1. Add IPv6 header to uip_buf
   *  2. Add UDP header
   *  3. Call 6LoWPAN for compression
   *  4. Pass to MAC layer via packetbuf
   */
}
```

**Processing flow:**
1. Application/protocol writes payload to `uip_appdata`
2. uIP adds IPv6 header and possible extension headers
3. 6LoWPAN compresses headers and fragments if needed
4. Each fragment is passed to MAC layer via `packetbuf`

### Reception Usage

At reception time, the reverse procedure takes place:

```c
void
input(void)
{
  /* MAC received frame in packetbuf */
  /* 6LoWPAN decompresses and reassembles into uip_buf */

  /* Now uIP processes the complete datagram */
  if(UIP_IP_BUF->proto == UIP_PROTO_UDP) {
    /* UDP datagram is now accessible */
    uint8_t *payload = UIP_UDP_PAYLOAD;
    uint16_t payload_len = uip_datalen();
    /* Process payload */
  }
}
```

**Processing flow:**
1. MAC layer receives frame and stores in `packetbuf`
2. 6LoWPAN decompresses headers
3. 6LoWPAN reassembles fragments (using `queuebuf` for storage)
4. Complete datagram is placed in `uip_buf`
5. uIP stack processes and delivers to application

### Access Rules for uip_buf

**Allowed:**
- Access from 6LoWPAN, uIP, or above
- Only outside of interrupt context

**Not allowed:**
- Access from MAC layer or below (use `packetbuf` instead)
- Access from interrupt context (not thread-safe)

## Packetbuf

The `packetbuf` module manages the **global link-layer packet buffer**. 6LoWPAN builds link-layer packets directly into `packetbuf`. In addition to the payload, `packetbuf` carries packet attributes and metadata.

### Architecture

Packetbuf is a **single global buffer** with header/data management:

```c
/* In os/net/packetbuf.c */
static uint32_t packetbuf_aligned[(PACKETBUF_SIZE + 3) / 4];
static uint8_t *packetbuf = (uint8_t *)packetbuf_aligned;

static uint16_t buflen, bufptr;  /* Data length and offset */
static uint8_t hdrlen;            /* Header length */
```

**Memory layout:**
```
packetbuf (PACKETBUF_SIZE = 128 bytes default):
┌─────────────────────────────────────────────────────────┐
│ [Header space] [Data]                    [Unused]       │
└─────────────────────────────────────────────────────────┘
 ^              ^                          ^              ^
 packetbuf      packetbuf_dataptr()        buflen+hdrlen  PACKETBUF_SIZE
 (base)         (bufptr + hdrlen)

Header allocation (via hdralloc) shifts data to the right:
Before: [Data.....................]
After:  [Hdr][Data................]
```

**Key internal variables:**
- `buflen`: Length of data portion
- `bufptr`: Offset for data (normally 0)
- `hdrlen`: Length of header portion

### Configuration

```c
/* In project-conf.h */

/* Link-layer packet buffer size (default: 128) */
#define PACKETBUF_CONF_SIZE 128

/* For IEEE 802.15.4: max frame size is 127 bytes */
/* Common values: 128 (default), 256 (for larger MACs) */
```

**Configuration guidelines:**
- **128 bytes**: Standard for IEEE 802.15.4 (127-byte max frame)
- **256 bytes**: For other link layers with larger frames
- Must be ≥ maximum MAC frame size for your hardware

### Packetbuf API Reference

#### Buffer Management

| Function | Purpose | Returns |
|----------|---------|---------|
| `void packetbuf_clear(void)` | Clear and reset packetbuf | - |
| `int packetbuf_copyfrom(const void *from, uint16_t len)` | Copy data into packetbuf | Bytes copied |
| `int packetbuf_copyto(void *to)` | Copy entire packet (header + data) to external buffer | Bytes copied |

#### Data Access

| Function | Purpose | Returns |
|----------|---------|---------|
| `void *packetbuf_dataptr(void)` | Get pointer to data portion | Pointer to data |
| `void *packetbuf_hdrptr(void)` | Get pointer to header portion | Pointer to header |
| `uint16_t packetbuf_datalen(void)` | Get length of data | Data length |
| `uint8_t packetbuf_hdrlen(void)` | Get length of header | Header length |
| `uint16_t packetbuf_totlen(void)` | Get total length (header + data) | Total length |
| `uint16_t packetbuf_remaininglen(void)` | Get remaining space | Available bytes |
| `void packetbuf_set_datalen(uint16_t len)` | Set data length | - |

#### Header Manipulation

| Function | Purpose | Returns |
|----------|---------|---------|
| `int packetbuf_hdralloc(int size)` | Extend header (shifts data right) | 1 on success, 0 on failure |
| `int packetbuf_hdrreduce(int size)` | Reduce header (advances data pointer) | 1 on success, 0 on failure |

**Header allocation example:**
```c
/* Outbound packet: add headers as we go down the stack */

/* Start with payload */
packetbuf_copyfrom("Hello", 5);
/* packetbuf: [Hello___________] (datalen=5, hdrlen=0) */

/* Add MAC header (10 bytes) */
if(packetbuf_hdralloc(10)) {
  uint8_t *hdr = packetbuf_hdrptr();
  /* Fill in MAC header fields */
  hdr[0] = frame_type;
  /* ... */
}
/* packetbuf: [MAC_HDR(10)][Hello___] (datalen=5, hdrlen=10) */

/* Add security header (14 bytes) */
if(packetbuf_hdralloc(14)) {
  uint8_t *sec_hdr = packetbuf_hdrptr();
  /* Fill in security header */
}
/* packetbuf: [SEC(14)][MAC_HDR(10)][Hello] (datalen=5, hdrlen=24) */
```

**Header reduction example:**
```c
/* Inbound packet: remove headers as we go up the stack */

/* Received frame in packetbuf */
/* packetbuf: [SEC(14)][MAC_HDR(10)][Hello] (datalen=19, hdrlen=0) */

/* Remove security header */
packetbuf_hdrreduce(14);
/* packetbuf: [MAC_HDR(10)][Hello] (datalen=5, bufptr=14) */

/* Remove MAC header */
packetbuf_hdrreduce(10);
/* packetbuf: [Hello] (datalen=5, bufptr=24) */

/* Now dataptr() points to payload */
uint8_t *payload = packetbuf_dataptr();  /* "Hello" */
```

#### Attributes and Addresses

| Function | Purpose | Returns |
|----------|---------|---------|
| `void packetbuf_set_attr(uint8_t type, packetbuf_attr_t val)` | Set attribute value | - |
| `packetbuf_attr_t packetbuf_attr(uint8_t type)` | Get attribute value | Attribute value |
| `void packetbuf_set_addr(uint8_t type, const linkaddr_t *addr)` | Set address attribute | - |
| `const linkaddr_t *packetbuf_addr(uint8_t type)` | Get address attribute | Address pointer |
| `void packetbuf_attr_clear(void)` | Clear all attributes | - |
| `void packetbuf_attr_copyto(struct packetbuf_attr *attrs, struct packetbuf_addr *addrs)` | Copy attributes to external storage | - |
| `void packetbuf_attr_copyfrom(struct packetbuf_attr *attrs, struct packetbuf_addr *addrs)` | Copy attributes from external storage | - |
| `bool packetbuf_holds_broadcast(void)` | Check if packet is broadcast | true if broadcast |

### Packetbuf Attributes

Packetbuf carries **metadata** alongside the packet data. Attributes are categorized by scope:

#### Scope 0: Local Node Only

These attributes are used only on the local node and are not transmitted:

| Attribute | Type | Description |
|-----------|------|-------------|
| `PACKETBUF_ATTR_CHANNEL` | uint16_t | Radio channel number |
| `PACKETBUF_ATTR_NETWORK_ID` | uint16_t | Network/PAN ID |
| `PACKETBUF_ATTR_LINK_QUALITY` | uint16_t | Link quality indicator (LQI) |
| `PACKETBUF_ATTR_RSSI` | uint16_t | Received signal strength indicator |
| `PACKETBUF_ATTR_MAX_MAC_TRANSMISSIONS` | uint16_t | Maximum retransmission attempts |
| `PACKETBUF_ATTR_MAC_SEQNO` | uint16_t | MAC sequence number |
| `PACKETBUF_ATTR_MAC_ACK` | uint16_t | ACK required flag |
| `PACKETBUF_ATTR_MAC_METADATA` | uint16_t | MAC-specific metadata |
| `PACKETBUF_ATTR_MAC_NO_SRC_ADDR` | uint16_t | Suppress source address |
| `PACKETBUF_ATTR_MAC_NO_DEST_ADDR` | uint16_t | Suppress destination address |

**TSCH-specific attributes** (when `TSCH_WITH_LINK_SELECTOR` is enabled):

| Attribute | Type | Description |
|-----------|------|-------------|
| `PACKETBUF_ATTR_TSCH_SLOTFRAME` | uint16_t | Target slotframe handle |
| `PACKETBUF_ATTR_TSCH_TIMESLOT` | uint16_t | Target timeslot |
| `PACKETBUF_ATTR_TSCH_CHANNEL_OFFSET` | uint16_t | Target channel offset |

#### Scope 1: Link-Layer (Neighbors)

These attributes are used between two neighbors only (embedded in MAC header):

| Attribute | Type | Description |
|-----------|------|-------------|
| `PACKETBUF_ATTR_FRAME_TYPE` | uint16_t | IEEE 802.15.4 frame type |
| `PACKETBUF_ATTR_SECURITY_LEVEL` | uint16_t | Link-layer security level (if enabled) |
| `PACKETBUF_ATTR_KEY_ID_MODE` | uint16_t | Key identifier mode (if explicit keys) |
| `PACKETBUF_ATTR_KEY_INDEX` | uint16_t | Key index (if explicit keys) |
| `PACKETBUF_ATTR_FRAME_COUNTER_BYTES_0_1` | uint16_t | Frame counter bytes 0-1 (if frame counter enabled) |
| `PACKETBUF_ATTR_FRAME_COUNTER_BYTES_2_3` | uint16_t | Frame counter bytes 2-3 (if frame counter enabled) |

#### Scope 2: End-to-End

These are addresses used end-to-end:

| Attribute | Type | Description |
|-----------|------|-------------|
| `PACKETBUF_ADDR_SENDER` | linkaddr_t | Source link-layer address |
| `PACKETBUF_ADDR_RECEIVER` | linkaddr_t | Destination link-layer address |

### Attribute Usage Example

```c
void
send_packet_with_attributes(void)
{
  /* Prepare packet data */
  packetbuf_copyfrom("sensor data", 11);

  /* Set addresses */
  linkaddr_t dest;
  linkaddr_copy(&dest, &coordinator_addr);
  packetbuf_set_addr(PACKETBUF_ADDR_RECEIVER, &dest);
  packetbuf_set_addr(PACKETBUF_ADDR_SENDER, &linkaddr_node_addr);

  /* Set MAC attributes */
  packetbuf_set_attr(PACKETBUF_ATTR_MAX_MAC_TRANSMISSIONS, 3);
  packetbuf_set_attr(PACKETBUF_ATTR_MAC_ACK, 1);  /* Request ACK */

  /* TSCH: specify which timeslot to use */
#if TSCH_WITH_LINK_SELECTOR
  packetbuf_set_attr(PACKETBUF_ATTR_TSCH_SLOTFRAME, 0);
  packetbuf_set_attr(PACKETBUF_ATTR_TSCH_TIMESLOT, 5);
#endif

  /* Send to MAC */
  NETSTACK_MAC.send(NULL, NULL);
}

void
receive_packet_with_attributes(void)
{
  /* MAC received packet in packetbuf */

  /* Read attributes */
  int8_t rssi = packetbuf_attr(PACKETBUF_ATTR_RSSI);
  uint8_t lqi = packetbuf_attr(PACKETBUF_ATTR_LINK_QUALITY);
  const linkaddr_t *sender = packetbuf_addr(PACKETBUF_ADDR_SENDER);

  LOG_INFO("Received from ");
  LOG_INFO_LLADDR(sender);
  LOG_INFO_(" RSSI: %d, LQI: %u\n", rssi, lqi);

  /* Process packet data */
  uint8_t *data = packetbuf_dataptr();
  uint16_t len = packetbuf_datalen();
}
```

### Access Rules for packetbuf

**Allowed:**
- Access from 6LoWPAN or below (MAC, radio drivers)
- Only outside of interrupt context

**Not allowed:**
- Access from network layer or above (use `uip_buf` instead)
- Access from interrupt context (not thread-safe)

## Queuebuf

The `queuebuf` module provides a way to manage **multiple packets at a time**. While `packetbuf` is a single global buffer, `queuebuf` instances are allocated from a MEMB pool and can store multiple packets.

### Architecture

```c
/* In os/net/queuebuf.c */

/* Queuebuf handle (points to data location) */
struct queuebuf {
#if QUEUEBUF_DEBUG
  const char *file;
  int line;
  clock_time_t time;
#endif
#if WITH_SWAP
  enum {IN_RAM, IN_CFS} location;
  union {
    struct queuebuf_data *ram_ptr;
    int swap_id;  /* CFS file offset */
  };
#else
  struct queuebuf_data *ram_ptr;
#endif
};

/* Actual packet data */
struct queuebuf_data {
  uint8_t data[PACKETBUF_SIZE];
  uint16_t len;
  struct packetbuf_attr attrs[PACKETBUF_NUM_ATTRS];
  struct packetbuf_addr addrs[PACKETBUF_NUM_ADDRS];
};

/* Memory pools */
MEMB(bufmem, struct queuebuf, QUEUEBUF_NUM);                 /* Handles */
MEMB(buframmem, struct queuebuf_data, QUEUEBUFRAM_NUM);     /* Data in RAM */
```

**Two-tier structure:**
1. **Queuebuf handle** (`struct queuebuf`): Small metadata structure
2. **Queuebuf data** (`struct queuebuf_data`): Actual packet + attributes

**Memory layout:**
```
┌──────────────────────────────────────────────────────────┐
│ MEMB pool: queuebuf handles (8 × ~12 bytes = 96 bytes)  │
│  [qbuf0] [qbuf1] [qbuf2] ... [qbuf7]                     │
└─────┬────────────────────────────────────────────────────┘
      │
      ↓ points to data
┌──────────────────────────────────────────────────────────┐
│ MEMB pool: queuebuf_data (8 × ~160 bytes = 1280 bytes)  │
│  [data0: 128B packet + attrs] [data1] ... [data7]        │
└──────────────────────────────────────────────────────────┘
```

**Total memory (default config):**
- 8 queuebuf handles: ~96 bytes
- 8 queuebuf_data: ~1280 bytes
- **Total: ~1.4 KB**

### Configuration

```c
/* In project-conf.h */

/* Number of queuebufs (default: 8) */
#define QUEUEBUF_CONF_NUM 8

/* Number of queuebufs stored in RAM (default: same as QUEUEBUF_NUM) */
/* If < QUEUEBUF_NUM, remaining are swapped to CFS (flash storage) */
#define QUEUEBUFRAM_CONF_NUM 4  /* 4 in RAM, 4 in CFS */

/* Enable/disable queuebuf module (default: 1) */
#define QUEUEBUF_CONF_ENABLED 1

/* Enable debug mode (tracks file/line of allocations) */
#define QUEUEBUF_CONF_DEBUG 1

/* Enable statistics tracking */
#define QUEUEBUF_CONF_STATS 1
```

**Configuration guidelines:**

**QUEUEBUF_NUM sizing:**
- **Minimum 4**: Basic operation with CSMA or simple applications
- **8 (default)**: Reasonable for most applications
- **16+**: High-traffic applications, many fragments, TSCH with multiple slotframes

**Memory vs storage tradeoff (QUEUEBUFRAM_NUM):**
```c
/* All in RAM (fast, uses more RAM) */
#define QUEUEBUF_CONF_NUM 8
/* QUEUEBUFRAM_CONF_NUM not set (defaults to QUEUEBUF_NUM) */

/* Mixed RAM + CFS (saves RAM, slower due to flash access) */
#define QUEUEBUF_CONF_NUM 8
#define QUEUEBUFRAM_CONF_NUM 4  /* 4 in RAM, 4 swapped to CFS */
```

**When to disable queuebuf:**
```c
#define QUEUEBUF_CONF_ENABLED 0
```
Only disable if:
- Not using CSMA (requires queuebuf for retransmissions)
- Not using TSCH (requires queuebuf for queues)
- Not using 6LoWPAN fragmentation
- Using simple point-to-point with no queuing (e.g., NullNet without retries)

### Queuebuf API Reference

#### Creation and Management

| Function | Purpose | Returns |
|----------|---------|---------|
| `struct queuebuf *queuebuf_new_from_packetbuf(void)` | Allocate queuebuf and copy current packetbuf into it | Queuebuf pointer, or NULL if pool exhausted |
| `void queuebuf_update_from_packetbuf(struct queuebuf *b)` | Update existing queuebuf with current packetbuf (data + attributes) | - |
| `void queuebuf_update_attr_from_packetbuf(struct queuebuf *b)` | Update only attributes from current packetbuf | - |
| `void queuebuf_to_packetbuf(struct queuebuf *b)` | Restore queuebuf contents to packetbuf | - |
| `void queuebuf_free(struct queuebuf *b)` | Free queuebuf | - |

#### Data Access

| Function | Purpose | Returns |
|----------|---------|---------|
| `void *queuebuf_dataptr(struct queuebuf *b)` | Get pointer to queuebuf data | Data pointer |
| `int queuebuf_datalen(struct queuebuf *b)` | Get length of queuebuf data | Data length |
| `linkaddr_t *queuebuf_addr(struct queuebuf *b, uint8_t type)` | Get address attribute | Address pointer |
| `packetbuf_attr_t queuebuf_attr(struct queuebuf *b, uint8_t type)` | Get attribute value | Attribute value |

#### Monitoring

| Function | Purpose | Returns |
|----------|---------|---------|
| `size_t queuebuf_numfree(void)` | Get number of free queuebufs | Free count |
| `void queuebuf_debug_print(void)` | Print debug info (if QUEUEBUF_DEBUG enabled) | - |

### Queuebuf Usage Examples

#### Example 1: Basic Queueing for Retransmission

```c
void
csma_transmit_packet(void)
{
  struct queuebuf *q;

  /* Current packet is in packetbuf */
  /* Queue it for potential retransmission */
  q = queuebuf_new_from_packetbuf();
  if(q == NULL) {
    LOG_WARN("Queuebuf pool exhausted\n");
    return;
  }

  /* Attempt transmission */
  radio_send(packetbuf_hdrptr(), packetbuf_totlen());

  /* Wait for ACK... */
  if(!ack_received) {
    /* Restore packet for retransmission */
    queuebuf_to_packetbuf(q);
    /* Retry */
    radio_send(packetbuf_hdrptr(), packetbuf_totlen());
  }

  /* Done with queuebuf */
  queuebuf_free(q);
}
```

#### Example 2: Fragmentation (6LoWPAN)

```c
void
fragment_and_send(uint8_t *data, uint16_t datalen)
{
  struct queuebuf *fragments[MAX_FRAGMENTS];
  int num_fragments = (datalen + FRAG_SIZE - 1) / FRAG_SIZE;

  /* Create fragments and queue them */
  for(int i = 0; i < num_fragments; i++) {
    /* Prepare fragment i in packetbuf */
    uint16_t frag_offset = i * FRAG_SIZE;
    uint16_t frag_len = MIN(FRAG_SIZE, datalen - frag_offset);

    packetbuf_clear();
    create_fragment_header(i, num_fragments);
    packetbuf_copyfrom(&data[frag_offset], frag_len);

    /* Queue this fragment */
    fragments[i] = queuebuf_new_from_packetbuf();
    if(fragments[i] == NULL) {
      /* Pool exhausted, free previous fragments */
      for(int j = 0; j < i; j++) {
        queuebuf_free(fragments[j]);
      }
      LOG_ERR("Cannot allocate fragment queuebufs\n");
      return;
    }
  }

  /* Send all fragments */
  for(int i = 0; i < num_fragments; i++) {
    queuebuf_to_packetbuf(fragments[i]);
    NETSTACK_MAC.send(NULL, NULL);
    queuebuf_free(fragments[i]);
  }
}
```

#### Example 3: Multi-Queue MAC (TSCH)

```c
#define NUM_SLOTFRAMES 2

struct packet_queue {
  struct queuebuf *packets[QUEUE_SIZE];
  int head, tail, count;
};

struct packet_queue queues[NUM_SLOTFRAMES];

void
enqueue_packet(int slotframe_id)
{
  struct packet_queue *q = &queues[slotframe_id];

  if(q->count >= QUEUE_SIZE) {
    LOG_WARN("Queue %d full\n", slotframe_id);
    return;
  }

  /* Queue current packetbuf */
  q->packets[q->tail] = queuebuf_new_from_packetbuf();
  if(q->packets[q->tail] == NULL) {
    LOG_ERR("Queuebuf pool exhausted\n");
    return;
  }

  q->tail = (q->tail + 1) % QUEUE_SIZE;
  q->count++;

  LOG_DBG("Queued packet in slotframe %d (%d packets queued, %zu free)\n",
          slotframe_id, q->count, queuebuf_numfree());
}

void
dequeue_and_send(int slotframe_id)
{
  struct packet_queue *q = &queues[slotframe_id];

  if(q->count == 0) {
    return;  /* Queue empty */
  }

  /* Restore packet to packetbuf */
  queuebuf_to_packetbuf(q->packets[q->head]);
  queuebuf_free(q->packets[q->head]);

  q->head = (q->head + 1) % QUEUE_SIZE;
  q->count--;

  /* Send */
  NETSTACK_RADIO.send(packetbuf_hdrptr(), packetbuf_totlen());
}
```

#### Example 4: Monitoring Queue Usage

```c
void
check_queuebuf_health(void)
{
  size_t free = queuebuf_numfree();
  size_t total = QUEUEBUF_NUM;
  size_t used = total - free;

  LOG_INFO("Queuebuf: %zu/%zu used (%.1f%%)\n",
           used, total, 100.0 * used / total);

  if(free < 2) {
    LOG_WARN("Queuebuf pool nearly exhausted (only %zu free)\n", free);
  }

#if QUEUEBUF_DEBUG
  /* Print allocation details */
  queuebuf_debug_print();
  /* Output: queuebuf_list: module.c,123,1000 other.c,456,2000 ... */
#endif
}
```

### Swapping to CFS (Advanced)

When `QUEUEBUFRAM_CONF_NUM < QUEUEBUF_CONF_NUM`, Contiki-NG uses the **Coffee File System (CFS)** to store excess queuebufs, saving RAM at the cost of flash access latency.

**How it works:**
```c
#define QUEUEBUF_CONF_NUM 8        /* 8 total queuebufs */
#define QUEUEBUFRAM_CONF_NUM 4     /* Only 4 in RAM */

/* First 4 allocations: stored in RAM (fast) */
struct queuebuf *q1 = queuebuf_new_from_packetbuf();  /* RAM */
struct queuebuf *q2 = queuebuf_new_from_packetbuf();  /* RAM */
struct queuebuf *q3 = queuebuf_new_from_packetbuf();  /* RAM */
struct queuebuf *q4 = queuebuf_new_from_packetbuf();  /* RAM */

/* Next 4 allocations: stored in CFS (slower, saves RAM) */
struct queuebuf *q5 = queuebuf_new_from_packetbuf();  /* CFS */
struct queuebuf *q6 = queuebuf_new_from_packetbuf();  /* CFS */
/* ... */
```

**Internal mechanism:**
1. Queuebuf handle always in RAM (~12 bytes)
2. If RAM pool exhausted, allocate from CFS swap files
3. Data written to flash using `cfs_write()`
4. When accessed, data loaded to temporary RAM buffer
5. Multiple swap files used to minimize write cycles

**Performance impact:**
```
RAM access:     ~10-100 CPU cycles
CFS read/write: ~1000-10000 CPU cycles (platform-dependent)
```

**When to use swapping:**
- Devices with very limited RAM (< 8 KB)
- Applications with occasional burst traffic (temporary queue spike)
- Platforms with fast flash access

**When NOT to use swapping:**
- Real-time applications (introduces latency jitter)
- High packet rate (flash wear, performance degradation)
- Platforms without CFS support

### Access Rules for queuebuf

**Allowed:**
- Access from 6LoWPAN or below (MAC layers)
- Outside of interrupt context (for allocation/free)
- From interrupt context if queuebuf is protected with lock (TSCH does this)

**Not allowed:**
- Access from network layer or above
- Unprotected access from ISRs (race conditions)

## Buffer Sizing Guidelines

### Determining Buffer Sizes

Use the following formulas to calculate appropriate buffer sizes:

#### uIP Buffer Size

```
UIP_CONF_BUFFER_SIZE ≥ max_application_payload + protocol_overhead

For IPv6 + UDP:
  overhead = 40 (IPv6) + 8 (UDP) = 48 bytes

For IPv6 + UDP + CoAP:
  overhead = 40 + 8 + ~10 (CoAP header) = 58 bytes

Minimum IPv6 compliance: 1280 bytes
```

**Example calculations:**
```c
/* CoAP application with 200-byte payloads */
#define UIP_CONF_BUFFER_SIZE (200 + 48 + 10)  /* 258 bytes */

/* UDP application with 512-byte datagrams */
#define UIP_CONF_BUFFER_SIZE (512 + 48)  /* 560 bytes */

/* Full IPv6 compliance */
#define UIP_CONF_BUFFER_SIZE 1280
```

#### Packetbuf Size

```
PACKETBUF_CONF_SIZE ≥ max_mac_frame_size

IEEE 802.15.4: 127 bytes max → PACKETBUF_SIZE = 128
IEEE 802.15.4g: 2047 bytes max → PACKETBUF_SIZE = 2048
```

#### Queuebuf Count

```
QUEUEBUF_NUM ≥ sum_of_all_queues

For CSMA:
  1-2 buffers per active conversation

For TSCH:
  buffers_per_queue × num_queues
  Example: 4 buffers/queue × 2 queues = 8

For 6LoWPAN fragmentation:
  max_fragments = ceil(max_datagram / fragment_size)
  Example: 1280 / 100 ≈ 13 fragments
```

**Example for TSCH network:**
```c
/* TSCH with 3 slotframes, each with 4-packet queue */
#define QUEUEBUF_CONF_NUM 12  /* 3 × 4 = 12 */

/* Save RAM by swapping to CFS */
#define QUEUEBUFRAM_CONF_NUM 6   /* 6 in RAM, 6 in CFS */
```

### Memory Budget Examples

#### Example 1: Minimal Configuration (8 KB RAM device)

```c
/* project-conf.h */

/* Small uIP buffer for CoAP */
#define UIP_CONF_BUFFER_SIZE 256            /* 256 bytes */

/* Standard packetbuf for 802.15.4 */
#define PACKETBUF_CONF_SIZE 128             /* 128 bytes */

/* Minimal queuebuf */
#define QUEUEBUF_CONF_NUM 4                 /* 4 buffers */
#define QUEUEBUFRAM_CONF_NUM 2              /* 2 in RAM, 2 in CFS */

/* Disable fragmentation to avoid needing many queuebufs */
#define SICSLOWPAN_CONF_FRAG 0

/*
Memory usage:
  uip_buf:          256 bytes
  packetbuf:        128 bytes
  queuebuf (2 RAM): 320 bytes (2 × 160)
  Total buffers:    ~704 bytes
*/
```

#### Example 2: Standard Configuration (16 KB RAM device)

```c
/* project-conf.h */

/* Standard IPv6 MTU */
#define UIP_CONF_BUFFER_SIZE 1280           /* 1280 bytes */

/* Standard packetbuf */
#define PACKETBUF_CONF_SIZE 128             /* 128 bytes */

/* Standard queuebuf */
#define QUEUEBUF_CONF_NUM 8                 /* 8 buffers */

/*
Memory usage:
  uip_buf:     1280 bytes
  packetbuf:    128 bytes
  queuebuf (8): 1280 bytes (8 × 160)
  Total:       ~2688 bytes
*/
```

#### Example 3: High-Performance TSCH (32 KB RAM device)

```c
/* project-conf.h */

/* Large IPv6 buffer */
#define UIP_CONF_BUFFER_SIZE 1280           /* 1280 bytes */

/* Standard packetbuf */
#define PACKETBUF_CONF_SIZE 128             /* 128 bytes */

/* Many queuebufs for TSCH queues */
#define QUEUEBUF_CONF_NUM 16                /* 16 buffers */

/* Enable debug tracking */
#define QUEUEBUF_CONF_DEBUG 1

/*
Memory usage:
  uip_buf:      1280 bytes
  packetbuf:     128 bytes
  queuebuf (16): 2560 bytes (16 × 160)
  Debug overhead: ~256 bytes
  Total:        ~4224 bytes
*/
```

## Troubleshooting

### Issue 1: Packet Too Large for packetbuf

**Symptom:**
```
WARN: Packet size 150 exceeds PACKETBUF_SIZE (128)
```

**Causes:**
- Link-layer frame larger than PACKETBUF_SIZE
- Too many headers added (6LoWPAN + security + MAC)

**Solutions:**
```c
/* Increase packetbuf size */
#define PACKETBUF_CONF_SIZE 256

/* OR reduce packet size */
#define UIP_CONF_BUFFER_SIZE 512  /* Smaller datagrams */

/* OR enable fragmentation */
#define SICSLOWPAN_CONF_FRAG 1    /* Fragment large packets */
```

### Issue 2: Queuebuf Pool Exhausted

**Symptom:**
```
ERR: queuebuf_new_from_packetbuf: could not allocate queuebuf
Queuebuf pool exhausted
```

**Causes:**
- Too many packets queued simultaneously
- Queuebufs not being freed (memory leak)
- Fragmentation requires many buffers

**Diagnosis:**
```c
/* Add monitoring */
void
diagnose_queuebuf(void)
{
  size_t free = queuebuf_numfree();
  LOG_INFO("Queuebuf free: %zu/%d\n", free, QUEUEBUF_NUM);

#if QUEUEBUF_DEBUG
  queuebuf_debug_print();  /* Shows allocation sites */
#endif
}
```

**Solutions:**
```c
/* Increase pool size */
#define QUEUEBUF_CONF_NUM 16

/* Use CFS swapping to save RAM */
#define QUEUEBUF_CONF_NUM 16
#define QUEUEBUFRAM_CONF_NUM 8   /* 8 RAM + 8 CFS */

/* Enable debug to find leaks */
#define QUEUEBUF_CONF_DEBUG 1
```

### Issue 3: Packet Corruption

**Symptom:**
- Received packets have corrupted data
- Checksums fail
- Random transmission failures

**Causes:**
- Concurrent access to packetbuf (ISR + main context)
- Not copying packetbuf before it's overwritten
- Header allocation overflow

**Solutions:**
```c
/* WRONG: Using packetbuf pointer after sending */
void
bad_example(void)
{
  uint8_t *data = packetbuf_dataptr();
  NETSTACK_MAC.send(NULL, NULL);
  /* packetbuf may be overwritten by now! */
  process_data(data);  /* DANGER: data may be corrupted */
}

/* CORRECT: Copy data before it can be overwritten */
void
good_example(void)
{
  uint8_t data_copy[128];
  uint16_t len = packetbuf_datalen();
  memcpy(data_copy, packetbuf_dataptr(), len);

  NETSTACK_MAC.send(NULL, NULL);
  /* Safe: working with copy */
  process_data(data_copy);
}

/* OR: Use queuebuf to preserve packet */
void
better_example(void)
{
  struct queuebuf *q = queuebuf_new_from_packetbuf();

  NETSTACK_MAC.send(NULL, NULL);

  /* Restore packet */
  queuebuf_to_packetbuf(q);
  process_data(packetbuf_dataptr());
  queuebuf_free(q);
}
```

### Issue 4: CFS Swap Errors

**Symptom:**
```
ERR: queuebuf_flush_tmpdata: cfs write error
ERR: queuebuf_load_to_ram: cfs read error
```

**Causes:**
- CFS not initialized
- Flash wear/failure
- Insufficient flash space

**Solutions:**
```c
/* Disable swapping if CFS unavailable */
#define QUEUEBUFRAM_CONF_NUM QUEUEBUF_CONF_NUM  /* All in RAM */

/* OR reduce queuebuf count */
#define QUEUEBUF_CONF_NUM 4  /* Fewer buffers, all in RAM */

/* Check CFS status */
void
check_cfs(void)
{
  int fd = cfs_open("test", CFS_WRITE);
  if(fd == -1) {
    LOG_ERR("CFS not available\n");
  } else {
    cfs_close(fd);
  }
}
```

### Issue 5: Fragmentation Failures

**Symptom:**
```
ERR: Cannot allocate fragment queuebufs
WARN: Fragmentation requires X queuebufs, only Y available
```

**Causes:**
- Not enough queuebufs for all fragments
- Fragments = ceil(datagram_size / fragment_size)

**Solutions:**
```c
/* Calculate required queuebufs */
/* Example: 1280-byte datagram, 80-byte fragments */
/* Fragments needed: ceil(1280/80) = 16 */

#define QUEUEBUF_CONF_NUM 20  /* 16 for fragments + 4 for other traffic */

/* OR reduce datagram size */
#define UIP_CONF_BUFFER_SIZE 640  /* Smaller datagrams = fewer fragments */

/* OR increase fragment size (if possible) */
/* Depends on link layer and compression efficiency */
```

### Issue 6: Attribute Loss

**Symptom:**
- Security attributes missing after queueing
- RSSI/LQI information lost
- Addresses incorrect

**Causes:**
- Attributes not copied when queueing
- Using `queuebuf_update_from_packetbuf()` vs `queuebuf_update_attr_from_packetbuf()`

**Solutions:**
```c
/* Ensure attributes are copied */
struct queuebuf *q = queuebuf_new_from_packetbuf();  /* Copies data + attrs */

/* When updating existing queuebuf */
queuebuf_update_from_packetbuf(q);  /* Updates both data and attrs */

/* To update only attributes (preserve data) */
queuebuf_update_attr_from_packetbuf(q);  /* Updates only attrs */
```

### Issue 7: Memory Leaks

**Symptom:**
- Queuebuf pool slowly depletes over time
- System stops working after hours/days

**Detection:**
```c
/* Enable debug mode */
#define QUEUEBUF_CONF_DEBUG 1

/* Periodically check */
void
check_for_leaks(void)
{
  static size_t last_free = QUEUEBUF_NUM;
  size_t current_free = queuebuf_numfree();

  if(current_free < last_free) {
    LOG_WARN("Queuebuf leak? Free decreased: %zu → %zu\n",
             last_free, current_free);
    queuebuf_debug_print();  /* Shows where buffers were allocated */
  }

  last_free = current_free;
}
```

**Common leak patterns:**
```c
/* LEAK: Forgetting to free on error path */
struct queuebuf *q = queuebuf_new_from_packetbuf();
if(q == NULL) return;

if(some_error) {
  return;  /* LEAK: forgot queuebuf_free(q) */
}
queuebuf_free(q);

/* FIX: Always free on all paths */
struct queuebuf *q = queuebuf_new_from_packetbuf();
if(q == NULL) return;

if(some_error) {
  queuebuf_free(q);  /* Free before return */
  return;
}
queuebuf_free(q);
```

## Advanced Topics

### Zero-Copy Optimizations

In some cases, packets can be processed without copying data between buffers:

**Direct radio to packetbuf (reception):**
```c
/* Radio driver writes directly to packetbuf */
void
radio_rx_handler(void)
{
  /* Radio DMA configured to write to packetbuf memory */
  radio_read(packetbuf_dataptr(), PACKETBUF_SIZE);

  /* Set length */
  packetbuf_set_datalen(received_len);

  /* Pass to MAC without copying */
  NETSTACK_MAC.input();
}
```

**Direct packetbuf to radio (transmission):**
```c
/* Radio reads directly from packetbuf */
void
transmit(void)
{
  /* No copy: radio DMA reads from packetbuf */
  radio_send(packetbuf_hdrptr(), packetbuf_totlen());
}
```

**Limitations:**
- Only works if radio supports scatter-gather DMA
- Must ensure buffer alignment matches radio requirements
- packetbuf must not be modified during radio operation

### Multi-Hop Forwarding

When forwarding packets, efficient buffer management is critical:

```c
void
forward_packet(void)
{
  /* Packet arrives in packetbuf */

  /* Option 1: Queue for forwarding (uses queuebuf) */
  struct queuebuf *q = queuebuf_new_from_packetbuf();
  add_to_forwarding_queue(q);

  /* Option 2: Immediate forward (modifies packetbuf in place) */
  /* Decrement hop limit */
  UIP_IP_BUF->ttl--;

  /* Update destination in packetbuf attributes */
  packetbuf_set_addr(PACKETBUF_ADDR_RECEIVER, &next_hop);

  /* Forward without copying */
  NETSTACK_MAC.send(NULL, NULL);
}
```

### Platform-Specific Optimizations

Some platforms can optimize buffer handling:

**DMA-capable platforms:**
```c
/* Configure DMA to automatically transfer between buffers */
void
setup_dma_transfer(void)
{
  /* DMA: radio RX buffer → packetbuf */
  dma_configure_channel(0,
                        radio_rx_buffer,
                        packetbuf_dataptr(),
                        PACKETBUF_SIZE);

  /* DMA: packetbuf → radio TX buffer */
  dma_configure_channel(1,
                        packetbuf_hdrptr(),
                        radio_tx_buffer,
                        PACKETBUF_SIZE);
}
```

**Platforms with hardware crypto:**
```c
/* Encrypt/decrypt in place in packetbuf */
void
encrypt_packet(void)
{
  /* Hardware crypto engine reads from and writes to packetbuf */
  aes_ccm_encrypt(packetbuf_dataptr(),
                  packetbuf_datalen(),
                  key,
                  nonce);
  /* No copy needed */
}
```

## Integration Examples

### Example 1: CoAP Server with Efficient Buffering

```c
#include "contiki.h"
#include "net/ipv6/uip.h"
#include "net/packetbuf.h"
#include "coap-engine.h"

/* Configuration */
#define UIP_CONF_BUFFER_SIZE 512    /* Moderate size for CoAP */
#define QUEUEBUF_CONF_NUM 8          /* Handle concurrent requests */

PROCESS(coap_server_process, "CoAP Server");
AUTOSTART_PROCESSES(&coap_server_process);

static void
sensor_get_handler(coap_message_t *request, coap_message_t *response,
                   uint8_t *buffer, uint16_t preferred_size,
                   int32_t *offset)
{
  /* Read sensor */
  int value = sensor_read();

  /* Prepare response in uip_buf (via CoAP engine) */
  snprintf((char *)buffer, preferred_size, "{\"value\":%d}", value);

  coap_set_header_content_format(response, APPLICATION_JSON);
  coap_set_payload(response, buffer, strlen((char *)buffer));

  /* CoAP engine will:
   *  1. Build CoAP message in uip_buf
   *  2. Add UDP/IPv6 headers
   *  3. Pass to 6LoWPAN → packetbuf
   *  4. MAC may queue in queuebuf
   */
}

PROCESS_THREAD(coap_server_process, ev, data)
{
  PROCESS_BEGIN();

  /* Activate CoAP resource */
  coap_activate_resource(&sensor_resource, "sensors/temp");

  PROCESS_END();
}
```

### Example 2: Custom MAC with Queuebuf Management

```c
#define TX_QUEUE_SIZE 4

struct tx_queue {
  struct queuebuf *packets[TX_QUEUE_SIZE];
  int head, tail, count;
};

static struct tx_queue queue;

void
custom_mac_init(void)
{
  queue.head = queue.tail = queue.count = 0;
}

void
custom_mac_send(mac_callback_t sent, void *ptr)
{
  /* Check if queue has space */
  if(queue.count >= TX_QUEUE_SIZE) {
    LOG_WARN("TX queue full\n");
    mac_call_sent_callback(sent, ptr, MAC_TX_ERR, 0);
    return;
  }

  /* Queue packet from packetbuf */
  queue.packets[queue.tail] = queuebuf_new_from_packetbuf();
  if(queue.packets[queue.tail] == NULL) {
    LOG_ERR("Queuebuf pool exhausted\n");
    mac_call_sent_callback(sent, ptr, MAC_TX_ERR, 0);
    return;
  }

  queue.tail = (queue.tail + 1) % TX_QUEUE_SIZE;
  queue.count++;

  LOG_DBG("Queued packet (%d in queue, %zu queuebufs free)\n",
          queue.count, queuebuf_numfree());

  /* Trigger transmission */
  process_poll(&custom_mac_process);
}

PROCESS_THREAD(custom_mac_process, ev, data)
{
  PROCESS_BEGIN();

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_POLL);

    /* Transmit queued packets */
    while(queue.count > 0) {
      /* Restore packet to packetbuf */
      queuebuf_to_packetbuf(queue.packets[queue.head]);

      /* Send */
      int ret = NETSTACK_RADIO.send(packetbuf_hdrptr(),
                                     packetbuf_totlen());

      /* Free queuebuf */
      queuebuf_free(queue.packets[queue.head]);
      queue.head = (queue.head + 1) % TX_QUEUE_SIZE;
      queue.count--;

      if(ret == RADIO_TX_OK) {
        LOG_DBG("Packet sent successfully\n");
      } else {
        LOG_WARN("Transmission failed\n");
      }
    }
  }

  PROCESS_END();
}
```

### Example 3: 6LoWPAN Fragmentation with Queuebuf

```c
#define MAX_FRAGMENTS 16

void
sicslowpan_fragment_and_send(void)
{
  struct queuebuf *fragments[MAX_FRAGMENTS];
  uint16_t datagram_size = uip_len;
  uint16_t frag_size = 80;  /* Payload per fragment */
  int num_fragments = (datagram_size + frag_size - 1) / frag_size;

  if(num_fragments > MAX_FRAGMENTS) {
    LOG_ERR("Too many fragments: %d (max %d)\n",
            num_fragments, MAX_FRAGMENTS);
    return;
  }

  /* Check if enough queuebufs available */
  if(queuebuf_numfree() < num_fragments) {
    LOG_WARN("Not enough queuebufs for %d fragments (%zu free)\n",
             num_fragments, queuebuf_numfree());
    return;
  }

  /* Create all fragments */
  for(int i = 0; i < num_fragments; i++) {
    uint16_t offset = i * frag_size;
    uint16_t len = MIN(frag_size, datagram_size - offset);

    /* Build fragment in packetbuf */
    packetbuf_clear();

    /* Add fragmentation header */
    if(i == 0) {
      /* First fragment: FRAG1 header */
      create_frag1_header(datagram_size, datagram_tag);
    } else {
      /* Subsequent fragments: FRAGN header */
      create_fragn_header(datagram_size, datagram_tag, offset);
    }

    /* Add fragment payload from uip_buf */
    memcpy(packetbuf_dataptr(), &uip_buf[UIP_IPH_LEN + offset], len);
    packetbuf_set_datalen(len);

    /* Queue fragment */
    fragments[i] = queuebuf_new_from_packetbuf();
    if(fragments[i] == NULL) {
      /* Cleanup: free previously allocated fragments */
      for(int j = 0; j < i; j++) {
        queuebuf_free(fragments[j]);
      }
      LOG_ERR("Failed to allocate fragment %d\n", i);
      return;
    }

    LOG_DBG("Created fragment %d/%d (%u bytes)\n",
            i + 1, num_fragments, len);
  }

  /* Send all fragments */
  for(int i = 0; i < num_fragments; i++) {
    queuebuf_to_packetbuf(fragments[i]);
    NETSTACK_MAC.send(NULL, NULL);
    queuebuf_free(fragments[i]);

    LOG_DBG("Sent fragment %d/%d\n", i + 1, num_fragments);
  }
}
```

## Performance Considerations

### Memory Usage Summary

| Configuration | RAM Usage | Notes |
|---------------|-----------|-------|
| **Minimal** | ~1.2 KB | uip_buf=256, packetbuf=128, queuebuf=4×160 |
| **Standard** | ~2.7 KB | uip_buf=1280, packetbuf=128, queuebuf=8×160 |
| **High-perf** | ~5.0 KB | uip_buf=1280, packetbuf=128, queuebuf=16×160 |
| **With CFS swap** | -50% queuebuf | Half queuebufs in flash instead of RAM |

### Latency Impact

**Buffer copy overhead:**
```
packetbuf_copyfrom(1000 bytes): ~1000 CPU cycles
queuebuf_new_from_packetbuf(): ~2000 cycles (copy + allocation)
queuebuf_to_packetbuf(): ~2000 cycles
CFS swap read/write: ~10000-100000 cycles (platform-dependent)
```

**Optimization strategies:**
- Minimize copies between buffers
- Use zero-copy when possible (direct DMA)
- Avoid CFS swapping in latency-critical applications
- Pre-allocate queuebufs during initialization

### Throughput Impact

**Queuebuf sizing for throughput:**
```
Max throughput ≈ (packet_size × queuebuf_count) / round_trip_time

Example:
  Packet size: 100 bytes
  Queuebuf count: 8
  RTT: 100 ms

  Throughput ≈ (100 × 8) / 0.1 = 8000 bytes/s = 64 kbps
```

**Increasing throughput:**
```c
/* More queuebufs = more packets in flight */
#define QUEUEBUF_CONF_NUM 16  /* 2× throughput */

/* Larger packets (if link supports) */
#define PACKETBUF_CONF_SIZE 256
```

## Best Practices

### 1. Always Initialize Buffers

```c
/* Before using packetbuf */
packetbuf_clear();  /* Clears data and attributes */

/* uip_buf is cleared by uIP stack automatically */
```

### 2. Check Allocation Failures

```c
/* WRONG: Assume allocation succeeds */
struct queuebuf *q = queuebuf_new_from_packetbuf();
queuebuf_to_packetbuf(q);  /* CRASH if q is NULL */

/* CORRECT: Check for NULL */
struct queuebuf *q = queuebuf_new_from_packetbuf();
if(q != NULL) {
  queuebuf_to_packetbuf(q);
  queuebuf_free(q);
} else {
  LOG_ERR("Queuebuf allocation failed\n");
}
```

### 3. Free Queuebufs Promptly

```c
/* Allocate queuebuf only when needed */
struct queuebuf *q = queuebuf_new_from_packetbuf();

/* Use it */
add_to_queue(q);
transmit_from_queue(q);

/* Free as soon as done */
queuebuf_free(q);  /* Don't hold longer than necessary */
```

### 4. Monitor Buffer Usage

```c
/* Periodic monitoring */
void
monitor_buffers(void)
{
  size_t qb_free = queuebuf_numfree();

  if(qb_free < QUEUEBUF_NUM / 4) {
    LOG_WARN("Low queuebufs: %zu/%d free\n", qb_free, QUEUEBUF_NUM);
  }
}
```

### 5. Use Appropriate Buffer Type

```c
/* Application layer: use uip_buf */
void
app_send(void)
{
  uint8_t *payload = uip_appdata;
  sprintf((char *)payload, "data");
  uip_udp_packet_send(conn, payload, strlen((char *)payload));
}

/* MAC layer: use packetbuf */
void
mac_send(void)
{
  packetbuf_set_addr(PACKETBUF_ADDR_RECEIVER, &dest);
  NETSTACK_RADIO.send(packetbuf_hdrptr(), packetbuf_totlen());
}

/* Queue management: use queuebuf */
void
queue_for_retry(void)
{
  struct queuebuf *q = queuebuf_new_from_packetbuf();
  add_to_retry_queue(q);
}
```

### 6. Respect Layer Boundaries

```c
/* WRONG: MAC accessing uip_buf */
void
bad_mac_implementation(void)
{
  uint8_t *data = &uip_buf[40];  /* WRONG: MAC shouldn't touch uip_buf */
  radio_send(data, 100);
}

/* CORRECT: MAC uses packetbuf */
void
good_mac_implementation(void)
{
  uint8_t *data = packetbuf_dataptr();  /* Correct buffer for MAC */
  radio_send(data, packetbuf_datalen());
}
```

### 7. Handle Fragmentation Carefully

```c
/* Ensure enough queuebufs for fragmentation */
void
safe_fragmentation(void)
{
  int frags_needed = calculate_fragments(uip_len);

  if(queuebuf_numfree() < frags_needed) {
    LOG_WARN("Not enough queuebufs for %d fragments\n", frags_needed);
    /* Retry later or drop packet */
    return;
  }

  /* Proceed with fragmentation */
  fragment_and_send();
}
```

### 8. Manage Attributes Properly

```c
/* Copy attributes when queueing */
struct queuebuf *q = queuebuf_new_from_packetbuf();
/* ✓ Attributes are copied automatically */

/* When restoring */
queuebuf_to_packetbuf(q);
/* ✓ Attributes are restored automatically */

/* When updating existing queuebuf */
queuebuf_update_from_packetbuf(q);  /* Updates data + attrs */
/* OR */
queuebuf_update_attr_from_packetbuf(q);  /* Updates only attrs */
```

### 9. Debug with Buffer Statistics

```c
/* Enable debugging during development */
#define QUEUEBUF_CONF_DEBUG 1

/* Check for issues */
void
debug_buffers(void)
{
  LOG_INFO("Queuebuf status:\n");
  LOG_INFO("  Free: %zu/%d\n", queuebuf_numfree(), QUEUEBUF_NUM);

#if QUEUEBUF_DEBUG
  queuebuf_debug_print();
  /* Shows: file.c,line,timestamp for each allocated queuebuf */
#endif
}
```

### 10. Configure for Your Application

```c
/* CoAP application (moderate requirements) */
#define UIP_CONF_BUFFER_SIZE 512
#define QUEUEBUF_CONF_NUM 8

/* TCP application (larger buffers) */
#define UIP_CONF_BUFFER_SIZE 1280
#define QUEUEBUF_CONF_NUM 12

/* Streaming application (many queued packets) */
#define UIP_CONF_BUFFER_SIZE 1280
#define QUEUEBUF_CONF_NUM 20

/* Constrained device (minimal RAM) */
#define UIP_CONF_BUFFER_SIZE 256
#define QUEUEBUF_CONF_NUM 4
#define QUEUEBUFRAM_CONF_NUM 2  /* Use CFS swapping */
```

## Summary

**Key Takeaways:**

1. **Three buffer types** serve different layers:
   - uip_buf: Network layer (IPv6 datagrams)
   - packetbuf: Link layer (current frame)
   - queuebuf: Queue management (stored frames)

2. **Respect layer boundaries**: Each buffer has specific access rules and permitted layers

3. **Size buffers appropriately**:
   - uIP buffer: ≥ max datagram size (1280 for IPv6 compliance)
   - Packetbuf: ≥ max MAC frame size (128 for 802.15.4)
   - Queuebuf: ≥ sum of all queue depths

4. **Always check allocations**: Queuebuf pool can be exhausted

5. **Free promptly**: Don't hold queuebufs longer than needed

6. **Monitor usage**: Track queuebuf_numfree() during development

7. **Use CFS swapping**: Save RAM on constrained devices (with latency tradeoff)

8. **Handle fragmentation**: Ensure enough queuebufs for all fragments

9. **Copy attributes**: Attributes are automatically copied with queuebufs

10. **Enable debugging**: Use QUEUEBUF_DEBUG to find allocation issues

**Buffer Management Checklist:**

- [ ] Configured UIP_CONF_BUFFER_SIZE for application needs
- [ ] Set PACKETBUF_CONF_SIZE ≥ maximum MAC frame size
- [ ] Calculated required QUEUEBUF_NUM based on queues and fragments
- [ ] Decided RAM vs CFS tradeoff (QUEUEBUFRAM_CONF_NUM)
- [ ] Added NULL checks for queuebuf allocations
- [ ] Ensured queuebufs are freed on all code paths
- [ ] Added monitoring for buffer exhaustion
- [ ] Tested with worst-case traffic scenarios
- [ ] Enabled QUEUEBUF_DEBUG during development
- [ ] Verified no cross-layer buffer access violations
