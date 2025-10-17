# Memory management

Contiki-NG supports both static and dynamic memory allocations. In embedded systems, memory allocations have traditionally been restricted to static sizes because static memory is free from leaks and fragmentation. Static memory is nevertheless cumbersome to handle when memory requirements change during run-time. Such changes may occur in a web server keeping track of connections or a virtual machine supporting dynamic programming languages.

When restricted to static memory, programmers have to guess the maximum usage of a resource and over-allocate a memory block to be safe from memory exhaustion. To mitigate such issues, we provide two different types of memory allocators in addition to static memory: the semi-dynamic **MEMB** module and the dynamic **HeapMem** module.

## Memory Allocation Strategies

Contiki-NG provides three memory management approaches:

| Approach | Overhead | Fragmentation | Safety | Allocation Speed | Use Case |
|----------|----------|---------------|--------|------------------|----------|
| **Static** | None | None | High | N/A | Fixed-size arrays, known at compile-time |
| **MEMB** | Low (~1 byte/block) | None | High | O(n) | Fixed-size objects, bounded quantity |
| **HeapMem** | Medium (~18-24 bytes/chunk) | Possible | Medium | O(n) bounded | Variable-size objects, dynamic needs |

**Choosing the right approach:**
- Use **static** allocation when the number and size of objects is known at compile time
- Use **MEMB** when you need dynamic allocation of same-sized objects with a known maximum count
- Use **HeapMem** only when you truly need variable-sized allocations and can handle potential fragmentation

**Memory allocation in Contiki-NG core:**

The Contiki-NG networking stack uses MEMB extensively for predictable memory management:
- **Queue buffers** (`queuebuf`): MEMB pool for packet queuing
- **Neighbor table** (`nbr-table`): MEMB for neighbor entries
- **Routing table**: MEMB for RPL routing entries
- **uIP connections**: MEMB for TCP/UDP connection structures
- **Packet buffers**: Static allocation for main IPv6 buffer

## MEMB: Memory Blocks

The MEMB library, declared in `os/lib/memb.h`, provides a set of memory block management functions. Memory blocks are allocated as an array of objects of constant size and are placed in static memory. MEMB provides O(1) allocation and O(n) deallocation with minimal overhead.

### MEMB API

| Function                                    | Purpose                                      | Time Complexity |
|---------------------------------------------|----------------------------------------------|-----------------|
|`MEMB(name, structure, num)`                 | Declare a memory block.                      | N/A (compile)   |
|`void memb_init(struct memb *m)`             | Initialize a memory block.                   | O(n)            |
|`void *memb_alloc(struct memb *m)`           | Allocate a memory block.                     | O(n) worst-case |
|`int memb_free(struct memb *m, void *ptr)`   | Free a memory block.                         | O(n)            |
|`int memb_inmemb(struct memb *m, void *ptr)` | Check if an address is in a memory block.    | O(1)            |
|`size_t memb_numfree(struct memb *m)`        | Count the number of free blocks available.   | O(n)            |

### Declaring Memory Blocks

The `MEMB()` macro declares a memory block, which has the type `struct memb`. Since the block is put into static memory, it is typically placed at the top of a C source file that uses memory blocks.

**Parameters:**
- `name`: Identifier for the memory block, used as an argument to other MEMB functions
- `structure`: C type of the objects to be allocated
- `num`: Maximum number of objects the block can accommodate

**Note:** Since the count is stored in a variable of type `unsigned short`, the memory block can hold at most `USHRT_MAX` (typically 65,535) objects.

The definition of `struct memb` is as follows:

```c
struct memb {
  unsigned short size;  /* Size of each object */
  unsigned short num;   /* Total number of objects */
  bool *used;           /* Array tracking which blocks are in use */
  void *mem;            /* Pointer to the memory array */
};
```

The expansion of the `MEMB()` macro yields three static declarations:
1. A boolean array (`used`) tracking allocation status for each block
2. An array of `num` structures of the specified type
3. A `struct memb` that references these arrays

**Memory overhead:** Approximately `num` bytes for the boolean array, plus the `struct memb` metadata (~8-12 bytes total).

Once the memory block has been declared by using `MEMB()`, it has to be initialized by calling `memb_init()`. This function takes a parameter of `struct memb`, identifying the memory block. Initialization zeros both the `used` array and all memory blocks.

After initializing a `struct memb`, we are ready to start allocating objects from it by using `memb_alloc()`. All objects allocated through the same `struct memb` have the same size,  which is determined by the size of the `structure` argument to `MEMB()`. `memb_alloc()` returns a pointer to the allocated object if the operation was  successful, or `NULL` if the memory block has no free object.

**Implementation note:** `memb_alloc()` performs a linear search through the `used` array to find the first free block. In the worst case (pool exhausted), this is O(n). In the average case with available blocks, it's much faster.

`memb_free()` deallocates an object that has previously been allocated using `memb_alloc()`. Two arguments are needed to free the object: `m` points to the memory block, whereas `ptr` points to the object within the memory block. **Returns:** 0 on success, -1 if `ptr` was not a valid pointer from this memory block or if the block was already free (double-free detection).

Any pointer can be checked to determine whether it is within the data area of a memory block. `memb_inmemb()` returns 1 if `ptr` is inside the memory block `m`, and 0 if it points to unknown memory. This check is performed using pointer arithmetic and is O(1).

`memb_numfree()` returns the count of available (unallocated) blocks in the memory block. This is useful for monitoring memory usage and detecting potential exhaustion. The function iterates through the entire `used` array, so it's O(n).

### MEMB Usage Example

The following example shows how the MEMB module can be used to manage a pool of connections. The `open_connection()` function allocates a new `struct connection` for each new connection. When a connection is closed, we free the memory block.

```c
#include "contiki.h"
#include "lib/memb.h"
#include "sys/log.h"

#define LOG_MODULE "Connection"
#define LOG_LEVEL LOG_LEVEL_INFO

#define MAX_CONNECTIONS 16

struct connection {
  int socket;
  uint32_t bytes_sent;
  uint32_t bytes_received;
};

/* Declare memory block for 16 connections */
MEMB(connections, struct connection, MAX_CONNECTIONS);

void
init_connections(void)
{
  /* Initialize the memory block before first use */
  memb_init(&connections);
  LOG_INFO("Initialized connection pool with %d slots\n", MAX_CONNECTIONS);
}

struct connection *
open_connection(int socket)
{
  struct connection *conn;

  /* Check available slots before allocating */
  size_t free_slots = memb_numfree(&connections);
  if(free_slots == 0) {
    LOG_WARN("Connection pool exhausted\n");
    return NULL;
  }

  conn = memb_alloc(&connections);
  if(conn == NULL) {
    LOG_ERR("Failed to allocate connection\n");
    return NULL;
  }

  /* Initialize the connection */
  conn->socket = socket;
  conn->bytes_sent = 0;
  conn->bytes_received = 0;

  LOG_INFO("Opened connection on socket %d (%zu slots remaining)\n",
           socket, free_slots - 1);
  return conn;
}

void
close_connection(struct connection *conn)
{
  if(conn == NULL) {
    return;
  }

  /* Verify pointer is valid before freeing */
  if(!memb_inmemb(&connections, conn)) {
    LOG_ERR("Attempted to free invalid connection pointer\n");
    return;
  }

  LOG_INFO("Closing connection on socket %d (sent: %lu, recv: %lu)\n",
           conn->socket,
           (unsigned long)conn->bytes_sent,
           (unsigned long)conn->bytes_received);

  if(memb_free(&connections, conn) != 0) {
    LOG_ERR("Failed to free connection\n");
  }
}

size_t
get_active_connections(void)
{
  return MAX_CONNECTIONS - memb_numfree(&connections);
}
```

### MEMB Integration with Processes

MEMB pools are commonly used with Contiki-NG processes for managing dynamic objects:

```c
#include "contiki.h"
#include "lib/memb.h"
#include "sys/log.h"

#define LOG_MODULE "Server"
#define LOG_LEVEL LOG_LEVEL_INFO

#define MAX_CLIENTS 8

struct client_state {
  struct etimer timeout;
  linkaddr_t addr;
  uint16_t request_count;
};

MEMB(client_pool, struct client_state, MAX_CLIENTS);

PROCESS(server_process, "Server process");
AUTOSTART_PROCESSES(&server_process);

PROCESS_THREAD(server_process, ev, data)
{
  static struct client_state *client;

  PROCESS_BEGIN();

  /* Initialize the client pool */
  memb_init(&client_pool);
  LOG_INFO("Server started with %d client slots\n", MAX_CLIENTS);

  while(1) {
    PROCESS_WAIT_EVENT();

    if(ev == new_client_event) {
      /* Allocate state for new client */
      client = memb_alloc(&client_pool);
      if(client == NULL) {
        LOG_WARN("Client pool exhausted, rejecting client\n");
        continue;
      }

      /* Initialize client state */
      linkaddr_copy(&client->addr, (linkaddr_t *)data);
      client->request_count = 0;
      etimer_set(&client->timeout, CLOCK_SECOND * 60);

      LOG_INFO("Accepted client %02x:%02x (%zu slots free)\n",
               client->addr.u8[0], client->addr.u8[1],
               memb_numfree(&client_pool));
    }
    else if(ev == PROCESS_EVENT_TIMER) {
      /* Find and free timed-out client */
      /* ... search logic ... */
      if(client != NULL) {
        LOG_INFO("Client %02x:%02x timed out\n",
                 client->addr.u8[0], client->addr.u8[1]);
        memb_free(&client_pool, client);
      }
    }
  }

  PROCESS_END();
}
```

### MEMB Performance Characteristics

**Time Complexity:**
- `memb_init()`: O(n) - zeros all memory
- `memb_alloc()`: O(k) where k is the index of the first free block (O(n) worst case when full)
- `memb_free()`: O(n) - must search for the block to validate pointer
- `memb_inmemb()`: O(1) - simple pointer arithmetic
- `memb_numfree()`: O(n) - iterates through entire used array

**Space Complexity:**
- Per pool: `num × size + num × 1 byte + ~12 bytes`
- Example: 16 × 32-byte structs = 512 + 16 + 12 = 540 bytes

**Best case scenario:** Allocations happen sequentially from the beginning of the pool. First allocation is O(1), second is O(2), etc.

**Worst case scenario:** Pool is nearly full. Each allocation scans most of the used array before finding a free slot or determining exhaustion.

### MEMB Best Practices

1. **Always call `memb_init()`** before using a memory block
2. **Check return value** of `memb_alloc()` - it returns NULL when exhausted
3. **Use `memb_numfree()`** to monitor availability and prevent exhaustion
4. **Validate pointers** with `memb_inmemb()` before freeing if the pointer source is uncertain
5. **Choose appropriate pool size** - balance between memory usage and avoiding exhaustion
6. **Consider multiple pools** for different object types rather than one large pool
7. **Monitor usage during development** - add debug logging to track peak usage
8. **Use power-of-two sizes** when possible for better memory alignment
9. **Initialize all fields** after allocation - MEMB doesn't zero individual blocks on allocation
10. **Avoid holding blocks long-term** - free as soon as possible to prevent exhaustion

### Common MEMB Patterns

**Pattern 1: Pool exhaustion fallback**
```c
struct my_object *obj = memb_alloc(&pool);
if(obj == NULL) {
  /* Fallback: try to reclaim old objects */
  cleanup_old_objects();
  obj = memb_alloc(&pool);
  if(obj == NULL) {
    LOG_ERR("Pool exhausted even after cleanup\n");
    return ERROR_POOL_FULL;
  }
}
```

**Pattern 2: Multiple pools for different sizes**
```c
MEMB(small_pool, struct small_obj, 32);   /* 16-byte objects */
MEMB(medium_pool, struct medium_obj, 16); /* 64-byte objects */
MEMB(large_pool, struct large_obj, 4);    /* 256-byte objects */

void *
allocate_by_size(size_t size)
{
  if(size <= 16) {
    return memb_alloc(&small_pool);
  } else if(size <= 64) {
    return memb_alloc(&medium_pool);
  } else if(size <= 256) {
    return memb_alloc(&large_pool);
  }
  return NULL;  /* Size too large */
}
```

**Pattern 3: Runtime monitoring**
```c
void
check_memory_health(void)
{
  size_t free = memb_numfree(&connections);
  size_t total = MAX_CONNECTIONS;
  size_t used = total - free;

  float usage = (100.0 * used) / total;

  LOG_INFO("Connection pool: %zu/%zu used (%.1f%%)\n",
           used, total, usage);

  if(usage > 80.0) {
    LOG_WARN("Connection pool over 80%% capacity\n");
  }
}
```

## Heap Memory (HeapMem)

The standard C library provides `malloc()`, `realloc()`, and `free()` for heap memory management. However, the behavior and performance of these functions vary significantly across compiler toolchains, especially in resource-constrained embedded environments. Allocation and deallocation patterns with objects of varying sizes can be problematic, leading to fragmentation and unpredictable behavior.

For this reason, Contiki-NG includes its own heap memory module (HeapMem) that has been tested on various hardware platforms and applications. The HeapMem module provides an API similar to standard C, but with predictable behavior suitable for embedded systems.

### HeapMem Architecture

HeapMem manages a statically allocated arena using a **best-fit allocation strategy** with **bounded search time**. The implementation uses:

- **Double-linked free list**: Faster list manipulation than single-linked (O(1) removal)
- **Chunk-based management**: Each allocation has a header (chunk) containing metadata
- **Automatic coalescing**: Adjacent free chunks are merged to reduce fragmentation
- **Zone support**: Subdivide heap into reserved areas for different subsystems
- **Bounded search**: Configurable limit on free list traversal for predictable performance

**Chunk structure:**
```c
struct chunk {
  struct chunk *prev;    /* Previous chunk in free list */
  struct chunk *next;    /* Next chunk in free list */
  size_t size;           /* Size of usable memory (excluding header) */
  uint8_t flags;         /* CHUNK_FLAG_ALLOCATED */
  heapmem_zone_t zone;   /* Zone ID for this chunk */
#if HEAPMEM_DEBUG
  const char *file;      /* Allocation source file */
  unsigned line;         /* Allocation source line */
#endif
};
```

**Memory layout:**
```
Heap Arena (HEAPMEM_ARENA_SIZE):
┌──────────────────────────────────────────────────────────┐
│ [chunk_t|data] [chunk_t|data] [chunk_t|data] ... [free] │
└──────────────────────────────────────────────────────────┘
 ^                                                    ^
 heap_base                                       heap_usage

Free list (double-linked):
  free_list → [chunk1] ⇄ [chunk2] ⇄ [chunk3] → NULL
```

### HeapMem Configuration

Before using HeapMem, you must configure the heap size in your `project-conf.h` or platform configuration:

```c
/* Define heap arena size (e.g., 4KB) */
#define HEAPMEM_CONF_ARENA_SIZE 4096
```

**Important:** If `HEAPMEM_CONF_ARENA_SIZE` is not set, the heapmem implementation will not be compiled, leading to linker errors if you call heapmem functions.

### HeapMem Configuration Reference

| Configuration Option | Default | Description | Trade-offs |
|---------------------|---------|-------------|------------|
| `HEAPMEM_CONF_ARENA_SIZE` | None (required) | Total heap size in bytes | More = more allocations possible; Less = saves RAM |
| `HEAPMEM_CONF_SEARCH_MAX` | 16 | Max chunks to search during allocation | Higher = better fit, more fragmentation control; Lower = faster allocation |
| `HEAPMEM_CONF_REALLOC` | 1 | Enable `heapmem_realloc()` | 1 = feature enabled; 0 = save ~300 bytes ROM |
| `HEAPMEM_CONF_MAX_ZONES` | 1 | Maximum number of zones | More = better isolation; Each zone adds ~12 bytes RAM |
| `HEAPMEM_CONF_ALIGNMENT` | `sizeof(size_t)` | Minimum alignment for allocations | Larger = waste space; Smaller = possible alignment faults |
| `HEAPMEM_CONF_PRINTF` | `printf` | Function for debug output | Set to custom logger if needed |
| `HEAPMEM_DEBUG` | 0 | Enable debug tracking | 1 = track file/line, detect leaks; Adds 8-12 bytes per chunk |

**Configuration example for constrained device:**
```c
/* project-conf.h for memory-constrained device */

/* Small heap for occasional dynamic allocations */
#define HEAPMEM_CONF_ARENA_SIZE 1024

/* Reduce search time for faster allocation */
#define HEAPMEM_CONF_SEARCH_MAX 8

/* Disable realloc to save ROM if not needed */
#define HEAPMEM_CONF_REALLOC 0

/* No zones needed */
#define HEAPMEM_CONF_MAX_ZONES 1
```

**Configuration example for gateway/border router:**
```c
/* project-conf.h for border router with more resources */

/* Larger heap for CoAP/MQTT processing */
#define HEAPMEM_CONF_ARENA_SIZE 8192

/* Better fragmentation control */
#define HEAPMEM_CONF_SEARCH_MAX 32

/* Enable realloc for flexible buffer management */
#define HEAPMEM_CONF_REALLOC 1

/* Separate zones for different subsystems */
#define HEAPMEM_CONF_MAX_ZONES 4

/* Enable debugging during development */
#define HEAPMEM_DEBUG 1
```

### HeapMem API

| Function                                       | Purpose                                   | Time Complexity |
|------------------------------------------------|-------------------------------------------|-----------------|
|`void *heapmem_alloc(size_t size)`              | Allocate uninitialized memory.            | O(n) bounded    |
|`void *heapmem_calloc(size_t nmemb, size_t size)` | Allocate zero-initialized array.       | O(n) bounded    |
|`void *heapmem_realloc(void *ptr, size_t size)` | Change the size of an allocated object.   | O(n) bounded    |
|`bool heapmem_free(void *ptr)`                  | Free memory.                              | O(1) or O(n)    |
|`void heapmem_stats(heapmem_stats_t *stats)`    | Get heap usage statistics.                | O(n)            |
|`size_t heapmem_alignment(void)`                | Get minimum alignment of allocations.     | O(1)            |
|`heapmem_zone_t heapmem_zone_register(const char *name, size_t size)` | Register memory zone. | O(1) |
|`void *heapmem_zone_alloc(heapmem_zone_t zone, size_t size)` | Allocate from specific zone. | O(n) bounded |
|`void heapmem_print_debug_info(bool print_chunks)` | Print debug information. | O(n) |

All functions are declared in `os/lib/heapmem.h`.

### Function Details

**`heapmem_alloc(size)`** allocates `size` bytes of uninitialized memory on the heap.
- **Returns:** Pointer to allocated memory, or `NULL` if allocation failed
- **Algorithm:** Best-fit search of free list (up to SEARCH_MAX chunks), then extend heap if needed
- **Performance:** O(SEARCH_MAX) in practice, bounded by configuration

**`heapmem_calloc(nmemb, size)`** allocates memory for an array of `nmemb` elements of `size` bytes each, and zeros the memory.
- **Returns:** Pointer to allocated memory, or `NULL` if allocation failed
- **Performance:** Same as `heapmem_alloc()` plus O(nmemb × size) for zeroing
- **Overflow protection:** Checks for `nmemb × size` overflow before allocation

**`heapmem_realloc(ptr, size)`** reallocates a previously allocated block with a new size.
- If `ptr` is `NULL`, behaves like `heapmem_alloc(size)`
- If `size` is zero, deallocates the chunk and returns `NULL`
- If the new size is smaller, splits the chunk if possible
- If the new size is larger, tries to extend in place by coalescing adjacent free chunks
- If in-place extension fails, allocates new block, copies data, and frees old block
- **Returns:** Pointer to new block, or `NULL` if allocation failed
- **Important:** The returned pointer may differ from `ptr` even on success

**`heapmem_free(ptr)`** deallocates a block previously allocated by `heapmem_alloc()`, `heapmem_calloc()`, or `heapmem_realloc()`.
- If `ptr` is `NULL`, no action is performed
- If the chunk is the last one in the heap, releases it back (shrinks heap_usage)
- Otherwise, adds chunk to free list for reuse
- **Returns:** `true` on success, `false` if deallocation failed
- **Protection:** Detects invalid pointers and double-free attempts

**`heapmem_stats(stats)`** retrieves internal statistics about heap usage:

```c
typedef struct heapmem_stats {
  size_t allocated;     /* Bytes currently allocated */
  size_t overhead;      /* Bytes used for chunk headers */
  size_t available;     /* Bytes available for allocation */
  size_t footprint;     /* Current heap usage (allocated + overhead) */
  size_t max_footprint; /* Peak heap usage since boot */
  size_t chunks;        /* Number of allocated chunks */
} heapmem_stats_t;
```

**`heapmem_zone_register(name, zone_size)`** creates a reserved subdivision of the heap:
- Reserves `zone_size` bytes from the general zone
- Returns zone ID for use with `heapmem_zone_alloc()`
- **Returns:** Zone ID on success, `HEAPMEM_ZONE_INVALID` on failure
- **Limit:** Maximum `HEAPMEM_CONF_MAX_ZONES` zones (default 1)

### HeapMem Usage Example

```c
#include "contiki.h"
#include "lib/heapmem.h"
#include "sys/log.h"

#define LOG_MODULE "HeapMem"
#define LOG_LEVEL LOG_LEVEL_INFO

void
process_dynamic_data(void)
{
  uint8_t *buffer;
  size_t buffer_size = 512;

  /* Allocate buffer */
  buffer = heapmem_alloc(buffer_size);
  if(buffer == NULL) {
    LOG_ERR("Failed to allocate %zu bytes\n", buffer_size);
    return;
  }

  /* Use buffer */
  LOG_INFO("Allocated %zu bytes at %p\n", buffer_size, buffer);
  /* ... process data ... */

  /* Reallocate if needed */
  buffer_size = 1024;
  uint8_t *new_buffer = heapmem_realloc(buffer, buffer_size);
  if(new_buffer == NULL) {
    LOG_ERR("Failed to reallocate to %zu bytes\n", buffer_size);
    heapmem_free(buffer);  /* Free original buffer */
    return;
  }
  buffer = new_buffer;

  /* Use larger buffer */
  LOG_INFO("Reallocated to %zu bytes at %p\n", buffer_size, buffer);
  /* ... process more data ... */

  /* Free when done */
  if(!heapmem_free(buffer)) {
    LOG_ERR("Failed to free buffer\n");
  }
}

void
monitor_heap_usage(void)
{
  heapmem_stats_t stats;

  heapmem_stats(&stats);
  LOG_INFO("Heap stats:\n");
  LOG_INFO("  Allocated: %zu bytes\n", stats.allocated);
  LOG_INFO("  Overhead:  %zu bytes\n", stats.overhead);
  LOG_INFO("  Available: %zu bytes\n", stats.available);
  LOG_INFO("  Footprint: %zu/%zu bytes (%.1f%%)\n",
           stats.footprint, stats.max_footprint,
           100.0 * stats.footprint / (stats.footprint + stats.available));
  LOG_INFO("  Chunks:    %zu\n", stats.chunks);
}
```

### HeapMem Zones (Advanced)

HeapMem supports multiple isolated memory zones for better memory organization:

```c
/* Initialize zones at startup */
void
init_memory_zones(void)
{
  heapmem_zone_t packet_zone, sensor_zone;

  /* Reserve 2KB for packet processing */
  packet_zone = heapmem_zone_register("packets", 2048);
  if(packet_zone == HEAPMEM_ZONE_INVALID) {
    LOG_ERR("Failed to register packet zone\n");
    return;
  }

  /* Reserve 512 bytes for sensor data */
  sensor_zone = heapmem_zone_register("sensors", 512);
  if(sensor_zone == HEAPMEM_ZONE_INVALID) {
    LOG_ERR("Failed to register sensor zone\n");
    return;
  }

  LOG_INFO("Initialized zones: packets=%u, sensors=%u\n",
           packet_zone, sensor_zone);
}

/* Allocate from specific zone */
void *
allocate_packet_buffer(size_t size)
{
  static heapmem_zone_t packet_zone = 1;  /* Assume zone ID from init */

  void *buffer = heapmem_zone_alloc(packet_zone, size);
  if(buffer == NULL) {
    LOG_WARN("Packet zone exhausted (%zu bytes requested)\n", size);
  }
  return buffer;
}
```

**Benefits of zones:**
- Isolate memory for different subsystems
- Prevent one subsystem from exhausting all heap memory
- Better tracking of memory usage per subsystem
- Debug which subsystem is using memory

**Zone allocation example:**
```
Total heap: 4096 bytes

After registering zones:
┌─────────────────────────────────────────────┐
│ General: 1536 │ Packets: 2048 │ Sensors: 512│
└─────────────────────────────────────────────┘

heapmem_alloc() → allocates from General zone
heapmem_zone_alloc(1, size) → allocates from Packets zone
heapmem_zone_alloc(2, size) → allocates from Sensors zone
```

### HeapMem Performance Characteristics

**Time Complexity:**
- `heapmem_alloc()`: O(SEARCH_MAX) average, O(1) if extending heap
- `heapmem_calloc()`: O(SEARCH_MAX + size) for allocation + zeroing
- `heapmem_realloc()`: O(SEARCH_MAX) for new allocation, O(size) for copy
- `heapmem_free()`: O(1) if last chunk, O(SEARCH_MAX) for defragmentation
- `heapmem_stats()`: O(n) where n is number of chunks in heap

**Space Overhead:**
- Per chunk: 18-24 bytes (depending on platform and debug mode)
  - 2 pointers (prev, next): 8 bytes on 32-bit, 16 bytes on 64-bit
  - size_t: 2-4 bytes
  - flags: 1 byte
  - zone: 1 byte
  - Debug mode adds: file pointer (4-8 bytes) + line number (2-4 bytes)
- Alignment padding: Up to `HEAPMEM_ALIGNMENT - 1` bytes per chunk

**Fragmentation behavior:**
- Best-fit allocation minimizes wasted space
- Automatic coalescing reduces fragmentation
- Bounded search trades perfect fit for speed
- Long-running systems may still fragment with mixed allocation sizes

**Example memory usage calculation:**
```
Configuration:
  HEAPMEM_ARENA_SIZE = 4096
  10 allocations of varying sizes
  Chunk header = 20 bytes (typical)

Worst case overhead:
  10 chunks × 20 bytes = 200 bytes
  Alignment waste: ~10 bytes
  Total overhead: ~210 bytes (~5% of heap)

Available for allocations: 4096 - 210 = 3886 bytes
```

### HeapMem Best Practices

1. **Always check return values** - heap allocation can fail
2. **Free memory promptly** when no longer needed to reduce fragmentation
3. **Monitor heap usage** with `heapmem_stats()` during development
4. **Avoid frequent allocations** - prefer MEMB for objects with known maximum count
5. **Consider fragmentation** - long-running systems may experience memory fragmentation
6. **Use appropriate arena size** - balance between available RAM and application needs
7. **Prefer `heapmem_calloc()`** when you need zero-initialized memory (more efficient than alloc + memset)
8. **Enable debug mode** during development by setting `#define HEAPMEM_DEBUG 1` for memory leak detection
9. **Use zones** to prevent subsystem interference in complex applications
10. **Avoid realloc in ISRs** - it can take unbounded time due to copying
11. **Test worst-case scenarios** - simulate heap exhaustion during development
12. **Use power-of-two sizes** when possible for better alignment and less waste

### Common HeapMem Patterns

**Pattern 1: Temporary buffer allocation**
```c
void
process_large_message(const char *msg, size_t msg_len)
{
  char *temp_buffer = NULL;

  /* Only allocate if message exceeds static buffer */
  if(msg_len > 256) {
    temp_buffer = heapmem_alloc(msg_len);
    if(temp_buffer == NULL) {
      LOG_ERR("Cannot process message: heap exhausted\n");
      return;
    }
    /* Process in temp_buffer */
  } else {
    /* Use static buffer for small messages */
    static char static_buffer[256];
    /* Process in static_buffer */
  }

  /* ... processing ... */

  /* Clean up */
  if(temp_buffer != NULL) {
    heapmem_free(temp_buffer);
  }
}
```

**Pattern 2: Growing buffer with realloc**
```c
void *
build_dynamic_packet(void)
{
  size_t capacity = 64;
  size_t length = 0;
  uint8_t *buffer = heapmem_alloc(capacity);

  if(buffer == NULL) {
    return NULL;
  }

  while(more_data_available()) {
    /* Check if we need to grow */
    if(length + next_chunk_size() > capacity) {
      size_t new_capacity = capacity * 2;
      uint8_t *new_buffer = heapmem_realloc(buffer, new_capacity);

      if(new_buffer == NULL) {
        LOG_ERR("Cannot grow buffer\n");
        heapmem_free(buffer);
        return NULL;
      }

      buffer = new_buffer;
      capacity = new_capacity;
    }

    /* Add data to buffer */
    length += append_data(&buffer[length]);
  }

  return buffer;
}
```

**Pattern 3: RAII-style cleanup with process events**
```c
PROCESS_THREAD(data_processor, ev, data)
{
  static uint8_t *work_buffer = NULL;

  PROCESS_BEGIN();

  while(1) {
    PROCESS_WAIT_EVENT();

    if(ev == start_processing_event) {
      /* Allocate working buffer */
      work_buffer = heapmem_alloc(1024);
      if(work_buffer == NULL) {
        LOG_ERR("Cannot allocate work buffer\n");
        continue;
      }

      /* Process data */
      /* ... */

    } else if(ev == processing_complete_event) {
      /* Free working buffer */
      if(work_buffer != NULL) {
        heapmem_free(work_buffer);
        work_buffer = NULL;
      }
    }
  }

  PROCESS_END();
}
```

### Debugging Memory Issues

Enable HeapMem debugging:

```c
/* In project-conf.h */
#define HEAPMEM_DEBUG 1
```

With debugging enabled, you get:
- File and line number tracking for allocations
- Automatic leak detection
- Enhanced error messages
- Ability to identify which code is allocating memory

Print debug information:

```c
/* Print heap structure and all allocated chunks */
heapmem_print_debug_info(true);
```

**Example debug output:**
```
* HeapMem statistics
* Allocated memory: 1024
* Available memory: 2816
* Heap usage: 1244
* Max heap usage: 1624
* Allocated chunks: 3
* Chunk size: 20
* Total chunk overhead: 60
* Allocated chunks:
* Chunk: heap offset 0, obj 0x20000014, flags 0x1 (coap-engine.c:142)
* Chunk: heap offset 536, obj 0x20000238, flags 0x1 (mqtt.c:89)
* Chunk: heap offset 1024, obj 0x20000430, flags 0x1 (lwm2m.c:201)
```

**Common issues and solutions:**

**Issue 1: Heap exhaustion**
```
Symptom: heapmem_alloc() returns NULL
Causes:
  - Arena too small for application needs
  - Memory leak (allocations without corresponding frees)
  - Fragmentation preventing large allocations

Solutions:
  - Increase HEAPMEM_CONF_ARENA_SIZE
  - Enable HEAPMEM_DEBUG and use heapmem_print_debug_info() to find leaks
  - Monitor with heapmem_stats() to track usage patterns
  - Consider using MEMB for fixed-size allocations
```

**Issue 2: Memory leaks**
```
Symptom: Available memory decreases over time, never freed
Detection:
  - Enable HEAPMEM_DEBUG
  - Periodically call heapmem_print_debug_info(true)
  - Look for chunks allocated from same file:line repeatedly

Prevention:
  - Always pair allocations with frees
  - Use RAII-style patterns with process events
  - Add allocation tracking in debug builds
```

**Issue 3: Heap fragmentation**
```
Symptom: Allocation fails despite sufficient total free space
Example:
  Available: 1000 bytes
  Largest free chunk: 200 bytes
  Request for 500 bytes → FAILS

Solutions:
  - Increase HEAPMEM_CONF_SEARCH_MAX for better coalescing
  - Allocate similar-sized objects together
  - Free objects in LIFO order when possible
  - Consider using MEMB for frequently allocated sizes
  - Avoid long-lived small allocations mixed with temporary large ones
```

**Issue 4: Double-free**
```
Symptom: heapmem_free() returns false, warning in logs
Causes:
  - Calling heapmem_free() twice on same pointer
  - Freeing pointer from MEMB or static memory

Detection:
  - HeapMem tracks allocation flag in chunk header
  - Checks if pointer is in heap range

Prevention:
  - Set pointer to NULL after freeing
  - Use memb_inmemb() / range checks before freeing
```

**Issue 5: Slow allocation performance**
```
Symptom: Delays during heapmem_alloc() in time-critical code
Causes:
  - HEAPMEM_CONF_SEARCH_MAX set too high
  - Heavily fragmented heap requires many iterations

Solutions:
  - Reduce HEAPMEM_CONF_SEARCH_MAX (default 16)
  - Avoid allocations in ISRs or time-critical paths
  - Pre-allocate buffers during initialization
  - Use MEMB for O(n) worst-case instead of O(SEARCH_MAX)
```

## Choosing Between MEMB and HeapMem

| Consideration | Prefer MEMB | Prefer HeapMem |
|---------------|-------------|----------------|
| Object sizes | All same size | Variable sizes |
| Maximum count | Known at compile time | Unknown or highly variable |
| Performance | Critical (bounded O(n)) | Less critical (bounded O(SEARCH_MAX)) |
| Fragmentation | Must avoid | Can tolerate |
| Memory overhead | Minimal (~1 byte/object) | Higher (~20 bytes/chunk) |
| Safety | High (no fragmentation) | Medium (fragmentation possible) |
| Allocation speed | O(n) worst case | O(SEARCH_MAX) worst case |
| Free speed | O(n) | O(1) for last chunk |
| Memory waste | Unused slots waste space | Alignment + chunk headers |

**Rule of thumb:** Use MEMB whenever possible, fall back to HeapMem only when truly necessary.

**Decision tree:**
```
Need dynamic allocation?
├─ No → Use static allocation
└─ Yes
   ├─ All objects same size?
   │  ├─ Yes → Use MEMB
   │  └─ No → Continue
   ├─ Maximum count known?
   │  ├─ Yes → Use MEMB (possibly multiple pools)
   │  └─ No → Use HeapMem
   └─ Object size varies widely?
      ├─ Yes → Use HeapMem
      └─ No → Use MEMB with size-based pools
```

### Hybrid Approaches

**Pattern: MEMB for common sizes + HeapMem for rare large allocations**
```c
/* Common case: use MEMB pools */
MEMB(small_pool, uint8_t[64], 16);    /* 16 × 64-byte buffers */
MEMB(medium_pool, uint8_t[256], 8);   /* 8 × 256-byte buffers */

/* Rare case: use HeapMem for large or unusual sizes */
#define HEAPMEM_CONF_ARENA_SIZE 2048

void *
allocate_buffer(size_t size)
{
  void *ptr;

  /* Try MEMB pools first (fast, no fragmentation) */
  if(size <= 64) {
    ptr = memb_alloc(&small_pool);
    if(ptr != NULL) return ptr;
  } else if(size <= 256) {
    ptr = memb_alloc(&medium_pool);
    if(ptr != NULL) return ptr;
  }

  /* Fallback to HeapMem for large or when pools exhausted */
  ptr = heapmem_alloc(size);
  if(ptr == NULL) {
    LOG_ERR("All memory exhausted (requested %zu bytes)\n", size);
  }

  return ptr;
}

void
free_buffer(void *ptr, size_t size)
{
  /* Try MEMB pools first */
  if(size <= 64 && memb_inmemb(&small_pool, ptr)) {
    memb_free(&small_pool, ptr);
  } else if(size <= 256 && memb_inmemb(&medium_pool, ptr)) {
    memb_free(&medium_pool, ptr);
  } else {
    /* Must be from HeapMem */
    heapmem_free(ptr);
  }
}
```

## Memory Usage in Contiki-NG Networking Stack

Understanding how the Contiki-NG core uses memory helps you plan your own allocations:

### Queue Buffers (queuebuf)

**Purpose:** Temporary storage for packets in MAC layer queues

**Implementation:** MEMB-based

**Configuration:**
```c
/* Number of queue buffers (default: 8) */
#define QUEUEBUF_CONF_NUM 8
```

**Memory usage:**
```
Per queuebuf: ~128-160 bytes (depends on packet buffer size)
Total: QUEUEBUF_CONF_NUM × 160 ≈ 1280 bytes (default)
```

**Tuning guidance:**
- Increase if you see packet drops under load
- Decrease to save RAM on simple applications
- Minimum 4 for reasonable operation

### Neighbor Table (nbr-table)

**Purpose:** Stores information about neighboring nodes

**Implementation:** MEMB-based

**Configuration:**
```c
/* Maximum neighbors (default: 16) */
#define NBR_TABLE_CONF_MAX_NEIGHBORS 16
```

**Memory usage:**
```
Per neighbor: ~60-80 bytes
Total: NBR_TABLE_CONF_MAX_NEIGHBORS × 80 ≈ 1280 bytes (default)
```

### Routing Table

**Purpose:** RPL routing entries

**Implementation:** MEMB-based

**Configuration:**
```c
/* Maximum routes (default: 16) */
#define NETSTACK_MAX_ROUTE_ENTRIES 16
```

**Memory usage:**
```
Per route: ~20-30 bytes
Total: NETSTACK_MAX_ROUTE_ENTRIES × 30 ≈ 480 bytes (default)
```

### uIP Buffers

**Purpose:** Main IPv6 packet buffer

**Implementation:** Static allocation

**Configuration:**
```c
/* IPv6 buffer size (default: 1280, minimum for IPv6) */
#define UIP_CONF_BUFFER_SIZE 1280
```

### Complete Memory Budget Example

**Platform: CC2538 (32 KB RAM)**

**Contiki-NG core:**
```
Stack:                  2048 bytes
uIP buffer:             1280 bytes
Queue buffers (8):      1280 bytes
Neighbor table (16):    1280 bytes
Route table (16):        480 bytes
TSCH schedule:           400 bytes (varies)
Processes/timers:        512 bytes
------------------------
Core total:           ~7280 bytes
```

**Available for application:**
```
Total RAM:             32768 bytes
Core usage:             7280 bytes
Safety margin:          1024 bytes
------------------------
Available:            ~24464 bytes
```

**Application allocation example:**
```c
/* CoAP server with dynamic resources */

/* Use MEMB for CoAP resources (fixed size) */
MEMB(coap_resources, struct coap_resource, 16);  /* 16 × 32 = 512 bytes */

/* Use MEMB for active requests (fixed size) */
MEMB(coap_requests, struct coap_request, 8);     /* 8 × 64 = 512 bytes */

/* Use HeapMem for variable-size payloads */
#define HEAPMEM_CONF_ARENA_SIZE 4096                 /* 4096 bytes */

/* Application structures */
static uint8_t sensor_data[1024];                    /* 1024 bytes */
static struct app_state state;                       /* 128 bytes */

/*
Total application usage:
  MEMB pools:          1024 bytes
  HeapMem arena:       4096 bytes
  Static data:         1152 bytes
  -----------------------
  Total:               6272 bytes

Remaining:           ~18192 bytes (safety margin)
*/
```

## Migration Guide

### From Static to MEMB

**When to migrate:**
- You need runtime allocation/deallocation
- Maximum count is known or can be estimated
- All objects are the same size

**Migration example:**
```c
/* Before: Static array (wastes space, no runtime allocation) */
#define MAX_CLIENTS 16
static struct client clients[MAX_CLIENTS];
static bool client_used[MAX_CLIENTS];

struct client *
allocate_client_old(void)
{
  for(int i = 0; i < MAX_CLIENTS; i++) {
    if(!client_used[i]) {
      client_used[i] = true;
      return &clients[i];
    }
  }
  return NULL;
}

/* After: MEMB (cleaner, same overhead) */
MEMB(clients, struct client, MAX_CLIENTS);

void
init_clients(void)
{
  memb_init(&clients);
}

struct client *
allocate_client_new(void)
{
  return memb_alloc(&clients);
}

void
free_client(struct client *c)
{
  memb_free(&clients, c);
}
```

### From MEMB to HeapMem

**When to migrate:**
- Object sizes vary significantly
- Maximum count is unknown
- Need to allocate variable-sized data

**Migration example:**
```c
/* Before: MEMB with worst-case sizing (wastes space) */
#define MAX_MESSAGE_SIZE 512
MEMB(messages, uint8_t[MAX_MESSAGE_SIZE], 8);
/* Wastes space: 8 × 512 = 4096 bytes even for small messages */

/* After: HeapMem (allocates exact size needed) */
#define HEAPMEM_CONF_ARENA_SIZE 2048
/* Typical usage: 4-5 messages of varying sizes, ~2KB total */

void *
allocate_message_old(size_t size)
{
  if(size > MAX_MESSAGE_SIZE) {
    return NULL;
  }
  return memb_alloc(&messages);  /* Always uses 512 bytes */
}

void *
allocate_message_new(size_t size)
{
  return heapmem_alloc(size);  /* Uses exact size + ~20 byte overhead */
}
```

### Estimating Appropriate Sizes

**MEMB pool sizing:**
```c
/* Method 1: Analyze worst-case scenarios */
// Network with max 10 neighbors, each can have 1 pending request
#define MAX_NEIGHBORS 10
MEMB(requests, struct request, MAX_NEIGHBORS);

/* Method 2: Runtime monitoring during development */
void
check_pool_usage(void)
{
  static size_t max_used = 0;
  size_t free = memb_numfree(&requests);
  size_t used = MAX_NEIGHBORS - free;

  if(used > max_used) {
    max_used = used;
    LOG_INFO("New peak pool usage: %zu/%d\n", max_used, MAX_NEIGHBORS);
  }
}

/* After testing: reduce MAX_NEIGHBORS to max_used + safety margin */
```

**HeapMem arena sizing:**
```c
/* Method: Monitor heap statistics during development */
void
periodic_heap_check(void)
{
  heapmem_stats_t stats;
  static size_t max_allocated = 0;

  heapmem_stats(&stats);

  if(stats.allocated > max_allocated) {
    max_allocated = stats.allocated;
    LOG_INFO("New peak heap usage: %zu bytes (overhead: %zu)\n",
             max_allocated, stats.overhead);
  }

  /* Check for fragmentation */
  size_t total_free = stats.available;
  if(total_free > 512 && last_allocation_failed) {
    LOG_WARN("Fragmentation detected: %zu bytes free but allocation failed\n",
             total_free);
  }
}

/* After testing: set HEAPMEM_CONF_ARENA_SIZE to max_allocated + overhead + 20% margin */
```

## Advanced Topics

### Stack vs Heap Allocation

**Stack allocation** (automatic variables):
```c
void
process_data(void)
{
  uint8_t buffer[128];  /* Stack allocation */
  /* ... use buffer ... */
}  /* buffer automatically freed */
```

**Pros:** Fast, automatic cleanup, no fragmentation
**Cons:** Fixed size, limited stack space, can't return to caller

**When to use stack:**
- Temporary buffers used only within a function
- Size known at compile time
- Total size < 512 bytes (typical safe limit)

**When to avoid stack:**
- Need to return pointer to caller
- Size is large (> 512 bytes) or unknown
- Recursive functions
- Deep call chains

**Stack overflow example:**
```c
/* BAD: Large stack allocation can overflow */
void
bad_function(void)
{
  uint8_t huge_buffer[4096];  /* 4KB on stack - dangerous! */
  /* ... */
}

/* GOOD: Use HeapMem for large buffers */
void
good_function(void)
{
  uint8_t *buffer = heapmem_alloc(4096);
  if(buffer != NULL) {
    /* ... */
    heapmem_free(buffer);
  }
}
```

### Memory Alignment Considerations

**Why alignment matters:**
- Some architectures require aligned access (ARM can fault on unaligned access)
- Aligned access is faster even on architectures that support unaligned
- Compiler pads structures to maintain alignment

**HeapMem alignment:**
```c
/* HeapMem automatically aligns allocations */
size_t alignment = heapmem_alignment();  /* Typically 4 or 8 bytes */

/* All allocations are aligned to this boundary */
void *ptr = heapmem_alloc(10);
/* ptr is aligned even though we only requested 10 bytes */
```

**MEMB alignment:**
```c
/* MEMB aligns based on structure type */
struct aligned_struct {
  uint32_t value;  /* Requires 4-byte alignment */
};

MEMB(pool, struct aligned_struct, 10);
/* Each block is properly aligned for uint32_t */
```

**Manual alignment (when needed):**
```c
/* Allocate with extra space for alignment */
void *
allocate_aligned(size_t size, size_t alignment)
{
  /* Allocate extra space for alignment */
  void *ptr = heapmem_alloc(size + alignment - 1);
  if(ptr == NULL) {
    return NULL;
  }

  /* Calculate aligned pointer */
  uintptr_t addr = (uintptr_t)ptr;
  uintptr_t aligned = (addr + alignment - 1) & ~(alignment - 1);

  return (void *)aligned;
  /* WARNING: Can't free this directly - need to track original ptr */
}
```

### Thread Safety

**Important:** Contiki-NG uses cooperative multitasking, not preemptive threading. Memory allocators are **not thread-safe** for preemptive systems, but are safe for cooperative processes.

**Safe in Contiki-NG:**
```c
/* Process 1 */
PROCESS_THREAD(process1, ev, data)
{
  PROCESS_BEGIN();

  void *ptr = memb_alloc(&pool);  /* Safe */
  /* ... */
  memb_free(&pool, ptr);  /* Safe */

  PROCESS_END();
}

/* Process 2 */
PROCESS_THREAD(process2, ev, data)
{
  PROCESS_BEGIN();

  void *ptr = memb_alloc(&pool);  /* Safe - processes don't preempt */
  /* ... */

  PROCESS_END();
}
```

**Not safe (if using preemptive RTOS):**
```c
/* ISR */
void
timer_interrupt(void)
{
  void *ptr = heapmem_alloc(64);  /* UNSAFE in preemptive system */
  /* Could corrupt heap if interrupted during allocation */
}
```

## Performance Optimization Strategies

### Strategy 1: Pre-allocate During Init

```c
/* Allocate all resources at startup */
void
init_application(void)
{
  /* Pre-allocate working buffers */
  for(int i = 0; i < NUM_WORKERS; i++) {
    workers[i].buffer = heapmem_alloc(BUFFER_SIZE);
    if(workers[i].buffer == NULL) {
      LOG_ERR("Initialization failed\n");
      /* Handle error */
    }
  }
}

/* No runtime allocation needed */
void
process_task(int worker_id)
{
  /* Use pre-allocated buffer */
  uint8_t *buffer = workers[worker_id].buffer;
  /* ... */
}
```

### Strategy 2: Object Pooling

```c
/* Pool of reusable objects */
MEMB(packet_pool, struct packet, 16);
LIST(free_packets);
LIST(active_packets);

void
init_packet_pool(void)
{
  memb_init(&packet_pool);
  list_init(free_packets);
  list_init(active_packets);

  /* Pre-allocate all packets and add to free list */
  for(int i = 0; i < 16; i++) {
    struct packet *pkt = memb_alloc(&packet_pool);
    list_add(free_packets, pkt);
  }
}

struct packet *
get_packet(void)
{
  struct packet *pkt = list_pop(free_packets);
  if(pkt != NULL) {
    list_add(active_packets, pkt);
  }
  return pkt;
}

void
release_packet(struct packet *pkt)
{
  list_remove(active_packets, pkt);
  list_add(free_packets, pkt);
  /* Note: Don't call memb_free() - keep in pool for reuse */
}
```

### Strategy 3: Lazy Allocation

```c
/* Only allocate when actually needed */
struct cache {
  uint8_t *data;
  size_t size;
};

void
ensure_cache_allocated(struct cache *c, size_t required_size)
{
  if(c->data == NULL || c->size < required_size) {
    /* Free old buffer if too small */
    if(c->data != NULL) {
      heapmem_free(c->data);
    }

    /* Allocate new buffer */
    c->data = heapmem_alloc(required_size);
    c->size = (c->data != NULL) ? required_size : 0;
  }
}

void
use_cache(struct cache *c)
{
  ensure_cache_allocated(c, 1024);
  if(c->data != NULL) {
    /* Use cache */
  }
}
```

## Summary

**Key takeaways:**

1. **Prefer static allocation** when size and count are known at compile time
2. **Use MEMB** for same-sized objects with bounded count - it's fast, safe, and has minimal overhead
3. **Use HeapMem** sparingly for variable-sized allocations - monitor fragmentation carefully
4. **Always check return values** - allocation can fail on embedded systems
5. **Free promptly** - don't hold memory longer than necessary
6. **Monitor during development** - use `memb_numfree()` and `heapmem_stats()` to understand actual usage
7. **Plan your memory budget** - know how much RAM the core uses and how much is available
8. **Consider hybrid approaches** - MEMB for common sizes, HeapMem for rare large allocations
9. **Enable debugging** - use `HEAPMEM_DEBUG` during development to catch leaks early
10. **Test exhaustion scenarios** - ensure graceful degradation when memory runs out

**Memory management checklist:**

- [ ] Estimated maximum object count for each dynamic allocation
- [ ] Chosen appropriate strategy (static/MEMB/HeapMem) for each allocation
- [ ] Configured MEMB pool sizes with safety margin
- [ ] Configured `HEAPMEM_CONF_ARENA_SIZE` if using HeapMem
- [ ] Added error handling for allocation failures
- [ ] Verified all allocations have corresponding frees
- [ ] Added runtime monitoring during development
- [ ] Tested with heap/pool exhaustion scenarios
- [ ] Checked for memory leaks with `HEAPMEM_DEBUG`
- [ ] Measured peak memory usage with monitoring code
- [ ] Optimized configuration based on measurements
- [ ] Removed debug code before production build
