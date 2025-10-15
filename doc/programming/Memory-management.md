# Memory management

Contiki-NG supports both static and dynamic memory allocations. In embedded systems, memory allocations have traditionally been restricted to static sizes because static memory is free from leaks and fragmentation. Static memory is nevertheless cumbersome to handle when memory requirements change during run-time. Such changes may occur in a web server keeping track of connections or a virtual machine supporting dynamic programming languages.

When restricted to static memory, programmers have to guess the maximum usage of a resource and over-allocate a memory block to be safe from memory exhaustion. To mitigate such issues, we provide two different types of memory allocators in addition to static memory: the semi-dynamic **MEMB** module and the dynamic **HeapMem** module.

## Memory Allocation Strategies

Contiki-NG provides three memory management approaches:

| Approach | Overhead | Fragmentation | Safety | Use Case |
|----------|----------|---------------|--------|----------|
| **Static** | None | None | High | Fixed-size arrays, known at compile-time |
| **MEMB** | Low (~2 bytes/block) | None | High | Fixed-size objects, bounded quantity |
| **HeapMem** | Medium (~8-16 bytes/chunk) | Possible | Medium | Variable-size objects, dynamic needs |

**Choosing the right approach:**
- Use **static** allocation when the number and size of objects is known at compile time
- Use **MEMB** when you need dynamic allocation of same-sized objects with a known maximum count
- Use **HeapMem** only when you truly need variable-sized allocations and can handle potential fragmentation

## MEMB: Memory Blocks

The MEMB library, declared in `os/lib/memb.h`, provides a set of memory block management functions. Memory blocks are allocated as an array of objects of constant size and are placed in static memory. MEMB provides O(1) allocation and deallocation with minimal overhead.

### MEMB API

| Function                                    | Purpose                                      |
|---------------------------------------------|----------------------------------------------|
|`MEMB(name, structure, num)`                 | Declare a memory block.                      |
|`void memb_init(struct memb *m)`             | Initialize a memory block.                   |
|`void *memb_alloc(struct memb *m)`           | Allocate a memory block.                     |
|`int memb_free(struct memb *m, void *ptr)`   | Free a memory block.                         |
|`int memb_inmemb(struct memb *m, void *ptr)` | Check if an address is in a memory block.    |
|`size_t memb_numfree(struct memb *m)`        | Count the number of free blocks available.   |

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

Once the memory block has been declared by using `MEMB()`, it has to be initialized by calling `memb_init()`. This function takes a parameter of `struct memb`, identifying the memory block.

After initializing a `struct memb`, we are ready to start allocating objects from it by using `memb_alloc()`. All objects allocated through the same `struct memb` have the same size,  which is determined by the size of the `structure` argument to `MEMB()`. `memb_alloc()` returns a pointer to the allocated object if the operation was  successful, or `NULL` if the memory block has no free object.

`memb_free()` deallocates an object that has previously been allocated using `memb_alloc()`. Two arguments are needed to free the object: `m` points to the memory block, whereas `ptr` points to the object within the memory block. **Returns:** 0 on success, -1 if `ptr` was not a valid pointer from this memory block.

Any pointer can be checked to determine whether it is within the data area of a memory block. `memb_inmemb()` returns 1 if `ptr` is inside the memory block `m`, and 0 if it points to unknown memory.

`memb_numfree()` returns the count of available (unallocated) blocks in the memory block. This is useful for monitoring memory usage and detecting potential exhaustion.

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

### MEMB Best Practices

1. **Always call `memb_init()`** before using a memory block
2. **Check return value** of `memb_alloc()` - it returns NULL when exhausted
3. **Use `memb_numfree()`** to monitor availability and prevent exhaustion
4. **Validate pointers** with `memb_inmemb()` before freeing if the pointer source is uncertain
5. **Choose appropriate pool size** - balance between memory usage and avoiding exhaustion
6. **Consider multiple pools** for different object types rather than one large pool

## Heap Memory (HeapMem)

The standard C library provides `malloc()`, `realloc()`, and `free()` for heap memory management. However, the behavior and performance of these functions vary significantly across compiler toolchains, especially in resource-constrained embedded environments. Allocation and deallocation patterns with objects of varying sizes can be problematic, leading to fragmentation and unpredictable behavior.

For this reason, Contiki-NG includes its own heap memory module (HeapMem) that has been tested on various hardware platforms and applications. The HeapMem module provides an API similar to standard C, but with predictable behavior suitable for embedded systems.

### HeapMem Configuration

Before using HeapMem, you must configure the heap size in your `project-conf.h` or platform configuration:

```c
/* Define heap arena size (e.g., 4KB) */
#define HEAPMEM_CONF_ARENA_SIZE 4096
```

**Important:** If `HEAPMEM_CONF_ARENA_SIZE` is not set, the heapmem implementation will not be compiled, leading to linker errors if you call heapmem functions.

### HeapMem API

| Function                                       | Purpose                                   |
|------------------------------------------------|-------------------------------------------|
|`void *heapmem_alloc(size_t size)`              | Allocate uninitialized memory.            |
|`void *heapmem_calloc(size_t nmemb, size_t size)` | Allocate zero-initialized array.       |
|`void *heapmem_realloc(void *ptr, size_t size)` | Change the size of an allocated object.   |
|`bool heapmem_free(void *ptr)`                  | Free memory.                              |
|`void heapmem_stats(heapmem_stats_t *stats)`    | Get heap usage statistics.                |
|`size_t heapmem_alignment(void)`                | Get minimum alignment of allocations.     |

All functions are declared in `os/lib/heapmem.h`.

### Function Details

**`heapmem_alloc(size)`** allocates `size` bytes of uninitialized memory on the heap.
- **Returns:** Pointer to allocated memory, or `NULL` if allocation failed

**`heapmem_calloc(nmemb, size)`** allocates memory for an array of `nmemb` elements of `size` bytes each, and zeros the memory.
- **Returns:** Pointer to allocated memory, or `NULL` if allocation failed
- **Note:** This is similar to standard C `calloc()`, which was not in the original documentation

**`heapmem_realloc(ptr, size)`** reallocates a previously allocated block with a new size.
- If `ptr` is `NULL`, behaves like `heapmem_alloc(size)`
- If `size` is zero, deallocates the chunk and returns `NULL`
- If the new size is smaller, `size` bytes are copied from the old block
- If the new size is larger, the entire old block is copied, and remaining bytes are uninitialized
- **Returns:** Pointer to new block, or `NULL` if allocation failed
- **Important:** The returned pointer may differ from `ptr` even on success

**`heapmem_free(ptr)`** deallocates a block previously allocated by `heapmem_alloc()`, `heapmem_calloc()`, or `heapmem_realloc()`.
- If `ptr` is `NULL`, no action is performed
- **Returns:** `true` on success, `false` if deallocation failed

**`heapmem_stats(stats)`** retrieves internal statistics about heap usage:

```c
typedef struct heapmem_stats {
  size_t allocated;     /* Bytes currently allocated */
  size_t overhead;      /* Bytes used for management */
  size_t available;     /* Bytes available for allocation */
  size_t footprint;     /* Current heap usage (allocated + overhead) */
  size_t max_footprint; /* Peak heap usage */
  size_t chunks;        /* Number of allocated chunks */
} heapmem_stats_t;
```

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
/* Register a zone with reserved space */
heapmem_zone_t my_zone = heapmem_zone_register("sensor-data", 1024);
if(my_zone == HEAPMEM_ZONE_INVALID) {
  LOG_ERR("Failed to register zone\n");
  return;
}

/* Allocate from specific zone */
void *data = heapmem_zone_alloc(my_zone, 256);
```

**Benefits of zones:**
- Isolate memory for different subsystems
- Prevent one subsystem from exhausting all heap memory
- Better tracking of memory usage per subsystem

### HeapMem Best Practices

1. **Always check return values** - heap allocation can fail
2. **Free memory promptly** when no longer needed to reduce fragmentation
3. **Monitor heap usage** with `heapmem_stats()` during development
4. **Avoid frequent allocations** - prefer MEMB for objects with known maximum count
5. **Consider fragmentation** - long-running systems may experience memory fragmentation
6. **Use appropriate arena size** - balance between available RAM and application needs
7. **Prefer `heapmem_calloc()`** when you need zero-initialized memory (more efficient than alloc + memset)
8. **Enable debug mode** during development by setting `#define HEAPMEM_DEBUG 1` for memory leak detection

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

Print debug information:

```c
/* Print heap structure and all allocated chunks */
heapmem_print_debug_info(true);
```

## Choosing Between MEMB and HeapMem

| Consideration | Prefer MEMB | Prefer HeapMem |
|---------------|-------------|----------------|
| Object sizes | All same size | Variable sizes |
| Maximum count | Known | Unknown |
| Performance | Critical (O(1) alloc/free) | Less critical |
| Fragmentation | Must avoid | Can tolerate |
| Memory overhead | Minimal (~2 bytes/object) | Higher (~8-16 bytes/chunk) |
| Safety | High (no fragmentation) | Medium (fragmentation possible) |

**Rule of thumb:** Use MEMB whenever possible, fall back to HeapMem only when truly necessary.
