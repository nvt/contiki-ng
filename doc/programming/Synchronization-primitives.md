# Synchronization Primitives

Contiki-NG provides several synchronization primitives to ensure data consistency when shared resources are accessed from different execution contexts. This guide covers when and how to use each primitive effectively.

## Execution Contexts

Contiki-NG code executes in two distinct contexts:

1. **Main Context** ("main thread"): Regular process code running outside interrupt handlers
2. **Interrupt Context**: Code executing within interrupt service routines (ISRs)

**Key principle**: When a shared resource is accessed **only** from the main context, no synchronization is needed because Contiki-NG uses cooperative multitasking—processes voluntarily yield control and cannot preempt each other.

**Synchronization is required** when:
- A shared resource is accessed from both main and interrupt contexts
- A shared resource is accessed from multiple interrupt sources
- You need to coordinate access between processes (use process mutexes)

For more details about Contiki-NG's multitasking model, see [Multitasking and Scheduling](Multitasking-and-scheduling.md).

## Choosing the Right Primitive

| Scenario | Use This | Why |
|----------|----------|-----|
| Protect variable accessed from ISR + main | **Critical Section** | Prevents ISR from interrupting main context |
| Very brief protection (< 100μs) | **Critical Section** | Simplest, fastest solution |
| Lock-based synchronization in ISR/main | **Mutex** | Try-lock semantics, can use CPU atomics |
| Coordinate between processes | **Process Mutex** | Yields and waits using events, doesn't block |
| Update single byte atomically | **Atomic CAS** | Lock-free, compare-and-swap |
| Prevent compiler reordering | **Memory Barrier** | Usually handled automatically by other primitives |

**Golden rules:**
- Use the **weakest** primitive that solves your problem
- Keep critical sections as **brief** as possible (ideally < 50μs)
- Never call long-running functions from critical sections
- Use process mutexes for process-level coordination

## Global Interrupt Manipulation

The most fundamental synchronization primitive is global interrupt control. **Use sparingly** and only for very brief periods.

### API

Declared in `os/sys/int-master.h`:

| Function | Purpose |
|----------|---------|
| `void int_master_enable(void)` | Enable global interrupt |
| `int_master_status_t int_master_read_and_disable(void)` | Disable interrupts, return previous state |
| `void int_master_status_set(int_master_status_t status)` | Restore interrupt state |
| `bool int_master_is_enabled(void)` | Check if interrupts are currently enabled |

### int_master_read_and_disable()

```c
int_master_status_t
int_master_read_and_disable(void)
```

Disables the global interrupt and returns its previous state.

**Returns:** Platform-specific value representing the interrupt state before disabling. **Do not** interpret this value—only use it as an argument to `int_master_status_set()`.

**Use case:** When you need to manually manage interrupt state (usually you should use critical sections instead).

### int_master_status_set()

```c
void
int_master_status_set(int_master_status_t status)
```

Restores the global interrupt to a previous state.

**Parameters:**
- `status`: Value previously returned by `int_master_read_and_disable()`

### int_master_is_enabled()

```c
bool
int_master_is_enabled(void)
```

Checks whether the global interrupt is currently enabled in a platform-independent way.

**Returns:**
- `true`: Interrupts are enabled
- `false`: Interrupts are disabled

### Usage Example

```c
#include "sys/int-master.h"

void
update_shared_data(void)
{
  int_master_status_t status;

  /* Save current interrupt state and disable */
  status = int_master_read_and_disable();

  /* Critical operations here */
  shared_counter++;

  /* Restore previous interrupt state */
  int_master_status_set(status);
}
```

**Important:** In most cases, you should use **critical sections** instead of manipulating interrupts directly.

## Critical Sections

Critical sections provide a platform-independent way to protect short code sections from being interrupted. They internally use interrupt manipulation and memory barriers.

### API

Declared in `os/sys/critical.h`:

| Function | Purpose |
|----------|---------|
| `int_master_status_t critical_enter(void)` | Enter critical section, return previous state |
| `void critical_exit(int_master_status_t status)` | Exit critical section, restore previous state |

### critical_enter()

```c
int_master_status_t
critical_enter(void)
```

Enters a critical section by disabling interrupts and inserting a memory barrier.

**Returns:** Platform-specific value representing interrupt state before entering. Use this value with `critical_exit()`.

**What it does:**
1. Saves current interrupt state
2. Disables global interrupt
3. Inserts a memory barrier to prevent compiler reordering

### critical_exit()

```c
void
critical_exit(int_master_status_t status)
```

Exits a critical section by inserting a memory barrier and restoring the previous interrupt state.

**Parameters:**
- `status`: Value returned by `critical_enter()`

**What it does:**
1. Inserts a memory barrier
2. Restores interrupt state to what it was before `critical_enter()`

### Usage Example: Protecting Shared Variables

```c
#include "sys/critical.h"
#include "sys/log.h"

#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_INFO

/* Shared between main context and ISR */
static volatile uint32_t packet_count = 0;
static volatile uint32_t byte_count = 0;

/* Called from interrupt context */
void
radio_rx_isr(uint8_t *data, size_t len)
{
  int_master_status_t status;

  /* Critical section to update shared counters */
  status = critical_enter();
  packet_count++;
  byte_count += len;
  critical_exit(status);

  /* Process packet (ISR work should be minimal) */
  process_poll(&network_process);
}

/* Called from main context */
void
print_statistics(void)
{
  uint32_t packets, bytes;
  int_master_status_t status;

  /* Critical section to read consistent snapshot */
  status = critical_enter();
  packets = packet_count;
  bytes = byte_count;
  critical_exit(status);

  LOG_INFO("Received %lu packets, %lu bytes\n",
           (unsigned long)packets, (unsigned long)bytes);
}

/* Called from main context */
void
reset_statistics(void)
{
  int_master_status_t status;

  status = critical_enter();
  packet_count = 0;
  byte_count = 0;
  critical_exit(status);

  LOG_INFO("Statistics reset\n");
}
```

### Critical Section Best Practices

1. **Keep them extremely brief** - Aim for < 50μs, never exceed 100μs
2. **Avoid function calls** - Only use inline operations
3. **Never allocate memory** - No `malloc()` or `memb_alloc()`
4. **Never call logging functions** - Logging can be slow
5. **Don't call blocking functions** - No I/O, no process operations
6. **Nesting is allowed** - But increases interrupt latency

**Example of what NOT to do:**

```c
/* WRONG - Critical section too long */
status = critical_enter();
for(int i = 0; i < 1000; i++) {
  complex_calculation(i);  /* BAD: Too much work */
}
LOG_INFO("Done\n");  /* BAD: Logging in critical section */
critical_exit(status);

/* CORRECT - Minimize critical section */
for(int i = 0; i < 1000; i++) {
  complex_calculation(i);  /* Outside critical section */
}
status = critical_enter();
update_shared_result();  /* Only shared access protected */
critical_exit(status);
LOG_INFO("Done\n");  /* Logging outside critical section */
```

## Memory Barriers

Memory barriers prevent the compiler and CPU from reordering memory operations, which can cause subtle bugs in concurrent code.

### API

Declared in `os/sys/memory-barrier.h`:

```c
void memory_barrier(void)
```

Inserts a compiler/CPU memory barrier at the call site.

**Purpose:** Ensures that:
1. All memory writes before the barrier complete before any writes after it
2. All memory reads before the barrier complete before any reads after it
3. Compiler doesn't reorder operations across the barrier

**Note:** By default, `memory_barrier()` expands to nothing. Platform/CPU developers must implement it if needed. It's automatically used by `critical_enter()` and `critical_exit()`.

### When Memory Barriers Are Needed

Memory barriers are typically handled automatically by other primitives. You rarely need to use them directly unless:
- Implementing your own synchronization primitive
- Working with memory-mapped hardware registers
- Implementing lock-free data structures

### Usage Example

```c
#include "sys/memory-barrier.h"

volatile bool ready = false;
volatile int data = 0;

void
producer(void)
{
  data = 42;          /* Write data first */
  memory_barrier();   /* Prevent reordering */
  ready = true;       /* Signal ready */
}

void
consumer(void)
{
  while(!ready) {     /* Wait for ready signal */
    /* spin */
  }
  memory_barrier();   /* Ensure we see latest data */
  int value = data;   /* Read data */
  /* use value */
}
```

**Note:** In practice, you'd use mutexes or critical sections instead of this pattern.

## Mutexes

Mutexes provide lock-based synchronization that can be implemented using efficient CPU-specific atomic instructions (e.g., LDREX/STREX on ARM Cortex-M).

### API

Declared in `os/sys/mutex.h`:

| Function | Purpose |
|----------|---------|
| `mutex_t` | Mutex data type (typically `uint_fast8_t`) |
| `bool mutex_try_lock(mutex_t *m)` | Try to acquire mutex (non-blocking) |
| `void mutex_unlock(mutex_t *m)` | Release mutex |

**Note:** There is no blocking `mutex_lock()`. Use `mutex_try_lock()` in a loop if you need blocking behavior, but consider using process mutexes instead.

### mutex_try_lock()

```c
bool
mutex_try_lock(volatile mutex_t *m)
```

Attempts to acquire the mutex. Returns immediately whether successful or not.

**Parameters:**
- `m`: Pointer to the mutex

**Returns:**
- `true`: Successfully acquired the mutex
- `false`: Mutex is already locked by someone else

**Thread safety:** Yes, can be called from ISR or main context.

### mutex_unlock()

```c
void
mutex_unlock(volatile mutex_t *m)
```

Releases a previously acquired mutex.

**Parameters:**
- `m`: Pointer to the mutex to release

**Important:** Only unlock a mutex that you successfully locked.

### Usage Example: Protecting a Queue

```c
#include "sys/mutex.h"
#include "sys/log.h"

#define LOG_MODULE "Queue"
#define LOG_LEVEL LOG_LEVEL_INFO

#define QUEUE_SIZE 16

static volatile mutex_t queue_mutex = MUTEX_STATUS_UNLOCKED;
static int queue[QUEUE_SIZE];
static int queue_head = 0;
static int queue_tail = 0;

bool
queue_enqueue(int value)
{
  bool success = false;

  /* Try to acquire mutex */
  if(mutex_try_lock(&queue_mutex)) {
    /* Check if queue has space */
    int next_tail = (queue_tail + 1) % QUEUE_SIZE;
    if(next_tail != queue_head) {
      queue[queue_tail] = value;
      queue_tail = next_tail;
      success = true;
    }

    /* Release mutex */
    mutex_unlock(&queue_mutex);
  }

  if(!success) {
    LOG_WARN("Failed to enqueue (queue full or locked)\n");
  }

  return success;
}

bool
queue_dequeue(int *value)
{
  bool success = false;

  /* Try to acquire mutex */
  if(mutex_try_lock(&queue_mutex)) {
    /* Check if queue has data */
    if(queue_head != queue_tail) {
      *value = queue[queue_head];
      queue_head = (queue_head + 1) % QUEUE_SIZE;
      success = true;
    }

    /* Release mutex */
    mutex_unlock(&queue_mutex);
  }

  return success;
}

/* Can be called from ISR */
void
sensor_isr(void)
{
  int reading = read_sensor();

  /* Non-blocking enqueue */
  if(!queue_enqueue(reading)) {
    /* Queue full or contended, drop sample */
  }
}
```

### Mutexes vs Critical Sections

| Feature | Mutex | Critical Section |
|---------|-------|------------------|
| **Granularity** | Per-resource | Global |
| **Blocking** | Non-blocking (try-lock) | Blocks all interrupts |
| **CPU Instructions** | Can use atomics (efficient) | Disable all interrupts |
| **Use Case** | Protecting specific resources | Very brief, simple protection |

## Process Mutexes

Process mutexes are specifically designed for coordinating access between **processes** (not between ISRs and processes). They integrate with the event system, allowing processes to yield while waiting for a mutex.

**Key difference:** Regular mutexes are for ISR/main synchronization. Process mutexes are for process-to-process coordination.

### API

Declared in `os/sys/process-mutex.h`:

| Function | Purpose |
|----------|---------|
| `process_mutex_t` | Process mutex data type |
| `void process_mutex_init(process_mutex_t *m)` | Initialize process mutex |
| `bool process_mutex_try_lock(process_mutex_t *m)` | Try to acquire process mutex |
| `void process_mutex_unlock(process_mutex_t *m)` | Release process mutex, notify waiters |

**Important:** Process mutexes use the `PROCESS_EVENT_UNLOCKED` event to notify waiting processes.

### process_mutex_init()

```c
void
process_mutex_init(process_mutex_t *mutex)
```

Initializes a process mutex. Must be called before first use.

**Parameters:**
- `mutex`: Pointer to process mutex to initialize

### process_mutex_try_lock()

```c
bool
process_mutex_try_lock(process_mutex_t *mutex)
```

Attempts to acquire the process mutex. If the mutex is locked, the calling process is registered as waiting and will receive `PROCESS_EVENT_UNLOCKED` when the mutex becomes available.

**Parameters:**
- `mutex`: Pointer to the process mutex

**Returns:**
- `true`: Successfully acquired the mutex
- `false`: Mutex is locked, process registered for notification

**Typical pattern:** Call in a loop, yielding with `PROCESS_WAIT_EVENT()` between attempts.

### process_mutex_unlock()

```c
void
process_mutex_unlock(process_mutex_t *mutex)
```

Releases the process mutex and posts `PROCESS_EVENT_UNLOCKED` to any waiting process.

**Parameters:**
- `mutex`: Pointer to the process mutex to release

**What happens:**
- If processes are waiting, posts `PROCESS_EVENT_UNLOCKED` to the next waiting process
- Clears the waiting process list
- Marks mutex as unlocked

### Usage Example: Coordinating Processes

```c
#include "contiki.h"
#include "sys/process-mutex.h"
#include "sys/log.h"

#define LOG_MODULE "Shared"
#define LOG_LEVEL LOG_LEVEL_INFO

/* Shared resource protected by process mutex */
static process_mutex_t shared_resource_mutex;
static int shared_counter = 0;

PROCESS(process_a, "Process A");
PROCESS(process_b, "Process B");

void
init_shared_resources(void)
{
  process_mutex_init(&shared_resource_mutex);
}

PROCESS_THREAD(process_a, ev, data)
{
  static struct etimer timer;

  PROCESS_BEGIN();

  etimer_set(&timer, CLOCK_SECOND * 2);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));

    LOG_INFO("Process A: Trying to acquire mutex\n");

    /* Try to lock, wait if necessary */
    while(!process_mutex_try_lock(&shared_resource_mutex)) {
      LOG_INFO("Process A: Waiting for mutex...\n");
      PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_UNLOCKED);
    }

    /* Critical section - mutex acquired */
    LOG_INFO("Process A: Mutex acquired, counter = %d\n", shared_counter);
    shared_counter++;

    /* Simulate some work */
    etimer_set(&timer, CLOCK_SECOND / 2);
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));

    /* Release mutex */
    LOG_INFO("Process A: Releasing mutex\n");
    process_mutex_unlock(&shared_resource_mutex);

    etimer_set(&timer, CLOCK_SECOND * 2);
  }

  PROCESS_END();
}

PROCESS_THREAD(process_b, ev, data)
{
  static struct etimer timer;

  PROCESS_BEGIN();

  etimer_set(&timer, CLOCK_SECOND * 3);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));

    LOG_INFO("Process B: Trying to acquire mutex\n");

    /* Try to lock, wait if necessary */
    while(!process_mutex_try_lock(&shared_resource_mutex)) {
      LOG_INFO("Process B: Waiting for mutex...\n");
      PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_UNLOCKED);
    }

    /* Critical section - mutex acquired */
    LOG_INFO("Process B: Mutex acquired, counter = %d\n", shared_counter);
    shared_counter++;

    /* Release immediately */
    LOG_INFO("Process B: Releasing mutex\n");
    process_mutex_unlock(&shared_resource_mutex);

    etimer_set(&timer, CLOCK_SECOND * 3);
  }

  PROCESS_END();
}

AUTOSTART_PROCESSES(&process_a, &process_b);
```

### Process Mutex Best Practices

1. **Always initialize** with `process_mutex_init()` before first use
2. **Use in processes only** - Not suitable for ISR/main synchronization
3. **Wait properly** - Use `PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_UNLOCKED)` in a loop
4. **Don't hold too long** - While you can hold it longer than critical sections, be considerate of other processes
5. **Always unlock** - Ensure all code paths unlock the mutex

**Common pattern:**

```c
/* Try to lock */
while(!process_mutex_try_lock(&mutex)) {
  PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_UNLOCKED);
}

/* Use protected resource */
/* ... do work ... */

/* Always unlock */
process_mutex_unlock(&mutex);
```

## Atomic Operations

Atomic operations provide lock-free synchronization for simple operations on small data types. They're more efficient than mutexes for basic operations.

### API

Declared in `os/sys/atomic.h`:

```c
bool atomic_cas_uint8(uint8_t *target, uint8_t old_val, uint8_t new_val)
```

Performs an atomic compare-and-swap (CAS) operation on a byte.

**Parameters:**
- `target`: Pointer to the byte to manipulate
- `old_val`: Expected current value
- `new_val`: New value to store if current value matches `old_val`

**Returns:**
- `true`: Swap succeeded (value was `old_val`, now set to `new_val`)
- `false`: Swap failed (value was not `old_val`, unchanged)

**Atomicity:** The entire read-compare-write operation is atomic—no other code can observe or modify the value between these steps.

### Usage Example: Lock-Free Flag

```c
#include "sys/atomic.h"
#include "sys/log.h"

#define LOG_MODULE "Atomic"
#define LOG_LEVEL LOG_LEVEL_INFO

#define STATE_IDLE     0
#define STATE_BUSY     1
#define STATE_DONE     2

static uint8_t operation_state = STATE_IDLE;

bool
start_operation(void)
{
  /* Try to transition from IDLE to BUSY */
  if(atomic_cas_uint8(&operation_state, STATE_IDLE, STATE_BUSY)) {
    LOG_INFO("Operation started\n");
    return true;
  } else {
    LOG_WARN("Operation already in progress\n");
    return false;
  }
}

void
complete_operation(void)
{
  /* Try to transition from BUSY to DONE */
  if(atomic_cas_uint8(&operation_state, STATE_BUSY, STATE_DONE)) {
    LOG_INFO("Operation completed\n");
  } else {
    LOG_ERR("Invalid state transition\n");
  }
}

void
reset_operation(void)
{
  /* Try to transition from DONE to IDLE */
  if(atomic_cas_uint8(&operation_state, STATE_DONE, STATE_IDLE)) {
    LOG_INFO("Operation reset\n");
  } else {
    LOG_WARN("Cannot reset (not in DONE state)\n");
  }
}
```

### Usage Example: Reference Counting

```c
#include "sys/atomic.h"
#include "sys/log.h"

#define LOG_MODULE "RefCount"
#define LOG_LEVEL LOG_LEVEL_INFO

static uint8_t ref_count = 0;

void
acquire_reference(void)
{
  uint8_t old_count, new_count;

  /* Atomic increment using CAS loop */
  do {
    old_count = ref_count;
    new_count = old_count + 1;

    /* Check for overflow */
    if(new_count == 0) {
      LOG_ERR("Reference count overflow\n");
      return;
    }
  } while(!atomic_cas_uint8(&ref_count, old_count, new_count));

  LOG_INFO("Reference acquired, count = %u\n", new_count);
}

void
release_reference(void)
{
  uint8_t old_count, new_count;

  /* Atomic decrement using CAS loop */
  do {
    old_count = ref_count;

    /* Check for underflow */
    if(old_count == 0) {
      LOG_ERR("Reference count underflow\n");
      return;
    }

    new_count = old_count - 1;
  } while(!atomic_cas_uint8(&ref_count, old_count, new_count));

  LOG_INFO("Reference released, count = %u\n", new_count);

  if(new_count == 0) {
    LOG_INFO("All references released, cleanup can occur\n");
  }
}
```

## Best Practices

### 1. Choose the Right Primitive

```c
/* Scenario: Protecting a counter accessed from ISR and main */

/* GOOD: Critical section (brief operation) */
int_master_status_t status = critical_enter();
packet_count++;
critical_exit(status);

/* GOOD: Atomic operation (single byte) */
atomic_cas_uint8(&state, OLD_STATE, NEW_STATE);

/* GOOD: Mutex (try-lock semantics) */
if(mutex_try_lock(&resource_mutex)) {
  use_resource();
  mutex_unlock(&resource_mutex);
}

/* WRONG: Process mutex for ISR/main synchronization */
process_mutex_try_lock(&mutex);  /* BAD: Only for processes */
```

### 2. Keep Critical Sections Brief

```c
/* WRONG - Too much work in critical section */
status = critical_enter();
for(int i = 0; i < len; i++) {
  buffer[i] = compute_value(i);  /* BAD: Complex computation */
}
critical_exit(status);

/* CORRECT - Minimize protected region */
for(int i = 0; i < len; i++) {
  buffer[i] = compute_value(i);  /* Computation outside */
}
status = critical_enter();
memcpy(shared_buffer, buffer, len);  /* Only copy protected */
critical_exit(status);
```

### 3. Always Pair Lock/Unlock

```c
/* WRONG - Missing unlock on error path */
if(mutex_try_lock(&mutex)) {
  if(error_condition) {
    return;  /* BAD: Forgot to unlock */
  }
  do_work();
  mutex_unlock(&mutex);
}

/* CORRECT - Unlock on all paths */
if(mutex_try_lock(&mutex)) {
  if(error_condition) {
    mutex_unlock(&mutex);  /* Unlock before return */
    return;
  }
  do_work();
  mutex_unlock(&mutex);
}
```

### 4. Avoid Deadlocks

```c
/* WRONG - Potential deadlock */
void
function_a(void)
{
  mutex_try_lock(&mutex1);
  mutex_try_lock(&mutex2);  /* BAD: Different order than function_b */
  /* work */
  mutex_unlock(&mutex2);
  mutex_unlock(&mutex1);
}

void
function_b(void)
{
  mutex_try_lock(&mutex2);  /* BAD: Could deadlock with function_a */
  mutex_try_lock(&mutex1);
  /* work */
  mutex_unlock(&mutex1);
  mutex_unlock(&mutex2);
}

/* CORRECT - Consistent lock ordering */
void
function_a(void)
{
  mutex_try_lock(&mutex1);  /* Always lock in same order */
  mutex_try_lock(&mutex2);
  /* work */
  mutex_unlock(&mutex2);    /* Unlock in reverse order */
  mutex_unlock(&mutex1);
}

void
function_b(void)
{
  mutex_try_lock(&mutex1);  /* Same order as function_a */
  mutex_try_lock(&mutex2);
  /* work */
  mutex_unlock(&mutex2);
  mutex_unlock(&mutex1);
}
```

### 5. Document Lock Requirements

```c
/* Shared queue protected by mutex */
static mutex_t queue_mutex = MUTEX_STATUS_UNLOCKED;
static int queue[SIZE];
static int queue_len = 0;

/**
 * Add item to queue.
 *
 * Thread safety: Acquires queue_mutex internally.
 * Can be called from ISR (non-blocking).
 *
 * Returns: true if added, false if queue full or mutex contended.
 */
bool
queue_add(int item)
{
  if(!mutex_try_lock(&queue_mutex)) {
    return false;
  }

  if(queue_len >= SIZE) {
    mutex_unlock(&queue_mutex);
    return false;
  }

  queue[queue_len++] = item;
  mutex_unlock(&queue_mutex);
  return true;
}
```

### 6. Be Careful with Nested Locks

```c
/* Nesting critical sections is allowed but increases latency */
void
nested_critical_sections(void)
{
  int_master_status_t status1, status2;

  status1 = critical_enter();
  /* ... work ... */

  status2 = critical_enter();  /* Allowed but increases latency */
  /* ... more work ... */
  critical_exit(status2);

  /* ... work ... */
  critical_exit(status1);
}

/* Prefer single critical section when possible */
void
single_critical_section(void)
{
  int_master_status_t status;

  status = critical_enter();
  /* ... all work ... */
  critical_exit(status);
}
```

### 7. Initialize Mutexes Properly

```c
/* WRONG - Uninitialized process mutex */
static process_mutex_t mutex;

void
use_mutex(void)
{
  process_mutex_try_lock(&mutex);  /* BAD: Not initialized */
}

/* CORRECT - Initialize before use */
static process_mutex_t mutex;

void
init(void)
{
  process_mutex_init(&mutex);  /* Initialize first */
}

void
use_mutex(void)
{
  process_mutex_try_lock(&mutex);  /* Now safe to use */
}

/* Regular mutexes can be statically initialized */
static mutex_t regular_mutex = MUTEX_STATUS_UNLOCKED;  /* OK */
```

## Common Pitfalls

### Pitfall 1: Long Critical Sections

```c
/* WRONG - Critical section too long */
int_master_status_t status = critical_enter();
process_sensor_data();       /* BAD: Could take milliseconds */
format_output_buffer();      /* BAD: More complex work */
LOG_INFO("Done\n");          /* BAD: Logging can be slow */
critical_exit(status);

/* CORRECT - Minimize critical section */
process_sensor_data();       /* Outside critical section */
format_output_buffer();      /* Outside critical section */

status = critical_enter();
memcpy(shared_buf, local_buf, sizeof(local_buf));  /* Only copy protected */
critical_exit(status);

LOG_INFO("Done\n");          /* Outside critical section */
```

**Impact:** Long critical sections increase interrupt latency and can cause missed interrupts, watchdog resets, or timing violations.

### Pitfall 2: Forgetting to Check Try-Lock Return Value

```c
/* WRONG - Not checking if lock succeeded */
mutex_try_lock(&mutex);
access_shared_resource();    /* BAD: Might not have lock! */
mutex_unlock(&mutex);

/* CORRECT - Check return value */
if(mutex_try_lock(&mutex)) {
  access_shared_resource();  /* Only access if we have lock */
  mutex_unlock(&mutex);
} else {
  LOG_WARN("Could not acquire lock\n");
}
```

### Pitfall 3: Using Wrong Mutex Type

```c
/* WRONG - Using process mutex for ISR synchronization */
static process_mutex_t mutex;

void
sensor_isr(void)
{
  process_mutex_try_lock(&mutex);  /* BAD: Process mutex in ISR */
  /* ... */
  process_mutex_unlock(&mutex);
}

/* CORRECT - Use regular mutex for ISR */
static mutex_t mutex = MUTEX_STATUS_UNLOCKED;

void
sensor_isr(void)
{
  if(mutex_try_lock(&mutex)) {     /* Regular mutex works in ISR */
    /* ... */
    mutex_unlock(&mutex);
  }
}

/* CORRECT - Use process mutex only between processes */
PROCESS_THREAD(my_process, ev, data)
{
  static process_mutex_t mutex;

  PROCESS_BEGIN();

  process_mutex_init(&mutex);

  while(!process_mutex_try_lock(&mutex)) {
    PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_UNLOCKED);
  }

  /* ... work ... */

  process_mutex_unlock(&mutex);

  PROCESS_END();
}
```

### Pitfall 4: Deadlock from Inconsistent Lock Order

```c
/* WRONG - Different lock order in different functions */
void
update_a_then_b(void)
{
  mutex_try_lock(&mutex_a);
  mutex_try_lock(&mutex_b);  /* Locks A then B */
  /* ... */
  mutex_unlock(&mutex_b);
  mutex_unlock(&mutex_a);
}

void
update_b_then_a(void)
{
  mutex_try_lock(&mutex_b);  /* BAD: Locks B then A */
  mutex_try_lock(&mutex_a);  /* Can deadlock with update_a_then_b */
  /* ... */
  mutex_unlock(&mutex_a);
  mutex_unlock(&mutex_b);
}

/* CORRECT - Consistent lock order everywhere */
void
update_a_then_b(void)
{
  mutex_try_lock(&mutex_a);  /* Always lock A before B */
  mutex_try_lock(&mutex_b);
  /* ... */
  mutex_unlock(&mutex_b);
  mutex_unlock(&mutex_a);
}

void
update_b_then_a(void)
{
  mutex_try_lock(&mutex_a);  /* Same order: A before B */
  mutex_try_lock(&mutex_b);
  /* ... */
  mutex_unlock(&mutex_b);
  mutex_unlock(&mutex_a);
}
```

### Pitfall 5: Calling process_post() from Critical Section

```c
/* WRONG - Posting events from critical section */
int_master_status_t status = critical_enter();
shared_count++;
process_post(&receiver, EVENT_COUNT_CHANGED, NULL);  /* BAD: Can be slow */
critical_exit(status);

/* CORRECT - Post event outside critical section */
int_master_status_t status = critical_enter();
shared_count++;
int new_count = shared_count;
critical_exit(status);

process_post(&receiver, EVENT_COUNT_CHANGED, &new_count);  /* Outside */
```

**Why:** `process_post()` can trigger complex operations and should not be called with interrupts disabled.

### Pitfall 6: Volatile Qualifier Issues

```c
/* WRONG - Missing volatile for ISR-shared variable */
static int sensor_value = 0;  /* BAD: Not volatile */

void
sensor_isr(void)
{
  sensor_value = read_sensor();  /* ISR writes */
}

void
main_context(void)
{
  while(sensor_value == 0) {  /* BAD: Compiler may optimize away check */
    /* wait */
  }
}

/* CORRECT - Use volatile for ISR-shared variables */
static volatile int sensor_value = 0;  /* Volatile prevents optimization */

void
sensor_isr(void)
{
  sensor_value = read_sensor();
}

void
main_context(void)
{
  int_master_status_t status;
  int value;

  /* Read with critical section for consistency */
  status = critical_enter();
  value = sensor_value;
  critical_exit(status);

  /* Use value */
}
```

**Important:** Always declare variables as `volatile` if they're accessed from both ISR and main context, even if you use synchronization primitives.

## Troubleshooting

### Issue: System Appears to Hang

**Symptoms:** System becomes unresponsive, no process execution.

**Possible causes:**
1. **Forgot to exit critical section**
   ```c
   /* Find code like this: */
   status = critical_enter();
   if(error) {
     return;  /* BUG: Never called critical_exit() */
   }
   ```
   **Fix:** Always exit on all code paths.

2. **Deadlock from lock ordering**
   ```c
   /* Process A: locks mutex1, then mutex2 */
   /* Process B: locks mutex2, then mutex1 */
   ```
   **Fix:** Ensure consistent lock ordering everywhere.

3. **Process mutex never unlocked**
   ```c
   /* Find process that locked but never unlocked */
   ```
   **Fix:** Ensure all code paths unlock.

### Issue: Data Corruption

**Symptoms:** Variables have unexpected values, data structures corrupted.

**Possible causes:**
1. **Missing synchronization**
   ```c
   /* Variable accessed from ISR but not protected */
   shared_data = new_value;  /* BUG: No critical section */
   ```
   **Fix:** Add critical section or mutex.

2. **Incorrect critical section placement**
   ```c
   temp = shared_value;       /* BUG: Read outside critical section */
   status = critical_enter();
   temp++;
   shared_value = temp;
   critical_exit(status);
   ```
   **Fix:** Protect entire read-modify-write sequence.

3. **Missing volatile qualifier**
   ```c
   static int flag = 0;  /* BUG: Should be volatile */
   ```
   **Fix:** Add `volatile` to ISR-shared variables.

### Issue: Increased Interrupt Latency

**Symptoms:** Interrupts arrive late, timing-sensitive operations fail.

**Possible causes:**
1. **Critical sections too long**
   ```c
   status = critical_enter();
   /* Too much work here */
   critical_exit(status);
   ```
   **Fix:** Minimize work in critical sections.

2. **Nested critical sections**
   ```c
   status1 = critical_enter();
   /* ... */
   status2 = critical_enter();  /* Increases latency */
   ```
   **Fix:** Restructure to avoid nesting when possible.

3. **Logging in critical sections**
   ```c
   status = critical_enter();
   LOG_INFO(...);  /* BUG: Logging is slow */
   critical_exit(status);
   ```
   **Fix:** Move logging outside critical sections.

### Issue: mutex_try_lock() Always Fails

**Symptoms:** Mutex is always locked, even though it should be available.

**Possible causes:**
1. **Never unlocked**
   ```c
   if(mutex_try_lock(&mutex)) {
     if(error) {
       return;  /* BUG: Forgot to unlock */
     }
     mutex_unlock(&mutex);
   }
   ```
   **Fix:** Unlock on all code paths.

2. **Unlocking wrong mutex**
   ```c
   mutex_try_lock(&mutex_a);
   /* ... */
   mutex_unlock(&mutex_b);  /* BUG: Wrong mutex */
   ```
   **Fix:** Ensure lock/unlock pairs match.

### Issue: Process Never Receives PROCESS_EVENT_UNLOCKED

**Symptoms:** Process waits forever for process mutex.

**Possible causes:**
1. **Process mutex not initialized**
   ```c
   static process_mutex_t mutex;  /* BUG: Not initialized */
   process_mutex_try_lock(&mutex);
   ```
   **Fix:** Call `process_mutex_init()` before first use.

2. **Wrong event check**
   ```c
   PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_CONTINUE);  /* Wrong event */
   ```
   **Fix:** Wait for `PROCESS_EVENT_UNLOCKED`.

3. **Mutex holder crashed**
   ```c
   /* Process that locked mutex terminated without unlocking */
   ```
   **Fix:** Ensure robust error handling and cleanup.

## Summary

| Primitive | Use Case | Context | Blocking |
|-----------|----------|---------|----------|
| **Critical Section** | Protect brief ISR/main shared access | Any | Yes (disables interrupts) |
| **Mutex** | Lock-based ISR/main synchronization | Any | No (try-lock only) |
| **Process Mutex** | Process-to-process coordination | Processes only | Yes (yields with event) |
| **Atomic CAS** | Lock-free single byte operations | Any | No |
| **Memory Barrier** | Prevent reordering (rarely used directly) | Any | No |

**Remember:**
- Use the **weakest** primitive that solves your problem
- Keep critical sections **< 50μs**
- Always check `try_lock()` return values
- Use consistent lock ordering to avoid deadlocks
- Initialize process mutexes before use
- Mark ISR-shared variables as `volatile`
- Document thread-safety requirements

For more information on related topics:
- [Processes and Events](Processes-and-events.md) - Process model and event system
- [Multitasking and Scheduling](Multitasking-and-scheduling.md) - Contiki-NG multitasking model
