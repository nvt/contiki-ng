# Processes and Events

Applications in Contiki-NG are typically written using the _Process_ abstraction. Processes provide a lightweight threading mechanism built on top of [Protothreads](http://dl.acm.org/citation.cfm?id=1182811), enabling sequential code structure with minimal memory overhead in an event-driven system.

## Overview

Contiki-NG processes combine three key concepts:

1. **Protothreads** - Lightweight, stackless threads that provide blocking semantics without per-thread stacks
2. **Event-driven execution** - Processes are scheduled when events occur
3. **Cooperative multitasking** - Processes voluntarily yield control to allow other processes to run

**Memory efficiency:** Each process requires only 2-12 bytes of state (depending on architecture), compared to hundreds or thousands of bytes for traditional threads with stacks.

**Trade-off:** Processes are stackless, which means **local variables are not preserved across yields**. This is the most important limitation to understand when writing process code.

## Process Lifecycle

A process goes through several states during its lifetime:

```
   process_start()
         |
         v
    [INIT event] -----> Running -----> YIELD/WAIT -----> Waiting
         |                                   ^                |
         |                                   |                |
         v                                   +---- Event -----+
   User code executes                                         |
         |                                                    v
         +----------> PROCESS_EXIT() or process_exit() ----> Exiting
                              |                                |
                              v                                v
                        [EXIT event]                    [EXITED event to all]
                              |
                              v
                           Stopped
```

**Key events in the lifecycle:**
- `PROCESS_EVENT_INIT` - Delivered once when process starts
- `PROCESS_EVENT_EXIT` - Delivered to the process itself before exiting
- `PROCESS_EVENT_EXITED` - Broadcast to all other processes after a process exits
- `PROCESS_EVENT_POLL` - Delivered when process is polled
- `PROCESS_EVENT_CONTINUE` - Delivered when resuming from `PROCESS_PAUSE()`

## Process Definition

### Basic Process Structure

A process is declared using the `PROCESS()` macro, which takes two arguments:
1. The variable identifier for the process
2. A human-readable name string (can be removed with `PROCESS_CONF_NO_PROCESS_NAMES` to save RAM)

```c
#include "contiki.h"
#include "sys/log.h"

#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_INFO

/* Declare the process */
PROCESS(hello_process, "Hello world process");

/* Auto-start the process at boot */
AUTOSTART_PROCESSES(&hello_process);

/* Define the process behavior */
PROCESS_THREAD(hello_process, ev, data)
{
  PROCESS_BEGIN();

  LOG_INFO("Hello, world!\n");

  PROCESS_END();
}
```

### Declaring Processes in Header Files

To reference a process from another file, use `PROCESS_NAME()` in a header file:

```c
/* In my-process.h */
#ifndef MY_PROCESS_H_
#define MY_PROCESS_H_

#include "contiki.h"

PROCESS_NAME(my_process);

#endif /* MY_PROCESS_H_ */
```

### Manual Process Start

If a process is not included in `AUTOSTART_PROCESSES()`, it must be started manually:

```c
void
start_my_processes(void)
{
  /* Start process with optional data pointer */
  process_start(&sensor_process, NULL);
  process_start(&network_process, &config);
}
```

## CRITICAL: Protothread Limitations

### Local Variables Must Be Static

**This is the most important rule when writing processes:** Because protothreads are stackless and do not save the stack context across blocking calls, **local variables are NOT preserved when a process yields or waits**.

**Wrong - Will fail:**
```c
PROCESS_THREAD(broken_process, ev, data)
{
  int counter = 0;  /* WRONG! Will not preserve value across yields */
  struct etimer et;  /* WRONG! Will be lost when yielding */

  PROCESS_BEGIN();

  etimer_set(&et, CLOCK_SECOND);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    counter++;  /* counter resets to 0 each time! */
    printf("Count: %d\n", counter);  /* Always prints "Count: 1" */
    etimer_reset(&et);
  }

  PROCESS_END();
}
```

**Correct - Use static:**
```c
PROCESS_THREAD(working_process, ev, data)
{
  static int counter = 0;  /* Correct! */
  static struct etimer et;  /* Correct! */

  PROCESS_BEGIN();

  etimer_set(&et, CLOCK_SECOND);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    counter++;  /* Now correctly increments */
    printf("Count: %d\n", counter);  /* Prints 1, 2, 3, ... */
    etimer_reset(&et);
  }

  PROCESS_END();
}
```

**Rule of thumb:** Declare ALL variables inside `PROCESS_THREAD()` as `static` unless they are only used before the first `PROCESS_BEGIN()` or after the last yield point.

### Cannot Use switch() Statements

Protothreads are implemented using the C `switch()` statement internally (similar to Duff's device). This means **you cannot use switch() statements in your process code**.

**Wrong:**
```c
PROCESS_THREAD(broken_process, ev, data)
{
  static int state = 0;

  PROCESS_BEGIN();

  while(1) {
    PROCESS_WAIT_EVENT();

    switch(state) {  /* ERROR! Cannot use switch() */
      case 0:
        /* ... */
        break;
      case 1:
        /* ... */
        break;
    }
  }

  PROCESS_END();
}
```

**Correct - Use if/else:**
```c
PROCESS_THREAD(working_process, ev, data)
{
  static int state = 0;

  PROCESS_BEGIN();

  while(1) {
    PROCESS_WAIT_EVENT();

    if(state == 0) {
      /* ... */
    } else if(state == 1) {
      /* ... */
    }
  }

  PROCESS_END();
}
```

### Cannot Block in Called Functions

A protothread runs within a single C function and cannot block inside called functions. If you need blocking behavior in a helper function, use `PROCESS_PT_SPAWN()` to spawn a child protothread.

**Wrong:**
```c
void
helper_function(void)
{
  static struct etimer et;
  etimer_set(&et, CLOCK_SECOND);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));  /* ERROR! */
}

PROCESS_THREAD(broken_process, ev, data)
{
  PROCESS_BEGIN();
  helper_function();  /* Won't work */
  PROCESS_END();
}
```

**Correct - Use child protothread:**
```c
static
PT_THREAD(helper_thread(struct pt *pt))
{
  static struct etimer et;

  PT_BEGIN(pt);

  etimer_set(&et, CLOCK_SECOND);
  PT_WAIT_UNTIL(pt, etimer_expired(&et));

  PT_END(pt);
}

PROCESS_THREAD(working_process, ev, data)
{
  static struct pt helper_pt;

  PROCESS_BEGIN();

  /* Spawn child protothread */
  PROCESS_PT_SPAWN(&helper_pt, helper_thread(&helper_pt));

  PROCESS_END();
}
```

## Process Control API

### Starting and Stopping Processes

| Function | Purpose |
|----------|---------|
|`void process_start(struct process *p, process_data_t data)` | Start a process with optional data pointer. |
|`void process_exit(struct process *p)` | Stop a process (can be called on self or other process). |
|`PROCESS_EXIT()` | Macro to exit current process from within `PROCESS_THREAD()`. |
|`bool process_is_running(struct process *p)` | Check if a process is currently running. |
|`PROCESS_CURRENT()` | Get pointer to currently running process. |

### Process Control Example

```c
PROCESS(main_process, "Main process");
PROCESS(worker_process, "Worker process");

AUTOSTART_PROCESSES(&main_process);

PROCESS_THREAD(worker_process, ev, data)
{
  static struct etimer et;
  static int count = 0;

  PROCESS_BEGIN();

  LOG_INFO("Worker started\n");

  etimer_set(&et, CLOCK_SECOND);

  while(count < 10) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    count++;
    LOG_INFO("Worker count: %d\n", count);
    etimer_reset(&et);
  }

  LOG_INFO("Worker finished\n");

  PROCESS_END();
}

PROCESS_THREAD(main_process, ev, data)
{
  static struct etimer et;

  PROCESS_BEGIN();

  /* Start worker process */
  process_start(&worker_process, NULL);

  /* Wait 5 seconds */
  etimer_set(&et, 5 * CLOCK_SECOND);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

  /* Check if worker is still running */
  if(process_is_running(&worker_process)) {
    LOG_INFO("Stopping worker process\n");
    process_exit(&worker_process);
  }

  PROCESS_END();
}
```

## Event System

### Event Posting and Delivery

| Function | Purpose |
|----------|---------|
|`int process_post(struct process *p, process_event_t ev, process_data_t data)` | Post asynchronous event (queued). Returns `PROCESS_ERR_OK` or `PROCESS_ERR_FULL`. |
|`void process_post_synch(struct process *p, process_event_t ev, process_data_t data)` | Post synchronous event (delivered immediately). |
|`void process_poll(struct process *p)` | Request process to be polled (from interrupt or other process). |
|`process_event_t process_alloc_event(void)` | Allocate a global event number (returns `PROCESS_EVENT_NONE` on failure). |
|`process_num_events_t process_nevents(void)` | Get number of pending events in queue. |

### Asynchronous vs Synchronous Events

**Asynchronous events (`process_post`):**
- Placed in event queue
- Delivered when target process is scheduled
- Can fail if queue is full (`PROCESS_ERR_FULL`)
- Safe to call from interrupts
- Used for most inter-process communication

**Synchronous events (`process_post_synch`):**
- Delivered immediately
- Target process executes before function returns
- Never fails (no queue)
- Cannot be called from interrupts
- Use sparingly (can cause deep call stacks)

### Event Posting Example

```c
PROCESS(sender_process, "Sender");
PROCESS(receiver_process, "Receiver");

AUTOSTART_PROCESSES(&sender_process, &receiver_process);

static process_event_t my_event;

PROCESS_THREAD(receiver_process, ev, data)
{
  PROCESS_BEGIN();

  while(1) {
    PROCESS_WAIT_EVENT();

    if(ev == my_event) {
      int *value = (int *)data;
      LOG_INFO("Received my_event with value: %d\n", *value);
    }
  }

  PROCESS_END();
}

PROCESS_THREAD(sender_process, ev, data)
{
  static struct etimer et;
  static int counter = 0;

  PROCESS_BEGIN();

  /* Allocate custom event */
  my_event = process_alloc_event();
  if(my_event == PROCESS_EVENT_NONE) {
    LOG_ERR("Failed to allocate event\n");
    PROCESS_EXIT();
  }

  etimer_set(&et, CLOCK_SECOND);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

    counter++;

    /* Post event with data */
    if(process_post(&receiver_process, my_event, &counter) != PROCESS_ERR_OK) {
      LOG_WARN("Event queue full\n");
    }

    etimer_reset(&et);
  }

  PROCESS_END();
}
```

### Broadcasting Events

Use `PROCESS_BROADCAST` to send events to all processes:

```c
static process_event_t shutdown_event;

void
initiate_shutdown(void)
{
  /* Broadcast event to all processes */
  process_post(PROCESS_BROADCAST, shutdown_event, NULL);
}

PROCESS_THREAD(some_process, ev, data)
{
  PROCESS_BEGIN();

  while(1) {
    PROCESS_WAIT_EVENT();

    if(ev == shutdown_event) {
      LOG_INFO("Received shutdown request\n");
      /* Cleanup and exit */
      PROCESS_EXIT();
    }
  }

  PROCESS_END();
}
```

### System-Defined Events

| Event | ID | Description |
|-------|-----|-------------|
|`PROCESS_EVENT_NONE` | 0x80 | No event (used as error indicator). |
|`PROCESS_EVENT_INIT` | 0x81 | Delivered once when process starts. |
|`PROCESS_EVENT_POLL` | 0x82 | Delivered when process is polled. |
|`PROCESS_EVENT_EXIT` | 0x83 | Delivered to process itself before it exits. |
|`PROCESS_EVENT_SERVICE_REMOVED` | 0x84 | Reserved (unused). |
|`PROCESS_EVENT_CONTINUE` | 0x85 | Delivered when resuming from `PROCESS_PAUSE()`. |
|`PROCESS_EVENT_MSG` | 0x86 | Delivered upon a sensor event. |
|`PROCESS_EVENT_EXITED` | 0x87 | Broadcast to all processes when another process exits. |
|`PROCESS_EVENT_TIMER` | 0x88 | Delivered when an etimer expires. |
|`PROCESS_EVENT_COM` | 0x89 | Reserved (unused). |
|`PROCESS_EVENT_UNLOCKED` | 0x8a | Delivered by process mutex when mutex becomes available. |
|`PROCESS_EVENT_MAX` | 0x8b | Maximum system-defined event number. |

### Event Numbering

- **0x00 - 0x7F**: Module-local events (can be used within a single module without allocation)
- **0x80 - 0x8A**: System-defined events (predefined by Contiki-NG)
- **0x8B+**: User-allocated global events (allocated with `process_alloc_event()`)

**Note:** There is no way to deallocate events. The number of allocatable events is limited by configuration (`PROCESS_CONF_NUMEVENTS`, default 32).

## Waiting and Yielding

### Waiting Macros

| Macro | Behavior | Use Case |
|-------|----------|----------|
|`PROCESS_WAIT_EVENT()` | Wait for any event | General event handling |
|`PROCESS_WAIT_EVENT_UNTIL(condition)` | Wait until condition is true | Waiting for specific event/state |
|`PROCESS_WAIT_UNTIL(condition)` | Wait for condition (may not yield) | Short waits, use with caution |
|`PROCESS_WAIT_WHILE(condition)` | Wait while condition is true | Inverse of WAIT_UNTIL |
|`PROCESS_YIELD()` | Yield and wait for any event | Allow other processes to run |
|`PROCESS_YIELD_UNTIL(condition)` | Yield and wait for condition | Guaranteed to yield at least once |
|`PROCESS_PAUSE()` | Yield briefly then resume | Break up long operations |

### PROCESS_PAUSE() vs PROCESS_YIELD()

**`PROCESS_PAUSE()`:**
- Posts a `PROCESS_EVENT_CONTINUE` to itself
- Allows other processes to run
- Immediately re-schedules itself
- Use to break up long-running operations

**`PROCESS_YIELD()`:**
- Waits for any event
- Will not run again until an event is delivered
- Use when waiting for external events

### Long Operation Example

```c
PROCESS_THREAD(long_operation_process, ev, data)
{
  static int i;
  static uint32_t sum = 0;

  PROCESS_BEGIN();

  /* Process large dataset, yielding periodically */
  for(i = 0; i < 10000; i++) {
    sum += compute_something(i);

    /* Yield every 100 iterations to allow other processes to run */
    if(i % 100 == 0) {
      PROCESS_PAUSE();
    }
  }

  LOG_INFO("Processing complete, sum = %lu\n", (unsigned long)sum);

  PROCESS_END();
}
```

### Polling

**From interrupt context:**
```c
void
uart_interrupt_handler(void)
{
  /* Receive data */
  char c = uart_read();

  /* Poll process to handle data */
  process_poll(&serial_process);
}
```

**In process code:**
```c
PROCESS_THREAD(serial_process, ev, data)
{
  PROCESS_POLLHANDLER({
    /* Executed when polled, before PROCESS_BEGIN */
    handle_incoming_data();
  });

  PROCESS_BEGIN();

  while(1) {
    PROCESS_WAIT_EVENT();

    if(ev == PROCESS_EVENT_POLL) {
      LOG_DBG("Process was polled\n");
    }
  }

  PROCESS_END();
}
```

## Exit Handlers

Use `PROCESS_EXITHANDLER()` to perform cleanup when a process exits:

```c
PROCESS_THREAD(resource_process, ev, data)
{
  static struct resource *res;

  PROCESS_EXITHANDLER({
    /* Cleanup when process exits */
    if(res != NULL) {
      release_resource(res);
      res = NULL;
    }
    LOG_INFO("Process exiting, cleanup complete\n");
  });

  PROCESS_BEGIN();

  res = allocate_resource();
  if(res == NULL) {
    PROCESS_EXIT();
  }

  /* Use resource */
  while(1) {
    PROCESS_WAIT_EVENT();
    /* ... */
  }

  PROCESS_END();
}
```

## Process Context Switching

When implementing library functions that need to perform process-specific operations (like starting etimers), use `PROCESS_CONTEXT_BEGIN/END` to switch context:

```c
void
schedule_callback(struct process *p, clock_time_t delay)
{
  static struct etimer timer;

  /* Switch to target process context */
  PROCESS_CONTEXT_BEGIN(p);

  /* This etimer will be associated with process p */
  etimer_set(&timer, delay);

  /* Restore original context */
  PROCESS_CONTEXT_END(p);
}

/* Usage */
PROCESS_THREAD(my_process, ev, data)
{
  PROCESS_BEGIN();

  /* Schedule callback in another process's context */
  schedule_callback(&other_process, CLOCK_SECOND);

  PROCESS_END();
}
```

## Common Pitfalls

### Pitfall 1: Forgetting Static on Local Variables

**Wrong:**
```c
PROCESS_THREAD(broken, ev, data)
{
  struct etimer et;  /* Lost on yield! */
  int count = 0;  /* Resets every time! */

  PROCESS_BEGIN();
  etimer_set(&et, CLOCK_SECOND);
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    count++;  /* Always 1 */
  }
  PROCESS_END();
}
```

**Correct:**
```c
PROCESS_THREAD(working, ev, data)
{
  static struct etimer et;  /* Preserved */
  static int count = 0;  /* Preserved */

  PROCESS_BEGIN();
  etimer_set(&et, CLOCK_SECOND);
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    count++;  /* Correctly increments */
  }
  PROCESS_END();
}
```

### Pitfall 2: Infinite Loop Without Yielding

**Wrong:**
```c
PROCESS_THREAD(broken, ev, data)
{
  PROCESS_BEGIN();

  while(1) {
    do_something();  /* Monopolizes CPU! */
  }

  PROCESS_END();
}
```

**Correct:**
```c
PROCESS_THREAD(working, ev, data)
{
  PROCESS_BEGIN();

  while(1) {
    do_something();
    PROCESS_PAUSE();  /* Allow other processes to run */
  }

  PROCESS_END();
}
```

### Pitfall 3: Not Checking process_post() Return Value

**Wrong:**
```c
process_post(&other_process, my_event, &data);  /* May fail! */
```

**Correct:**
```c
if(process_post(&other_process, my_event, &data) != PROCESS_ERR_OK) {
  LOG_WARN("Event queue full, message dropped\n");
  /* Handle error - maybe retry, use synchronous post, or log */
}
```

### Pitfall 4: Using switch() Statements

**Wrong:**
```c
PROCESS_THREAD(broken, ev, data)
{
  PROCESS_BEGIN();
  while(1) {
    PROCESS_WAIT_EVENT();
    switch(ev) {  /* ERROR! Breaks protothreads */
      case EVENT_A:
        /* ... */
        break;
    }
  }
  PROCESS_END();
}
```

**Correct:**
```c
PROCESS_THREAD(working, ev, data)
{
  PROCESS_BEGIN();
  while(1) {
    PROCESS_WAIT_EVENT();
    if(ev == EVENT_A) {
      /* ... */
    } else if(ev == EVENT_B) {
      /* ... */
    }
  }
  PROCESS_END();
}
```

### Pitfall 5: Blocking in Called Functions

**Wrong:**
```c
void helper(void) {
  PROCESS_WAIT_EVENT();  /* ERROR! Can't block outside PROCESS_THREAD */
}

PROCESS_THREAD(broken, ev, data)
{
  PROCESS_BEGIN();
  helper();  /* Won't work */
  PROCESS_END();
}
```

**Correct:**
```c
static
PT_THREAD(helper_pt(struct pt *pt))
{
  PT_BEGIN(pt);
  PT_YIELD(pt);
  PT_END(pt);
}

PROCESS_THREAD(working, ev, data)
{
  static struct pt pt;
  PROCESS_BEGIN();
  PROCESS_PT_SPAWN(&pt, helper_pt(&pt));
  PROCESS_END();
}
```

### Pitfall 6: Handling PROCESS_EVENT_INIT Incorrectly

**Wrong:**
```c
PROCESS_THREAD(broken, ev, data)
{
  static struct etimer et;

  PROCESS_BEGIN();

  /* etimer_set() is called on EVERY event, including INIT */
  etimer_set(&et, CLOCK_SECOND);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    /* ... */
  }
  PROCESS_END();
}
```

**Correct:**
```c
PROCESS_THREAD(working, ev, data)
{
  static struct etimer et;
  static bool initialized = false;

  PROCESS_BEGIN();

  if(!initialized) {
    /* One-time initialization */
    etimer_set(&et, CLOCK_SECOND);
    initialized = true;
  }

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    /* ... */
    etimer_reset(&et);
  }
  PROCESS_END();
}
```

## Best Practices

### 1. Always Use Static for Local Variables

Unless a variable is only used before `PROCESS_BEGIN()` or is a true temporary used between yield points, declare it `static`:

```c
PROCESS_THREAD(example, ev, data)
{
  /* Static - preserved across yields */
  static struct etimer et;
  static int counter;
  static char buffer[64];

  PROCESS_BEGIN();

  /* Non-static is OK here - used before any yield */
  int init_value = compute_initial_value();
  counter = init_value;

  /* ... */

  PROCESS_END();
}
```

### 2. Check Event Types Explicitly

Always check which event you received before processing:

```c
PROCESS_THREAD(example, ev, data)
{
  static struct etimer et;

  PROCESS_BEGIN();

  etimer_set(&et, CLOCK_SECOND);

  while(1) {
    PROCESS_WAIT_EVENT();

    if(ev == PROCESS_EVENT_TIMER && data == &et) {
      /* Handle timer event */
      handle_timer();
      etimer_reset(&et);
    } else if(ev == custom_event) {
      /* Handle custom event */
      handle_custom(data);
    }
    /* Ignore other events */
  }

  PROCESS_END();
}
```

### 3. Use PROCESS_PAUSE() for Long Operations

Break up CPU-intensive operations to prevent monopolizing the CPU:

```c
PROCESS_THREAD(computation, ev, data)
{
  static int i;
  static uint32_t result;

  PROCESS_BEGIN();

  result = 0;
  for(i = 0; i < 10000; i++) {
    result += expensive_computation(i);

    if(i % 50 == 0) {
      PROCESS_PAUSE();  /* Yield periodically */
    }
  }

  LOG_INFO("Result: %lu\n", (unsigned long)result);

  PROCESS_END();
}
```

### 4. Handle PROCESS_EVENT_EXITED for Cleanup

Monitor when other processes exit:

```c
PROCESS_THREAD(manager, ev, data)
{
  PROCESS_BEGIN();

  process_start(&worker_process, NULL);

  while(1) {
    PROCESS_WAIT_EVENT();

    if(ev == PROCESS_EVENT_EXITED) {
      struct process *exited = (struct process *)data;
      if(exited == &worker_process) {
        LOG_INFO("Worker process has exited\n");
        /* Restart or cleanup */
      }
    }
  }

  PROCESS_END();
}
```

### 5. Use Descriptive Event Names

When allocating custom events, use descriptive variable names:

```c
static process_event_t sensor_reading_event;
static process_event_t network_packet_event;
static process_event_t timeout_event;

void
init_events(void)
{
  sensor_reading_event = process_alloc_event();
  network_packet_event = process_alloc_event();
  timeout_event = process_alloc_event();
}
```

## Inter-Process Communication Patterns

### Pattern 1: Producer-Consumer

```c
PROCESS(producer, "Data producer");
PROCESS(consumer, "Data consumer");

AUTOSTART_PROCESSES(&producer, &consumer);

static process_event_t data_ready_event;

PROCESS_THREAD(consumer, ev, data)
{
  PROCESS_BEGIN();

  while(1) {
    PROCESS_WAIT_EVENT();

    if(ev == data_ready_event) {
      int *value = (int *)data;
      LOG_INFO("Consumed value: %d\n", *value);
    }
  }

  PROCESS_END();
}

PROCESS_THREAD(producer, ev, data)
{
  static struct etimer et;
  static int produced_value = 0;

  PROCESS_BEGIN();

  data_ready_event = process_alloc_event();
  etimer_set(&et, CLOCK_SECOND);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

    produced_value++;
    process_post(&consumer, data_ready_event, &produced_value);

    etimer_reset(&et);
  }

  PROCESS_END();
}
```

### Pattern 2: Request-Response

```c
static process_event_t request_event;
static process_event_t response_event;

PROCESS_THREAD(server, ev, data)
{
  static int result;

  PROCESS_BEGIN();

  while(1) {
    PROCESS_WAIT_EVENT();

    if(ev == request_event) {
      struct process *requester = (struct process *)data;

      /* Process request */
      result = compute_result();

      /* Send response back */
      process_post(requester, response_event, &result);
    }
  }

  PROCESS_END();
}

PROCESS_THREAD(client, ev, data)
{
  static struct etimer timeout;

  PROCESS_BEGIN();

  /* Send request */
  process_post(&server, request_event, PROCESS_CURRENT());

  /* Wait for response with timeout */
  etimer_set(&timeout, 5 * CLOCK_SECOND);

  while(1) {
    PROCESS_WAIT_EVENT();

    if(ev == response_event) {
      int *result = (int *)data;
      LOG_INFO("Received response: %d\n", *result);
      break;
    } else if(ev == PROCESS_EVENT_TIMER && etimer_expired(&timeout)) {
      LOG_WARN("Response timeout\n");
      break;
    }
  }

  PROCESS_END();
}
```

### Pattern 3: State Machine

```c
typedef enum {
  STATE_IDLE,
  STATE_CONNECTING,
  STATE_CONNECTED,
  STATE_DISCONNECTING
} connection_state_t;

PROCESS_THREAD(connection_manager, ev, data)
{
  static connection_state_t state = STATE_IDLE;
  static struct etimer retry_timer;

  PROCESS_BEGIN();

  while(1) {
    PROCESS_WAIT_EVENT();

    if(state == STATE_IDLE) {
      if(ev == connect_request_event) {
        LOG_INFO("Starting connection\n");
        start_connection();
        state = STATE_CONNECTING;
        etimer_set(&retry_timer, 10 * CLOCK_SECOND);
      }

    } else if(state == STATE_CONNECTING) {
      if(ev == connection_success_event) {
        LOG_INFO("Connected\n");
        state = STATE_CONNECTED;
      } else if(ev == PROCESS_EVENT_TIMER && etimer_expired(&retry_timer)) {
        LOG_WARN("Connection timeout, retrying\n");
        start_connection();
        etimer_reset(&retry_timer);
      }

    } else if(state == STATE_CONNECTED) {
      if(ev == disconnect_request_event) {
        LOG_INFO("Disconnecting\n");
        start_disconnect();
        state = STATE_DISCONNECTING;
      } else if(ev == data_event) {
        handle_data(data);
      }

    } else if(state == STATE_DISCONNECTING) {
      if(ev == disconnection_complete_event) {
        LOG_INFO("Disconnected\n");
        state = STATE_IDLE;
      }
    }
  }

  PROCESS_END();
}
```

## Advanced Topics

### Spawning Child Protothreads

For complex operations that need their own blocking behavior, spawn child protothreads:

```c
static
PT_THREAD(network_send_pt(struct pt *pt, uint8_t *data, size_t len))
{
  static struct etimer retry_timer;
  static int retries;

  PT_BEGIN(pt);

  retries = 0;
  while(retries < 3) {
    if(send_packet(data, len)) {
      PT_EXIT(pt);  /* Success */
    }

    retries++;
    etimer_set(&retry_timer, CLOCK_SECOND);
    PT_WAIT_UNTIL(pt, etimer_expired(&retry_timer));
  }

  PT_END(pt);
}

PROCESS_THREAD(network_process, ev, data)
{
  static struct pt send_pt;
  static uint8_t packet[128];
  static size_t packet_len;

  PROCESS_BEGIN();

  while(1) {
    PROCESS_WAIT_EVENT();

    if(ev == send_request_event) {
      prepare_packet(packet, &packet_len);

      /* Spawn child protothread to handle send with retries */
      PROCESS_PT_SPAWN(&send_pt, network_send_pt(&send_pt, packet, packet_len));

      LOG_INFO("Packet sent successfully\n");
    }
  }

  PROCESS_END();
}
```

### System Integration Functions

These functions are typically only used by the Contiki-NG core or main loop:

| Function | Purpose |
|----------|---------|
|`void process_init(void)` | Initialize process system (called at boot). |
|`process_num_events_t process_run(void)` | Run one scheduling iteration (returns pending event count). |
|`struct process *PROCESS_LIST()` | Access linked list of all processes. |

**Typical main loop:**
```c
int
main(void)
{
  /* Initialize system */
  platform_init();
  process_init();

  /* Start autostart processes */
  autostart_start(autostart_processes);

  /* Main event loop */
  while(1) {
    process_num_events_t n = process_run();

    if(n == 0) {
      /* No events pending, can enter low power mode */
      platform_idle();
    }
  }

  return 0;
}
```

## Configuration

### Event Queue Size

The event queue size can be configured in `project-conf.h`:

```c
/* Increase event queue size (default is 32) */
#define PROCESS_CONF_NUMEVENTS 64
```

A larger queue reduces the risk of `PROCESS_ERR_FULL` errors but uses more RAM. Each event requires approximately 4-8 bytes depending on architecture.

### Disabling Process Names

To save RAM, disable process name strings:

```c
/* Remove process name strings (saves ~10-20 bytes per process) */
#define PROCESS_CONF_NO_PROCESS_NAMES 1
```

With this option, `PROCESS_NAME_STRING(p)` returns an empty string.

## Summary

### Key Concepts

1. **Processes are stackless** - Use `static` for all persistent local variables
2. **Cooperative multitasking** - Always yield periodically with `PROCESS_PAUSE()` or wait macros
3. **Event-driven** - Processes run when events are delivered
4. **Lightweight** - Only 2-12 bytes of overhead per process

### When to Use Processes

- **Use processes for:** Application logic, protocol implementations, state machines
- **Don't use processes for:** Interrupt handlers (use `process_poll()` instead), very short operations (use functions)

### Process Development Checklist

- [ ] All local variables declared `static` (except temporaries)
- [ ] No `switch()` statements in process body
- [ ] Long operations broken up with `PROCESS_PAUSE()`
- [ ] Event types checked explicitly (don't assume event type)
- [ ] `process_post()` return values checked
- [ ] Exit handler implemented for cleanup if needed
- [ ] Process handles `PROCESS_EVENT_INIT` correctly
- [ ] No blocking calls in helper functions (use child protothreads instead)

### Common APIs Used with Processes

- **Timers:** `etimer` for process-based timing (see Timers.md)
- **Memory:** `MEMB` for process-local memory pools (see Memory-management.md)
- **Sensors:** Sensor API delivers events to processes
- **Networking:** Network stack posts events to protocol processes

Processes are the foundation of Contiki-NG applications. Master the static variable requirement and cooperative yielding, and you'll be able to write complex, efficient embedded applications with minimal memory overhead.
