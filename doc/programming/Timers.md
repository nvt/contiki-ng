# Timers

Contiki-NG provides a comprehensive set of timer libraries used by both applications and the OS itself. The timer libraries contain functionality for checking if a time period has passed, waking up the system from low power mode at scheduled times, and real-time task scheduling.

## Timer Types Overview

All timers build on the `clock` module, which manages basic system time. Understanding which timer to use is crucial for correct and efficient operation:

| Timer Type | Resolution | Interrupt Safe | Event Notification | Use Case |
|------------|------------|----------------|-------------------|----------|
| **clock** | Platform-specific (1-10ms typical) | Yes | No | System time, basic delays |
| **timer** | `CLOCK_SECOND` ticks | Yes | No | Manual timeout checks in interrupts |
| **stimer** | Seconds | Yes | No | Long-duration timeouts (hours/days) |
| **etimer** | `CLOCK_SECOND` ticks | **No** | Yes (process event) | Process-based periodic tasks |
| **ctimer** | `CLOCK_SECOND` ticks | **No** | Yes (callback) | Callback-based timeouts |
| **rtimer** | High (platform-specific) | Yes | Yes (ISR callback) | Real-time tasks, MAC protocols |

### Choosing the Right Timer

- **Use `timer`** for timeout detection in interrupts or when you need to manually poll for expiration
- **Use `stimer`** for long-duration timers measured in seconds (avoids frequent wrapping)
- **Use `etimer`** for process-based periodic tasks (most common for application logic)
- **Use `ctimer`** when you need a callback function but don't want to create a full process
- **Use `rtimer`** only for real-time critical tasks requiring microsecond precision (MAC layers, TSCH)

**Important:** Only `timer`, `stimer`, and `rtimer` are interrupt-safe. Never manipulate `etimer` or `ctimer` from interrupt context.

## The Clock Module

The clock module provides functions for handling system time. It forms the foundation for all other timer libraries except `rtimer` (which has its own high-resolution clock).

### Clock API

| Function | Purpose |
|----------|---------|
|`clock_time_t clock_time()` | Get the system time in `clock_time_t` ticks. |
|`unsigned long clock_seconds()` | Get the system time in seconds. |
|`void clock_set_seconds(unsigned long sec)` | Set the system time in seconds. |
|`void clock_wait(clock_time_t delay)` | Busy-wait for a number of clock ticks. |
|`void clock_delay_usec(uint16_t dt)` | Delay for a number of microseconds. |
|`void clock_init(void)` | Initialize the clock module. |
|`CLOCK_SECOND` | The number of ticks per second. |
|`CLOCK_LT(a, b)` | Check if time `a` is less than `b` (handles wrapping). |

### Clock Characteristics

The system time is specified as the platform-dependent type `clock_time_t`, which can be 32-bit or 64-bit depending on platform configuration (`CLOCK_CONF_SIZE`). This is typically an unsigned value that wraps around when it gets too large. The system time starts from zero at boot.

**Typical values:**
- `CLOCK_SECOND` is often 128 on embedded platforms (7.8ms per tick)
- A 32-bit clock at 128 Hz wraps every ~388 days
- A 16-bit clock at 128 Hz would wrap every ~8.5 minutes

### Clock Usage Example

```c
#include "sys/clock.h"

void
delay_example(void)
{
  clock_time_t start;

  /* Get current time */
  start = clock_time();

  /* Busy-wait for 100ms */
  clock_wait(CLOCK_SECOND / 10);

  /* Delay for 500 microseconds */
  clock_delay_usec(500);

  /* Check elapsed time using CLOCK_LT to handle wrapping */
  clock_time_t now = clock_time();
  if(CLOCK_LT(start + CLOCK_SECOND, now)) {
    /* More than 1 second has elapsed */
  }
}
```

**Note:** `clock_wait()` and `clock_delay_usec()` are busy-wait functions that block the CPU. They should be used sparingly, typically only during initialization or in time-critical code. For application-level delays, use `etimer` instead to allow the system to sleep.

## The Timer Library

The timer library provides functions for setting, resetting and restarting timers, and for checking if a timer has expired. Unlike event timers, the application must manually check if a timer has expired - there is no automatic notification.

A timer is declared as a `struct timer` and all access to the timer is made by a pointer to the declared timer.

### Timer API

| Function | Purpose |
|----------|---------|
|`void timer_set(struct timer *t, clock_time_t interval)` | Start the timer. |
|`void timer_reset(struct timer *t)` | Restart the timer from the previous expire time. |
|`void timer_restart(struct timer *t)` | Restart the timer from current time. |
|`bool timer_expired(struct timer *t)` | Check if the timer has expired. |
|`clock_time_t timer_remaining(struct timer *t)` | Get the time until the timer expires. |

### Timer Behavior

A timer is always initialized by a call to `timer_set()`, which sets the timer to expire the specified delay from current time and also stores the time interval. All the other functions operate on this stored interval.

**`timer_reset()` vs `timer_restart()`:**
- `timer_reset()` restarts from the previous expiration time (prevents drift in periodic timers)
- `timer_restart()` restarts from the current time (simpler but accumulates drift)

### Timer Usage Example

The following example shows how a timer can be used to detect timeouts in an interrupt handler:

```c
#include "sys/timer.h"
#include "sys/log.h"

#define LOG_MODULE "UART"
#define LOG_LEVEL LOG_LEVEL_DBG

static struct timer rxtimer;

void
init(void)
{
  /* Set timeout to 500ms */
  timer_set(&rxtimer, CLOCK_SECOND / 2);
}

/* Example interrupt handler */
interrupt(UART1RX_VECTOR)
uart1_rx_interrupt(void)
{
  if(timer_expired(&rxtimer)) {
    /* Timeout occurred - no data received for 500ms */
    LOG_DBG("RX timeout\n");
  }

  /* Restart timer from current time */
  timer_restart(&rxtimer);

  /* Process received data */
  process_received_byte();
}
```

**Best Practice:** For periodic operations without drift, use `timer_reset()`. For simple timeout detection where slight drift is acceptable, use `timer_restart()`.

## The Stimer Library

The stimer library provides a timer mechanism similar to the timer library but uses time values in seconds, allowing much longer expiration times. This is particularly useful for long timeouts (minutes, hours, or days) where using clock ticks would be cumbersome or cause frequent wrapping.

The stimer library uses `clock_seconds()` to get the current system time in seconds.

### Stimer API

| Function | Purpose |
|----------|---------|
|`void stimer_set(struct stimer *t, unsigned long interval)` | Start the timer. |
|`void stimer_reset(struct stimer *t)` | Restart the stimer from the previous expire time. |
|`void stimer_restart(struct stimer *t)` | Restart the stimer from current time. |
|`bool stimer_expired(struct stimer *t)` | Check if the stimer has expired. |
|`unsigned long stimer_remaining(struct stimer *t)` | Get the time until the timer expires. |

The stimer library API is identical to the timer library, but uses seconds instead of clock ticks. Like `timer`, stimer is interrupt-safe.

### Stimer Usage Example

```c
#include "sys/stimer.h"

static struct stimer connection_timer;

void
start_connection_timeout(void)
{
  /* Set timeout to 5 minutes */
  stimer_set(&connection_timer, 5 * 60);
}

void
check_connection_status(void)
{
  if(stimer_expired(&connection_timer)) {
    /* 5 minutes have passed without activity */
    close_connection();
  }
}
```

**When to use stimer:** Use stimer instead of timer when your timeout is measured in multiple seconds or longer. This avoids arithmetic with large tick values and reduces wrapping issues.

## The Etimer Library

The etimer (event timer) library provides a timer mechanism that generates timed events. An event timer will post the event `PROCESS_EVENT_TIMER` to the process that set the timer when the event timer expires.

An event timer is declared as a `struct etimer` and all access to the event timer is made by a pointer to the declared event timer.

### Etimer API

| Function | Purpose |
|----------|---------|
|`void etimer_set(struct etimer *t, clock_time_t interval)` | Start the timer. |
|`void etimer_reset(struct etimer *t)` | Restart the timer from the previous expire time. |
|`void etimer_reset_with_new_interval(struct etimer *t, clock_time_t interval)` | Reset with a new interval (no drift). |
|`void etimer_restart(struct etimer *t)` | Restart the timer from current time. |
|`void etimer_adjust(struct etimer *t, int td)` | Adjust expiration time by time difference. |
|`void etimer_stop(struct etimer *t)` | Stop the timer. |
|`bool etimer_expired(struct etimer *t)` | Check if the timer has expired. |
|`clock_time_t etimer_expiration_time(struct etimer *t)` | Get the expiration time. |
|`clock_time_t etimer_start_time(struct etimer *t)` | Get the start time. |
|`int etimer_pending()` | Check if there are any non-expired event timers. |
|`clock_time_t etimer_next_expiration_time()` | Get the next event timer expiration time. |
|`void etimer_request_poll()` | Inform the etimer library that the system clock has changed. |

### Etimer Behavior

**Process Context:** The timer event is sent to the Contiki-NG process that set the event timer. If an event timer should be scheduled from a callback function or another process, use `PROCESS_CONTEXT_BEGIN()` and `PROCESS_CONTEXT_END()` to temporarily change the process context.

**Reset vs Restart:**
- `etimer_reset()` maintains the original interval and restarts from the last expiration time (prevents drift)
- `etimer_restart()` restarts from the current time (simpler but accumulates drift)
- `etimer_reset_with_new_interval()` allows changing the interval while maintaining drift-free operation

**Adjust:** `etimer_adjust()` allows fine-tuning the expiration time without changing the interval. This is useful for synchronizing timers. Only use for small adjustments; for large changes use `etimer_set()`.

### Etimer Usage Example

The following example shows how an etimer can be used to schedule a process to run once per second:

```c
#include "contiki.h"
#include "sys/etimer.h"
#include "sys/log.h"

#define LOG_MODULE "Periodic"
#define LOG_LEVEL LOG_LEVEL_INFO

PROCESS(example_process, "Periodic example");
AUTOSTART_PROCESSES(&example_process);

PROCESS_THREAD(example_process, ev, data)
{
  static struct etimer et;
  static int count = 0;

  PROCESS_BEGIN();

  /* Set timer for 1 second */
  etimer_set(&et, CLOCK_SECOND);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

    /* Timer expired - do periodic work */
    count++;
    LOG_INFO("Periodic tick %d\n", count);

    /* Reset timer to trigger again in 1 second (no drift) */
    etimer_reset(&et);
  }

  PROCESS_END();
}
```

### Etimer Advanced Example - Variable Intervals

```c
PROCESS_THREAD(adaptive_process, ev, data)
{
  static struct etimer et;
  static int fast_mode = 1;

  PROCESS_BEGIN();

  etimer_set(&et, CLOCK_SECOND);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

    /* Do work */
    do_sensor_reading();

    /* Adapt interval based on conditions */
    if(needs_fast_sampling()) {
      fast_mode = 1;
      etimer_reset_with_new_interval(&et, CLOCK_SECOND / 4);
    } else {
      if(fast_mode) {
        fast_mode = 0;
        etimer_reset_with_new_interval(&et, CLOCK_SECOND * 5);
      } else {
        etimer_reset(&et);
      }
    }
  }

  PROCESS_END();
}
```

**Warning:** Etimers are NOT interrupt-safe. Never call etimer functions from interrupt handlers. Use `process_poll()` from the interrupt and handle timer operations in the process context.

## The Ctimer Library

The ctimer (callback timer) library provides a timer mechanism that calls a specified function when the timer expires. Unlike etimers which send events to processes, ctimers directly invoke a callback function.

### Ctimer API

| Function | Purpose |
|----------|---------|
|`void ctimer_set(struct ctimer *t, clock_time_t interval, void (*callback)(void *), void *ptr)` | Start the timer. |
|`void ctimer_set_with_process(struct ctimer *t, clock_time_t interval, void (*callback)(void *), void *ptr, struct process *p)` | Start timer with explicit process context. |
|`void ctimer_reset(struct ctimer *t)` | Restart the timer from the previous expire time. |
|`void ctimer_reset_with_new_interval(struct ctimer *t, clock_time_t interval)` | Reset with a new interval. |
|`void ctimer_restart(struct ctimer *t)` | Restart the timer from current time. |
|`void ctimer_stop(struct ctimer *t)` | Stop the timer. |
|`bool ctimer_expired(struct ctimer *t)` | Check if the timer has expired. |
|`clock_time_t ctimer_expiration_time(struct ctimer *t)` | Get the expiration time. |
|`clock_time_t ctimer_start_time(struct ctimer *t)` | Get the start time. |

### Ctimer Behavior

**Process Context:** Although ctimers call a callback function, the process context for the callback is set to the process that scheduled the ctimer. Do not assume any specific process context in the callback unless you are certain about how the ctimer was scheduled. Use `ctimer_set_with_process()` to explicitly specify the process context if needed.

**Callback Signature:** The callback function has the signature `void callback(void *ptr)` where `ptr` is the opaque pointer passed to `ctimer_set()`.

### Ctimer Usage Example

The following example shows how a ctimer can be used to schedule a callback function once per second:

```c
#include "contiki.h"
#include "sys/ctimer.h"
#include "sys/log.h"

#define LOG_MODULE "Callback"
#define LOG_LEVEL LOG_LEVEL_INFO

static struct ctimer timer;
static int counter = 0;

static void
timer_callback(void *ptr)
{
  counter++;
  LOG_INFO("Callback executed: %d\n", counter);

  /* Reschedule for next second (periodic) */
  ctimer_reset(&timer);
}

void
init(void)
{
  /* Initialize counter */
  counter = 0;

  /* Set callback timer for 1 second */
  ctimer_set(&timer, CLOCK_SECOND, timer_callback, NULL);
}
```

### Ctimer Advanced Example - Timeout Handler

```c
#include "sys/ctimer.h"

static struct ctimer timeout_timer;
static int connection_active = 0;

static void
timeout_callback(void *ptr)
{
  if(connection_active) {
    /* Connection timed out */
    close_connection();
    connection_active = 0;
  }
}

void
start_connection(void)
{
  connection_active = 1;
  /* Set 30 second timeout */
  ctimer_set(&timeout_timer, 30 * CLOCK_SECOND, timeout_callback, NULL);
}

void
activity_detected(void)
{
  if(connection_active) {
    /* Reset timeout on activity */
    ctimer_restart(&timeout_timer);
  }
}

void
close_connection(void)
{
  if(connection_active) {
    ctimer_stop(&timeout_timer);
    connection_active = 0;
    /* ... connection cleanup ... */
  }
}
```

**Warning:** Ctimers are NOT interrupt-safe. Never call ctimer functions from interrupt handlers.

## The Rtimer Library

The rtimer (real-time timer) library provides scheduling and execution of real-time tasks with high temporal precision. The rtimer library uses its own high-resolution clock for scheduling.

**WARNING: Contiki-NG currently supports only one active rtimer at a time.** If you use system functionality that has its own rtimer (for example, the TSCH MAC stack), you will not be able to use rtimers at the application level. Attempting to schedule multiple rtimers will lead to undefined behavior.

### Rtimer API

| Function | Purpose |
|----------|---------|
|`int rtimer_set(struct rtimer *task, rtimer_clock_t time, rtimer_clock_t duration, rtimer_callback_t func, void *ptr)` | Schedule a real-time task. |
|`void rtimer_init(void)` | Initialize the rtimer library. |
|`void rtimer_run_next(void)` | Called by the rtimer scheduler to run next real-time task. |
|`rtimer_clock_t rtimer_arch_now(void)` | Get current time in rtimer ticks. |
|`void rtimer_arch_schedule(rtimer_clock_t t)` | Architecture-specific scheduling function. |
|`RTIMER_NOW()` | Get the current time. |
|`RTIMER_TIME(task)` | Get the time when the task was last executed. |
|`RTIMER_CLOCK_LT(t0, t1)` | Check if time `t0` is less than time `t1`. |
|`RTIMER_SECOND` | The number of rtimer ticks per second. |
|`RTIMER_GUARD_TIME` | Minimum ticks between now and scheduled time. |
|`RTIMER_BUSYWAIT(duration)` | Busy-wait for a fixed duration. |
|`RTIMER_BUSYWAIT_UNTIL(cond, max_time)` | Busy-wait until condition or timeout. |
|`RTIMER_BUSYWAIT_UNTIL_ABS(cond, t0, max_time)` | Busy-wait with absolute reference time. |

### Rtimer Characteristics

**High Resolution:** Rtimers typically operate at much higher resolution than the system clock. While `CLOCK_SECOND` might be 128 Hz, `RTIMER_SECOND` is often 32768 Hz or higher (30.5 μs per tick at 32768 Hz).

**Preemptive Execution:** Unlike other timer libraries, rtimer callbacks execute from interrupt context and preempt normal execution. This provides precise timing but imposes strict constraints on what can be done in rtimer callbacks.

**Interrupt Safety Requirements:** Most Contiki-NG functions do not handle preemption. Only use interrupt-safe functions in rtimer callbacks:
- **Safe:** `process_poll()`, `NETSTACK_RADIO` functions, basic hardware access
- **Unsafe:** Memory allocation, etimer/ctimer operations, printf, most library functions

**Guard Time:** `RTIMER_GUARD_TIME` defines the minimum number of ticks between the current time and when a task can be scheduled. Attempting to schedule too close to the current time will fail. This is typically 2-4 ticks.

### Rtimer Return Values

`rtimer_set()` returns:
- `RTIMER_OK` - Task scheduled successfully
- `RTIMER_ERR_FULL` - No space for additional tasks
- `RTIMER_ERR_TIME` - Scheduled time is in the past or too soon
- `RTIMER_ERR_ALREADY_SCHEDULED` - Task already scheduled

### Rtimer Usage Example

The following example shows how to schedule a real-time task that executes four times per second:

```c
#include "sys/rtimer.h"
#include "sys/log.h"

#define LOG_MODULE "Rtimer"
#define LOG_LEVEL LOG_LEVEL_INFO

static struct rtimer task;
static int callback_count = 0;

static void
rt_callback(struct rtimer *t, void *ptr)
{
  callback_count++;

  /* Reschedule for 250ms from the last execution time */
  rtimer_clock_t next_time = RTIMER_TIME(t) + (RTIMER_SECOND / 4);

  if(rtimer_set(t, next_time, 0, rt_callback, NULL) != RTIMER_OK) {
    /* Failed to reschedule - might be too late */
    LOG_ERR("Failed to reschedule rtimer\n");
    /* Try scheduling from current time + guard time */
    rtimer_set(t, RTIMER_NOW() + RTIMER_GUARD_TIME + 1,
               0, rt_callback, NULL);
  }

  /* Only interrupt-safe operations allowed here */
  process_poll(&my_process);
}

void
start_rtimer_task(void)
{
  rtimer_clock_t start_time;

  callback_count = 0;

  /* Schedule first execution 250ms from now */
  start_time = RTIMER_NOW() + (RTIMER_SECOND / 4);

  if(rtimer_set(&task, start_time, 0, rt_callback, NULL) != RTIMER_OK) {
    LOG_ERR("Failed to schedule rtimer\n");
  } else {
    LOG_INFO("Rtimer scheduled at time %" RTIMER_PRI "\n", start_time);
  }
}
```

### Rtimer Busy-Wait Example

Rtimer provides macros for precise busy-waiting, useful in time-critical code:

```c
#include "sys/rtimer.h"

void
precise_radio_timing(void)
{
  rtimer_clock_t t0;

  /* Turn on radio */
  NETSTACK_RADIO.on();

  /* Wait exactly 100 rtimer ticks (e.g., ~3ms at 32768 Hz) */
  RTIMER_BUSYWAIT(100);

  /* Wait until radio is ready or timeout after 1000 ticks */
  t0 = RTIMER_NOW();
  if(!RTIMER_BUSYWAIT_UNTIL_ABS(radio_ready(), t0, 1000)) {
    /* Timeout occurred */
    return;
  }

  /* Radio is ready, transmit */
  NETSTACK_RADIO.transmit();
}
```

### Rtimer Best Practices

1. **Check return values:** Always check if `rtimer_set()` returns `RTIMER_OK`
2. **Respect guard time:** Don't schedule too close to current time
3. **Use `RTIMER_TIME()` for periodic tasks:** Schedule relative to last execution, not current time
4. **Keep callbacks short:** Rtimer callbacks run in interrupt context and block all other processing
5. **Only use interrupt-safe functions:** No memory allocation, no logging (except in development), no blocking
6. **Have a fallback strategy:** If rescheduling fails, decide whether to retry or abort
7. **Be aware of the one-rtimer limitation:** Check if your platform/MAC layer already uses rtimers
8. **Test thoroughly:** Timing bugs can be subtle and platform-dependent

## Timer Comparison and Selection

### Feature Comparison

| Feature | clock | timer | stimer | etimer | ctimer | rtimer |
|---------|-------|-------|--------|--------|--------|--------|
| **Resolution** | Platform (1-10ms) | Same as clock | 1 second | Same as clock | Same as clock | High (μs) |
| **Max Duration** | Wraps (~days) | Wraps (~days) | Years | Wraps (~days) | Wraps (~days) | Wraps (hours) |
| **Interrupt Safe** | ✓ | ✓ | ✓ | ✗ | ✗ | ✓ |
| **Auto Notification** | ✗ | ✗ | ✗ | ✓ (event) | ✓ (callback) | ✓ (ISR callback) |
| **Allows Sleep** | N/A | N/A | N/A | ✓ | ✓ | ✗ (preemptive) |
| **Overhead** | Minimal | Minimal | Minimal | Low | Low | Low |
| **Precision** | Low | Low | Very Low | Low | Low | Very High |

### Common Use Cases

**Periodic Application Tasks (>100ms)**
```c
/* Use etimer */
PROCESS_THREAD(sensor_process, ev, data) {
  static struct etimer et;
  PROCESS_BEGIN();
  etimer_set(&et, 10 * CLOCK_SECOND);
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    read_sensor();
    etimer_reset(&et);
  }
  PROCESS_END();
}
```

**Timeout Detection in Interrupts**
```c
/* Use timer */
static struct timer rx_timeout;
interrupt() {
  if(timer_expired(&rx_timeout)) {
    handle_timeout();
  }
  timer_restart(&rx_timeout);
}
```

**Long Duration Timeouts (hours/days)**
```c
/* Use stimer */
static struct stimer session_timer;
stimer_set(&session_timer, 24 * 60 * 60); /* 24 hours */
if(stimer_expired(&session_timer)) {
  end_session();
}
```

**Non-Process Callback Functions**
```c
/* Use ctimer */
static struct ctimer blink_timer;
static void blink(void *ptr) {
  leds_toggle(LEDS_RED);
  ctimer_reset(&blink_timer);
}
ctimer_set(&blink_timer, CLOCK_SECOND / 2, blink, NULL);
```

**Real-Time MAC Protocol Timing**
```c
/* Use rtimer */
static struct rtimer slot_timer;
static void slot_operation(struct rtimer *t, void *ptr) {
  radio_transmit_in_slot();
  rtimer_set(t, RTIMER_TIME(t) + SLOT_DURATION, 0, slot_operation, NULL);
}
```

## Common Pitfalls and Solutions

### Pitfall 1: Using etimer/ctimer from Interrupts

**Wrong:**
```c
interrupt() {
  etimer_set(&my_timer, CLOCK_SECOND); /* CRASH! */
}
```

**Correct:**
```c
interrupt() {
  process_poll(&my_process); /* Safe from interrupt */
}

PROCESS_THREAD(my_process, ev, data) {
  PROCESS_BEGIN();
  while(1) {
    PROCESS_WAIT_EVENT();
    etimer_set(&my_timer, CLOCK_SECOND); /* Safe in process */
  }
  PROCESS_END();
}
```

### Pitfall 2: Ignoring Timer Wrapping

**Wrong:**
```c
clock_time_t start = clock_time();
clock_time_t timeout = start + TIMEOUT;
if(clock_time() > timeout) { /* Breaks when wrapping occurs */ }
```

**Correct:**
```c
clock_time_t start = clock_time();
clock_time_t timeout = start + TIMEOUT;
if(CLOCK_LT(timeout, clock_time())) { /* Handles wrapping */ }
```

### Pitfall 3: Periodic Drift with restart()

**Wrong (accumulates drift):**
```c
while(1) {
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
  do_work();
  etimer_restart(&et); /* Drifts due to processing time */
}
```

**Correct (no drift):**
```c
while(1) {
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
  do_work();
  etimer_reset(&et); /* Maintains original interval */
}
```

### Pitfall 4: Scheduling rtimer Too Close to Now

**Wrong:**
```c
rtimer_set(&task, RTIMER_NOW() + 1, 0, callback, NULL); /* May fail */
```

**Correct:**
```c
rtimer_clock_t safe_time = RTIMER_NOW() + RTIMER_GUARD_TIME + 1;
if(rtimer_set(&task, safe_time, 0, callback, NULL) != RTIMER_OK) {
  /* Handle error */
}
```

### Pitfall 5: Using Multiple rtimers

**Wrong:**
```c
rtimer_set(&task1, time1, 0, callback1, NULL);
rtimer_set(&task2, time2, 0, callback2, NULL); /* Only one active! */
```

**Correct:** Only use one rtimer at a time, or manage scheduling manually within a single rtimer callback.

## Platform-Specific Considerations

### Clock Resolution

Different platforms have different clock resolutions:
- **Native platform:** `CLOCK_SECOND` = 1000 (1ms ticks)
- **CC2538/CC26xx:** `CLOCK_SECOND` = 128 (7.8ms ticks)
- **nRF52840:** `CLOCK_SECOND` = 128 (7.8ms ticks)

Always use `CLOCK_SECOND` in calculations rather than hardcoding values.

### Rtimer Resolution

Rtimer resolution varies significantly:
- **CC2538:** `RTIMER_SECOND` = 32768 (30.5μs ticks)
- **CC26xx:** `RTIMER_SECOND` = 65536 (15.3μs ticks)
- **nRF52840:** `RTIMER_SECOND` = 62500 (16μs ticks)

Use the conversion macros provided by rtimer-arch.h:
- `US_TO_RTIMERTICKS(us)` - Convert microseconds to rtimer ticks
- `RTIMERTICKS_TO_US(t)` - Convert rtimer ticks to microseconds
- `RTIMERTICKS_TO_US_64(t)` - 64-bit version for long durations

### Low Power Mode Behavior

- **timer/stimer/etimer/ctimer:** System can sleep, wakes on timer expiration
- **rtimer:** May prevent deep sleep on some platforms (depends on rtimer implementation)
- **clock_wait/RTIMER_BUSYWAIT:** Busy-wait, blocks sleep, wastes power

For power-efficient applications, prefer etimer over busy-waiting.

## Summary

Contiki-NG's timer libraries provide flexible timing mechanisms for different use cases:

- **For application logic:** Use `etimer` (process-based) or `ctimer` (callback-based)
- **For interrupt handlers:** Use `timer` or `stimer`
- **For long timeouts:** Use `stimer` (seconds)
- **For real-time tasks:** Use `rtimer` (but be aware of the one-active-timer limitation)
- **For delays:** Use `etimer` for delays >10ms, `clock_wait()` for short delays, `RTIMER_BUSYWAIT()` for precise μs delays

Always choose the simplest timer that meets your requirements. Use interrupt-safe timers only when necessary, as they require manual polling. Prefer etimers for most application code as they integrate well with the Contiki-NG process model and power management.
