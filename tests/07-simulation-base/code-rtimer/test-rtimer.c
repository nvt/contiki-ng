/*
 * Multi-RTimer Test Application for Cooja Simulation
 * Tests the new multi-rtimer implementation with concurrent timers
 */

#include "contiki.h"
#include "sys/rtimer.h"
#include "sys/log.h"
#include <stdio.h>
#include <stdint.h>

#define LOG_MODULE "RTimerTest"
#define LOG_LEVEL LOG_LEVEL_INFO

static struct rtimer timer1, timer2, timer3, timer4, timer5;
static volatile int test_phase = 0;
static volatile int callback_count = 0;
static volatile int error_count = 0;

static void
test_callback_1(struct rtimer *t, void *ptr)
{
  callback_count++;
  printf("RTIMER: Timer 1 fired at %lu (count=%d, active=%d)\n", 
         (unsigned long)RTIMER_NOW(), callback_count, rtimer_active_count());
}

static void
test_callback_2(struct rtimer *t, void *ptr)
{
  callback_count++;
  printf("RTIMER: Timer 2 fired at %lu (count=%d, active=%d)\n", 
         (unsigned long)RTIMER_NOW(), callback_count, rtimer_active_count());
}

static void
test_callback_3(struct rtimer *t, void *ptr)
{
  callback_count++;
  printf("RTIMER: Timer 3 fired at %lu (count=%d, active=%d)\n", 
         (unsigned long)RTIMER_NOW(), callback_count, rtimer_active_count());
}

static void
stress_callback(struct rtimer *t, void *ptr)
{
  int timer_id = (int)(uintptr_t)ptr;
  callback_count++;
  
  printf("RTIMER: Stress timer %d fired (count=%d, active=%d)\n", 
         timer_id, callback_count, rtimer_active_count());
  
  if(timer_id == 4 && callback_count < 15) {
    rtimer_set(t, RTIMER_NOW() + RTIMER_SECOND/8, 0, stress_callback, ptr);
  }
}

static void
cancellation_callback(struct rtimer *t, void *ptr)
{
  error_count++;
  printf("RTIMER: ERROR - Cancelled timer fired! This should not happen.\n");
}

PROCESS(rtimer_test_process, "Multi-RTimer Test Process");
AUTOSTART_PROCESSES(&rtimer_test_process);

PROCESS_THREAD(rtimer_test_process, ev, data)
{
  static struct etimer et;
  static struct rtimer capacity_timers[RTIMER_MAX_TIMERS + 2];
  rtimer_clock_t now;
  int result;
  int successful_sets = 0;
  int failed_sets = 0;
  
  PROCESS_BEGIN();
  
  printf("RTIMER-TEST: Starting multi-rtimer test\n");
  printf("RTIMER-TEST: RTIMER_MAX_TIMERS=%d\n", RTIMER_MAX_TIMERS);
  
  etimer_set(&et, CLOCK_SECOND);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
  
  test_phase = 1;
  printf("RTIMER-TEST: Phase 1 - Basic concurrent timer test\n");
  
  now = RTIMER_NOW();
  result = rtimer_set(&timer1, now + RTIMER_SECOND/4, 0, test_callback_1, NULL);
  printf("RTIMER-TEST: Set timer 1, result=%d\n", result);
  
  result = rtimer_set(&timer2, now + RTIMER_SECOND/2, 0, test_callback_2, NULL);
  printf("RTIMER-TEST: Set timer 2, result=%d\n", result);
  
  result = rtimer_set(&timer3, now + RTIMER_SECOND/8, 0, test_callback_3, NULL);
  printf("RTIMER-TEST: Set timer 3, result=%d\n", result);
  
  printf("RTIMER-TEST: Active timers=%d\n", rtimer_active_count());
  
  etimer_set(&et, CLOCK_SECOND);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
  
  test_phase = 2;
  printf("RTIMER-TEST: Phase 2 - Timer cancellation test\n");
  
  now = RTIMER_NOW();
  result = rtimer_set(&timer4, now + RTIMER_SECOND * 2, 0, cancellation_callback, NULL);
  printf("RTIMER-TEST: Set cancellation test timer, result=%d\n", result);
  printf("RTIMER-TEST: Active timers before cancel=%d\n", rtimer_active_count());
  
  etimer_set(&et, CLOCK_SECOND/4);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
  
  result = rtimer_cancel(&timer4);
  printf("RTIMER-TEST: Cancel timer result=%d\n", result);
  printf("RTIMER-TEST: Active timers after cancel=%d\n", rtimer_active_count());
  
  etimer_set(&et, CLOCK_SECOND);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
  
  test_phase = 3;
  printf("RTIMER-TEST: Phase 3 - Stress test with recurring timer\n");
  
  now = RTIMER_NOW();
  result = rtimer_set(&timer4, now + RTIMER_SECOND/16, 0, stress_callback, (void*)(uintptr_t)4);
  printf("RTIMER-TEST: Set stress timer, result=%d\n", result);
  
  result = rtimer_set(&timer5, now + RTIMER_SECOND/8, 0, stress_callback, (void*)(uintptr_t)5);
  printf("RTIMER-TEST: Set second stress timer, result=%d\n", result);
  
  etimer_set(&et, CLOCK_SECOND * 3);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
  
  test_phase = 4;
  printf("RTIMER-TEST: Phase 4 - Maximum capacity test\n");
  
  now = RTIMER_NOW();
  for(int i = 0; i < RTIMER_MAX_TIMERS + 2; i++) {
    result = rtimer_set(&capacity_timers[i], now + RTIMER_SECOND * 10, 
                       0, test_callback_1, NULL);
    if(result == 0) {
      successful_sets++;
    } else {
      failed_sets++;
    }
  }
  
  printf("RTIMER-TEST: Capacity test - successful=%d, failed=%d\n",
         successful_sets, failed_sets);
  printf("RTIMER-TEST: Active timers=%d\n", rtimer_active_count());

  /* Validate capacity before cancelling */
  int active_timers = rtimer_active_count();
  printf("RTIMER-TEST: - Active timers should be %d: %s\n", RTIMER_MAX_TIMERS,
         active_timers == RTIMER_MAX_TIMERS ? "PASS" : "FAIL");

  /* Cancel all capacity test timers to clean up the queue */
  for(int i = 0; i < RTIMER_MAX_TIMERS + 2; i++) {
    rtimer_cancel(&capacity_timers[i]);
  }
  printf("RTIMER-TEST: Active timers after cleanup=%d\n", rtimer_active_count());

  etimer_set(&et, CLOCK_SECOND);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

  printf("RTIMER-TEST: Final results\n");
  printf("RTIMER-TEST: Total callbacks=%d\n", callback_count);
  printf("RTIMER-TEST: Errors=%d\n", error_count);
  printf("RTIMER-TEST: Successful timer sets=%d\n", successful_sets);
  printf("RTIMER-TEST: Failed timer sets=%d\n", failed_sets);

  printf("RTIMER-TEST: Test criteria:\n");
  printf("RTIMER-TEST: - Errors should be 0: %s\n", error_count == 0 ? "PASS" : "FAIL");
  printf("RTIMER-TEST: - Callbacks should be >= 10: %s\n", callback_count >= 10 ? "PASS" : "FAIL");

  /* Basic test criteria: no errors, sufficient callbacks, proper queue management */
  if(error_count == 0 && callback_count >= 10 && active_timers == RTIMER_MAX_TIMERS) {
    printf("RTIMER-TEST: SUCCESS - All tests passed\n");
  } else {
    printf("RTIMER-TEST: FAILURE - Some tests failed\n");
  }

  printf("RTIMER-TEST: Test completed\n");

  PROCESS_END();
}
