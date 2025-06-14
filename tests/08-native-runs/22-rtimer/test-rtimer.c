/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "contiki.h"
#include "unit-test.h"
#include "sys/rtimer.h"
#include <stdio.h>
#include <stdint.h>

#define TEST_MAX_TIMERS RTIMER_MAX_TIMERS

static volatile int callback_order[TEST_MAX_TIMERS];
static volatile int callback_index;

PROCESS(test_process, "rtimer-test");
AUTOSTART_PROCESSES(&test_process);

/*---------------------------------------------------------------------------*/
static void
ordered_callback(struct rtimer *t, void *ptr)
{
  int id = (int)(uintptr_t)ptr;
  if(callback_index < TEST_MAX_TIMERS) {
    callback_order[callback_index++] = id;
  }
}
/*---------------------------------------------------------------------------*/
static void
cancelled_callback(struct rtimer *t, void *ptr)
{
  /* This should never execute */
  callback_order[0] = -1;
}
/*---------------------------------------------------------------------------*/
UNIT_TEST_REGISTER(test_concurrent_set, "concurrent rtimer_set");
UNIT_TEST(test_concurrent_set)
{
  struct rtimer timers[3];
  int r;

  UNIT_TEST_BEGIN();

  callback_index = 0;

  /* Schedule 3 timers: timer 0 at +3s, timer 1 at +1s, timer 2 at +2s */
  r = rtimer_set(&timers[0], RTIMER_NOW() + RTIMER_SECOND * 3, 0,
                 ordered_callback, (void *)(uintptr_t)0);
  UNIT_TEST_ASSERT(r == RTIMER_OK);

  r = rtimer_set(&timers[1], RTIMER_NOW() + RTIMER_SECOND, 0,
                 ordered_callback, (void *)(uintptr_t)1);
  UNIT_TEST_ASSERT(r == RTIMER_OK);

  r = rtimer_set(&timers[2], RTIMER_NOW() + RTIMER_SECOND * 2, 0,
                 ordered_callback, (void *)(uintptr_t)2);
  UNIT_TEST_ASSERT(r == RTIMER_OK);

  UNIT_TEST_ASSERT(rtimer_active_count() == 3);

  /* Clean up */
  rtimer_cancel(&timers[0]);
  rtimer_cancel(&timers[1]);
  rtimer_cancel(&timers[2]);

  UNIT_TEST_END();
}
/*---------------------------------------------------------------------------*/
UNIT_TEST_REGISTER(test_cancel, "rtimer_cancel");
UNIT_TEST(test_cancel)
{
  struct rtimer t;
  int r;

  UNIT_TEST_BEGIN();

  r = rtimer_set(&t, RTIMER_NOW() + RTIMER_SECOND * 10, 0,
                 cancelled_callback, NULL);
  UNIT_TEST_ASSERT(r == RTIMER_OK);
  UNIT_TEST_ASSERT(rtimer_active_count() >= 1);

  r = rtimer_cancel(&t);
  UNIT_TEST_ASSERT(r == RTIMER_OK);

  /* Cancel again should fail */
  r = rtimer_cancel(&t);
  UNIT_TEST_ASSERT(r == RTIMER_ERR_TIME);

  UNIT_TEST_END();
}
/*---------------------------------------------------------------------------*/
UNIT_TEST_REGISTER(test_capacity, "rtimer queue capacity");
UNIT_TEST(test_capacity)
{
  struct rtimer timers[TEST_MAX_TIMERS + 2];
  int r;
  int successful = 0;
  int failed = 0;

  UNIT_TEST_BEGIN();

  /* Fill the queue */
  for(int i = 0; i < TEST_MAX_TIMERS + 2; i++) {
    r = rtimer_set(&timers[i], RTIMER_NOW() + RTIMER_SECOND * 20, 0,
                   ordered_callback, (void *)(uintptr_t)i);
    if(r == RTIMER_OK) {
      successful++;
    } else {
      failed++;
    }
  }

  UNIT_TEST_ASSERT(successful == TEST_MAX_TIMERS);
  UNIT_TEST_ASSERT(failed == 2);
  UNIT_TEST_ASSERT(rtimer_active_count() == TEST_MAX_TIMERS);

  /* Clean up */
  for(int i = 0; i < TEST_MAX_TIMERS + 2; i++) {
    rtimer_cancel(&timers[i]);
  }

  UNIT_TEST_ASSERT(rtimer_active_count() == 0);

  UNIT_TEST_END();
}
/*---------------------------------------------------------------------------*/
UNIT_TEST_REGISTER(test_reschedule, "rtimer reschedule active timer");
UNIT_TEST(test_reschedule)
{
  struct rtimer t;
  int r;

  UNIT_TEST_BEGIN();

  r = rtimer_set(&t, RTIMER_NOW() + RTIMER_SECOND * 10, 0,
                 ordered_callback, NULL);
  UNIT_TEST_ASSERT(r == RTIMER_OK);

  /* Reschedule the same timer to a different time */
  r = rtimer_set(&t, RTIMER_NOW() + RTIMER_SECOND * 5, 0,
                 ordered_callback, NULL);
  UNIT_TEST_ASSERT(r == RTIMER_OK);

  /* Should still be just 1 active timer, not 2 */
  UNIT_TEST_ASSERT(rtimer_active_count() == 1);

  rtimer_cancel(&t);

  UNIT_TEST_END();
}
/*---------------------------------------------------------------------------*/
UNIT_TEST_REGISTER(test_empty_cancel, "cancel on empty queue");
UNIT_TEST(test_empty_cancel)
{
  struct rtimer t = { .active = 0 };
  int r;

  UNIT_TEST_BEGIN();

  r = rtimer_cancel(&t);
  UNIT_TEST_ASSERT(r == RTIMER_ERR_TIME);
  UNIT_TEST_ASSERT(rtimer_active_count() == 0);

  UNIT_TEST_END();
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(test_process, ev, data)
{
  PROCESS_BEGIN();

  printf("Run unit-test\n");
  printf("---\n");

  UNIT_TEST_RUN(test_concurrent_set);
  UNIT_TEST_RUN(test_cancel);
  UNIT_TEST_RUN(test_capacity);
  UNIT_TEST_RUN(test_reschedule);
  UNIT_TEST_RUN(test_empty_cancel);

  if(!UNIT_TEST_PASSED(test_concurrent_set)
     || !UNIT_TEST_PASSED(test_cancel)
     || !UNIT_TEST_PASSED(test_capacity)
     || !UNIT_TEST_PASSED(test_reschedule)
     || !UNIT_TEST_PASSED(test_empty_cancel)) {
    printf("=check-me= FAILED\n");
    printf("---\n");
  }

  printf("=check-me= DONE\n");
  printf("---\n");

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
