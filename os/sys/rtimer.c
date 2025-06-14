/*
 * Copyright (c) 2005, Swedish Institute of Computer Science
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
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *         Implementation of the architecture-agnostic parts of the real-time timer module.
 * \author
 *         Adam Dunkels <adam@sics.se>
 *
 */

/**
 * \addtogroup rt
 * @{
 */

#include "sys/rtimer.h"
#include "contiki.h"
#include "sys/critical.h"

#include "sys/log.h"
#define LOG_MODULE "RTimer"
#define LOG_LEVEL LOG_LEVEL_NONE

struct rtimer_queue {
  struct rtimer *timers[RTIMER_MAX_TIMERS];
  uint8_t count;
};

static struct rtimer_queue rtimer_queue = { .count = 0 };
static volatile bool rtimer_running;

/*---------------------------------------------------------------------------*/
/*
 * Insert a timer into the sorted queue. The sort uses RTIMER_CLOCK_LT,
 * which relies on signed difference for wraparound-safe comparison.
 * This provides a correct total order only when all timers in the queue
 * are within half the clock range of each other — which holds in practice
 * since timers are scheduled at most seconds into the future on a clock
 * that wraps in minutes to hours.
 */
static void
rtimer_queue_insert(struct rtimer *rtimer)
{
  uint8_t i, j;

  for(i = 0; i < rtimer_queue.count; i++) {
    if(RTIMER_CLOCK_LT(rtimer->time, rtimer_queue.timers[i]->time)) {
      break;
    }
  }
  
  for(j = rtimer_queue.count; j > i; j--) {
    rtimer_queue.timers[j] = rtimer_queue.timers[j-1];
  }
  
  rtimer_queue.timers[i] = rtimer;
  rtimer_queue.count++;
}

static void
rtimer_queue_remove(struct rtimer *rtimer)
{
  uint8_t i, j;
  
  for(i = 0; i < rtimer_queue.count; i++) {
    if(rtimer_queue.timers[i] == rtimer) {
      for(j = i; j < rtimer_queue.count - 1; j++) {
        rtimer_queue.timers[j] = rtimer_queue.timers[j+1];
      }
      rtimer_queue.count--;
      rtimer->active = 0;
      break;
    }
  }
}

static struct rtimer *
rtimer_queue_next(void)
{
  return (rtimer_queue.count > 0) ? rtimer_queue.timers[0] : NULL;
}

int
rtimer_set(struct rtimer *rtimer, rtimer_clock_t time,
	   rtimer_clock_t duration,
	   rtimer_callback_t func, void *ptr)
{
  int_master_status_t status;
  struct rtimer *next;

  LOG_DBG("rtimer_set time %" RTIMER_PRI "\n", time);

  status = critical_enter();

  if(rtimer->active) {
    rtimer_queue_remove(rtimer);
  }

  if(rtimer_queue.count >= RTIMER_MAX_TIMERS) {
    critical_exit(status);
    return RTIMER_ERR_FULL;
  }

  rtimer->func = func;
  rtimer->ptr = ptr;
  rtimer->time = time;
  rtimer->active = 1;

  rtimer_queue_insert(rtimer);

  next = rtimer_queue_next();
  if(next) {
    rtimer_arch_schedule(next->time);
  }

  critical_exit(status);

  return RTIMER_OK;
}
/*---------------------------------------------------------------------------*/
void
rtimer_run_next(void)
{
  struct rtimer *t;
  rtimer_clock_t now;
  int_master_status_t status;

  status = critical_enter();

  /* Guard against re-entrancy (e.g., SIGALRM on native, nested IRQ). */
  if(rtimer_running) {
    critical_exit(status);
    return;
  }
  rtimer_running = true;

  if(rtimer_queue.count == 0) {
    rtimer_running = false;
    critical_exit(status);
    return;
  }

  now = RTIMER_NOW();

  while(rtimer_queue.count > 0) {
    t = rtimer_queue.timers[0];

    if(RTIMER_CLOCK_LT(now, t->time)) {
      break;
    }

    rtimer_queue_remove(t);
    critical_exit(status);

    t->func(t, t->ptr);

    status = critical_enter();
    now = RTIMER_NOW();
  }

  if(rtimer_queue.count > 0) {
    rtimer_arch_schedule(rtimer_queue.timers[0]->time);
  }

  rtimer_running = false;
  critical_exit(status);
}

int
rtimer_cancel(struct rtimer *rtimer)
{
  int_master_status_t status;
  
  status = critical_enter();
  
  if(!rtimer->active) {
    critical_exit(status);
    return RTIMER_ERR_TIME;
  }
  
  rtimer_queue_remove(rtimer);
  
  if(rtimer_queue.count > 0) {
    rtimer_arch_schedule(rtimer_queue.timers[0]->time);
  }
  
  critical_exit(status);
  return RTIMER_OK;
}

uint8_t
rtimer_active_count(void)
{
  int_master_status_t status;
  uint8_t count;
  
  status = critical_enter();
  count = rtimer_queue.count;
  critical_exit(status);
  
  return count;
}
/*---------------------------------------------------------------------------*/

/** @}*/
