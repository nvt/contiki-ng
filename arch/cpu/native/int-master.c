/*
 * Copyright (c) 2018, George Oikonomou - http://www.spd.gr
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*---------------------------------------------------------------------------*/
#include "contiki.h"
#include "sys/int-master.h"

#include <signal.h>
#include <stdbool.h>
/*---------------------------------------------------------------------------*/
#define DISABLED 0
#define ENABLED  1
/*---------------------------------------------------------------------------*/
static int_master_status_t stat = ENABLED;
/*
 * On native, "interrupts" are SIGALRM deliveries from rtimer-arch.c.
 * Without a real signal mask, code that takes int_master_read_and_disable()
 * as a synchronization primitive (much of os/sys/) is silently incorrect:
 * SIGALRM can fire and re-enter the rtimer queue inside what callers
 * believe is a critical section. Use sigprocmask() so disabling actually
 * blocks the signal until enable.
 */
static sigset_t alrm_mask;
static bool mask_initialized;

static void
ensure_mask(void)
{
  if(!mask_initialized) {
    sigemptyset(&alrm_mask);
    sigaddset(&alrm_mask, SIGALRM);
    mask_initialized = true;
  }
}
/*---------------------------------------------------------------------------*/
void
int_master_enable(void)
{
  ensure_mask();
  sigprocmask(SIG_UNBLOCK, &alrm_mask, NULL);
  stat = ENABLED;
}
/*---------------------------------------------------------------------------*/
int_master_status_t
int_master_read_and_disable(void)
{
  ensure_mask();
  int_master_status_t rv = stat;
  sigprocmask(SIG_BLOCK, &alrm_mask, NULL);
  stat = DISABLED;
  return rv;
}
/*---------------------------------------------------------------------------*/
void
int_master_status_set(int_master_status_t status)
{
  ensure_mask();
  if(status == ENABLED) {
    sigprocmask(SIG_UNBLOCK, &alrm_mask, NULL);
  } else {
    sigprocmask(SIG_BLOCK, &alrm_mask, NULL);
  }
  stat = status;
}
/*---------------------------------------------------------------------------*/
bool
int_master_is_enabled(void)
{
  return stat == DISABLED ? false : true;
}
/*---------------------------------------------------------------------------*/
