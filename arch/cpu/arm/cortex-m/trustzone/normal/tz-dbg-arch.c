/*
 * Copyright (c) 2023, RISE Research Institutes of Sweden
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
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

/*
 * Authors: Niclas Finne <niclas.finne@ri.se>
 *          Nicolas Tsiftes <nicolas.tsiftes@ri.se>
 */

/*---------------------------------------------------------------------------*/
#include "contiki.h"
#include "trustzone/tz-api.h"

#define DBG_BUF_SIZE 256
static char dbg_buf[DBG_BUF_SIZE];
static uint16_t dbg_pos;
/*---------------------------------------------------------------------------*/
int
dbg_putchar(int c)
{
  if(dbg_pos < DBG_BUF_SIZE) {
    dbg_buf[dbg_pos++] = c;
  }

  if(c == '\n' || dbg_pos >= DBG_BUF_SIZE - 1) {
    dbg_buf[MIN(dbg_pos - 1, DBG_BUF_SIZE - 1)] = '\0';
    tz_api_println(dbg_buf);
    dbg_pos = 0;
  }

  return c;
}
/*---------------------------------------------------------------------------*/
unsigned int
dbg_send_bytes(const unsigned char *s, unsigned int len)
{
  unsigned int i = 0;

  while(s && *s != 0) {
    if(i >= len) {
      break;
    }
    dbg_putchar(*s++);
    i++;
  }

  return i;
}
/*---------------------------------------------------------------------------*/
