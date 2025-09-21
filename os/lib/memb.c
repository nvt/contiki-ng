/*
 * Copyright (c) 2004, Swedish Institute of Computer Science.
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
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

/**
 * \addtogroup memb
 * @{
 */

 /**
 * \file
 * Memory block allocation routines.
 * \author Adam Dunkels <adam@sics.se>
 */
#include <string.h>

#include "contiki.h"
#include "lib/memb.h"

/*---------------------------------------------------------------------------*/
void
memb_init(struct memb *m)
{
  memset(m->used, 0, m->num);
  memset(m->mem, 0, m->size * m->num);
}
/*---------------------------------------------------------------------------*/
void *
memb_alloc(struct memb *m)
{
  int i;

  for(i = 0; i < m->num; ++i) {
    if(m->used[i] == false) {
      /* If this block was unused, we set the used flag on
	 and return a pointer to the memory block. */
      m->used[i] = true;
      return (void *)((char *)m->mem + (i * m->size));
    }
  }

  /* No free block was found, so we return NULL to indicate failure to
     allocate block. */
  return NULL;
}
/*---------------------------------------------------------------------------*/
int
memb_free(struct memb *m, void *ptr)
{
  size_t offset;
  size_t index;

  /* First check if the pointer is within the valid memory range */
  if(!memb_inmemb(m, ptr)) {
    return -1;
  }

  /* Calculate the offset from the start of the memory block */
  offset = (char *)ptr - (char *)m->mem;

  /* Check if the pointer is properly aligned to a block boundary */
  if(offset % m->size != 0) {
    return -1;
  }

  /* Calculate the block index directly */
  index = offset / m->size;

  /* Check for double-free */
  if(m->used[index] == false) {
    return -1;
  }

  /* Mark the block as free */
  m->used[index] = false;

  /* Clear the memory block contents for security */
  memset(ptr, 0, m->size);

  return 0;
}
/*---------------------------------------------------------------------------*/
int
memb_inmemb(struct memb *m, void *ptr)
{
  return (char *)ptr >= (char *)m->mem &&
    (char *)ptr < (char *)m->mem + (m->num * m->size);
}
/*---------------------------------------------------------------------------*/
size_t
memb_numfree(struct memb *m)
{
  int i;
  size_t num_free = 0;

  for(i = 0; i < m->num; ++i) {
    if(m->used[i] == false) {
      ++num_free;
    }
  }

  return num_free;
}
/** @} */
