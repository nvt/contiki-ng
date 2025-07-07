/*
 * Copyright (c) 2025, RISE Research Institutes of Sweden AB.
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
 */

/**
 * \file
 *         A simple Contiki-NG application demonstrating Rust integration
 * \author
 *         Nicolas Tsiftes <nicolas.tsiftes@ri.se>
 */

#include "contiki.h"
#include <stdio.h>

/* Declare external Rust functions */
extern void rust_hello_world(void);
extern uint32_t rust_calculate_fibonacci(uint32_t n);
extern void rust_print_system_info(void);

/*---------------------------------------------------------------------------*/
PROCESS(hello_world_process, "Rust Hello World Process");
AUTOSTART_PROCESSES(&hello_world_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(hello_world_process, ev, data)
{
  static struct etimer timer;
  static uint32_t counter = 0;

  PROCESS_BEGIN();

  printf("Starting Rust Hello World example!\n");

  /* Call Rust function to print hello world */
  rust_hello_world();

  /* Print system information from Rust */
  rust_print_system_info();

  /* Set timer for periodic execution */
  etimer_set(&timer, CLOCK_SECOND * 2);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));

    counter++;
    printf("Iteration %lu: ", (unsigned long)counter);

    /* Calculate Fibonacci number using Rust */
    uint32_t fib_input = (counter % 20) + 1;
    uint32_t fib_result = rust_calculate_fibonacci(fib_input);
    printf("Fibonacci(%lu) = %lu\n",
           (unsigned long)fib_input,
           (unsigned long)fib_result);

    /* Reset timer */
    etimer_reset(&timer);

    /* Exit after 10 iterations */
    if(counter >= 10) {
      printf("Rust example completed!\n");
      PROCESS_EXIT();
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
