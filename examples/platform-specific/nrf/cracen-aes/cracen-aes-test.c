/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB
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
/*---------------------------------------------------------------------------*/
/**
 * \file
 *      Known-answer test for the CRACEN AES-128 driver.
 *
 *      Encrypts the FIPS-197 AES-128 example block through the AES_128
 *      interface (which the nRF54L15 maps to cracen_aes_128_driver) and
 *      compares against the published ciphertext.
 * \author
 *      Nicolas Tsiftes <nicolas.tsiftes@ri.se>
 */
/*---------------------------------------------------------------------------*/
#include "contiki.h"
#include "lib/aes-128.h"

#include <stdio.h>
#include <string.h>
/*---------------------------------------------------------------------------*/
/* FIPS-197, Appendix B / C.1 AES-128 example. */
static const uint8_t key[AES_128_KEY_LENGTH] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
static const uint8_t plaintext[AES_128_BLOCK_SIZE] = {
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};
static const uint8_t expected[AES_128_BLOCK_SIZE] = {
  0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
  0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
};
/*---------------------------------------------------------------------------*/
PROCESS(cracen_aes_test_process, "CRACEN AES-128 KAT");
AUTOSTART_PROCESSES(&cracen_aes_test_process);
/*---------------------------------------------------------------------------*/
static void
print_hex(const char *label, const uint8_t *data, size_t len)
{
  printf("%s", label);
  for(size_t i = 0; i < len; i++) {
    printf("%02x", data[i]);
  }
  printf("\n");
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(cracen_aes_test_process, ev, data)
{
  static uint8_t block[AES_128_BLOCK_SIZE];
  static struct etimer et;

  PROCESS_BEGIN();

  /* Let the boot/network logging settle so the KAT result is readable. */
  etimer_set(&et, 3 * CLOCK_SECOND);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

  memcpy(block, plaintext, sizeof(block));

  AES_128.set_key(key);
  AES_128.encrypt(block);

  print_hex("key        = ", key, sizeof(key));
  print_hex("plaintext  = ", plaintext, sizeof(plaintext));
  print_hex("ciphertext = ", block, sizeof(block));
  print_hex("expected   = ", expected, sizeof(expected));

  if(memcmp(block, expected, sizeof(block)) == 0) {
    printf("CRACEN AES-128 KAT: PASS\n");
  } else {
    printf("CRACEN AES-128 KAT: FAIL\n");
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
