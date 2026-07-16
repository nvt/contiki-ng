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

/**
 * \file
 *         Unit tests for the CoAP message parser.
 * \author
 *         Nicolas Tsiftes <nvt@ri.se>
 */

#include "contiki.h"
#include "unit-test.h"
#include "coap.h"

#include <stdio.h>
#include <string.h>

PROCESS(run_tests, "CoAP parser unit tests");
AUTOSTART_PROCESSES(&run_tests);

#define CANARY 0xAA

/*
 * A CoAP message is built in a buffer that has a canary byte directly
 * after the message. The parser must not write to the canary, because
 * the transport is not required to supply any space beyond the message
 * itself.
 */
static uint8_t buffer[COAP_MAX_PACKET_SIZE + 64];

/*
 * Builds a minimal CoAP POST request carrying payload_len payload bytes,
 * and places a canary directly after the message. Returns the message
 * length.
 */
static uint16_t
build_message(size_t payload_len)
{
  uint16_t len = 0;
  size_t i;

  buffer[len++] = (1 << 6);          /* Version 1, type CON, token length 0. */
  buffer[len++] = COAP_POST;         /* Code. */
  buffer[len++] = 0x12;              /* Message ID, high byte. */
  buffer[len++] = 0x34;              /* Message ID, low byte. */
  buffer[len++] = 0xFF;              /* Payload marker. */

  for(i = 0; i < payload_len; i++) {
    buffer[len++] = 'a' + (i % 26);
  }

  buffer[len] = CANARY;

  return len;
}
/*---------------------------------------------------------------------------*/
/* The parser must report the payload without writing past the message. */
UNIT_TEST_REGISTER(test_parse_payload_keeps_canary,
                   "coap_parse_message() does not write past the message");
UNIT_TEST(test_parse_payload_keeps_canary)
{
  coap_message_t message;
  uint16_t len;

  UNIT_TEST_BEGIN();

  len = build_message(10);

  UNIT_TEST_ASSERT(coap_parse_message(&message, buffer, len) == NO_ERROR);
  UNIT_TEST_ASSERT(message.payload_len == 10);
  UNIT_TEST_ASSERT(memcmp(message.payload, "abcdefghij", 10) == 0);
  UNIT_TEST_ASSERT(buffer[len] == CANARY);

  UNIT_TEST_END();
}
/*---------------------------------------------------------------------------*/
/*
 * A payload that reaches the end of the message is the case that used to
 * write a null terminator one byte past the buffer.
 */
UNIT_TEST_REGISTER(test_parse_max_payload_keeps_canary,
                   "a maximum-sized payload does not write past the message");
UNIT_TEST(test_parse_max_payload_keeps_canary)
{
  coap_message_t message;
  uint16_t len;

  UNIT_TEST_BEGIN();

  len = build_message(COAP_MAX_CHUNK_SIZE);

  UNIT_TEST_ASSERT(coap_parse_message(&message, buffer, len) == NO_ERROR);
  UNIT_TEST_ASSERT(message.payload_len == COAP_MAX_CHUNK_SIZE);
  UNIT_TEST_ASSERT(buffer[len] == CANARY);

  UNIT_TEST_END();
}
/*---------------------------------------------------------------------------*/
/* An oversized payload is rejected rather than truncated. */
UNIT_TEST_REGISTER(test_parse_oversized_payload_is_rejected,
                   "an oversized payload is rejected rather than truncated");
UNIT_TEST(test_parse_oversized_payload_is_rejected)
{
  coap_message_t message;
  uint16_t len;

  UNIT_TEST_BEGIN();

  len = build_message(COAP_MAX_CHUNK_SIZE + 8);

  UNIT_TEST_ASSERT(coap_parse_message(&message, buffer, len) ==
                   REQUEST_ENTITY_TOO_LARGE_4_13);
  UNIT_TEST_ASSERT(buffer[len] == CANARY);

  UNIT_TEST_END();
}
/*---------------------------------------------------------------------------*/
/* Binary payloads containing null bytes are reported by length. */
UNIT_TEST_REGISTER(test_parse_payload_with_null_bytes,
                   "a payload containing null bytes is reported by length");
UNIT_TEST(test_parse_payload_with_null_bytes)
{
  coap_message_t message;
  uint16_t len;

  UNIT_TEST_BEGIN();

  len = build_message(4);
  buffer[5] = 'x';
  buffer[6] = '\0';
  buffer[7] = 'y';
  buffer[8] = '\0';

  UNIT_TEST_ASSERT(coap_parse_message(&message, buffer, len) == NO_ERROR);
  UNIT_TEST_ASSERT(message.payload_len == 4);
  UNIT_TEST_ASSERT(memcmp(message.payload, "x\0y\0", 4) == 0);
  UNIT_TEST_ASSERT(buffer[len] == CANARY);

  UNIT_TEST_END();
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(run_tests, ev, data)
{
  PROCESS_BEGIN();

  printf("\nRunning CoAP parser unit tests\n");

  UNIT_TEST_RUN(test_parse_payload_keeps_canary);
  UNIT_TEST_RUN(test_parse_max_payload_keeps_canary);
  UNIT_TEST_RUN(test_parse_oversized_payload_is_rejected);
  UNIT_TEST_RUN(test_parse_payload_with_null_bytes);

  if(!UNIT_TEST_PASSED(test_parse_payload_keeps_canary) ||
     !UNIT_TEST_PASSED(test_parse_max_payload_keeps_canary) ||
     !UNIT_TEST_PASSED(test_parse_oversized_payload_is_rejected) ||
     !UNIT_TEST_PASSED(test_parse_payload_with_null_bytes)) {
    printf("=check-me= FAILED\n");
  } else {
    printf("=check-me= DONE\n");
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
