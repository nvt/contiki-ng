/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB
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
 *   A TCP server that exercises the tcp-socket flow-control mechanism.
 *
 *   The server's data callback runs through three phases driven by the
 *   number of bytes consumed so far:
 *
 *     - Phase 1 (until PHASE1_END):       drain everything.
 *     - Phase 2 (PHASE1_END..PHASE2_END): retain RETAIN_BYTES per call,
 *                                         exercising dynamic receive
 *                                         window shrink.
 *     - Phase 3 (after PHASE2_END):       drain everything, exercising
 *                                         dynamic receive window grow.
 *
 *   Every byte is validated against the same modulo-256 pattern used
 *   by the existing tcp-client. The test reports "Server OK" only if
 *   the full stream is delivered without validation errors and every
 *   phase has been entered.
 *
 * \author
 *   Nicolas Tsiftes <nicolas.tsiftes@ri.se>
 */

#include <contiki.h>
#include <net/ipv6/uip-ds6.h>
#include <net/ipv6/tcp-socket.h>

#include "sys/log.h"
#define LOG_MODULE "TCPFlow"
#define LOG_LEVEL LOG_LEVEL_INFO

PROCESS(test_tcp_flow_server, "TCP flow-control server");
AUTOSTART_PROCESSES(&test_tcp_flow_server);

#define TCP_TEST_PORT      18962
#define SOCKET_BUF_SIZE    128
#define TEST_STREAM_LENGTH 100000
#define RETAIN_BYTES       64

#define PHASE1_END         (TEST_STREAM_LENGTH / 3)        /* ~33333 */
#define PHASE2_END         ((TEST_STREAM_LENGTH * 2) / 3)  /* ~66666 */

static struct tcp_socket server_sock;
static uint8_t in_buf[SOCKET_BUF_SIZE];
static uint8_t out_buf[SOCKET_BUF_SIZE];
static size_t bytes_received;
static bool validation_failed;
static bool phase2_entered;
static bool phase3_entered;
/*****************************************************************************/
static int
data_callback(struct tcp_socket *sock, void *ptr, const uint8_t *input, int len)
{
  size_t retain;
  int i;

  if(len <= 0) {
    return 0;
  }

  /* The buffer's first byte corresponds to stream offset
     bytes_received. With retention, some bytes are presented again
     on subsequent calls; they always carry the same stream offset,
     so the same expected value applies. */
  for(i = 0; i < len; i++) {
    uint8_t expected = (uint8_t)((bytes_received + i) % 256);
    if(input[i] != expected) {
      LOG_ERR("Validation failed at byte %zu: expected 0x%02x, got 0x%02x\n",
              bytes_received + i, expected, input[i]);
      validation_failed = true;
      tcp_socket_close(sock);
      return 0;
    }
  }

  /* Decide how many bytes to retain based on the phase. */
  if(bytes_received < PHASE1_END) {
    /* Phase 1: baseline, drain everything. */
    retain = 0;
  } else if(bytes_received < PHASE2_END) {
    /* Phase 2: keep RETAIN_BYTES so the advertised window shrinks
       and the sender adapts. Skip retention on short segments where
       it would consume the whole buffer. */
    retain = (size_t)len > RETAIN_BYTES ? RETAIN_BYTES : 0;
    if(!phase2_entered) {
      phase2_entered = true;
      LOG_INFO("Phase 2 begins (partial retention)\n");
    }
  } else {
    /* Phase 3: drain everything again so the receive window grows
       back to its full size. */
    retain = 0;
    if(!phase3_entered) {
      phase3_entered = true;
      LOG_INFO("Phase 3 begins (drain after retention)\n");
    }
  }

  bytes_received += len - retain;
  return retain;
}
/*****************************************************************************/
static void
event_callback(struct tcp_socket *sock, void *ptr, tcp_socket_event_t event)
{
  switch(event) {
  case TCP_SOCKET_CONNECTED:
    LOG_INFO("CONNECTED\n");
    break;
  case TCP_SOCKET_CLOSED:
    LOG_INFO("CLOSED, bytes_received=%zu\n", bytes_received);
    if(validation_failed) {
      LOG_ERR("Server FAILED: byte validation error\n");
    } else if(bytes_received < TEST_STREAM_LENGTH) {
      LOG_ERR("Server FAILED: received %zu of %u bytes\n",
              bytes_received, (unsigned)TEST_STREAM_LENGTH);
    } else if(!phase2_entered) {
      LOG_ERR("Server FAILED: phase 2 not exercised\n");
    } else if(!phase3_entered) {
      LOG_ERR("Server FAILED: phase 3 not exercised\n");
    } else {
      LOG_INFO("Server OK: %zu bytes validated across all phases\n",
               bytes_received);
    }
    break;
  case TCP_SOCKET_TIMEDOUT:
    LOG_INFO("TIMED OUT\n");
    break;
  case TCP_SOCKET_ABORTED:
    LOG_INFO("ABORTED\n");
    break;
  case TCP_SOCKET_DATA_SENT:
    LOG_INFO("DATA SENT\n");
    break;
  case TCP_SOCKET_INPUT_OVERFLOW:
    /* Not expected in this test (the phase-2 retention is sized
       smaller than the buffer). Treat it as a failure if it ever
       fires. */
    LOG_ERR("Unexpected INPUT_OVERFLOW (input_data_len=%u)\n",
            server_sock.input_data_len);
    validation_failed = true;
    tcp_socket_close(sock);
    break;
  default:
    LOG_INFO("UNKNOWN EVENT (%d)\n", (int)event);
    break;
  }
}
/*****************************************************************************/
PROCESS_THREAD(test_tcp_flow_server, ev, data)
{
  int ret;

  PROCESS_BEGIN();

  bytes_received = 0;
  validation_failed = false;
  phase2_entered = false;
  phase3_entered = false;

  LOG_INFO("Flow-control test server listening on port %d\n", TCP_TEST_PORT);

  ret = tcp_socket_register(&server_sock, NULL, in_buf, sizeof(in_buf),
                            out_buf, sizeof(out_buf),
                            data_callback, event_callback);
  if(ret < 0) {
    LOG_ERR("Failed to register TCP socket\n");
    PROCESS_EXIT();
  }

  if(tcp_socket_listen(&server_sock, TCP_TEST_PORT) < 0) {
    LOG_ERR("Failed to listen on port %d\n", TCP_TEST_PORT);
    tcp_socket_unregister(&server_sock);
    PROCESS_EXIT();
  }

  for(;;) {
    PROCESS_YIELD();
  }

  PROCESS_END();
}
/*****************************************************************************/
