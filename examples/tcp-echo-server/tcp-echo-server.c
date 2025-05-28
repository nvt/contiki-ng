/*
 * Copyright (c) 2025, RISE Research Institutes of Sweden AB
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
 *   A TCP echo server example.
 * \author
 *   Nicolas Tsiftes <nicolas.tsiftes@ri.se>
 */


#include <contiki.h>
#include <net/ipv6/uip-ds6.h>
#include <net/ipv6/tcp-socket.h>

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "TCPEchoServer"
#define LOG_LEVEL LOG_LEVEL_DBG

PROCESS(tcp_echo_server, "TCP echo server");
AUTOSTART_PROCESSES(&tcp_echo_server);

#define TCP_ECHO_PORT 7
#define SOCKET_BUF_SIZE 128

static struct tcp_socket server_sock;
static uint8_t in_buf[SOCKET_BUF_SIZE];
#if CONTIKI_TARGET_NATIVE
static uint8_t out_buf[SOCKET_BUF_SIZE * 1000];
#else
static uint8_t out_buf[SOCKET_BUF_SIZE * 2];
#endif
static size_t bytes_received;
/*****************************************************************************/
static int
data_callback(struct tcp_socket *sock, void *ptr, const uint8_t *input, int len)
{
  if(len >= 0) {
    bytes_received += len;
  }
  LOG_INFO("RECV %d bytes (total %zu)\n", len, bytes_received);

  int ret = tcp_socket_send(sock, input, len);
  if(ret < 0) {
    LOG_WARN("Failed to send echo reply\n");
    tcp_socket_close(sock);
    return 0;
  }

  if(ret > len) {
    LOG_ERR("invalid return value from tcp_socket_sent: ret %d > len %d!\n",
            ret, len);
    tcp_socket_close(sock);
    return 0;
  }

  LOG_INFO("SEND %d of %d bytes\n", ret, len);

  /* Leave the unsent bytes in the socket buffer for future processing. */
  return len - ret;
}
/*****************************************************************************/
static void
event_callback(struct tcp_socket *sock, void *ptr, tcp_socket_event_t event)
{
  LOG_INFO("TCP socket event: ");
  switch(event) {
  case TCP_SOCKET_CONNECTED:
    LOG_INFO_("CONNECTED\n");
    break;
  case TCP_SOCKET_CLOSED:
    LOG_INFO_("CLOSED\n");
    break;
  case TCP_SOCKET_TIMEDOUT:
    LOG_INFO_("TIMED OUT\n");
    break;
  case TCP_SOCKET_ABORTED:
    LOG_INFO_("ABORTED\n");
    break;
  case TCP_SOCKET_DATA_SENT:
    LOG_INFO_("DATA SENT\n");
    break;
  default:
    LOG_INFO_("UNKNOWN (%d)\n", (int)event);
    break;
  }
}
/*****************************************************************************/
PROCESS_THREAD(tcp_echo_server, ev, data)
{
  PROCESS_BEGIN();

  LOG_INFO("Listening for TCP connections on port %d\n", TCP_ECHO_PORT);

  LOG_DBG("Socket input buffer size: %zu\n", sizeof(in_buf));
  LOG_DBG("Socket output buffer size: %zu\n", sizeof(out_buf));

  int ret = tcp_socket_register(&server_sock, NULL, in_buf, sizeof(in_buf),
                                out_buf, sizeof(out_buf),
                                data_callback, event_callback);
  if(ret < 0) {
    LOG_ERR("Failed to register a TCP socket\n");
    PROCESS_EXIT();
  }

  if(tcp_socket_listen(&server_sock, TCP_ECHO_PORT) < 0) {
    LOG_ERR("Failed to listen on port %d\n", TCP_ECHO_PORT);
    tcp_socket_unregister(&server_sock);
    PROCESS_EXIT();
  }

  for(;;) {
    PROCESS_YIELD();
  }

  PROCESS_END();
}
/*****************************************************************************/
