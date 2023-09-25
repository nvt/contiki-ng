/*
 *  TCP/IP or UDP/IP networking functions
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/* Enable definition of getaddrinfo() even when compiling with -std=c99. Must
 * be set before config.h, which pulls in glibc's features.h indirectly.
 * Harmless on other platforms. */

#include "common.h"
#include <string.h>
#include <stdbool.h>
#include "sys/log.h"
#define LOG_MODULE "Mbed"
#define LOG_LEVEL LOG_LEVEL_INFO

#include "net_sockets_alt.h"
#include "mbedtls/error.h"



static uint8_t data_buf[UIP_CONF_BUFFER_SIZE];
static struct udp_socket* data_owner;
static uip_ipaddr_t peer_ip;
static uint16_t peer_port;
static uint16_t length = 0;
static int overwrite = 0;

void mbedtls_callback(struct udp_socket *c,
                      void *ptr,
                      const uip_ipaddr_t *source_addr,
                      uint16_t source_port,
                      const uip_ipaddr_t *dest_addr,
                      uint16_t dest_port,
                      const uint8_t *data,
                      uint16_t datalen)
{
  data_owner = c;

  peer_ip = *source_addr;
  peer_port = source_port;

  if ( datalen > sizeof(data_buf) ){
    LOG_ERR("Received data larger than buffer");
    datalen = 0;
    return;
  }

  memcpy(data_buf, data, datalen);
  length = datalen;
  if (overwrite == 1) {
    printf("MbedTLS overwritten!\n");
  };
  overwrite = 1;

  process_poll(c->p);
}


int mbedtls_net_recv( void *ctx, unsigned char *buf, size_t len )
{
  struct udp_socket* sock = (struct udp_socket*) ctx;

  
  if ( !sock )
  {
    return MBEDTLS_ERR_NET_INVALID_CONTEXT;
  }
  if (  !length || ( sock != data_owner ) )
  {
    return MBEDTLS_ERR_SSL_WANT_READ;
  }
  if (len > length)
  {
    len = length;
  }

  memcpy(buf, data_buf, len);
  memmove(data_buf, data_buf + len, length - len);
  length = length - len;
  overwrite = 2;

  return len;

}

/*
 * Write at most 'len' characters
 */
int mbedtls_net_send( void *ctx, const unsigned char *buf, size_t len )
{
  struct udp_socket* sock = (struct udp_socket*) ctx;

  if ( !sock )
    return MBEDTLS_ERR_NET_INVALID_CONTEXT;

  int res = udp_socket_send(sock, buf, len);

  if (res < 0){
    return MBEDTLS_ERR_NET_SEND_FAILED;
  }

  return res;
}


int mbedtls_net_sendto( void *ctx, const unsigned char *buf, size_t len )
{
  struct udp_socket* sock = (struct udp_socket*) ctx;

  if ( !sock )
    return MBEDTLS_ERR_NET_INVALID_CONTEXT;

  if ( sock != data_owner ){
    return MBEDTLS_ERR_SSL_WANT_WRITE;
  }

  int res = udp_socket_sendto(sock, buf, len, &peer_ip, peer_port);

  if (res < 0){
    return MBEDTLS_ERR_NET_SEND_FAILED;
  }

  return res;
}
