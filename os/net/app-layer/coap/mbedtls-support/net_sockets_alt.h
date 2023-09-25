/**
 * \file net_sockets.h
 *
 * \brief   Network sockets abstraction layer to integrate Mbed TLS into a
 *          BSD-style sockets API.
 *
 *          The network sockets module provides an example integration of the
 *          Mbed TLS library into a BSD sockets implementation. The module is
 *          intended to be an example of how Mbed TLS can be integrated into a
 *          networking stack, as well as to be Mbed TLS's network integration
 *          for its supported platforms.
 *
 *          The module is intended only to be used with the Mbed TLS library and
 *          is not intended to be used by third party application software
 *          directly.
 *
 *          The supported platforms are as follows:
 *              * Microsoft Windows and Windows CE
 *              * POSIX/Unix platforms including Linux, OS X
 *
 */
/*
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
#ifndef MBEDTLS_NET_SOCKETS_H
#define MBEDTLS_NET_SOCKETS_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/ssl.h"
#include "contiki-net.h"
#include "contiki.h"

#include <stddef.h>
#include <stdint.h>


#define MBEDTLS_ERR_NET_SOCKET_FAILED                     -0x0042  /**< Failed to open a socket. */
#define MBEDTLS_ERR_NET_CONNECT_FAILED                    -0x0044  /**< The connection to the given server / port failed. */
#define MBEDTLS_ERR_NET_BIND_FAILED                       -0x0046  /**< Binding of the socket failed. */
#define MBEDTLS_ERR_NET_LISTEN_FAILED                     -0x0048  /**< Could not listen on the socket. */
#define MBEDTLS_ERR_NET_ACCEPT_FAILED                     -0x004A  /**< Could not accept the incoming connection. */
#define MBEDTLS_ERR_NET_RECV_FAILED                       -0x004C  /**< Reading information from the socket failed. */
#define MBEDTLS_ERR_NET_SEND_FAILED                       -0x004E  /**< Sending information through the socket failed. */
#define MBEDTLS_ERR_NET_CONN_RESET                        -0x0050  /**< Connection was reset by peer. */
#define MBEDTLS_ERR_NET_UNKNOWN_HOST                      -0x0052  /**< Failed to get an IP address for the given hostname. */
#define MBEDTLS_ERR_NET_BUFFER_TOO_SMALL                  -0x0043  /**< Buffer is too small to hold the data. */
#define MBEDTLS_ERR_NET_INVALID_CONTEXT                   -0x0045  /**< The context is invalid, eg because it was free()ed. */
#define MBEDTLS_ERR_NET_POLL_FAILED                       -0x0047  /**< Polling the net context failed. */
#define MBEDTLS_ERR_NET_BAD_INPUT_DATA                    -0x0049  /**< Input invalid. */

#define MBEDTLS_NET_LISTEN_BACKLOG         10 /**< The backlog that listen() should use. */

#define MBEDTLS_NET_PROTO_TCP 0 /**< The TCP transport protocol */
#define MBEDTLS_NET_PROTO_UDP 1 /**< The UDP transport protocol */

#define MBEDTLS_NET_POLL_READ  1 /**< Used in \c mbedtls_net_poll to check for pending data  */
#define MBEDTLS_NET_POLL_WRITE 2 /**< Used in \c mbedtls_net_poll to check if write possible */



struct socket_info{
    const uip_ipaddr_t * source_addr;
    uint16_t source_port;
};

void mbedtls_callback(struct udp_socket *c,
                      void *ptr,
                      const uip_ipaddr_t *source_addr,
                      uint16_t source_port,
                      const uip_ipaddr_t *dest_addr,
                      uint16_t dest_port,
                      const uint8_t *data,
                      uint16_t datalen);


int mbedtls_net_recv( void *ctx, unsigned char *buf, size_t len );

/**
 * \brief          Write at most 'len' characters. If no error occurs,
 *                 the actual amount read is returned.
 *
 * \param ctx      Socket
 * \param buf      The buffer to read from
 * \param len      The length of the buffer
 *
 * \return         the number of bytes sent,
 *                 or a non-zero error code; with a non-blocking socket,
 *                 MBEDTLS_ERR_SSL_WANT_WRITE indicates write() would block.
 */
int mbedtls_net_send( void *ctx, const unsigned char *buf, size_t len );


int mbedtls_net_sendto( void *ctx, const unsigned char *buf, size_t len );




#endif /* net_sockets.h */
