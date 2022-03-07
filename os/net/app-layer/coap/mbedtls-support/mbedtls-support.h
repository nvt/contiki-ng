/*
 * Copyright (c) 2016, SICS, Swedish ICT AB.
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
 *      DTLS(MbedTLS implementation) support for CoAP
 * \author
 *      Jayendra Ellamathy <ejayen@gmail.com>
 */

#ifndef __MBEDTLS_SUPPORT_H__
#define __MBEDTLS_SUPPORT_H__

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/timing.h"
#include "mbedtls/debug.h"

#include "coap-endpoint.h"
#include "coap-keystore.h"


/* DTLS peer info, their config, current state, etc */
typedef struct mbedtls_peer_info_s {
  struct mbedtls_peer_info_s *next;  
  coap_endpoint_t ep;
  coap_keystore_psk_entry_t ks;
  char *hostname; 
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt cacert;
  mbedtls_timing_delay_context timer;
} mbedtls_peer_info_t;

/* Struct stores global DTLS info */
typedef struct mbedtls_context_t {
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  /* DTLS will listen on this udp port */
  struct uip_udp_conn *udp_conn;

  /* List of DTLS peers */
  LIST_STRUCT(peer_info_list);
} mbedtls_context_t;

//TODO: Use uip_appdata instead  
unsigned char data_buf[UIP_CONF_BUFFER_SIZE];

mbedtls_peer_info_t * coap_ep_get_mbedtls_peer_info(const coap_endpoint_t *ep);
int coap_ep_is_mbedtls_peer(const coap_endpoint_t *ep);
int coap_ep_is_mbedtls_connected(const coap_endpoint_t *ep);
int coap_ep_get_mbedtls_state(const coap_endpoint_t *ep);

void coap_mbedtls_init();
void coap_mbedtls_conn_init(struct uip_udp_conn *udp_conn);
int coap_ep_mbedtls_connect(const coap_endpoint_t *ep, const coap_keystore_psk_entry_t *ks);
int coap_ep_mbedtls_write(const coap_endpoint_t *ep, const unsigned char *message, int len);
int coap_ep_mbedtls_handle_message(const coap_endpoint_t *ep);
void coap_ep_mbedtls_disconnect(const coap_endpoint_t *ep);

#endif /* __MBEDTLS_SUPPORT_H__ */
