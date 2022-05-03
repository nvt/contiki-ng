/*
 * Copyright (c) 2022, SICS, Swedish ICT AB.
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

#ifndef MBEDTLS_SUPPORT_H_
#define MBEDTLS_SUPPORT_H_

#include "mbedtls/config.h"
//TODO: SHould these files be moved to .c
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/timing.h"
#ifdef COAP_DTLS_CONF_WITH_CERT
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#endif /* COAP_DTLS_CONF_WITH_CERT */

#include "coap-endpoint.h"
#include "coap-keystore.h"

//TODO: Move this to be used in project_conf.h
#define MBEDTLS_LIB_DEBUG_LEVEL 0 //Value between 0 to 5

//TODO: Make configurable in project-conf.h
#define READ_TIMEOUT_MS 20000
#define HANDHSAKE_MIN_TIMEOUT 20000
#define HANDSHAKE_MAX_TIMEOUT 60000

typedef enum coap_mbedtls_sec_mode_e {
  COAP_MBEDTLS_SEC_MODE_NONE = 0,
  COAP_MBEDTLS_SEC_MODE_PSK,
  COAP_MBEDTLS_SEC_MODE_CERT,
} coap_mbedtls_sec_mode_t;

/* DTLS peer info, their config, current state, etc */
typedef struct mbedtls_peer_info_s {
  struct mbedtls_peer_info_s *next;  
  
  coap_endpoint_t ep;
  uint8_t is_packet_consumed; 

  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
#ifdef COAP_DTLS_CONF_WITH_CERT
  char *hostname; 
  mbedtls_x509_crt cacert; /* Root CA certificate */
  mbedtls_x509_crt clicert; /* Client certificate */
  mbedtls_pk_context pkey; /* Client private key */
#endif /* COAP_DTLS_CONF_WITH_CERT */
  mbedtls_timing_delay_context timer;
} mbedtls_peer_info_t;

/* Struct stores global DTLS info */
typedef struct mbedtls_context_t {
  uint8_t ready; /* 1 = DTLS initialized and ready; 0 = Not ready */
  
  /* DTLS will listen on this udp port */
  struct uip_udp_conn *udp_conn;

  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  /* List of DTLS peers */
  LIST_STRUCT(peer_info_list);
} mbedtls_context_t;

//TODO: Use uip_appdata instead  
extern unsigned char data_buf1[512];

mbedtls_peer_info_t * coap_ep_get_mbedtls_peer_info(const coap_endpoint_t *ep);
int coap_ep_is_mbedtls_peer(const coap_endpoint_t *ep);
int coap_ep_is_mbedtls_connected(const coap_endpoint_t *ep);
int coap_ep_get_mbedtls_state(const coap_endpoint_t *ep);

void coap_mbedtls_init();
void coap_mbedtls_conn_init(struct uip_udp_conn *udp_conn);
int coap_ep_mbedtls_connect(const coap_endpoint_t *ep, 
    coap_mbedtls_sec_mode_t sec_mode, const void *keystore_entry);
int coap_ep_mbedtls_write(const coap_endpoint_t *ep, const unsigned char *message, int len);
int coap_ep_mbedtls_handle_message(const coap_endpoint_t *ep);
void coap_ep_mbedtls_disconnect(const coap_endpoint_t *ep);
void coap_ep_mbedtls_poll_send_data();

#endif /* MBEDTLS_SUPPORT_H_ */
