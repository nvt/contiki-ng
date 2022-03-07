/*
 * Copyright (c) 2022, RISE Research Institutes of Sweden AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *		notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *		notice, this list of conditions and the following disclaimer in the
 *		documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *		may be used to endorse or promote products derived from this software
 *		without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.	IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 */

/**
 * \file
 *			DTLS(MbedTLS implementation) support for CoAP
 *			
 * \Author 
 *			Jayendra Ellamathy <ejayen@gmail.com> 
 */

#include "contiki.h"
#include "contiki-net.h"

#include "mbedtls-support.h"
#include "mbedtls-config.h"

/* Log configuration */
#define LOG_MODULE "DTLS"
#define LOG_LEVEL  LOG_LEVEL_DTLS
#define LOG_LEVEL_DTLS LOG_LEVEL_COAP
#include "coap-log.h"

#define MBEDTLS_MAX_PEERS 10


static mbedtls_context_t mbedtls_context; 
MEMB(mbedtls_peer_info_memb, mbedtls_peer_info_t, MBEDTLS_MAX_PEERS);

/*---------------------------------------------------------------------------*/
  void 
coap_mbedtls_init()
{
  int ret;
  const char *pers = "dtls_client";

  LIST_STRUCT_INIT(&mbedtls_context, peer_info_list);

  mbedtls_ctr_drbg_init(&mbedtls_context.ctr_drbg);
  mbedtls_entropy_init(&mbedtls_context.entropy);

  LOG_DBG("Seeding the random number generator...\n");
  if((ret = mbedtls_ctr_drbg_seed(&mbedtls_context.ctr_drbg, 
          mbedtls_entropy_func, 
          &mbedtls_context.entropy,
          (const unsigned char *)pers,
          strlen(pers))) != 0) {
    LOG_ERR("mbedtls_ctr_drbg_seed returned %d\n", ret);
  }
}
/*---------------------------------------------------------------------------*/
  void 
coap_mbedtls_conn_init(struct uip_udp_conn *udp_conn)
{
  mbedtls_context.udp_conn = udp_conn;
}
/*---------------------------------------------------------------------------*/
  int 
coap_ep_is_mbedtls_peer(const coap_endpoint_t *ep)
{
  mbedtls_peer_info_t *info = NULL; 

  for (info = list_head(mbedtls_context.peer_info_list); 
      info; info = info->next) {
    if (coap_endpoint_cmp(&info->ep, ep)) {
      return 1;
    }
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
  mbedtls_peer_info_t *
coap_ep_get_mbedtls_peer_info(const coap_endpoint_t *ep)
{
  mbedtls_peer_info_t *info = NULL; 

  for (info = list_head(mbedtls_context.peer_info_list); 
      info; info = info->next) {
    if (coap_endpoint_cmp(&info->ep, ep)) {
      break;
    }
  }
  return info;
}
/*---------------------------------------------------------------------------*/
  int 
coap_ep_is_mbedtls_connected(const coap_endpoint_t *ep)
{
  mbedtls_peer_info_t *info = NULL; 

  if (NULL != (info = coap_ep_get_mbedtls_peer_info(ep))) {
    if (info->ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER) {
      return 1;
    }
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
  int 
coap_ep_get_mbedtls_state(const coap_endpoint_t *ep)
{
  mbedtls_peer_info_t *info = NULL; 

  if (NULL != (info = coap_ep_get_mbedtls_peer_info(ep))) {
    return info->ssl.state;
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
  static int 
coap_ep_mbedtls_sendto(void *ctx, const unsigned char *buf, size_t len)
{
  coap_endpoint_t *ep = (coap_endpoint_t *) ctx;

  if (!ep) {
    return MBEDTLS_ERR_NET_INVALID_CONTEXT;
  }

  uip_udp_packet_sendto(mbedtls_context.udp_conn, buf, len, 
      &ep->ipaddr, ep->port);

  return len;
}
/*---------------------------------------------------------------------------*/
  static int 
coap_ep_mbedtls_recv(void *ctx, unsigned char *buf, size_t len)
{
  coap_endpoint_t *ep = (coap_endpoint_t *) ctx;

  if (!ep) {
    return MBEDTLS_ERR_NET_INVALID_CONTEXT;
  }

  if (uip_datalen() == 0) {
    return MBEDTLS_ERR_SSL_WANT_READ;
  }

  /* TODO: Check and extend for if len < uip_datalen() */
  memcpy(buf, uip_appdata, uip_datalen());

  return uip_datalen(); 
}
/*---------------------------------------------------------------------------*/
  int 
coap_ep_mbedtls_connect(const coap_endpoint_t *ep, 
    const coap_keystore_psk_entry_t *ks)
{
  mbedtls_peer_info_t *peer_info = NULL; 
  int ret;

  /* Create peer info if it does not exist already */
  if (NULL == (peer_info = coap_ep_get_mbedtls_peer_info(ep))) {
    peer_info = memb_alloc(&mbedtls_peer_info_memb);
    if (!peer_info) {
      LOG_ERR("Unable to allocate memory for DTLS peer ");
      LOG_ERR_COAP_EP(ep);
      LOG_ERR("\n");
      return 0;
    }
    list_add(mbedtls_context.peer_info_list, peer_info);
  } else {
    /* Peer already exists, we may want to retry handshake */
    if ((peer_info->ssl.state != 0) 
        && (2 == mbedtls_timing_get_delay(&peer_info->timer))) {
      goto perform_handshake; 
    } else {
      return 0;
    }
  }

  memcpy(&peer_info->ep, ep, sizeof(coap_endpoint_t));

  /* Init mbedtls ssl and config structs */
  mbedtls_ssl_init(&peer_info->ssl);
  mbedtls_ssl_config_init(&peer_info->conf);

  if((ret = mbedtls_ssl_config_defaults(&peer_info->conf,
          MBEDTLS_SSL_IS_CLIENT,
          MBEDTLS_SSL_TRANSPORT_DATAGRAM,
          MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    LOG_ERR("mbedtls_ssl_config_defaults returned %d\n", ret);
    return 0;
  }

  memcpy(&peer_info->ks, ks, sizeof(coap_keystore_psk_entry_t));
  if (peer_info->ks.identity == NULL || peer_info->ks.key == NULL) {
    LOG_ERR("PSK identity or key missing\n");
    return 0;
  }

  mbedtls_ssl_conf_authmode(&peer_info->conf, 
      MBEDTLS_SSL_VERIFY_OPTIONAL);
  mbedtls_ssl_conf_psk(&peer_info->conf, 
      (const unsigned char *)peer_info->ks.key, 
      peer_info->ks.key_len, 
      (const unsigned char *)peer_info->ks.identity, 
      peer_info->ks.identity_len);
  mbedtls_ssl_conf_rng(&peer_info->conf, 
      mbedtls_ctr_drbg_random, 
      &mbedtls_context.ctr_drbg);
  mbedtls_ssl_conf_max_frag_len(&peer_info->conf, 
      MBEDTLS_SSL_MAX_FRAG_LEN_1024);

  if((ret = mbedtls_ssl_setup(&peer_info->ssl, &peer_info->conf)) != 0) {
    LOG_ERR("mbedtls_ssl_setup returned -0x%x\n", (unsigned int)-ret);
    return 0;
  }

  if((ret = mbedtls_ssl_set_hostname(&peer_info->ssl, 
          peer_info->hostname)) != 0) {
    LOG_ERR("mbedtls_ssl_set_hostname returned %d\n", ret);
    return 0;
  }

  mbedtls_ssl_set_bio(&peer_info->ssl, 
      &peer_info->ep,
      coap_ep_mbedtls_sendto,
      coap_ep_mbedtls_recv, 
      NULL);

  mbedtls_ssl_set_timer_cb(&peer_info->ssl, 
      &peer_info->timer, 
      mbedtls_timing_set_delay,
      mbedtls_timing_get_delay);

  mbedtls_ssl_set_mtu(&peer_info->ssl, UIP_CONF_BUFFER_SIZE);

perform_handshake:
  ret = mbedtls_ssl_handshake(&peer_info->ssl);
  LOG_DBG("DTLS handshake returned %x in %s\n", 
      (unsigned int)-ret, __func__);
  return 1;
}
/*---------------------------------------------------------------------------*/
  int 
coap_ep_mbedtls_write(const coap_endpoint_t *ep, 
    const unsigned char *message, int len)
{
  mbedtls_peer_info_t *info = NULL; 
  int ret;

  if (NULL != (info = coap_ep_get_mbedtls_peer_info(ep))) {
    if (info->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
      LOG_ERR("DTLS handshake not complete yet!\n");
      return -1;
    }
  } else {
    LOG_ERR("Unable to find DTLS peer ");
    LOG_ERR_COAP_EP(ep);
    LOG_ERR("\n");
    return -1;
  }

  do {
    ret = mbedtls_ssl_write(&info->ssl, message, len);
  } while(ret == MBEDTLS_ERR_SSL_WANT_READ ||
      ret == MBEDTLS_ERR_SSL_WANT_WRITE);

  if(ret < 0) {
    LOG_ERR("mbedtls_ssl_write returned -0x%x\n", ret);
    return -1;
  }

  return len;
}
/*---------------------------------------------------------------------------*/
  int
coap_ep_mbedtls_handle_message(const coap_endpoint_t *ep)
{
  mbedtls_peer_info_t *peer_info = NULL; 
  int ret;
  int len;

  if (NULL != (peer_info = coap_ep_get_mbedtls_peer_info(ep))) {
    /* Handle handshake messages */
    if (peer_info->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
      ret = mbedtls_ssl_handshake(&peer_info->ssl);
      LOG_DBG("DTLS handshake returned %x in %s\n", 
          (unsigned int)-ret, __func__);
      return -1;
    }
  } else {
    LOG_ERR("DTLS peer ");
    LOG_ERR_COAP_EP(ep);
    LOG_ERR("not registered!\n");
    return -1;
  }

  len = sizeof(data_buf) - 1;
  memset(data_buf, 0, sizeof(data_buf));

  ret = mbedtls_ssl_read(&peer_info->ssl, data_buf, len);

  if(ret <= 0) {
    LOG_DBG("mbedtls_ssl_read returned -0x%x\n", (unsigned int)-ret);
  }

  len = ret;
  data_buf[len] = '\0';
  LOG_DBG(" %d bytes read\n\n%s\n\n", len, data_buf);

  return 0;
}
/*---------------------------------------------------------------------------*/
  void 
coap_ep_mbedtls_disconnect(const coap_endpoint_t *ep)
{
  mbedtls_peer_info_t *info = NULL; 

  if (NULL != (info = coap_ep_get_mbedtls_peer_info(ep))) {
    list_remove(mbedtls_context.peer_info_list, info);
    memb_free(&mbedtls_peer_info_memb, info);
  }
}
/*---------------------------------------------------------------------------*/
/** @} */
