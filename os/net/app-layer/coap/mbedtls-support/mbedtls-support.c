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
 *		DTLS(MbedTLS implementation) support for CoAP
 *			
 * \Author 
 *		Jayendra Ellamathy <ejayen@gmail.com> 
 */

#include "contiki.h"
#include "contiki-net.h"
#include "sys/rtimer.h"

#include "mbedtls-support.h"

/* Log configuration */
#define LOG_MODULE "DTLS"
#define LOG_LEVEL_DTLS LOG_LEVEL_ERR
#define LOG_LEVEL LOG_LEVEL_DTLS
#include "coap-log.h"

#ifdef COAP_DTLS_CONF_MAX_PEERS 
#define COAP_DTLS_MAX_PEERS COAP_DTLS_CONF_MAX_PEERS 
#else /* COAP_DTLS_CONF_MAX_PEERS */
#define COAP_DTLS_MAX_PEERS 1
#endif /* COAP_DTLS_CONF_MAX_PEERS */

#ifdef COAP_DTLS_CONF_SEND_BUF_SIZE 
#define COAP_DTLS_SEND_BUF_SIZE COAP_DTLS_CONF_SEND_BUF_SIZE 
#else /* COAP_DTLS_CONF_SEND_BUF_SIZE */
#define COAP_DTLS_SEND_BUF_SIZE 3
#endif /* COAP_DTLS_CONF_SEND_BUF_SIZE */

unsigned char data_buf1[512];

mbedtls_peer_info_t *curr_peer;
unsigned char send_buf[MBEDTLS_SSL_OUT_CONTENT_LEN];
uint16_t packet_cnt; 
uint16_t packet_length[20];
uint16_t total_send_length; 

MEMB(mbedtls_peer_info_memb, mbedtls_peer_info_t, COAP_DTLS_MAX_PEERS);
static mbedtls_context_t mbedtls_context; 

/*---------------------------------------------------------------------------*/
#if defined(MBEDTLS_DEBUG_C)
static void 
mbedtls_debug(void *ctx, int level, 
    const char *file, int line, const char *str)
{
#if 0 
    /* Note: possible to add filename and line number */
    if(level == 1) {
      LOG_ERR("%s", str);
    } else if(level == 2) {
      LOG_INFO("State change: %s", str);
    } else if(level == 3) {
      LOG_INFO("%s", str);
    } else { 
      LOG_DBG("%s", str);
    }
#endif 
    printf("%s", str);
}
#endif
/*---------------------------------------------------------------------------*/
static int 
random_number_generator(void *ctx, unsigned char *buffer, size_t length)
{
  uint16_t rand_num = 0; 
  size_t len = 0;

  while(length < (len + sizeof(rand_num))) {
    rand_num = random_rand();
    memcpy(buffer + len, &rand_num, sizeof(rand_num));
    len += sizeof(rand_num);
  }
  rand_num = random_rand();
  memcpy(buffer, &rand_num, length - len);
  printf("Generated random bytes of length = %d\n", length);
  int i;
  for (i = 0; i < length; i++) {
    printf("%u ", buffer[i]);
  }
  printf("\n");

  return 0;
}
/*---------------------------------------------------------------------------*/
void 
coap_mbedtls_init()
{
  int ret;
  //TODO: What does pers do?
  const char *pers = "dtls_client";

#if defined(MBEDTLS_DEBUG_C)
  mbedtls_debug_set_threshold(MBEDTLS_LIB_DEBUG_LEVEL);
#endif

#if !defined(MBEDTLS_SSL_CLI_C) || !defined(MBEDTLS_SSL_PROTO_DTLS) || \
  !defined(MBEDTLS_NET_C) || !defined(MBEDTLS_TIMING_C) || \
  !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C) || \
  !defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED) 
  LOG_ERR("MBEDTLS_SSL_CLI_C and/or MBEDTLS_SSL_PROTO_DTLS and/or "
      "MBEDTLS_NET_C and/or MBEDTLS_TIMING_C and/or "
      "MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C and/or"
      "MBEDTLS_KEY_EXCHANGE_PSK_ENABLED not defined.\n");
#endif 

#ifdef COAP_DTLS_CONF_WITH_CERT
#if !defined(MBEDTLS_X509_CRT_PARSE_C) || \
  !defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED) || \
  !defined(MBEDTLS_PEM_PARSE_C)
  LOG_ERR("MBEDTLS_X509_CRT_PARSE_C and/or "
      "MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED and/or "
      "MBEDTLS_PEM_PARSE_C not defined.\n");
#endif 
#endif /* COAP_DTLS_CONF_WITH_CERT */

  LIST_STRUCT_INIT(&mbedtls_context, peer_info_list);

  //TODO; Can these two be global info?  
  mbedtls_ctr_drbg_init(&mbedtls_context.ctr_drbg);
  mbedtls_entropy_init(&mbedtls_context.entropy);

#if 0 
  LOG_DBG("Seeding the random number generator...\n");
  if((ret = mbedtls_ctr_drbg_seed(&mbedtls_context.ctr_drbg, 
          mbedtls_entropy_func, 
          &mbedtls_context.entropy,
          (const unsigned char *)pers,
          strlen(pers))) != 0) {
    LOG_ERR("mbedtls_ctr_drbg_seed returned %d\n", ret);
    goto cleanup;
  }
#endif 

  /* DTLS context initialised and ready */
  mbedtls_context.ready = 1;
  return;

cleanup: 
  mbedtls_ctr_drbg_free(&mbedtls_context.ctr_drbg);
  mbedtls_entropy_free(&mbedtls_context.entropy);
  return;
}
/*---------------------------------------------------------------------------*/
void //Add NULL check for this -- what if conn is closed and a packet is recieved 
coap_mbedtls_conn_init(struct uip_udp_conn *udp_conn)
{
  mbedtls_context.udp_conn = udp_conn;
}
/*---------------------------------------------------------------------------*/
int 
coap_ep_is_mbedtls_peer(const coap_endpoint_t *ep)
{
  mbedtls_peer_info_t *info = NULL; 

  for(info = list_head(mbedtls_context.peer_info_list); 
      info; info = info->next) {
    if(coap_endpoint_cmp(&info->ep, ep)) {
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

  for(info = list_head(mbedtls_context.peer_info_list); 
      info; info = info->next) {
    if(coap_endpoint_cmp(&info->ep, ep)) {
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

  if((info = coap_ep_get_mbedtls_peer_info(ep)) != NULL) {
    if(info->ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER) {
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

  if((info = coap_ep_get_mbedtls_peer_info(ep)) != NULL) {
    return info->ssl.state;
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
extern struct process coap_engine;
void 
coap_ep_mbedtls_poll_send_data()
{
  int i;

  uip_udp_packet_sendto(mbedtls_context.udp_conn, send_buf, packet_length[0], 
      &curr_peer->ep.ipaddr, curr_peer->ep.port);
  
  memmove(send_buf, send_buf + packet_length[0], 
      total_send_length - packet_length[0]);
  total_send_length = total_send_length - packet_length[0];
  packet_cnt--;
  for (i = 1; i < packet_cnt; i++) {
    packet_length[i - 1] = packet_length[i];
  }

  if (total_send_length != 0) {
    process_poll(&coap_engine);
  }
}
/*---------------------------------------------------------------------------*/
static int 
coap_ep_mbedtls_sendto(void *ctx, const unsigned char *buf, size_t len)
{
  mbedtls_peer_info_t *peer_info = (mbedtls_peer_info_t *) ctx;

  if(!peer_info) {
    return MBEDTLS_ERR_NET_INVALID_CONTEXT;
  }
  
  if ((total_send_length + len) > MBEDTLS_SSL_OUT_CONTENT_LEN) {
    return MBEDTLS_ERR_SSL_WANT_WRITE;
  }

  curr_peer = coap_ep_get_mbedtls_peer_info(&peer_info->ep);
  memcpy(send_buf + total_send_length, buf, len);
  packet_length[packet_cnt] = len;
  total_send_length += len;
  packet_cnt++;

#if 0 
  uip_udp_packet_sendto(mbedtls_context.udp_conn, buf, len, 
      &peer_info->ep.ipaddr, peer_info->ep.port);
#endif 
  process_poll(&coap_engine);

  return len;
}
/*---------------------------------------------------------------------------*/
static int 
coap_ep_mbedtls_recv(void *ctx, unsigned char *buf, size_t len)
{
  mbedtls_peer_info_t *peer_info = (mbedtls_peer_info_t *) ctx;

  if(!peer_info) {
    return MBEDTLS_ERR_NET_INVALID_CONTEXT;
  }

  if(uip_datalen() == 0) {
    return MBEDTLS_ERR_SSL_WANT_READ;
  }
  
  if(peer_info->is_packet_consumed == 1) {
    return MBEDTLS_ERR_SSL_WANT_READ;
  }
  
  //TODO: Leave a comment about fragmentation length 
  if(len < uip_datalen()) {
    LOG_ERR("DTLS incoming buffer too small, len = %d, uip_datalen = %d\n", 
        (unsigned int)len, uip_datalen());
    return 0;
  }
  
  memcpy(buf, uip_appdata, uip_datalen());
  peer_info->is_packet_consumed = 1;
  
  return uip_datalen(); 
}
/*---------------------------------------------------------------------------*/
int 
coap_ep_mbedtls_connect(const coap_endpoint_t *ep, 
    coap_mbedtls_sec_mode_t sec_mode, const void *keystore_entry)
{
  rtimer_clock_t  start = RTIMER_NOW();
  rtimer_clock_t end = 0; 
  rtimer_clock_t total = 0; 
  mbedtls_peer_info_t *peer_info = NULL; 
  int ret;
    
  if(!mbedtls_context.ready) {
    LOG_WARN("DTLS not initialized but %s called!\n", __func__);
    return 0;
  }

  /* Create peer info if it does not exist already */
  if((peer_info = coap_ep_get_mbedtls_peer_info(ep)) == NULL) {
    peer_info = memb_alloc(&mbedtls_peer_info_memb);
    if(!peer_info) {
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
      /* Maybe func. called prematurely */
      return 0;
    }
  }

  memcpy(&peer_info->ep, ep, sizeof(coap_endpoint_t));

  /* Init mbedtls structs */
  mbedtls_ssl_init(&peer_info->ssl);
  mbedtls_ssl_config_init(&peer_info->conf);
#ifdef COAP_DTLS_CONF_WITH_CERT
  if(sec_mode == COAP_MBEDTLS_SEC_MODE_CERT) {
    mbedtls_x509_crt_init(&peer_info->cacert);
    mbedtls_x509_crt_init(&peer_info->clicert);
    mbedtls_pk_init(&peer_info->pkey);
  }
#endif /* COAP_DTLS_CONF_WITH_CERT */

  /* Configure as client, over DTLS protocol */
  if((ret = mbedtls_ssl_config_defaults(&peer_info->conf,
          MBEDTLS_SSL_IS_CLIENT,
          MBEDTLS_SSL_TRANSPORT_DATAGRAM,
          MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    LOG_ERR("mbedtls_ssl_config_defaults returned %d\n", ret);
    goto clean_and_ret_err;
  }

  //TODO: Change this to a user-configurable parameter 
  mbedtls_ssl_conf_authmode(&peer_info->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_rng(&peer_info->conf, 
      //mbedtls_ctr_drbg_random, 
      random_number_generator, 
      &mbedtls_context.ctr_drbg);
#ifdef COAP_DTLS_CONF_WITH_CERT 
  if(sec_mode == COAP_MBEDTLS_SEC_MODE_CERT) {
    coap_keystore_cert_entry_t *ks = 
      (coap_keystore_cert_entry_t *) keystore_entry;
  
    /* Load the root CA certificate */
    ret = mbedtls_x509_crt_parse(&peer_info->cacert, 
        (const unsigned char *) ks->ca_cert,
        ks->ca_cert_len);

    if(ret < 0) {
      LOG_ERR("mbedtls_x509_crt_parse returned -0x%x\n", 
          (unsigned int) -ret );
      goto clean_and_ret_err;
    }
  
    /* Load the client certificate */
    ret = mbedtls_x509_crt_parse(&peer_info->clicert, 
        (const unsigned char *) ks->client_cert,
        ks->client_cert_len);

    if(ret < 0) {
      LOG_ERR("mbedtls_x509_crt_parse returned -0x%x\n", 
          (unsigned int) -ret );
      goto clean_and_ret_err;
    }
  
    /* Load the client private key */
    ret = mbedtls_pk_parse_key(&peer_info->pkey, 
        (const unsigned char *) ks->client_key, ks->client_key_len, NULL, 0);

    if(ret < 0) {
      LOG_DBG("mbedtls_pk_parse_key returned -0x%x\n", 
          (unsigned int) -ret );
      goto clean_and_ret_err;
    }

    mbedtls_ssl_conf_ca_chain(&peer_info->conf, &peer_info->cacert, NULL);
    if((ret = mbedtls_ssl_conf_own_cert(&peer_info->conf, 
            &peer_info->clicert, &peer_info->pkey)) != 0) {
      LOG_ERR( "mbedtls_ssl_conf_own_cert returned %d\n", ret );
      goto clean_and_ret_err;
    }
  } else 
#endif /* COAP_DTLS_CONF_WITH_CERT */
  if(sec_mode == COAP_MBEDTLS_SEC_MODE_PSK) {
    coap_keystore_psk_entry_t *ks = 
      (coap_keystore_psk_entry_t *) keystore_entry;

    if(ks->identity == NULL || ks->key == NULL) {
      LOG_ERR("PSK identity or key missing\n");
      goto clean_and_ret_err;
    }

    mbedtls_ssl_conf_psk(&peer_info->conf, 
        (const unsigned char *)ks->key, 
        ks->key_len, 
        (const unsigned char *)ks->identity, 
        ks->identity_len);
  } 

#if defined(MBEDTLS_DEBUG_C)
  mbedtls_ssl_conf_dbg(&peer_info->conf, mbedtls_debug, stdout);
#endif 
  mbedtls_ssl_conf_handshake_timeout(&peer_info->conf, 
      HANDHSAKE_MIN_TIMEOUT, HANDSHAKE_MAX_TIMEOUT);
  mbedtls_ssl_conf_read_timeout(&peer_info->conf, READ_TIMEOUT_MS);
  mbedtls_ssl_conf_max_frag_len(&peer_info->conf, MBEDTLS_SSL_MAX_FRAG_LEN_512);

  if((ret = mbedtls_ssl_setup(&peer_info->ssl, &peer_info->conf)) != 0) {
    LOG_ERR("mbedtls_ssl_setup returned -0x%x\n", (unsigned int)-ret);
    goto clean_and_ret_err;
  }

  mbedtls_ssl_set_mtu(&peer_info->ssl, UIP_CONF_BUFFER_SIZE - UIP_UDPH_LEN);

#if 0 
  //TODO: This is only needed for certificate based, right? 
  if((ret = mbedtls_ssl_set_hostname(&peer_info->ssl, 
          peer_info->hostname)) != 0) {
    LOG_ERR("mbedtls_ssl_set_hostname returned %d\n", ret);
    return 0;
  }
#endif 

  mbedtls_ssl_set_bio(&peer_info->ssl, 
      peer_info,
      coap_ep_mbedtls_sendto,
      coap_ep_mbedtls_recv, 
      NULL);
  //mbedtls_net_recv_timeout -- TODO -- Is this needed? 

  mbedtls_ssl_set_timer_cb(&peer_info->ssl, 
      &peer_info->timer, 
      mbedtls_timing_set_delay,
      mbedtls_timing_get_delay);

  //TODO -- How did we choose the value of these timers?

  mbedtls_ssl_set_mtu(&peer_info->ssl, UIP_CONF_BUFFER_SIZE - UIP_UDPH_LEN);

perform_handshake:
  ret = mbedtls_ssl_handshake(&peer_info->ssl);
  end = RTIMER_NOW();
  total = end - start;
  LOG_DBG("DTLS handshake time(usec) = %lu\n", 
      (uint32_t)((uint64_t)total * 1000000 / RTIMER_SECOND));
  LOG_DBG("DTLS handshake returned %x in %s\n", 
      (unsigned int)-ret, __func__);
  return 1;

clean_and_ret_err: 
  list_remove(mbedtls_context.peer_info_list, peer_info);
  memb_free(&mbedtls_peer_info_memb, peer_info);
  return 0;
}
/*---------------------------------------------------------------------------*/
int 
coap_ep_mbedtls_write(const coap_endpoint_t *ep, 
    const unsigned char *message, int len)
{
  mbedtls_peer_info_t *info = NULL; 
  int ret;

  if(!mbedtls_context.ready) {
    LOG_WARN("DTLS not initialized but %s called!\n", __func__);
    return -1;
  }

  if((info = coap_ep_get_mbedtls_peer_info(ep)) != NULL) {
    if (info->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
      LOG_ERR("DTLS handshake not complete yet, but %s called!\n", __func__);
      return -1;
    }
  } else {
    LOG_ERR("Unable to find DTLS peer ");
    LOG_ERR_COAP_EP(ep);
    LOG_ERR("\n");
    return -1;
  }

  //TODO; Why do we need a want read here?
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
  rtimer_clock_t start = RTIMER_NOW();
  rtimer_clock_t end = 0; 
  rtimer_clock_t total = 0; 

  mbedtls_peer_info_t *peer_info = NULL; 
  int ret;
  int len;

  if(!mbedtls_context.ready) {
      LOG_WARN("DTLS not initialized but %s called!\n", __func__);
      return -1;
  }
  
  if ((peer_info = coap_ep_get_mbedtls_peer_info(ep)) != NULL) {
    peer_info->is_packet_consumed = 0;
    /* Handle handshake message first */
    if (peer_info->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
      ret = mbedtls_ssl_handshake(&peer_info->ssl);
      end = RTIMER_NOW();
      total = end - start;
      LOG_DBG("DTLS handshake time(usec) = %lu\n", 
      (uint32_t)((uint64_t)total * 1000000 / RTIMER_SECOND));
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

  len = sizeof(data_buf1) - 1;
  memset(data_buf1, 0, sizeof(data_buf1));

  ret = mbedtls_ssl_read(&peer_info->ssl, data_buf1, len);

  if(ret <= 0) {
    switch(ret) {
    case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
      //TODO: We need to send a close notify as well
      //TODO: Add debug message 
      list_remove(mbedtls_context.peer_info_list, peer_info);
      memb_free(&mbedtls_peer_info_memb, peer_info);
      break;
    default:
      //TODO: Convert the error message into prints using the MbedTLS lib 
      //use __func__ instead 
      LOG_DBG("mbedtls_ssl_read returned -0x%x\n", (unsigned int)-ret);
    }
  }

  len = ret;
  LOG_DBG(" %d bytes read\n\n%s\n\n", len, data_buf1);

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
