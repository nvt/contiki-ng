/*
 * Copyright (c) 2022, RISE Research Institutes of Sweden AB
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

/**
 * \file
 *		Mbed TLS library configuration for CoAP
 *
 * \Author
 *		Jayendra Ellamathy <ejayen@gmail.com>
 */

#include "dtls-config.h"
#include "lib/heapmem.h"

/* Basic settings */
#define MBEDTLS_SSL_TLS_C

/* RNG Support */
#ifndef CONTIKI_TARGET_NATIVE
#define MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES
#define MBEDTLS_NO_PLATFORM_ENTROPY
#endif /* CONTIKI_TARGET_NATIVE */
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_CTR_DRBG_C

#ifdef COAP_DTLS_CONF_WITH_CERT
#define MBEDTLS_HMAC_DRBG_C
#endif /* COAP_DTLS_CONF_WITH_CERT */

/* RFC 7925 profile */
#define MBEDTLS_SSL_PROTO_DTLS
#define MBEDTLS_SSL_PROTO_TLS1_2
#ifdef COAP_DTLS_CONF_WITH_PSK
#define MBEDTLS_KEY_EXCHANGE_PSK_ENABLED
#endif /* COAP_DTLS_CONF_WITH_PSK */
#ifdef COAP_DTLS_CONF_WITH_CERT
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_OID_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PK_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_ECP_NIST_OPTIM
#define MBEDTLS_ECDSA_DETERMINISTIC
#endif /* COAP_DTLS_CONF_WITH_CERT */
#define MBEDTLS_AES_C
#define MBEDTLS_CCM_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_MD_C
#define MBEDTLS_CIPHER_C

/* DTLS */
#define MBEDTLS_SSL_DTLS_ANTI_REPLAY
#define MBEDTLS_SSL_DTLS_HELLO_VERIFY

/* I/O message buffer sizes */
#define MBEDTLS_SSL_IN_CONTENT_LEN COAP_MBEDTLS_MTU
#define MBEDTLS_SSL_OUT_CONTENT_LEN COAP_MBEDTLS_MTU
#define MBEDTLS_SSL_DTLS_MAX_BUFFERING (2 * COAP_MBEDTLS_MTU)

/* Networking */
/*#define MBEDTLS_NET_C //TODO */

/* Client Role */
#ifdef COAP_DTLS_CONF_WITH_CLIENT
#define MBEDTLS_SSL_CLI_C
/*#define MBEDTLS_SSL_SERVER_NAME_INDICATION */
#endif /* COAP_DTLS_CONF_WITH_CLIENT */

/* Server Role */
#ifdef COAP_DTLS_CONF_WITH_SERVER
#define MBEDTLS_SSL_SRV_C
#define MBEDTLS_SSL_COOKIE_C
#define MBEDTLS_SSL_CACHE_C
#endif /* COAP_DTLS_CONF_WITH_SERVER */

#if 0 /* Disable to save memory */
/* Debugging */
#define MBEDTLS_DEBUG_C
#define MBEDTLS_ERROR_C
#define MBEDTLS_SSL_ALL_ALERT_MESSAGES
#define MBEDTLS_SSL_DEBUG_ALL
#endif

/* IoT features */
#define MBEDTLS_SSL_MAX_FRAGMENT_LENGTH

/* HW Acceleration */
#ifdef COAP_DTLS_CONF_WITH_CERT
#ifdef NRF52840_XXAA /* Curr. only for nRF52840 */
#define NRF_HW_ACCEL_FOR_MBEDTLS
#define MBEDTLS_ECDSA_VERIFY_ALT
#define MBEDTLS_ECDH_COMPUTE_SHARED_ALT
#endif /* NRF52840_XXAA */
#endif /* COAP_DTLS_CONF_WITH_CERT */

/* Use the Contiki-NG HeapMem module for Mbed TLS dynamic memory. */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_CALLOC_MACRO heapmem_calloc
#define MBEDTLS_PLATFORM_FREE_MACRO heapmem_free

/*#include "mbedtls/config.h" //TODO: decide best place to add/include */
#include "mbedtls/build_info.h"
/*#include "mbedtls/check_config.h" //TODO: when to do the checking? */
