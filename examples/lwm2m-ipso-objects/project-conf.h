/*
 * Copyright (c) 2015, Yanzi Networks AB.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *    3. Neither the name of the copyright holder nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

#ifdef BOARD_STRING
#define LWM2M_DEVICE_MODEL_NUMBER BOARD_STRING
#elif defined(CONTIKI_TARGET_WISMOTE)
#include "dev/watchdog.h"
#define LWM2M_DEVICE_MODEL_NUMBER "LWM2M_DEVICE_MODEL_NUMBER"
#define LWM2M_DEVICE_MANUFACTURER "LWM2M_DEVICE_MANUFACTURER"
#define LWM2M_DEVICE_SERIAL_NO    "LWM2M_DEVICE_SERIAL_NO"
#define PLATFORM_REBOOT watchdog_reboot
#endif

#if BOARD_SENSORTAG
/* Real sensor is present... */
#else
#define IPSO_TEMPERATURE example_ipso_temperature
#endif /* BOARD_SENSORTAG */

/* Increase rpl-border-router IP-buffer when using more than 64. */
#define COAP_MAX_CHUNK_SIZE           200

/* Multiplies with chunk size, be aware of memory constraints. */
#define COAP_MAX_OPEN_TRANSACTIONS     4

/* Filtering .well-known/core per query can be disabled to save space. */
#define COAP_LINK_FORMAT_FILTERING     0
#define COAP_PROXY_OPTION_PROCESSING   0

/* Enable client-side support for COAP observe */
#define COAP_OBSERVE_CLIENT 1

/* Definitions to enable Queue Mode, include the dynamic adaptation and change the default parameters  */
/* #define LWM2M_QUEUE_MODE_CONF_ENABLED 1
   #define LWM2M_QUEUE_MODE_CONF_INCLUDE_DYNAMIC_ADAPTATION 1
   #define LWM2M_QUEUE_MODE_CONF_DEFAULT_CLIENT_AWAKE_TIME 2000
   #define LWM2M_QUEUE_MODE_CONF_DEFAULT_CLIENT_SLEEP_TIME 10000
   #define LWM2M_QUEUE_MODE_CONF_DEFAULT_DYNAMIC_ADAPTATION_FLAG 0
   #define LWM2M_QUEUE_MODE_OBJECT_CONF_ENABLED 1 */


/* Dynamic mem needed for Mbed TLS library operation */
#define HEAPMEM_CONF_ARENA_SIZE 1024 * 30
#define HEAPMEM_CONF_ALIGNMENT sizeof(uint64_t)

/* DTLS configurations */
//#define LWM2M_SERVER_ADDRESS "coaps://[fe80::f6ce:364d:c62e:6c68]"
//#define LWM2M_SERVER_ADDRESS "coaps://[fe80::f6ce:3606:5e1d:d8e4]"
#define LWM2M_SERVER_ADDRESS "coaps://[fd00::1]" // Border-router + Leshan 


#ifdef COAP_DTLS_CONF_WITH_CERT
#define COAP_DTLS_TEST_CA_CERT  \
"-----BEGIN CERTIFICATE-----\r\n" \
"MIICITCCAcYCCQDfbROysgtSGzAKBggqhkjOPQQDAjCBljELMAkGA1UEBhMCU0Ux\r\n" \
"EjAQBgNVBAgMCVN0b2NraG9sbTEOMAwGA1UEBwwFS2lzdGExEjAQBgNVBAoMCVJJ\r\n" \
"U0UtU0lDUzEfMB0GA1UECwwWQ29ubmVjdGVkLUludGVsbGlnZW5jZTENMAsGA1UE\r\n" \
"AwwEUm9vdDEfMB0GCSqGSIb3DQEJARYQZWpheWVuQGdtYWlsLmNvbTAgFw0yMjA3\r\n" \
"MjgxNDA2MjJaGA8yMTIyMDcwNDE0MDYyMlowgZYxCzAJBgNVBAYTAlNFMRIwEAYD\r\n" \
"VQQIDAlTdG9ja2hvbG0xDjAMBgNVBAcMBUtpc3RhMRIwEAYDVQQKDAlSSVNFLVNJ\r\n" \
"Q1MxHzAdBgNVBAsMFkNvbm5lY3RlZC1JbnRlbGxpZ2VuY2UxDTALBgNVBAMMBFJv\r\n" \
"b3QxHzAdBgkqhkiG9w0BCQEWEGVqYXllbkBnbWFpbC5jb20wWTATBgcqhkjOPQIB\r\n" \
"BggqhkjOPQMBBwNCAAQg8wdkfjxntwOkpK5HYpL4kO7/5LsVFobnU4D8jZlfX/Z8\r\n" \
"Ys+TPUqVmDVwwMXWy6ELs51nOBh8WLvlAC5KVeESMAoGCCqGSM49BAMCA0kAMEYC\r\n" \
"IQCAgRf942+typj1XFq8/4/+msOSE0HmfluR75wfa2PY6AIhAJW0ebNkiNgUKvmW\r\n" \
"fktB3aee55zvJc0piQblFe0OgJ3e\r\n" \
"-----END CERTIFICATE-----\r\n"

#ifdef COAP_DTLS_CONF_WITH_SERVER
#define COAP_DTLS_TEST_OWN_CERT \
"-----BEGIN CERTIFICATE-----\r\n" \
"MIIBpDCCAUkCCQCLI2CsMlVzyTAKBggqhkjOPQQDAjCBljELMAkGA1UEBhMCU0Ux\r\n" \
"EjAQBgNVBAgMCVN0b2NraG9sbTEOMAwGA1UEBwwFS2lzdGExEjAQBgNVBAoMCVJJ\r\n" \
"U0UtU0lDUzEfMB0GA1UECwwWQ29ubmVjdGVkLUludGVsbGlnZW5jZTENMAsGA1UE\r\n" \
"AwwEUm9vdDEfMB0GCSqGSIb3DQEJARYQZWpheWVuQGdtYWlsLmNvbTAgFw0yMjA3\r\n" \
"MjgxNDI5MzNaGA8yMTIyMDcwNDE0MjkzM1owGjEYMBYGA1UEAwwPMC4wLjAuMC8w\r\n" \
"LjAuMC4wMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbqosQlT76df51GPIi9/J\r\n" \
"JQtrPgukBnzH+qKtuZ2z+rZktFHRhm6h1hkl5I7NeymI5uWsKy4JsU2jTpdY05x+\r\n" \
"oTAKBggqhkjOPQQDAgNJADBGAiEAp6bOSfYw9ufBU/4kpxg+0d+harc949ItICXq\r\n" \
"kqaqhI0CIQDPfHeICJcKgYqgk6SxRJ0Gvq73S6XGmIo5t6vpO838Ag==\r\n" \
"-----END CERTIFICATE-----\r\n"
#define COAP_DTLS_TEST_PRIV_KEY \
"-----BEGIN EC PARAMETERS-----\r\n" \
"BggqhkjOPQMBBw==\r\n" \
"-----END EC PARAMETERS-----\r\n" \
"-----BEGIN EC PRIVATE KEY-----\r\n" \
"MHcCAQEEIMp44kGpPZdPsGtGswoNrMhGQx2ea2iD/+1Hh63zXT7poAoGCCqGSM49\r\n" \
"AwEHoUQDQgAEbqosQlT76df51GPIi9/JJQtrPgukBnzH+qKtuZ2z+rZktFHRhm6h\r\n" \
"1hkl5I7NeymI5uWsKy4JsU2jTpdY05x+oQ==\r\n" \
"-----END EC PRIVATE KEY-----\r\n"

#else /* COAP_DTLS_CONF_WITH_SERVER */ 

#define COAP_DTLS_TEST_OWN_CERT \
"-----BEGIN CERTIFICATE-----\r\n" \
"MIIBqDCCAU0CCQCLI2CsMlVzyDAKBggqhkjOPQQDAjCBljELMAkGA1UEBhMCU0Ux\r\n" \
"EjAQBgNVBAgMCVN0b2NraG9sbTEOMAwGA1UEBwwFS2lzdGExEjAQBgNVBAoMCVJJ\r\n" \
"U0UtU0lDUzEfMB0GA1UECwwWQ29ubmVjdGVkLUludGVsbGlnZW5jZTENMAsGA1UE\r\n" \
"AwwEUm9vdDEfMB0GCSqGSIb3DQEJARYQZWpheWVuQGdtYWlsLmNvbTAgFw0yMjA3\r\n" \
"MjgxNDI5MDhaGA8yMTIyMDcwNDE0MjkwOFowHjEcMBoGA1UEAwwTQ29udGlraS1O\r\n" \
"RzM2MDY1RTFERDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJhSKiXGjvzFwe6S\r\n" \
"XJR7Ai9+Ct/8PQVyJjNLAJLFrGBy0ELB8JqnpuaN4xkBoKopq48vOQHl8CvSsxpK\r\n" \
"UhcLrOEwCgYIKoZIzj0EAwIDSQAwRgIhAIOMOq0LvIHgPXUYx/eH7htnXDfevT7a\r\n" \
"c8iN6l55AQsRAiEA/AiLeDdc/YCnjfghBKs8us0kxZp5gXylVOLGtLaluMY=\r\n" \
"-----END CERTIFICATE-----\r\n"
#define COAP_DTLS_TEST_PRIV_KEY \
"-----BEGIN EC PARAMETERS-----\r\n" \
"BggqhkjOPQMBBw==\r\n" \
"-----END EC PARAMETERS-----\r\n" \
"-----BEGIN EC PRIVATE KEY-----\r\n" \
"MHcCAQEEIDhoMzFVUcmwhmlhSWZC4crijj48IvaUslsjWvHWiFNpoAoGCCqGSM49\r\n" \
"AwEHoUQDQgAEmFIqJcaO/MXB7pJclHsCL34K3/w9BXImM0sAksWsYHLQQsHwmqem\r\n" \
"5o3jGQGgqimrjy85AeXwK9KzGkpSFwus4Q==\r\n" \
"-----END EC PRIVATE KEY-----\r\n"

#endif /* COAP_DTLS_CONF_WITH_SERVER */
#else /* COAP_DTLS_CONF_WITH_CERT */

#define COAP_DTLS_PSK_DEFAULT_IDENTITY "Client_identity"
#define COAP_DTLS_PSK_DEFAULT_KEY      "secretPSK"
#endif /* COAP_DTLS_CONF_WITH_CERT */

#define COAP_DTLS_CONF_MAX_PEERS 1
//#define COAP_MBEDTLS_CONF_MTU 200
//#define COAP_MBEDTLS_CONF_MAX_FRAG_LEN 1

#define LOG_CONF_LEVEL_DTLS LOG_LEVEL_DBG
#define COAP_MBEDTLS_LIB_CONF_DEBUG_LEVEL 0 /* Ensure debugs are compiled before 
                                               increasing this value */

//#define COAP_MBEDTLS_EVALUATION //Eval msgs are at LOG_DBG level 
//#define COAP_MBEDTLS_NETWORKING_EVALUATION
//#define COAP_MBEDTLS_TIMING_EVALUATION
//#define COAP_MBEDTLS_MEM_EVALUATION
//#define COAP_MBEDTLS_ENERGY_EVALUATION
//#define ENERGEST_CONF_ON 1 // Needed for energy evaluation 

//#define LOG_CONF_LEVEL_LWM2M LOG_LEVEL_DBG
//#define LOG_CONF_LEVEL_COAP LOG_LEVEL_DBG
//#define LOG_CONF_LEVEL_IPV6 LOG_LEVEL_INFO
//#define LOG_CONF_LEVEL_TCPIP LOG_LEVEL_INFO
//#define LOG_CONF_LEVEL_RPL LOG_LEVEL_INFO 
//#define LOG_CONF_LEVEL_6LOWPAN LOG_LEVEL_INFO
//#define LOG_CONF_LEVEL_MAIN LOG_LEVEL_WARN
//#define LOG_CONF_LEVEL_MAC LOG_LEVEL_INFO
//#define LOG_CONF_LEVEL_FRAMER LOG_LEVEL_INFO

#endif /* PROJECT_CONF_H_ */
