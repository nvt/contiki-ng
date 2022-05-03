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
#define COAP_MAX_CHUNK_SIZE            64

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

#define HEAPMEM_CONF_ARENA_SIZE 1024 * 50

#define HEAPMEM_CONF_ALIGNMENT sizeof(uint64_t)

/* DTLS configurations */
#define LWM2M_SERVER_ADDRESS "coaps://[fe80::f6ce:364d:c62e:6c68]"

#ifdef COAP_DTLS_CONF_WITH_CERT
#define COAP_DTLS_TEST_CA_CERT  \
"-----BEGIN CERTIFICATE-----\r\n"                                       \
"MIICOzCCAeGgAwIBAgIUfzfBiH6jO1KBjj9oKdX5+l5mcpMwCgYIKoZIzj0EAwIw\r\n"  \
"czELMAkGA1UEBhMCSU4xEzARBgNVBAgMClNvbWUtU3RhdGUxDTALBgNVBAoMBFJJ\r\n"  \
"U0UxDTALBgNVBAsMBFNJQ1MxEDAOBgNVBAMMB2ZkMDA6OjExHzAdBgkqhkiG9w0B\r\n"  \
"CQEWEGVqYXllbkBnbWFpbC5jb20wHhcNMjIwMzA4MTkzNzEyWhcNMzIwMzA1MTkz\r\n"  \
"NzEyWjBzMQswCQYDVQQGEwJJTjETMBEGA1UECAwKU29tZS1TdGF0ZTENMAsGA1UE\r\n"  \
"CgwEUklTRTENMAsGA1UECwwEU0lDUzEQMA4GA1UEAwwHZmQwMDo6MTEfMB0GCSqG\r\n"  \
"SIb3DQEJARYQZWpheWVuQGdtYWlsLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEH\r\n"  \
"A0IABL4Q/r8TZ59ekfn4DO7zd7uEnohDWU0tHb681RatPzBfK9VIyaMEKfRzA7kV\r\n"  \
"Ym1zZmUUEREJ/iY9U5UbRD4fcQajUzBRMB0GA1UdDgQWBBQPRsxpJT52d06eUETD\r\n"  \
"dkTSks75pjAfBgNVHSMEGDAWgBQPRsxpJT52d06eUETDdkTSks75pjAPBgNVHRMB\r\n"  \
"Af8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQDgH5j1AtKkq7WXL4qft4CmyQNb\r\n"  \
"IU11hu3Sz5bYYnez5QIgLV2zZLzkSdDreIxgq5zE9WDdn9U9Uvmp++ASMb0tBSs=\r\n"  \
"-----END CERTIFICATE-----\r\n"  

#define COAP_DTLS_TEST_CLIENT_CERT  \
"-----BEGIN CERTIFICATE-----\r\n"                                      \
"MIIB3TCCAYQCFCBMicgvp2utdFNtIszhVqvHi3gdMAoGCCqGSM49BAMCMHMxCzAJ\r\n" \
"BgNVBAYTAklOMRMwEQYDVQQIDApTb21lLVN0YXRlMQ0wCwYDVQQKDARSSVNFMQ0w\r\n" \
"CwYDVQQLDARTSUNTMRAwDgYDVQQDDAdmZDAwOjoxMR8wHQYJKoZIhvcNAQkBFhBl\r\n" \
"amF5ZW5AZ21haWwuY29tMB4XDTIyMDMwODIzMTgzMFoXDTMyMDMwNTIzMTgzMFow\r\n" \
"cDELMAkGA1UEBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCQU5HQUxPUkUx\r\n" \
"DTALBgNVBAoMBFJJU0UxEDAOBgNVBAMMB2NvbnRpa2kxHzAdBgkqhkiG9w0BCQEW\r\n" \
"EGVqYXllbkBnbWFpbC5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASdmneT\r\n" \
"AUGfgQ1Z2quiKG1z2/xQysD9qGEaGGMRe7OEqs8FUkYtbJcUBO21qP3OWTVG+1Eb\r\n" \
"J11UJ1yIAVIb7DfdMAoGCCqGSM49BAMCA0cAMEQCIG5KDar1EzCwKFKvxwGe8Uyx\r\n" \
"DiD/GlwBvkyrZmxiuH+BAiArfQpzUofZIlOeRs05u1Sb3GXGzSOMtMiNSGip/to1\r\n" \
"JQ==\r\n"                                                             \
"-----END CERTIFICATE-----\r\n"

#define COAP_DTLS_TEST_CLIENT_KEY  \
"-----BEGIN EC PRIVATE KEY-----\r\n"                                    \
"MHcCAQEEID56YGjTjDnooB5Kp3tq7UtrJX118HGpfctUnXn58PDZoAoGCCqGSM49\r\n"  \
"AwEHoUQDQgAEnZp3kwFBn4ENWdqroihtc9v8UMrA/ahhGhhjEXuzhKrPBVJGLWyX\r\n"  \
"FATttaj9zlk1RvtRGyddVCdciAFSG+w33Q==\r\n"                              \
"-----END EC PRIVATE KEY-----\r\n"
#else /* COAP_DTLS_CONF_WITH_CERT */
#define COAP_DTLS_PSK_DEFAULT_IDENTITY "Client_identity"
#define COAP_DTLS_PSK_DEFAULT_KEY      "secretPSK"
#endif /* COAP_DTLS_CONF_WITH_CERT */

/* Number of DTLS peers --  LwM2M servers */
#define COAP_DTLS_CONF_MAX_PEERS 1

//#define LOG_CONF_LEVEL_LWM2M LOG_LEVEL_DBG
//#define LOG_CONF_LEVEL_DTLS LOG_LEVEL_DBG

#define LOG_CONF_LEVEL_IPV6 LOG_LEVEL_WARN
#define LOG_CONF_LEVEL_TCPIP LOG_LEVEL_INFO
#define LOG_CONF_LEVEL_6LOWPAN LOG_LEVEL_WARN
#define LOG_CONF_LEVEL_MAIN LOG_LEVEL_WARN
//#define LOG_CONF_LEVEL_MAC LOG_LEVEL_WARN

#endif /* PROJECT_CONF_H_ */
