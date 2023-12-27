# Building CoAP with DTLS support

The DTLS functionality for CoAP in Contiki-NG is based on the Mbed TLS
library. When building a CoAP application with DTLS support, one
should set the `MAKE_WITH_DTLS` compilation flag to 1.

Furthermore, the DTLS compilation can be configured as follows.
* Security mode selection:
    1. `MAKE_COAP_DTLS_WITH_CERT=1`  (Certificate-based)
    2. `MAKE_COAP_DTLS_WITH_PSK=1` (Pre-Shared Keys)
* Role selection:
    1. `MAKE_COAP_DTLS_WITH_CLIENT=1` (Client)
    2. `MAKE_COAP_DTLS_WITH_SERVER=1` (Server)

For example, to compile a DTLS client with certificate support, one
can run the following command. `make MAKE_WITH_DTLS=1
MAKE_COAP_DTLS_WITH_CERT=1 MAKE_COAP_DTLS_WITH_CLIENT=1`

# Mbed TLS configuration

Files: 

* The DTLS implementation configuration is placed in
  mbedtls-support/dtls-config.h.
  
* The Mbed TLS library configuration is placed in
  mbedtls-support/mbedtls-config.h.

* Interfaces for the DTLS implementation usage are placed in
  mbedtls-support/mbedtls-support.h, and their corresponding
  implementation in mbedtls-support/mbedtls-support.c.

# Network stack configuration

* The uIP buffer size, which is configurable through
  `UIP_CONF_BUFFER_SIZE`, must be set to be longer than the longest
  Mbed TLS handshake (HS) message size (e.g., ~1000 bytes for
  TLS-ECDHE-ECDSA-WITH-AES-128-CCM-8 ciphersuite based HS). The
  longest message can be found with the help of IPv6 debug logs, which
  is configurable through `LOG_CONF_LEVEL_TCPIP`.

* The number of queue buffers, which is configurable through
  `QUEUEBUF_CONF_NUM`, must be sufficient to handle the fragmentation
  of the longest Mbed TLS HS message (e.g., 11 for
  TLS-ECDHE-ECDSA-WITH-AES-CCM-8 ciphersuite based HS on the
  server-side). The maximum number of fragments can be found with the
  help of 6LoWPAN debug logs, which is configurable through
  `LOG_CONF_LEVEL_6LOWPAN`.

* These long HS messages can be fragmented by using the Maximum
  Fragment Length (MFL) extension configured to a size of 512 through
  `COAP_MBEDTLS_CONF_MAX_FRAG_LEN`. In this case, the uIP buffer can
  be reduced to ~600 and the number of queue buffers to 7 for the
  TLS-ECDHE-ECDSA-WITH-AES-CCM-8 ciphersuite based HS.

* While using fragmentation, it might be necessary to use an interval
  between the sending of consecutive fragmented messages to avoid
  choking of a limited queue buffer. This is configurable through
  `COAP_MBEDTLS_FRAGMENT_TIMER`.

# System configuration

Depending on the Contiki-NG platform being used, additional system
configurations options may need to be changed.

## Watchdog time-out configuration

Generally, ECC operations during the HS take a long time on embedded
platforms (~5s on the nRF52840). The user must ensure that the
watchdog timeout is configured longer than this.

## Dynamic memory requirement

Mbed TLS is configured to use the heapmem library in Contiki-NG for
its dynamic memory. The amount of usage can be found out with the help
of memory evaluation debug logs, which is configurable through
`COAP_MBEDTLS_MEM_EVALUATION`. The size allocated for the heapmem
module is configurable through `HEAPMEM_CONF_ARENA_SIZE`.

