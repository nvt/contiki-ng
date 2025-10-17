# Communication Security

Contiki-NG provides comprehensive security mechanisms at both the link layer (hop-by-hop) and application layer (end-to-end) to protect IoT communications in Low-Power and Lossy Networks (LLNs).

## Security Architecture

```
┌───────────────────────────────────────────────────┐
│         Application Layer (End-to-End)            │
│  ┌──────────────────────────────────────────┐    │
│  │   DTLS 1.2 / CoAPs (Port 5684)           │    │
│  │   - Pre-Shared Keys (PSK)                │    │
│  │   - Certificate-based (Mbed TLS)         │    │
│  └──────────────────────────────────────────┘    │
├───────────────────────────────────────────────────┤
│         Transport Layer                           │
│  ┌──────────────────────────────────────────┐    │
│  │   UDP (CoAP, DNS)                        │    │
│  └──────────────────────────────────────────┘    │
├───────────────────────────────────────────────────┤
│         Network Layer                             │
│  ┌──────────────────────────────────────────┐    │
│  │   IPv6 / 6LoWPAN / RPL                   │    │
│  └──────────────────────────────────────────┘    │
├───────────────────────────────────────────────────┤
│         Link Layer (Hop-by-Hop)                   │
│  ┌──────────────────────────────────────────┐    │
│  │   IEEE 802.15.4 Security (CCM*)          │    │
│  │   - TSCH Security (K1/K2 keys)           │    │
│  │   - CSMA Security                        │    │
│  │   - Hardware AES acceleration            │    │
│  └──────────────────────────────────────────┘    │
└───────────────────────────────────────────────────┘
```

**Security layers:**
- **Link-layer**: Protects all frames between neighbors (hop-by-hop)
- **Application-layer**: Protects application data between endpoints (end-to-end)

**Defense in depth:** Using both layers provides comprehensive protection against different threat models.

## Link-Layer Security (IEEE 802.15.4)

Link-layer security provides hop-by-hop protection using AES-128 in CCM* (Counter with CBC-MAC) mode as defined in IEEE 802.15.4-2015.

### Security Levels

IEEE 802.15.4 defines 8 security levels (0-7):

| Level | Name | Encryption | Authentication | MIC Length | Use Case |
|-------|------|------------|----------------|------------|----------|
| **0** | None | No | No | 0 bytes | No security (testing only) |
| **1** | MIC-32 | No | Yes | 4 bytes | Authentication only |
| **2** | MIC-64 | No | Yes | 8 bytes | Strong authentication |
| **3** | MIC-128 | No | Yes | 16 bytes | Very strong authentication |
| **4** | ENC | Yes | No | 0 bytes | Encryption only (not recommended) |
| **5** | ENC-MIC-32 | Yes | Yes | 4 bytes | **Standard for data (6TiSCH)** |
| **6** | ENC-MIC-64 | Yes | Yes | 8 bytes | Strong encryption + auth |
| **7** | ENC-MIC-128 | Yes | Yes | 16 bytes | Maximum security |

**Recommendations:**
- **Level 5 (ENC-MIC-32)**: Standard for data and ACKs (6TiSCH minimal)
- **Level 1 (MIC-32)**: For beacons (well-known key K1)
- **Never use Level 4**: Encryption without authentication is vulnerable to tampering

### CCM* Mode

CCM* (Counter with CBC-MAC) is an authenticated encryption mode combining:
- **CTR mode** for confidentiality (encryption)
- **CBC-MAC** for authenticity and integrity (MIC)

**Details in IEEE 802.15.4-2015 Annex B** and **NIST SP 800-38C**.

### TSCH Security

TSCH (Time-Slotted Channel Hopping) security follows the 6TiSCH minimal security specification.

**Key architecture:**
- **K1** (well-known key): Used for Enhanced Beacons (EBs)
  - Default: ASCII "6TiSCH minimal15"
  - Security level 1 (MIC-32)
  - Provides authentication only (K1 is public)
- **K2** (network key): Used for all other traffic (data, ACKs)
  - Must be configured per-network
  - Security level 5 (ENC-MIC-32)
  - Provides encryption and authentication

**Security frame structure:**
```
┌──────────────┬───────────┬─────────┬─────────┬─────┐
│ MAC Header   │ Aux Hdr   │ Payload │ MIC     │ FCS │
├──────────────┼───────────┼─────────┼─────────┼─────┤
│ Frame control│ Security  │ Data    │ 4/8/16  │ 2   │
│ Sequence #   │ level     │ (encr.) │ bytes   │bytes│
│ Addressing   │ Key ID    │         │         │     │
│              │ Frame ctr │         │         │     │
└──────────────┴───────────┴─────────┴─────────┴─────┘
```

**Auxiliary security header:**
- Security level (3 bits)
- Key identifier mode (2 bits)
- Frame counter (4 bytes) - anti-replay protection
- Key index (1 byte)

### Frame Counter and Anti-Replay

**Frame counter** (32-bit):
- Increments with each transmitted secured frame
- Never repeats for same key
- Receiver maintains per-neighbor counter
- Frames with counter ≤ stored value are rejected (replay protection)

**Rollover:** When counter reaches 2^32-1, key MUST be changed.

### Hardware AES Acceleration

Platforms with hardware AES support:
- **CC2538**: AES-128 CCM* in hardware (fast, low power)
- **CC26xx/CC13xx**: Crypto accelerator with AES
- **nRF52840**: ARM CryptoCell-310

**Performance impact:**
- Hardware: ~50-200 µs per frame
- Software: ~2-10 ms per frame (100× slower)

### CSMA Security

CSMA (Carrier Sense Multiple Access) also supports IEEE 802.15.4 security with the same mechanisms as TSCH.

**Configuration:**
```c
/* Enable CSMA security */
#define LLSEC802154_CONF_ENABLED 1
#define LLSEC802154_CONF_USES_EXPLICIT_KEYS 1
```

See `os/net/mac/csma/csma-security.h` for implementation details.

## Link-Layer Configuration

### Core Parameters

| Parameter | Description | Default | Range |
|-----------|-------------|---------|-------|
| `LLSEC802154_CONF_ENABLED` | Enable link-layer security | 0 | 0 or 1 |
| `LLSEC802154_CONF_USES_EXPLICIT_KEYS` | Use explicit key indexing | 0 | 0 or 1 |
| `LLSEC802154_CONF_USES_AUX_HEADER` | Include auxiliary security header | `LLSEC802154_ENABLED` | 0 or 1 |
| `LLSEC802154_CONF_USES_FRAME_COUNTER` | Enable frame counter | `LLSEC802154_ENABLED` | 0 or 1 |

### TSCH Security Parameters

| Parameter | Description | Default | Valid Values |
|-----------|-------------|---------|--------------|
| `TSCH_SECURITY_CONF_K1` | Key for EBs (16 bytes) | "6TiSCH minimal15" | Any 128-bit key |
| `TSCH_SECURITY_CONF_K2` | Key for data/ACKs (16 bytes) | 0xdeadbeef... | Any 128-bit key |
| `TSCH_SECURITY_CONF_KEY_INDEX_EB` | Key index for EBs | 1 | 0-255 |
| `TSCH_SECURITY_CONF_SEC_LEVEL_EB` | Security level for EBs | 1 | 0-7 |
| `TSCH_SECURITY_CONF_KEY_INDEX_ACK` | Key index for ACKs | 2 | 0-255 |
| `TSCH_SECURITY_CONF_SEC_LEVEL_ACK` | Security level for ACKs | 5 | 0-7 |
| `TSCH_SECURITY_CONF_KEY_INDEX_OTHER` | Key index for data | 2 | 0-255 |
| `TSCH_SECURITY_CONF_SEC_LEVEL_OTHER` | Security level for data | 5 | 0-7 |
| `TSCH_CONF_JOIN_SECURED_ONLY` | Join only secured networks | `LLSEC802154_ENABLED` | 0 or 1 |

**Security level encoding:**
- 0 = No security
- 1 = MIC-32
- 2 = MIC-64
- 3 = MIC-128
- 4 = ENC
- 5 = ENC-MIC-32 (**recommended for data**)
- 6 = ENC-MIC-64
- 7 = ENC-MIC-128

## Application-Layer Security (DTLS/CoAPs)

Application-layer security provides end-to-end protection using DTLS 1.2 (Datagram Transport Layer Security) as defined in RFC 6347.

### DTLS Overview

**DTLS features:**
- End-to-end encryption (protects against malicious routers)
- Mutual authentication (PSK or certificates)
- Session resumption (reduced handshake overhead)
- Replay protection
- Runs over UDP (suitable for CoAP)

**CoAPs = CoAP + DTLS:**
- Standard port: 5684 (CoAP uses 5683)
- URL scheme: `coaps://` (instead of `coap://`)
- Encrypts CoAP header and payload

### Mbed TLS Integration

Contiki-NG uses Mbed TLS for DTLS implementation.

**Build with DTLS support:**
```bash
make TARGET=<platform> MAKE_WITH_DTLS=1
```

**Mbed TLS location:** `/os/net/security/mbedtls/`

### Authentication Modes

#### Pre-Shared Key (PSK)

PSK is recommended for constrained devices due to low overhead.

**Advantages:**
- Small handshake (~200-400 bytes total)
- Fast handshake (~1-3 seconds)
- Low memory footprint (~2-4 KB RAM)
- No certificate management

**Configuration in `project-conf.h`:**
```c
#define WITH_DTLS 1

/* PSK identity (any string) */
#define DTLS_PSK_IDENTITY "Client_identity"

/* PSK key (16 bytes for AES-128) */
#define DTLS_PSK_KEY "secretPSK123456"  /* Must be exactly 16 chars */
#define DTLS_PSK_KEY_LEN 16
```

#### Certificate-Based Authentication

Certificate authentication provides PKI (Public Key Infrastructure) support.

**Advantages:**
- Stronger authentication
- Scalable key management
- Standard PKI trust model

**Disadvantages:**
- Large handshake (~2-8 KB total)
- Slow handshake (~5-15 seconds)
- High memory footprint (~10-20 KB RAM)
- Certificate management overhead

**Configuration:**
```c
/* In project-conf.h */
#define MBEDTLS_CONF_FILE "mbedtls-config.h"

/* Provide certificates in DER format */
extern const unsigned char server_cert_der[];
extern const size_t server_cert_der_len;
extern const unsigned char server_key_der[];
extern const size_t server_key_der_len;
extern const unsigned char ca_cert_der[];
extern const size_t ca_cert_der_len;
```

### DTLS Session Management

**Session lifecycle:**
1. **Handshake** (establish keys)
2. **Application data** (encrypted CoAP messages)
3. **Session timeout** or **explicit close**

**Session resumption:**
- DTLS supports abbreviated handshake
- Reduces handshake from ~5 RTT to ~2 RTT
- Saves energy and time

**Keep-alive:**
```c
/* Send periodic NON messages to maintain DTLS session */
#define COAP_KEEPALIVE_INTERVAL (30 * CLOCK_SECOND)
```

## Code Examples

### Example 1: TSCH with Link-Layer Security

```c
#include "contiki.h"
#include "net/mac/tsch/tsch.h"
#include "sys/log.h"

#define LOG_MODULE "TSCH-Sec"
#define LOG_LEVEL LOG_LEVEL_INFO

/* project-conf.h configuration:
 *
 * #define LLSEC802154_CONF_ENABLED 1
 * #define LLSEC802154_CONF_USES_EXPLICIT_KEYS 1
 * #define TSCH_CONF_JOIN_SECURED_ONLY 1
 */

PROCESS(tsch_secure_node, "TSCH Secure Node");
AUTOSTART_PROCESSES(&tsch_secure_node);

PROCESS_THREAD(tsch_secure_node, ev, data)
{
  PROCESS_BEGIN();

  LOG_INFO("Starting TSCH with security\n");

#if LLSEC802154_ENABLED
  LOG_INFO("Link-layer security: ENABLED\n");
  LOG_INFO("Join secured only: %d\n", TSCH_JOIN_SECURED_ONLY);
#else
  LOG_WARN("Link-layer security: DISABLED\n");
#endif

  /* TSCH will automatically use security if enabled */
  /* EBs will use K1 with security level 1 (MIC-32) */
  /* Data/ACKs will use K2 with security level 5 (ENC-MIC-32) */

  PROCESS_END();
}
```

### Example 2: Custom Security Keys

```c
/* project-conf.h */

#define LLSEC802154_CONF_ENABLED 1
#define LLSEC802154_CONF_USES_EXPLICIT_KEYS 1

/* Custom K1 key for EBs (still authentication-only) */
#define TSCH_SECURITY_CONF_K1 { \
  0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, \
  0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 \
}

/* Custom K2 key for data (MUST be secret) */
#define TSCH_SECURITY_CONF_K2 { \
  0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF, \
  0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 \
}

/* Use higher security level for critical data */
#define TSCH_SECURITY_CONF_SEC_LEVEL_OTHER 6  /* ENC-MIC-64 */
```

### Example 3: Monitoring Security Status

```c
#include "contiki.h"
#include "net/mac/tsch/tsch.h"
#include "net/mac/llsec802154.h"
#include "sys/log.h"

#define LOG_MODULE "Sec-Monitor"
#define LOG_LEVEL LOG_LEVEL_INFO

PROCESS(security_monitor, "Security Monitor");
AUTOSTART_PROCESSES(&security_monitor);

PROCESS_THREAD(security_monitor, ev, data)
{
  static struct etimer periodic_timer;

  PROCESS_BEGIN();

  etimer_set(&periodic_timer, 30 * CLOCK_SECOND);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));

    LOG_INFO("Security status:\n");

#if LLSEC802154_ENABLED
    LOG_INFO("  Link-layer security: ENABLED\n");

#if TSCH_SECURITY_ENABLED
    LOG_INFO("  TSCH security: ENABLED\n");
    LOG_INFO("  EB security level: %d\n", TSCH_SECURITY_KEY_SEC_LEVEL_EB);
    LOG_INFO("  Data security level: %d\n", TSCH_SECURITY_KEY_SEC_LEVEL_OTHER);
    LOG_INFO("  ACK security level: %d\n", TSCH_SECURITY_KEY_SEC_LEVEL_ACK);

    /* Check if joined secured network */
    if(tsch_is_associated) {
      LOG_INFO("  Joined secured TSCH network\n");
    }
#endif

#else
    LOG_WARN("  Link-layer security: DISABLED\n");
#endif

    etimer_reset(&periodic_timer);
  }

  PROCESS_END();
}
```

### Example 4: CoAPs Server with PSK

```c
#include "contiki.h"
#include "coap-engine.h"
#include "sys/log.h"

#define LOG_MODULE "CoAPs-Server"
#define LOG_LEVEL LOG_LEVEL_INFO

/* project-conf.h:
 * #define WITH_DTLS 1
 * #define DTLS_PSK_IDENTITY "sensor-node-01"
 * #define DTLS_PSK_KEY "SecretKey1234567"  // 16 bytes
 * #define DTLS_PSK_KEY_LEN 16
 */

static void
secure_resource_handler(coap_message_t *request,
                        coap_message_t *response,
                        uint8_t *buffer,
                        uint16_t preferred_size,
                        int32_t *offset)
{
  const char *msg = "Secure data from sensor";

  LOG_INFO("Handling secure CoAP request\n");

  coap_set_header_content_format(response, TEXT_PLAIN);
  coap_set_payload(response, msg, strlen(msg));
}

RESOURCE(secure_resource,
         "title=\"Secure Resource\";rt=\"sensor\"",
         secure_resource_handler,
         NULL, NULL, NULL);

PROCESS(coaps_server_process, "CoAPs Server");
AUTOSTART_PROCESSES(&coaps_server_process);

PROCESS_THREAD(coaps_server_process, ev, data)
{
  PROCESS_BEGIN();

  LOG_INFO("Starting CoAPs server (port 5684)\n");

#if WITH_DTLS
  LOG_INFO("DTLS enabled with PSK\n");
  LOG_INFO("PSK Identity: %s\n", DTLS_PSK_IDENTITY);
#else
  LOG_ERR("DTLS not enabled!\n");
#endif

  /* Activate resource on secure endpoint */
  coap_activate_resource(&secure_resource, "secure/sensor");

  PROCESS_END();
}
```

### Example 5: CoAPs Client with PSK

```c
#include "contiki.h"
#include "coap-engine.h"
#include "coap-blocking-api.h"
#include "sys/log.h"

#define LOG_MODULE "CoAPs-Client"
#define LOG_LEVEL LOG_LEVEL_INFO

/* PSK must match server */
/* project-conf.h:
 * #define WITH_DTLS 1
 * #define DTLS_PSK_IDENTITY "client-node-01"
 * #define DTLS_PSK_KEY "SecretKey1234567"
 * #define DTLS_PSK_KEY_LEN 16
 */

PROCESS(coaps_client_process, "CoAPs Client");
AUTOSTART_PROCESSES(&coaps_client_process);

static void
response_handler(coap_message_t *response)
{
  const uint8_t *payload;
  int len;

  if(response == NULL) {
    LOG_ERR("DTLS handshake or request timeout\n");
    return;
  }

  len = coap_get_payload(response, &payload);
  LOG_INFO("Secure response: %.*s\n", len, (char *)payload);
}

PROCESS_THREAD(coaps_client_process, ev, data)
{
  static coap_endpoint_t server_endpoint;
  static coap_message_t request[1];
  static struct etimer periodic_timer;

  PROCESS_BEGIN();

  /* Wait for network to be ready */
  etimer_set(&periodic_timer, 10 * CLOCK_SECOND);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));

  /* Parse CoAPs endpoint (note: coaps:// and port 5684) */
  coap_endpoint_parse("coaps://[fd00::1]:5684",
                      strlen("coaps://[fd00::1]:5684"),
                      &server_endpoint);

  LOG_INFO("Connecting to secure CoAP server\n");
  LOG_INFO("DTLS PSK Identity: %s\n", DTLS_PSK_IDENTITY);

  /* Prepare request */
  coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
  coap_set_header_uri_path(request, "secure/sensor");

  /* Send secure request (DTLS handshake happens automatically) */
  COAP_BLOCKING_REQUEST(&server_endpoint, request, response_handler);

  PROCESS_END();
}
```

### Example 6: Mixed Security (Link + Application Layer)

```c
/* project-conf.h - Defense in depth configuration */

/* Enable link-layer security (hop-by-hop) */
#define LLSEC802154_CONF_ENABLED 1
#define LLSEC802154_CONF_USES_EXPLICIT_KEYS 1

/* Custom network key */
#define TSCH_SECURITY_CONF_K2 { \
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, \
  0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF \
}

/* Join only secured networks */
#define TSCH_CONF_JOIN_SECURED_ONLY 1

/* Enable application-layer security (end-to-end) */
#define WITH_DTLS 1
#define DTLS_PSK_IDENTITY "iot-device-42"
#define DTLS_PSK_KEY "AppLayerSecret16"
#define DTLS_PSK_KEY_LEN 16

/* This provides:
 * - Link-layer: Protects against eavesdropping on RF, malicious neighbors
 * - Application-layer: Protects against malicious routers, end-to-end auth
 */
```

### Example 7: Secure Border Router

```c
#include "contiki.h"
#include "rpl.h"
#include "rpl-dag-root.h"
#include "net/mac/tsch/tsch.h"
#include "sys/log.h"

#define LOG_MODULE "Secure-BR"
#define LOG_LEVEL LOG_LEVEL_INFO

/* project-conf.h:
 * #define LLSEC802154_CONF_ENABLED 1
 * #define LLSEC802154_CONF_USES_EXPLICIT_KEYS 1
 * #define TSCH_CONF_JOIN_SECURED_ONLY 1
 */

PROCESS(secure_border_router, "Secure Border Router");
AUTOSTART_PROCESSES(&secure_border_router);

PROCESS_THREAD(secure_border_router, ev, data)
{
  static struct etimer timer;

  PROCESS_BEGIN();

  LOG_INFO("Secure Border Router starting\n");

#if LLSEC802154_ENABLED
  LOG_INFO("Link-layer security: ENABLED\n");
  LOG_INFO("Only secured nodes can join\n");
#else
  LOG_ERR("WARNING: Link-layer security DISABLED\n");
#endif

  /* Wait for network stack */
  etimer_set(&timer, 5 * CLOCK_SECOND);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));

  /* Initialize RPL DAG root */
  rpl_dag_root_init();
  rpl_dag_root_init_dag_immediately();

  LOG_INFO("RPL DAG created (secured network)\n");
  LOG_INFO("Nodes must have matching security keys to join\n");

  /* Start sending secured EBs */
  LOG_INFO("Advertising secured TSCH network\n");

  PROCESS_END();
}
```

### Example 8: Secure Node Joining

```c
#include "contiki.h"
#include "net/mac/tsch/tsch.h"
#include "net/ipv6/uip-ds6.h"
#include "rpl.h"
#include "sys/log.h"

#define LOG_MODULE "Secure-Join"
#define LOG_LEVEL LOG_LEVEL_INFO

PROCESS(secure_joining_node, "Secure Joining Node");
AUTOSTART_PROCESSES(&secure_joining_node);

PROCESS_THREAD(secure_joining_node, ev, data)
{
  static struct etimer join_timer;
  static uint8_t join_attempts = 0;

  PROCESS_BEGIN();

  LOG_INFO("Node starting - attempting to join secured network\n");

#if !LLSEC802154_ENABLED
  LOG_ERR("ERROR: Security not enabled but trying to join secured network\n");
  PROCESS_EXIT();
#endif

#if !TSCH_JOIN_SECURED_ONLY
  LOG_WARN("WARNING: TSCH_JOIN_SECURED_ONLY is disabled\n");
  LOG_WARN("Node may join insecure networks\n");
#endif

  /* TSCH association happens automatically */
  /* Security keys must match the network */

  etimer_set(&join_timer, 30 * CLOCK_SECOND);

  while(join_attempts < 10) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&join_timer));

    if(tsch_is_associated) {
      LOG_INFO("Successfully joined secured TSCH network\n");

      /* Check if we have IPv6 address */
      if(uip_ds6_get_global(ADDR_PREFERRED) != NULL) {
        LOG_INFO("Obtained global IPv6 address\n");

        /* Check RPL */
        if(rpl_get_any_dag() != NULL) {
          LOG_INFO("Joined RPL DODAG\n");
          LOG_INFO("Node is fully operational in secured network\n");
          break;
        }
      }
    } else {
      join_attempts++;
      LOG_WARN("Join attempt %d failed - checking security keys\n", join_attempts);
      LOG_WARN("Verify K1 and K2 match the network\n");
    }

    etimer_reset(&join_timer);
  }

  if(join_attempts >= 10) {
    LOG_ERR("Failed to join after 10 attempts\n");
    LOG_ERR("Possible causes:\n");
    LOG_ERR("  - Security keys don't match\n");
    LOG_ERR("  - Network not in range\n");
    LOG_ERR("  - Security level mismatch\n");
  }

  PROCESS_END();
}
```

## Key Management

### Key Generation

**Best practices:**
```c
/* NEVER use default keys in production */

/* Good: Random 128-bit keys */
#define NETWORK_KEY_K2 { \
  0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, \
  0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C \
}

/* Bad: Predictable keys */
#define BAD_KEY { \
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, \
  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F \
}
```

**Generate secure keys:**
```bash
# Use cryptographically secure random number generator
openssl rand -hex 16
# Output: 2b7e151628aed2a6abf7158809cf4f3c

# Or use /dev/urandom
od -An -tx1 -N16 /dev/urandom | tr -d ' \n'
```

### Key Distribution

**Methods:**

1. **Pre-configuration** (factory provisioning)
   - Keys programmed during manufacturing
   - Stored in protected flash
   - Most secure for constrained devices

2. **Out-of-band** (QR code, NFC, physical button)
   - User scans QR code with network key
   - NFC tap for key transfer
   - Physical button for pairing mode

3. **Key establishment protocol** (PANA, EAP)
   - Automated key distribution
   - Requires initial trust anchor
   - Complex, higher overhead

**For Contiki-NG:**
- Pre-configuration is standard approach
- Keys defined in `project-conf.h` or build-time
- Consider per-device keys for large deployments

### Key Storage

**Secure storage recommendations:**
```c
/* Store keys in protected flash region if available */
#if PLATFORM_SUPPORTS_SECURE_STORAGE
  /* Use platform-specific secure storage */
  secure_storage_write(KEY_ID_K2, network_key, 16);
#else
  /* Keys in regular flash - ensure flash read protection enabled */
  /* Prevent dumping keys via JTAG/SWD */
#endif
```

**Platform-specific protection:**
- **CC26xx/CC13xx**: Crypto key RAM (protected memory region)
- **nRF52840**: Access Port Protection (APP)
- **CC2538**: Flash lock bits

### Key Rotation

**When to rotate keys:**
- Frame counter approaching 2^32 (rollover)
- Suspected compromise
- Periodic rotation (e.g., monthly)
- Node removed from network

**Rotation strategy:**
```c
/* Dual-key approach for seamless rotation */
#define ACTIVE_KEY_INDEX 2
#define NEXT_KEY_INDEX 3

/* Old frames accepted with old key */
/* New frames sent with new key */
/* After grace period, old key removed */
```

**Note:** Contiki-NG doesn't provide automatic key rotation - must be implemented by application.

### Default Key Security

**K1 (EB key) security:**
```
K1 = ASCII "6TiSCH minimal15"
   = 0x36 0x54 0x69 0x53 0x43 0x48 0x20 0x6D
     0x69 0x6E 0x69 0x6D 0x61 0x6C 0x31 0x35
```

**Security implications:**
- K1 is **well-known** (public)
- Provides **authentication only** (MIC-32)
- **No confidentiality** for EBs
- This is by design (per 6TiSCH minimal specification)
- Allows nodes to discover and authenticate network
- Actual data encrypted with K2 (secret)

**K2 MUST be secret** - never use default value in production.

## Security Best Practices

### 1. Defense in Depth

**Use both security layers:**
```c
/* Link-layer: Protects against RF eavesdropping, rogue neighbors */
#define LLSEC802154_CONF_ENABLED 1

/* Application-layer: Protects against malicious routers */
#define WITH_DTLS 1
```

**Threat coverage:**
| Threat | Link-Layer | App-Layer | Both |
|--------|------------|-----------|------|
| Eavesdropping (RF) | ✓ | ✓ | ✓✓ |
| Malicious neighbor | ✓ | ✓ | ✓✓ |
| Malicious router | ✗ | ✓ | ✓ |
| End-to-end tampering | ✗ | ✓ | ✓ |
| Replay attacks | ✓ | ✓ | ✓✓ |

### 2. Security Level Selection

**For link-layer:**
```c
/* Standard configuration (6TiSCH minimal) */
#define TSCH_SECURITY_CONF_SEC_LEVEL_EB 1     /* MIC-32 for EBs */
#define TSCH_SECURITY_CONF_SEC_LEVEL_ACK 5    /* ENC-MIC-32 for ACKs */
#define TSCH_SECURITY_CONF_SEC_LEVEL_OTHER 5  /* ENC-MIC-32 for data */

/* High-security configuration */
#define TSCH_SECURITY_CONF_SEC_LEVEL_ACK 6    /* ENC-MIC-64 */
#define TSCH_SECURITY_CONF_SEC_LEVEL_OTHER 6  /* ENC-MIC-64 */
```

**Tradeoffs:**
- **Higher security level** = Longer MIC = Less payload per frame
- Level 5 (4-byte MIC): Standard, good balance
- Level 6 (8-byte MIC): Better protection, -4 bytes payload
- Level 7 (16-byte MIC): Maximum security, -12 bytes payload

### 3. Secure Commissioning

**Join process:**
```c
/* Only join secured networks */
#define TSCH_CONF_JOIN_SECURED_ONLY 1

/* Verify network credentials before joining */
/* Option 1: Pre-configured PAN ID */
#define IEEE802154_CONF_PANID 0xABCD
#define TSCH_CONF_JOIN_MY_PANID_ONLY 1

/* Option 2: Out-of-band authentication */
/* Use button press + LED indication for secure pairing */
```

### 4. Key Management

**DO:**
- ✓ Generate keys from CSPRNG
- ✓ Use unique keys per network
- ✓ Consider per-device keys for large deployments
- ✓ Protect keys with flash read protection
- ✓ Plan for key rotation

**DON'T:**
- ✗ Use default K2 value
- ✗ Hard-code keys in source code repositories
- ✗ Use predictable or sequential keys
- ✗ Reuse keys across multiple networks
- ✗ Log or print keys to console

### 5. Performance Considerations

**Optimize for battery life:**
```c
/* Use NON messages for frequent updates */
coap_init_message(request, COAP_TYPE_NON, COAP_POST, 0);

/* Reuse DTLS sessions (avoid repeated handshakes) */
#define COAP_KEEPALIVE_INTERVAL (60 * CLOCK_SECOND)

/* Use link-layer security (lower overhead than DTLS) */
#define LLSEC802154_CONF_ENABLED 1
```

### 6. Monitoring and Logging

**Security events to log:**
```c
LOG_WARN("Authentication failure from ");
LOG_WARN_LLADDR(&sender);

LOG_ERR("Frame counter mismatch - possible replay attack\n");

LOG_INFO("Rejected frame with security level %d (expected %d)\n",
         received_level, expected_level);

LOG_INFO("DTLS handshake completed with ");
LOG_INFO_6ADDR(&peer_addr);
```

**Avoid logging sensitive data:**
```c
/* NEVER log keys */
LOG_ERR("Using key: %s\n", key);  /* WRONG! */

/* NEVER log plaintext of encrypted data */
LOG_DBG("Decrypted payload: %s\n", plaintext);  /* WRONG! */
```

### 7. Testing Security

**Verification checklist:**
- [ ] Keys are unique and random
- [ ] Default keys not used in production
- [ ] TSCH_JOIN_SECURED_ONLY enabled
- [ ] Security levels configured correctly
- [ ] Wireshark shows encrypted packets
- [ ] Unauthorized nodes cannot join
- [ ] DTLS handshake completes successfully
- [ ] Replay attacks are rejected

## Threat Model and Attacks

### Threat Landscape

**Attacker capabilities:**
- **Passive eavesdropper**: Listens to RF traffic
- **Active attacker**: Transmits malicious frames
- **Node capture**: Physical access to deployed node
- **Malicious insider**: Compromised legitimate node

### Attack Vectors and Mitigations

#### 1. Eavesdropping

**Attack:** Attacker captures wireless traffic to read sensitive data.

**Mitigation:**
```c
/* Link-layer encryption (all traffic) */
#define LLSEC802154_CONF_ENABLED 1
#define TSCH_SECURITY_CONF_SEC_LEVEL_OTHER 5  /* ENC-MIC-32 */

/* Application-layer encryption (end-to-end) */
#define WITH_DTLS 1
```

**Protection level:** High (with proper keys)

#### 2. Replay Attacks

**Attack:** Attacker records and retransmits legitimate frames.

**Mitigation:**
- **Frame counter** (link-layer): Automatically increments, old frames rejected
- **DTLS sequence number** (application-layer): Built into DTLS

**Protection level:** High (automatic with security enabled)

#### 3. Man-in-the-Middle (MITM)

**Attack:** Attacker intercepts and modifies traffic between nodes.

**Link-layer MITM:**
- Prevented by MIC (authentication)
- Attacker without key cannot forge valid MIC

**Application-layer MITM:**
- Prevented by DTLS mutual authentication
- PSK or certificate verifies peer identity

**Protection level:** High (with authentication)

#### 4. Sinkhole Attack

**Attack:** Malicious node advertises itself as best route, attracts traffic.

**Mitigation:**
```c
/* RPL security (optional) */
#define RPL_CONF_SECURITY 1  /* Requires additional configuration */

/* Link-layer security prevents unauthorized nodes from participating */
#define LLSEC802154_CONF_ENABLED 1

/* Monitor routing metrics for anomalies */
/* Implement hop limit checks */
```

**Protection level:** Medium (link-layer helps, but requires routing security)

#### 5. Wormhole Attack

**Attack:** Attackers tunnel packets between two distant locations.

**Mitigation:**
- Difficult to prevent completely
- Time-based detection (TSCH timing)
- Hop count verification
- Geographic constraints if location known

**Protection level:** Low to Medium

#### 6. Sybil Attack

**Attack:** Single malicious node presents multiple identities.

**Mitigation:**
```c
/* Unique keys per node */
/* Central key management with node identity binding */

/* Monitor for duplicate addresses */
if(uip_ds6_get_link_local(-1) == NULL) {
  LOG_WARN("Duplicate address detected\n");
}
```

**Protection level:** Medium (requires identity management)

#### 7. Denial of Service (DoS)

**Attack:** Overwhelm network with traffic or jam RF.

**Link-layer DoS:**
- **RF jamming**: Physical attack, hard to prevent
- **Frame flooding**: Rate limiting at MAC layer

**Application-layer DoS:**
```c
/* Implement rate limiting */
static uint8_t requests_per_minute = 0;

if(requests_per_minute++ > MAX_REQUESTS) {
  coap_set_status_code(response, SERVICE_UNAVAILABLE_5_03);
  return;
}
```

**Protection level:** Low (physical attacks are hard to prevent)

#### 8. Node Capture/Compromise

**Attack:** Attacker gains physical access to node, extracts keys.

**Mitigation:**
```c
/* Use tamper-resistant hardware if available */
/* Enable flash read protection */
/* Implement per-node keys (limits damage) */
/* Plan for revocation mechanism */

/* Detect tampered nodes */
#if PLATFORM_HAS_TAMPER_DETECT
  if(tamper_detected()) {
    erase_keys();
    LOG_CRIT("Tamper detected - keys erased\n");
  }
#endif
```

**Protection level:** Medium (perfect protection is impossible)

### Security Monitoring

**Detect attacks:**
```c
/* Count authentication failures */
static uint16_t auth_failures = 0;

void on_auth_failure(const linkaddr_t *sender) {
  auth_failures++;
  if(auth_failures > AUTH_FAILURE_THRESHOLD) {
    LOG_CRIT("Possible attack - %u auth failures\n", auth_failures);
    /* Consider disabling reception temporarily */
  }
}

/* Monitor frame counter gaps */
void on_frame_counter_gap(uint32_t expected, uint32_t received) {
  if(received < expected) {
    LOG_WARN("Replay attempt detected\n");
  } else if((received - expected) > FRAME_COUNTER_GAP_THRESHOLD) {
    LOG_WARN("Large frame counter gap - possible attack or packet loss\n");
  }
}
```

## Performance Impact

### Link-Layer Security Overhead

**Packet overhead:**
```
Without security:
  MAC header: 9-25 bytes
  Payload: variable
  FCS: 2 bytes

With security (level 5):
  MAC header: 9-25 bytes
  Aux security header: 6 bytes
  Payload: variable (encrypted)
  MIC-32: 4 bytes
  FCS: 2 bytes

Additional overhead: 10 bytes
```

**Processing time:**
| Platform | Hardware AES | Software AES |
|----------|--------------|--------------|
| CC2538 | 50-200 µs | ~5 ms |
| CC2640 | 40-150 µs | ~4 ms |
| nRF52840 | 60-180 µs | ~6 ms |
| Native (PC) | N/A | ~0.1 ms |

**Power consumption:**
- **Hardware AES**: +1-5% total power (negligible)
- **Software AES**: +50-100% processing power, +10-20% total power
- **Recommendation**: Use hardware AES when available

### Application-Layer Security Overhead

**DTLS handshake (PSK):**
```
Packet exchange: 6-8 packets (3-4 RTT)
Total data: 200-400 bytes
Time: 1-3 seconds (depends on network latency)
Energy: 100-300 mJ
Memory: 2-4 KB RAM during handshake
```

**DTLS per-packet overhead:**
```
DTLS header: 13 bytes
Encrypted payload: same as plaintext
MIC: included in encryption
Total overhead: ~13 bytes per packet
```

**Processing time:**
- **Encryption/decryption**: 0.5-2 ms per packet (hardware crypto)
- **Handshake**: 5-15 seconds (certificate-based)

**Power impact:**
- PSK handshake: ~200 mJ
- Per-packet crypto: ~1-2 mJ
- Recommendation: Reuse sessions, use keep-alive

### Memory Footprint

**Link-layer security:**
```
Code: ~2-5 KB (CCM* implementation)
RAM: ~100-500 bytes (frame counter, keys)
```

**Application-layer security (DTLS):**
```
Code (Mbed TLS): ~40-80 KB
RAM: ~10-25 KB (depends on configuration)
  - Handshake buffers: 2-8 KB
  - Session state: 2-4 KB
  - Crypto state: 1-3 KB
```

**Total overhead (both layers):**
- Flash: ~45-85 KB
- RAM: ~12-26 KB

### Throughput Impact

**Without security:**
- Theoretical max: ~250 kbps (802.15.4 at 250 kbps)
- Practical UDP: ~100-150 kbps

**With link-layer security:**
- Overhead: ~5-10% (10 bytes per frame)
- Practical UDP: ~90-140 kbps

**With link + application security:**
- Overhead: ~10-20% (combined)
- Practical UDP: ~80-130 kbps
- Plus handshake latency (~1-3s initial connection)

## Troubleshooting

### Authentication Failures

**Symptoms:** Nodes cannot join network, "authentication failed" errors

**Causes:**
1. **Key mismatch** - K1 or K2 doesn't match network
2. **Security level mismatch** - Different levels configured
3. **Key index mismatch** - Using different key indexes

**Debug:**
```c
/* Enable security debugging */
#define LOG_CONF_LEVEL_MAC LOG_LEVEL_DBG

/* Check key configuration */
LOG_DBG("K1: ");
for(int i = 0; i < 16; i++) {
  LOG_DBG_("%02x ", k1_key[i]);
}
LOG_DBG_("\n");

/* Verify security levels match */
LOG_DBG("Expected sec level: %d, Received: %d\n",
        expected_level, received_level);
```

**Solutions:**
1. Verify all nodes use same K2 key
2. Check security level configuration matches
3. Ensure `LLSEC802154_CONF_ENABLED` set on all nodes
4. Verify `LLSEC802154_CONF_USES_EXPLICIT_KEYS` matches across network

### Frame Counter Issues

**Symptoms:** Frames rejected, "frame counter" errors in logs

**Causes:**
1. **Counter rollover** - Reached 2^32, key must be rotated
2. **Node reboot** - Counter reset to 0, neighbors reject frames
3. **Clock skew** - Node counter ahead of neighbor's expectation

**Solutions:**
```c
/* After node reboot, neighbors need to reset counter */
/* Option 1: Wait for neighbor timeout and removal */
/* Option 2: Manually reset neighbor table on reboot */

/* Detect rollover */
extern uint32_t tsch_security_frame_counter;
if(tsch_security_frame_counter > 0xFFFFFFF0) {
  LOG_WARN("Frame counter approaching rollover - rotate key\n");
}
```

### DTLS Handshake Failures

**Symptoms:** CoAPs requests timeout, "handshake failed" errors

**Causes:**
1. **PSK mismatch** - Identity or key doesn't match
2. **Memory exhaustion** - Not enough RAM for handshake
3. **Network issues** - Packet loss during handshake
4. **Timeout too short** - Handshake takes longer than timeout

**Debug:**
```c
/* Enable DTLS debugging */
#define MBEDTLS_DEBUG_C 1
#define MBEDTLS_DEBUG_LEVEL 3  /* 0-4, higher = more verbose */

/* Check PSK configuration */
LOG_DBG("DTLS PSK Identity: %s\n", DTLS_PSK_IDENTITY);
LOG_DBG("DTLS PSK Key length: %d\n", DTLS_PSK_KEY_LEN);
```

**Solutions:**
1. Verify PSK identity and key match between client/server
2. Increase heap size: `#define UIP_CONF_BUFFER_SIZE 1500`
3. Extend timeout: `#define COAP_ACK_TIMEOUT 5`
4. Ensure good network connectivity before handshake

### Packet Overhead Issues

**Symptoms:** Packets don't fit in 802.15.4 frame, fragmentation issues

**Causes:**
Security overhead reduces available payload:
```
802.15.4 max: 127 bytes
MAC header: ~25 bytes
Security (level 5): 10 bytes
IPv6 header: 40 bytes
UDP header: 8 bytes
Available: ~44 bytes

With DTLS:
DTLS header: 13 bytes
Available: ~31 bytes
```

**Solutions:**
```c
/* Reduce CoAP payload size */
#define COAP_MAX_CHUNK_SIZE 32  /* Instead of default 64 */

/* Use 6LoWPAN compression */
#define SICSLOWPAN_CONF_COMPRESSION SICSLOWPAN_COMPRESSION_IPHC

/* Minimize CoAP options */
/* Use short URI paths */
/* Avoid large headers */
```

### High Power Consumption

**Symptoms:** Battery drains faster with security enabled

**Causes:**
1. Software AES (slow, power-hungry)
2. Frequent DTLS handshakes
3. Retransmissions due to MIC failures

**Solutions:**
```c
/* Use hardware AES */
#define AES_128_CONF aes_128_driver  /* Platform-specific */

/* Reuse DTLS sessions */
#define COAP_OBSERVE_REFRESH_INTERVAL 300  /* 5 minutes */

/* Optimize security level (lower MIC = smaller packets) */
#define TSCH_SECURITY_CONF_SEC_LEVEL_OTHER 5  /* Not 6 or 7 */

/* Monitor retransmission rate */
LOG_INFO("Retransmissions: %u%%\n",
         (retransmits * 100) / total_transmits);
```

### Join Failures in Secured Network

**Symptoms:** Node cannot join, scanning indefinitely

**Debug steps:**
```c
/* 1. Verify security is enabled */
#if !LLSEC802154_ENABLED
  LOG_ERR("Security not enabled - cannot join secured network\n");
#endif

/* 2. Check if receiving EBs */
LOG_DBG("EB received from ");
LOG_DBG_LLADDR(&eb_source);
LOG_DBG_(" security level: %d\n", eb_sec_level);

/* 3. Verify K1 key matches */
/* K1 should be default unless network uses custom K1 */

/* 4. Check TSCH_JOIN_SECURED_ONLY setting */
#if TSCH_JOIN_SECURED_ONLY
  LOG_DBG("Will only join secured networks\n");
#endif
```

**Common fixes:**
1. Set `LLSEC802154_CONF_ENABLED 1`
2. Set `LLSEC802154_CONF_USES_EXPLICIT_KEYS 1`
3. Verify K1 matches (usually default is OK)
4. Check radio is working (`NETSTACK_RADIO.on()`)
5. Verify PAN ID matches if `TSCH_JOIN_MY_PANID_ONLY` set

## Comparison: Link-Layer vs Application-Layer Security

| Aspect | Link-Layer (802.15.4) | Application-Layer (DTLS) |
|--------|----------------------|--------------------------|
| **Scope** | Hop-by-hop | End-to-end |
| **Protocol** | CCM* (AES-128) | DTLS 1.2 (AES, RSA, ECC) |
| **Protects** | All MAC frames (including beacons, ACKs) | UDP payload only |
| **Overhead** | 10 bytes/frame | 13 bytes/packet + handshake |
| **Handshake** | None | 3-4 RTT (200-400 bytes total) |
| **Setup time** | Immediate | 1-15 seconds |
| **Power cost** | +1-5% (HW AES) or +10-20% (SW AES) | +100-500mJ handshake, +1-2mJ/packet |
| **Memory** | ~2-5 KB code, ~100-500B RAM | ~40-80 KB code, ~10-25 KB RAM |
| **Key mgmt** | Pre-shared (K1, K2) | PSK or certificates |
| **Trust model** | Shared network key | Peer authentication |
| **Protects against** | RF eavesdrop, rogue neighbor | Malicious router, E2E tamper |
| **Standard** | IEEE 802.15.4-2015 | RFC 6347 (DTLS 1.2) |
| **Use when** | Always (defense in depth) | Untrusted routers, Internet |

**Recommendation:** Use **both** for maximum security (defense in depth).

## Migration Guide

### From Unsecured to Secured Network

**Planning:**
1. **Prepare new keys** - Generate secure K2
2. **Test in lab** - Verify security works before deployment
3. **Plan deployment** - Phased rollout or flash all nodes
4. **Monitor join process** - Watch for authentication failures

**Migration steps:**
```c
/* Phase 1: Enable on new nodes only */
#define LLSEC802154_CONF_ENABLED 1
#define TSCH_CONF_JOIN_SECURED_ONLY 0  /* Allow mixed network */

/* Phase 2: All nodes have security, but accept unsecured */
#define TSCH_CONF_JOIN_SECURED_ONLY 0

/* Phase 3: Enforce secured-only */
#define TSCH_CONF_JOIN_SECURED_ONLY 1

/* Phase 4: Production */
/* All nodes secured, no backward compatibility */
```

**Rollback plan:**
- Keep unsecured firmware available
- Test new firmware on small subset first
- Monitor network health during rollout

### Backward Compatibility

**Mixed secured/unsecured network:**
```c
/* Allow both secured and unsecured nodes */
#define LLSEC802154_CONF_ENABLED 1
#define TSCH_CONF_JOIN_SECURED_ONLY 0

/* Border router broadcasts both types of EBs */
/* Secured nodes use K2 for data */
/* Unsecured nodes send unencrypted */
```

**Warning:** Mixed networks have reduced security - temporary only.

## Platform-Specific Notes

### CC2538 (Zoul, Firefly, etc.)

**Hardware AES:**
```c
/* AES-128 CCM* accelerator built-in */
/* Automatically used when LLSEC802154_ENABLED */
/* Performance: ~50-200 µs per frame */
```

**Flash protection:**
```c
/* Enable flash lock bits to prevent key extraction */
/* Use cc2538 bootloader with read protection */
```

### CC26xx/CC13xx (LaunchPad, SensorTag)

**Crypto accelerator:**
```c
/* AES, SHA-256, ECC in hardware */
/* DTLS handshake 2-5× faster than software */
/* Low power consumption (<1 mA for crypto) */
```

**Secure key storage:**
```c
/* Use CryptoRAM for runtime key storage */
/* Keys cleared on power-down */
```

### nRF52840 (DK, Dongle)

**CryptoCell-310:**
```c
/* Hardware crypto: AES, SHA, ECC, RSA */
/* Fast DTLS handshake (~1-2 seconds with PSK) */
/* Supports TrustZone for key isolation */
```

**Access port protection:**
```c
/* Enable APPROTECT to prevent JTAG key extraction */
/* Configure via Nordic SDK */
```

### Native (Linux/Mac)

**Software crypto:**
```c
/* All crypto in software (Mbed TLS) */
/* Fast on PC but not representative of constrained device */
/* Use for development and testing */
```

## References

**Standards:**
- **IEEE 802.15.4-2015** - Low-Rate Wireless Personal Area Networks (Security: Section 9)
- **RFC 4493** - The AES-CMAC Algorithm
- **RFC 5246** - The Transport Layer Security (TLS) Protocol Version 1.2
- **RFC 6347** - Datagram Transport Layer Security Version 1.2 (DTLS 1.2)
- **RFC 7252** - The Constrained Application Protocol (CoAP)
- **RFC 7925** - TLS/DTLS Profiles for the Internet of Things
- **NIST SP 800-38C** - Recommendation for Block Cipher Modes (CCM)
- **6TiSCH Minimal Security** - draft-ietf-6tisch-minimal-security

**Related Documentation:**
- [CoAP and CoAPs](/doc/programming/CoAP) - Application-layer CoAP security
- [TSCH and 6TiSCH](/doc/programming/TSCH-and-6TiSCH) - TSCH link-layer overview
- [RPL](/doc/programming/RPL) - Routing protocol

**External Resources:**
- [Mbed TLS Documentation](https://tls.mbed.org/kb)
- [IEEE 802.15.4 Working Group](http://www.ieee802.org/15/)
- [6TiSCH Working Group](https://datatracker.ietf.org/wg/6tisch/)

## Summary

Contiki-NG provides comprehensive security mechanisms for IoT networks:

**Link-Layer Security (IEEE 802.15.4):**
- Hop-by-hop protection with AES-128 CCM*
- Encrypts all MAC frames (data, ACKs, beacons)
- Low overhead (~10 bytes per frame)
- Hardware acceleration on most platforms
- Protects against RF eavesdropping and rogue neighbors

**Application-Layer Security (DTLS/CoAPs):**
- End-to-end protection for application data
- DTLS 1.2 with PSK or certificates
- Higher overhead (~13 bytes + handshake)
- Protects against malicious routers
- Essential for Internet connectivity

**Best Practices:**
1. **Enable both layers** for defense in depth
2. **Use unique random keys** (never defaults in production)
3. **Configure appropriate security levels** (5 = ENC-MIC-32 standard)
4. **Plan key management** (generation, distribution, rotation)
5. **Monitor security events** (auth failures, replay attempts)
6. **Test thoroughly** before production deployment
7. **Use hardware crypto** when available (CC2538, CC26xx, nRF52)

**Security enables trustworthy IoT deployments** - essential for production networks handling sensitive data.
