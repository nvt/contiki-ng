# CoAP - Constrained Application Protocol

## Overview

CoAP (Constrained Application Protocol) is an application-layer protocol designed for constrained devices and networks in the Internet of Things (IoT). It provides a RESTful architecture similar to HTTP but is optimized for low-power, lossy networks with UDP transport.

**Key features:**
- **Lightweight**: Minimal overhead, runs efficiently on constrained devices (< 10 KB RAM, < 100 KB flash)
- **RESTful**: Uses familiar HTTP-like methods (GET, POST, PUT, DELETE)
- **UDP-based**: Connectionless transport with optional reliability (Confirmable messages)
- **Binary protocol**: Compact 4-byte fixed header
- **Built-in discovery**: Resource discovery via .well-known/core
- **Observe pattern**: Efficient publish-subscribe for sensor data
- **Block transfer**: Transparent fragmentation for large payloads ([RFC 7959])
- **Security**: DTLS support for encrypted communication (CoAPs)

**CoAP is defined in [RFC 7252].**

## Why CoAP for IoT?

| Feature | CoAP | MQTT | HTTP/REST |
|---------|------|------|-----------|
| **Transport** | UDP | TCP | TCP |
| **Overhead** | 4-byte header | 2-byte header + TCP | 100+ bytes |
| **Pattern** | Request/Response + Observe | Publish/Subscribe | Request/Response |
| **Discovery** | Built-in (.well-known/core) | None | None |
| **Caching** | Yes | No | Yes |
| **Reliability** | Optional (CON/NON) | Always (TCP) | Always (TCP) |
| **Best for** | Sensor networks, constrained devices | Telemetry, mobile | Web services, APIs |

**Use CoAP when:**
- Devices have very limited resources (RAM, power)
- Network is lossy or intermittent
- Need efficient request/response or observe patterns
- Want standard RESTful architecture for IoT
- Need multicast support

## CoAP in Contiki-NG

The Contiki-NG CoAP implementation is based on the Erbium implementation by Matthias Kovatsch but has been refactored for better portability. It is located in `/os/net/app-layer/coap/`.

**Architecture components:**
- **CoAP Engine**: Resource registration and request handling
- **CoAP Messages**: Message parsing and serialization
- **CoAP Transport**: UDP integration (with optional DTLS)
- **CoAP Transactions**: Reliable delivery with retransmissions
- **CoAP Observe**: Publish-subscribe pattern implementation
- **CoAP Block Transfer**: Transparent large payload handling

## CoAP Fundamentals

### Message Types

CoAP defines four message types:

| Type | Value | Description | Use Case |
|------|-------|-------------|----------|
| **CON** (Confirmable) | 0 | Requires ACK response | Important requests, guaranteed delivery |
| **NON** (Non-confirmable) | 1 | No ACK required | Repeated sensor readings, non-critical data |
| **ACK** (Acknowledgement) | 2 | Acknowledges CON message | Response to confirmable request |
| **RST** (Reset) | 3 | Rejects message | Error, unknown message ID |

**Message flow examples:**

```
CON Request/Response (reliable):
Client          Server
  |---CON GET--->|
  |<--ACK 2.05---|

NON Request/Response (unreliable, faster):
Client          Server
  |---NON GET--->|
  |<--NON 2.05---|

Separate Response (for slow operations):
Client          Server
  |---CON GET--->|
  |<----ACK------|  (Empty ACK)
  |              |  (Server processes...)
  |<--CON 2.05---|  (Later response)
  |----ACK------>|
```

### Request Methods

| Method | Code | Description |
|--------|------|-------------|
| **GET** | 0.01 | Retrieve resource representation |
| **POST** | 0.02 | Create resource or trigger action |
| **PUT** | 0.03 | Update/create resource |
| **DELETE** | 0.04 | Delete resource |

### Response Codes

| Code | Description | Usage |
|------|-------------|-------|
| **2.01 Created** | Resource created | POST response |
| **2.02 Deleted** | Resource deleted | DELETE response |
| **2.03 Valid** | Cached value still valid | GET with ETag |
| **2.04 Changed** | Resource updated | PUT/POST response |
| **2.05 Content** | Success with payload | GET response |
| **4.00 Bad Request** | Malformed request | Invalid syntax |
| **4.04 Not Found** | Resource doesn't exist | Unknown URI |
| **4.05 Method Not Allowed** | Method not supported | POST on read-only |
| **5.00 Internal Server Error** | Server error | Processing failed |
| **5.03 Service Unavailable** | Temporarily unavailable | Overloaded |

### Content Formats

Common content format identifiers:

| Format | Value | Description |
|--------|-------|-------------|
| `TEXT_PLAIN` | 0 | Plain text |
| `APPLICATION_LINK_FORMAT` | 40 | Resource discovery format |
| `APPLICATION_XML` | 41 | XML |
| `APPLICATION_OCTET_STREAM` | 42 | Binary data |
| `APPLICATION_EXI` | 47 | Efficient XML |
| `APPLICATION_JSON` | 50 | JSON |
| `APPLICATION_CBOR` | 60 | CBOR |

### Observe Pattern

The observe pattern enables efficient publish-subscribe for resource changes:

```
Initial request:
Client          Server
  |--CON GET---->|  (Observe: 0)
  |<-ACK 2.05----|  (Observe: 12)
  |              |
  |              |  (Resource changes)
  |<-CON 2.05----|  (Observe: 13)
  |----ACK------>|
  |              |
  |              |  (Resource changes)
  |<-CON 2.05----|  (Observe: 14)
  |----ACK------>|

Deregister:
  |--CON GET---->|  (Observe: 1)
  |<-ACK 2.05----|  (No Observe option)
```

**Advantages:**
- Server pushes updates without polling
- Saves power and bandwidth
- Automatic deregistration on client timeout

### Block Transfer

Block transfer (RFC 7959) enables reliable transfer of large payloads that exceed the maximum message size:

```
GET with block transfer:
Client          Server
  |--CON GET---->|  (Block2: 0/0/64)
  |<-ACK 2.05----|  (Block2: 0/1/64, Size2: 512)
  |--CON GET---->|  (Block2: 1/0/64)
  |<-ACK 2.05----|  (Block2: 1/1/64)
  |--CON GET---->|  (Block2: 2/0/64)
  |<-ACK 2.05----|  (Block2: 2/0/64) (Last block)
```

**When to use:**
- Payload > `COAP_MAX_CHUNK_SIZE` (default 64 bytes)
- Firmware updates
- Large sensor logs
- Image transfer

## Server API

### Resource Definition Macros

| Macro | Purpose |
|-------|---------|
| `RESOURCE(name, attributes, get, post, put, delete)` | Define a standard resource |
| `PARENT_RESOURCE(name, attributes, get, post, put, delete)` | Resource with sub-resources |
| `EVENT_RESOURCE(name, attributes, get, post, put, delete, trigger)` | Observable resource with manual triggering |
| `PERIODIC_RESOURCE(name, attributes, get, post, put, delete, period, handler)` | Observable resource with periodic updates |
| `SEPARATE_RESOURCE(name, attributes, get, post, put, delete, resume)` | Resource with separate (delayed) response |

**Parameters:**
- `name`: Resource identifier (C variable name)
- `attributes`: Link-format attributes string (can be NULL)
- `get/post/put/delete`: Handler functions (NULL if not supported)
- `trigger`: Manual trigger callback for event resources
- `period`: Update period in seconds for periodic resources
- `handler`: Periodic callback function
- `resume`: Resume callback for separate responses

### Resource Handler Signature

```c
void
resource_handler(coap_message_t *request,
                 coap_message_t *response,
                 uint8_t *buffer,
                 uint16_t preferred_size,
                 int32_t *offset)
```

**Parameters:**
- `request`: Incoming CoAP request message
- `response`: Response message to populate
- `buffer`: Buffer for response payload
- `preferred_size`: Maximum payload size client can accept
- `offset`: Current offset for block transfer (set to -1 when complete)

### Core Server Functions

| Function | Purpose |
|----------|---------|
| `coap_engine_init()` | Initialize CoAP engine (called by system) |
| `coap_activate_resource(resource, path)` | Register resource at URI path |
| `coap_init_message(message, type, code, mid)` | Initialize message structure |
| `coap_set_status_code(response, code)` | Set response code (e.g., 2.05) |
| `coap_set_payload(response, data, length)` | Set response payload |
| `coap_notify_observers(resource)` | Notify all observers of resource change |

### Setting Response Headers

| Function | Purpose |
|----------|---------|
| `coap_set_header_content_format(msg, format)` | Set Content-Format option |
| `coap_set_header_max_age(msg, age)` | Set Max-Age option (seconds) |
| `coap_set_header_etag(msg, etag, len)` | Set ETag option |
| `coap_set_header_location_path(msg, path)` | Set Location-Path (after POST) |
| `coap_set_header_observe(msg, value)` | Set Observe sequence number |
| `coap_set_header_size2(msg, size)` | Set total size for block transfer |

### Getting Request Headers

| Function | Purpose |
|----------|---------|
| `coap_get_header_uri_path(request, &path)` | Get URI path |
| `coap_get_header_uri_query(request, &query)` | Get URI query string |
| `coap_get_header_accept(request, &format)` | Get Accept option |
| `coap_get_header_if_match(request, &etag)` | Get If-Match option |
| `coap_get_header_observe(request, &observe)` | Get Observe option |
| `coap_get_payload(request, &payload)` | Get request payload |

### Query and POST Variables

```c
/* Get query parameter: /resource?name=value */
const char *value;
int len = coap_get_query_variable(request, "name", &value);

/* Get POST form parameter (application/x-www-form-urlencoded) */
const char *field;
int len = coap_get_post_variable(request, "field", &field);
```

## Server Examples

### Example 1: Simple GET Resource

```c
#include "coap-engine.h"
#include "sys/log.h"

#define LOG_MODULE "CoAP"
#define LOG_LEVEL LOG_LEVEL_INFO

/* Define resource */
static void
hello_get_handler(coap_message_t *request,
                  coap_message_t *response,
                  uint8_t *buffer,
                  uint16_t preferred_size,
                  int32_t *offset);

RESOURCE(hello_resource,
         "title=\"Hello World\";rt=\"text\"",
         hello_get_handler,
         NULL,  /* POST */
         NULL,  /* PUT */
         NULL); /* DELETE */

/* GET handler implementation */
static void
hello_get_handler(coap_message_t *request,
                  coap_message_t *response,
                  uint8_t *buffer,
                  uint16_t preferred_size,
                  int32_t *offset)
{
  const char *msg = "Hello, World!";
  size_t len = strlen(msg);

  /* Set response payload */
  coap_set_header_content_format(response, TEXT_PLAIN);
  coap_set_payload(response, msg, len);
}

/* Activate resource in main process */
PROCESS_THREAD(coap_server_process, ev, data)
{
  PROCESS_BEGIN();

  coap_activate_resource(&hello_resource, "hello");
  LOG_INFO("CoAP server started\n");

  PROCESS_END();
}
```

### Example 2: POST Resource with Payload

```c
static void
data_post_handler(coap_message_t *request,
                  coap_message_t *response,
                  uint8_t *buffer,
                  uint16_t preferred_size,
                  int32_t *offset)
{
  const uint8_t *payload;
  int payload_len;
  unsigned int format;

  /* Get request payload */
  payload_len = coap_get_payload(request, &payload);

  if(payload_len <= 0) {
    coap_set_status_code(response, BAD_REQUEST_4_00);
    return;
  }

  /* Check content format */
  if(!coap_get_header_content_format(request, &format) ||
     format != APPLICATION_JSON) {
    coap_set_status_code(response, BAD_REQUEST_4_00);
    return;
  }

  /* Process payload */
  LOG_INFO("Received %d bytes of JSON data\n", payload_len);
  process_json_data(payload, payload_len);

  /* Send response */
  coap_set_status_code(response, CREATED_2_01);
  coap_set_header_location_path(response, "data/123");
}

RESOURCE(data_resource,
         "title=\"Data Endpoint\";rt=\"data\"",
         NULL,               /* GET */
         data_post_handler,  /* POST */
         NULL,               /* PUT */
         NULL);              /* DELETE */
```

### Example 3: Observable Resource with Query Parameters

```c
static uint16_t sensor_value = 0;

static void
sensor_get_handler(coap_message_t *request,
                   coap_message_t *response,
                   uint8_t *buffer,
                   uint16_t preferred_size,
                   int32_t *offset)
{
  const char *unit = NULL;
  int len;
  char payload[64];

  /* Check for query parameter: /sensor?unit=celsius */
  len = coap_get_query_variable(request, "unit", &unit);

  if(len > 0 && strncmp(unit, "fahrenheit", len) == 0) {
    /* Convert to Fahrenheit */
    snprintf(payload, sizeof(payload), "{\"temperature\":%d,\"unit\":\"F\"}",
             (sensor_value * 9 / 5) + 32);
  } else {
    /* Default to Celsius */
    snprintf(payload, sizeof(payload), "{\"temperature\":%d,\"unit\":\"C\"}",
             sensor_value);
  }

  coap_set_header_content_format(response, APPLICATION_JSON);
  coap_set_header_max_age(response, 60);
  coap_set_payload(response, payload, strlen(payload));
}

EVENT_RESOURCE(sensor_resource,
               "title=\"Temperature\";rt=\"sensor\";obs",
               sensor_get_handler,
               NULL,  /* POST */
               NULL,  /* PUT */
               NULL,  /* DELETE */
               NULL); /* trigger */

/* Notify observers when sensor value changes */
void
sensor_value_updated(uint16_t new_value)
{
  sensor_value = new_value;
  coap_notify_observers(&sensor_resource);
}
```

### Example 4: Periodic Observable Resource

```c
static int counter = 0;

static void
periodic_handler(void)
{
  counter++;
  LOG_DBG("Periodic update: counter = %d\n", counter);
  /* Resource will automatically notify observers */
}

static void
counter_get_handler(coap_message_t *request,
                    coap_message_t *response,
                    uint8_t *buffer,
                    uint16_t preferred_size,
                    int32_t *offset)
{
  char payload[32];

  snprintf(payload, sizeof(payload), "{\"counter\":%d}", counter);

  coap_set_header_content_format(response, APPLICATION_JSON);
  coap_set_payload(response, payload, strlen(payload));
}

/* Update every 10 seconds */
PERIODIC_RESOURCE(counter_resource,
                  "title=\"Counter\";obs",
                  counter_get_handler,
                  NULL,  /* POST */
                  NULL,  /* PUT */
                  NULL,  /* DELETE */
                  10,    /* period in seconds */
                  periodic_handler);
```

### Example 5: Resource with Block Transfer

```c
static void
large_get_handler(coap_message_t *request,
                  coap_message_t *response,
                  uint8_t *buffer,
                  uint16_t preferred_size,
                  int32_t *offset)
{
  const char *large_data = /* ... large data ... */;
  size_t total_len = strlen(large_data);
  size_t chunk_len;

  /* Calculate chunk size */
  if(*offset >= total_len) {
    coap_set_status_code(response, BAD_REQUEST_4_00);
    return;
  }

  chunk_len = MIN(preferred_size, total_len - *offset);

  /* Set total size (only on first block) */
  if(*offset == 0) {
    coap_set_header_size2(response, total_len);
  }

  /* Copy chunk to buffer */
  memcpy(buffer, large_data + *offset, chunk_len);

  /* Update offset */
  *offset += chunk_len;

  /* Signal completion when all data sent */
  if(*offset >= total_len) {
    *offset = -1;
  }

  coap_set_header_content_format(response, TEXT_PLAIN);
  coap_set_payload(response, buffer, chunk_len);
}

RESOURCE(large_resource,
         "title=\"Large Data\";sz=4096",
         large_get_handler,
         NULL, NULL, NULL);
```

## Client API

### Client Request Functions

| Function | Purpose |
|----------|---------|
| `coap_init_message(request, type, code, mid)` | Initialize request message |
| `coap_send_request(response_handler, endpoint, request, buffer)` | Send request |
| `coap_new_transaction(mid, endpoint)` | Create transaction for reliable delivery |
| `coap_send_transaction(transaction)` | Send transaction |

### Client Response Handler

```c
void
response_handler(coap_message_t *response)
{
  const uint8_t *payload;
  int payload_len;

  if(response == NULL) {
    LOG_ERR("Request timeout\n");
    return;
  }

  LOG_INFO("Response code: %d.%02d\n",
           response->code >> 5, response->code & 0x1F);

  payload_len = coap_get_payload(response, &payload);
  if(payload_len > 0) {
    LOG_INFO("Payload: %.*s\n", payload_len, payload);
  }
}
```

## Client Examples

### Example 1: Simple GET Request

```c
#include "coap-engine.h"
#include "coap-blocking-api.h"

static void
client_response_handler(coap_message_t *response)
{
  const uint8_t *payload;
  int len;

  if(response == NULL) {
    LOG_ERR("Request timed out\n");
    return;
  }

  len = coap_get_payload(response, &payload);
  LOG_INFO("Response: %.*s\n", len, (char *)payload);
}

PROCESS_THREAD(coap_client_process, ev, data)
{
  static coap_endpoint_t server_endpoint;
  static coap_message_t request[1];

  PROCESS_BEGIN();

  /* Set server endpoint */
  coap_endpoint_parse("coap://[fd00::1]:5683", strlen("coap://[fd00::1]:5683"),
                      &server_endpoint);

  /* Prepare GET request */
  coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
  coap_set_header_uri_path(request, "hello");

  /* Send request */
  LOG_INFO("Sending GET request\n");
  COAP_BLOCKING_REQUEST(&server_endpoint, request, client_response_handler);

  PROCESS_END();
}
```

### Example 2: POST Request with Payload

```c
static void
post_response_handler(coap_message_t *response)
{
  const char *location;

  if(response == NULL) {
    LOG_ERR("Request timeout\n");
    return;
  }

  if(response->code == CREATED_2_01) {
    if(coap_get_header_location_path(response, &location)) {
      LOG_INFO("Resource created at: %s\n", location);
    }
  } else {
    LOG_WARN("POST failed with code %d.%02d\n",
             response->code >> 5, response->code & 0x1F);
  }
}

PROCESS_THREAD(post_client_process, ev, data)
{
  static coap_endpoint_t server_endpoint;
  static coap_message_t request[1];
  static char payload[] = "{\"temperature\":25,\"humidity\":60}";

  PROCESS_BEGIN();

  coap_endpoint_parse("coap://[fd00::1]:5683", strlen("coap://[fd00::1]:5683"),
                      &server_endpoint);

  /* Prepare POST request */
  coap_init_message(request, COAP_TYPE_CON, COAP_POST, 0);
  coap_set_header_uri_path(request, "sensor/data");
  coap_set_header_content_format(request, APPLICATION_JSON);
  coap_set_payload(request, payload, strlen(payload));

  LOG_INFO("Sending POST request\n");
  COAP_BLOCKING_REQUEST(&server_endpoint, request, post_response_handler);

  PROCESS_END();
}
```

### Example 3: Observe Client

```c
#include "coap-observe-client.h"

static coap_observee_t *obs;

static void
notification_callback(coap_observee_t *observee,
                      coap_message_t *notification,
                      coap_notification_flag_t flag)
{
  const uint8_t *payload;
  int len;

  if(flag == NOTIFICATION_OK) {
    len = coap_get_payload(notification, &payload);
    LOG_INFO("Notification: %.*s\n", len, (char *)payload);
  } else if(flag == OBSERVE_OK) {
    LOG_INFO("Observe request accepted\n");
  } else {
    LOG_WARN("Observe failed or deregistered\n");
    obs = NULL;
  }
}

PROCESS_THREAD(observe_client_process, ev, data)
{
  static coap_endpoint_t server_endpoint;
  static struct etimer et;

  PROCESS_BEGIN();

  coap_endpoint_parse("coap://[fd00::1]:5683", strlen("coap://[fd00::1]:5683"),
                      &server_endpoint);

  /* Start observing */
  LOG_INFO("Starting observe\n");
  obs = coap_obs_request_registration(&server_endpoint, "sensor",
                                      notification_callback, NULL);

  /* Run for 60 seconds */
  etimer_set(&et, 60 * CLOCK_SECOND);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

  /* Deregister observe */
  if(obs != NULL) {
    LOG_INFO("Stopping observe\n");
    coap_obs_remove_observee(obs);
  }

  PROCESS_END();
}
```

## Configuration

### Core Configuration Options

Add these to your `project-conf.h`:

```c
/* Maximum CoAP message payload size (excluding headers) */
#define COAP_MAX_CHUNK_SIZE 64  /* Default: 64, Range: 16-2048 */

/* Maximum number of concurrent transactions */
#define COAP_MAX_OPEN_TRANSACTIONS 4  /* Default: 4 */

/* Maximum number of active observers */
#define COAP_MAX_OBSERVERS 3  /* Default: COAP_MAX_OPEN_TRANSACTIONS - 1 */

/* Observe refresh interval (seconds) */
#define COAP_OBSERVE_REFRESH_INTERVAL 30  /* Default: 30 */

/* Token length (bytes) */
#define COAP_TOKEN_LEN 4  /* Default: 4, Range: 1-8 */
```

### Retransmission Parameters

```c
/* ACK timeout (seconds) */
#define COAP_ACK_TIMEOUT 2  /* Default: 2 */

/* Random factor for timeout backoff */
#define COAP_ACK_RANDOM_FACTOR 1.5  /* Default: 1.5 */

/* Maximum number of retransmissions */
#define COAP_MAX_RETRANSMIT 4  /* Default: 4 */
```

**Retransmission timing:**
- First timeout: 2-3 seconds (randomized)
- Each retry: timeout × 2 (exponential backoff)
- After 4 retries: Give up (total ~45 seconds)

### Block Transfer Configuration

```c
/* Preferred block size (will be rounded down to power of 2) */
#define COAP_MAX_BLOCK_SIZE 64  /* Auto-calculated from COAP_MAX_CHUNK_SIZE */
```

**Block size recommendations:**
| Network | Recommended Size | Reason |
|---------|------------------|--------|
| 6LoWPAN | 64-128 bytes | Fits in single 802.15.4 frame |
| WiFi | 512-1024 bytes | Larger MTU allows bigger blocks |
| Ethernet | 1024-2048 bytes | Maximum efficiency |

### Memory Considerations

**Memory usage per configuration:**
```
Transaction: ~60-80 bytes
Observer: ~40-60 bytes
Open socket: ~40-80 bytes (platform-dependent)

Example with defaults:
- 4 transactions: ~320 bytes
- 3 observers: ~180 bytes
- Total CoAP: ~500 bytes RAM
```

**Tuning for constrained devices:**
```c
/* Minimal configuration (< 256 bytes RAM) */
#define COAP_MAX_CHUNK_SIZE 32
#define COAP_MAX_OPEN_TRANSACTIONS 2
#define COAP_MAX_OBSERVERS 1
```

## CoAPs - Secure CoAP

### Enabling DTLS

Build with DTLS support:
```bash
make TARGET=<platform> MAKE_WITH_DTLS=1
```

This enables:
- CoAPs on port 5684 (default CoAP uses port 5683)
- DTLS 1.2 encryption
- Support for PSK (Pre-Shared Key) or certificate authentication

### Pre-Shared Key (PSK) Configuration

In `project-conf.h`:

```c
/* Enable DTLS */
#define WITH_DTLS 1

/* PSK identity and key */
#define DTLS_PSK_IDENTITY "Client_identity"
#define DTLS_PSK_KEY "secretPSK"
#define DTLS_PSK_KEY_LEN 9
```

In your code:

```c
#include "tinydtls.h"

static void
setup_dtls_psk(void)
{
  /* PSK is configured at build time via defines */
  LOG_INFO("DTLS PSK configured\n");
}

PROCESS_THREAD(coaps_client_process, ev, data)
{
  static coap_endpoint_t secure_endpoint;

  PROCESS_BEGIN();

  /* Use coaps:// scheme for secure connection */
  coap_endpoint_parse("coaps://[fd00::1]:5684",
                      strlen("coaps://[fd00::1]:5684"),
                      &secure_endpoint);

  /* Secure endpoint is automatically used with DTLS */
  /* ... rest of client code ... */

  PROCESS_END();
}
```

### Certificate-Based Authentication (Mbed TLS)

For certificate-based DTLS, configure Mbed TLS:

```c
/* In project-conf.h */
#define MBEDTLS_CONF_FILE "mbedtls-config.h"

/* Certificate and key in DER format */
extern const unsigned char server_cert_der[];
extern const size_t server_cert_der_len;
extern const unsigned char server_key_der[];
extern const size_t server_key_der_len;
```

### CoAPs Best Practices

1. **Use PSK for constrained devices**: Much lower overhead than certificates
2. **Reuse DTLS sessions**: DTLS handshake is expensive (~5-10 seconds)
3. **Implement connection keep-alive**: Send periodic NON messages to maintain session
4. **Handle session failures**: Implement reconnection logic with exponential backoff
5. **Consider power impact**: DTLS uses significantly more power than plain CoAP

## Resource Discovery

CoAP provides built-in resource discovery via the `.well-known/core` resource:

### Automatic Discovery Support

Contiki-NG automatically provides `.well-known/core`:

```c
/* Resources are automatically discoverable if they have attributes */
RESOURCE(sensor_resource,
         "title=\"Temperature\";rt=\"sensor\";if=\"sensor\";obs",
         sensor_get_handler,
         NULL, NULL, NULL);

coap_activate_resource(&sensor_resource, "sensors/temperature");
```

### Client Discovery Request

```c
static void
discovery_response_handler(coap_message_t *response)
{
  const uint8_t *payload;
  int len;

  if(response == NULL) {
    LOG_ERR("Discovery timeout\n");
    return;
  }

  len = coap_get_payload(response, &payload);
  LOG_INFO("Available resources:\n%.*s\n", len, (char *)payload);

  /* Parse link-format response */
  /* Example output:
   * </sensors/temperature>;title="Temperature";rt="sensor";obs,
   * </actuators/led>;title="LED Control";rt="actuator"
   */
}

/* Send discovery request */
coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
coap_set_header_uri_path(request, ".well-known/core");
COAP_BLOCKING_REQUEST(&endpoint, request, discovery_response_handler);
```

## Best Practices

### 1. Choose Appropriate Message Type

**Use CON (Confirmable) when:**
- Request must succeed (state changes, POST/PUT/DELETE)
- Need to know if message was received
- Okay with retransmission overhead

**Use NON (Non-confirmable) when:**
- Sending frequent sensor readings
- Data is not critical or will be sent again soon
- Want to minimize power consumption
- Network is reliable

### 2. Implement Proper Error Handling

```c
static void
robust_resource_handler(coap_message_t *request,
                        coap_message_t *response,
                        uint8_t *buffer,
                        uint16_t preferred_size,
                        int32_t *offset)
{
  const uint8_t *payload;
  int payload_len;

  /* Validate method */
  if(coap_get_method_type(request) != METHOD_POST) {
    coap_set_status_code(response, METHOD_NOT_ALLOWED_4_05);
    return;
  }

  /* Check payload exists */
  payload_len = coap_get_payload(request, &payload);
  if(payload_len <= 0) {
    coap_set_status_code(response, BAD_REQUEST_4_00);
    const char *msg = "Payload required";
    coap_set_payload(response, msg, strlen(msg));
    return;
  }

  /* Validate payload size */
  if(payload_len > MAX_DATA_SIZE) {
    coap_set_status_code(response, REQUEST_ENTITY_TOO_LARGE_4_13);
    return;
  }

  /* Process data */
  if(!process_data(payload, payload_len)) {
    coap_set_status_code(response, INTERNAL_SERVER_ERROR_5_00);
    return;
  }

  /* Success */
  coap_set_status_code(response, CHANGED_2_04);
}
```

### 3. Use Observe for Periodic Data

**Wrong - Polling:**
```c
/* Client polls every second - wastes power and bandwidth */
while(1) {
  send_get_request("sensor");
  wait(1 second);
}
```

**Correct - Observe:**
```c
/* Server pushes updates only when value changes */
coap_obs_request_registration(&endpoint, "sensor", callback, NULL);
/* Client receives updates automatically */
```

### 4. Manage Observer Resources

```c
/* Limit active observers */
#define MAX_SENSOR_OBSERVERS 5

static int active_observers = 0;

static void
check_observer_limit(coap_message_t *request,
                     coap_message_t *response)
{
  uint32_t observe;

  if(coap_get_header_observe(request, &observe) && observe == 0) {
    /* New observe request */
    if(active_observers >= MAX_SENSOR_OBSERVERS) {
      coap_set_status_code(response, SERVICE_UNAVAILABLE_5_03);
      const char *msg = "Too many observers";
      coap_set_payload(response, msg, strlen(msg));
      return;
    }
    active_observers++;
  }
}
```

### 5. Set Appropriate Max-Age

```c
/* Fast-changing data - short cache time */
coap_set_header_max_age(response, 5);  /* 5 seconds */

/* Slow-changing data - long cache time */
coap_set_header_max_age(response, 3600);  /* 1 hour */

/* Never cache */
coap_set_header_max_age(response, 0);
```

### 6. Use Appropriate Content Formats

- Use **JSON** for human-readable, web-compatible data
- Use **CBOR** for compact binary encoding (50-80% smaller than JSON)
- Use **TEXT_PLAIN** for simple values
- Always set Content-Format option

### 7. Implement Rate Limiting

```c
static struct ctimer rate_limit_timer;
static uint8_t request_count = 0;

static void
reset_rate_limit(void *ptr)
{
  request_count = 0;
}

static bool
check_rate_limit(void)
{
  if(request_count == 0) {
    /* Start timer for rate limit window */
    ctimer_set(&rate_limit_timer, 60 * CLOCK_SECOND,
               reset_rate_limit, NULL);
  }

  request_count++;

  if(request_count > MAX_REQUESTS_PER_MINUTE) {
    return false;  /* Rate limit exceeded */
  }

  return true;
}
```

## Common Pitfalls

### Pitfall 1: Forgetting to Activate Resources

**Wrong:**
```c
RESOURCE(my_resource, "title=\"Test\"", handler, NULL, NULL, NULL);

PROCESS_THREAD(server, ev, data)
{
  PROCESS_BEGIN();
  /* Resource defined but never activated! */
  PROCESS_END();
}
```

**Correct:**
```c
PROCESS_THREAD(server, ev, data)
{
  PROCESS_BEGIN();
  coap_activate_resource(&my_resource, "test");
  PROCESS_END();
}
```

### Pitfall 2: Not Checking Payload Length

**Wrong:**
```c
const uint8_t *payload;
coap_get_payload(request, &payload);
memcpy(buffer, payload, sizeof(buffer));  /* Buffer overflow! */
```

**Correct:**
```c
const uint8_t *payload;
int len = coap_get_payload(request, &payload);
if(len > 0 && len <= sizeof(buffer)) {
  memcpy(buffer, payload, len);
}
```

### Pitfall 3: Exceeding COAP_MAX_CHUNK_SIZE

**Wrong:**
```c
char response[512];  /* Might exceed COAP_MAX_CHUNK_SIZE */
sprintf(response, "...");
coap_set_payload(response, response, strlen(response));
```

**Correct:**
```c
char response[COAP_MAX_CHUNK_SIZE];
int len = snprintf(response, sizeof(response), "...");
if(len < sizeof(response)) {
  coap_set_payload(response, response, len);
}
/* For larger payloads, implement block transfer support */
```

### Pitfall 4: Blocking in Resource Handlers

**Wrong:**
```c
static void
slow_handler(coap_message_t *request, coap_message_t *response,
             uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  clock_wait(5 * CLOCK_SECOND);  /* WRONG! Blocks CoAP engine */
  /* ... */
}
```

**Correct - Use Separate Response:**
```c
static void
slow_resume_handler(void)
{
  /* Called when slow operation completes */
  coap_separate_accept(&slow_request, &slow_ep);
  /* ... build response ... */
  coap_separate_resume(&response, &slow_ep, COAP_TYPE_CON);
}

SEPARATE_RESOURCE(slow_resource,
                  "title=\"Slow Operation\"",
                  NULL, slow_handler, NULL, NULL,
                  slow_resume_handler);
```

### Pitfall 5: Not Handling Timeouts

**Wrong:**
```c
static void
client_handler(coap_message_t *response)
{
  /* Assumes response is never NULL */
  process_response(response);  /* Crash on timeout! */
}
```

**Correct:**
```c
static void
client_handler(coap_message_t *response)
{
  if(response == NULL) {
    LOG_WARN("Request timeout, retrying...\n");
    retry_request();
    return;
  }
  process_response(response);
}
```

### Pitfall 6: Ignoring Response Codes

**Wrong:**
```c
/* Assumes all requests succeed */
COAP_BLOCKING_REQUEST(&endpoint, request, NULL);
proceed_as_if_successful();
```

**Correct:**
```c
static bool request_succeeded = false;

static void
response_handler(coap_message_t *response)
{
  if(response != NULL &&
     (response->code >= CREATED_2_01 && response->code <= CONTENT_2_05)) {
    request_succeeded = true;
  }
}

COAP_BLOCKING_REQUEST(&endpoint, request, response_handler);
if(request_succeeded) {
  proceed();
}
```

## Troubleshooting

### Issue: Resources Not Accessible

**Symptoms:** Client receives 4.04 Not Found

**Solutions:**
1. Verify resource is activated: `coap_activate_resource(&res, "path")`
2. Check path matches exactly (case-sensitive)
3. Ensure CoAP engine is initialized: `coap_engine_init()`
4. Check resource is not NULL in handler

### Issue: Observe Not Working

**Symptoms:** No notifications received

**Solutions:**
1. Verify resource has `obs` attribute in definition
2. Check observer limit not exceeded (`COAP_MAX_OBSERVERS`)
3. Ensure `coap_notify_observers()` is called when resource changes
4. Verify client uses CON messages (ACKs needed for reliability)
5. Check observer refresh interval not too short

### Issue: Messages Being Dropped

**Symptoms:** Frequent timeouts, retransmissions

**Solutions:**
1. Check network connectivity (`ping6`)
2. Reduce `COAP_MAX_CHUNK_SIZE` for lossy networks
3. Use NON messages for non-critical data
4. Verify firewall allows UDP port 5683
5. Check `COAP_MAX_OPEN_TRANSACTIONS` not exhausted

### Issue: "Transaction buffer full" Error

**Symptoms:** Cannot send messages, error logged

**Solutions:**
```c
/* Increase transaction limit */
#define COAP_MAX_OPEN_TRANSACTIONS 8  /* Default: 4 */
```

Or reduce concurrent requests:
```c
/* Wait for previous request to complete */
COAP_BLOCKING_REQUEST(&ep, request, handler);
/* Before sending next request */
```

### Issue: Block Transfer Fails

**Symptoms:** Large payloads not received completely

**Solutions:**
1. Implement `*offset` handling correctly in GET handler
2. Set `size2` header on first block:
   ```c
   if(*offset == 0) {
     coap_set_header_size2(response, total_size);
   }
   ```
3. Signal completion: `*offset = -1` when done
4. Check `COAP_MAX_CHUNK_SIZE` is sufficient

### Issue: High Power Consumption

**Symptoms:** Device battery drains quickly

**Solutions:**
1. Use NON instead of CON for frequent messages
2. Use observe instead of polling
3. Increase observe refresh interval:
   ```c
   #define COAP_OBSERVE_REFRESH_INTERVAL 60
   ```
4. Batch multiple readings into single message
5. Use longer Max-Age for caching

### Debugging CoAP Messages

Enable detailed logging:

```c
/* In project-conf.h */
#define LOG_CONF_LEVEL_COAP LOG_LEVEL_DBG

/* Shows all CoAP messages */
#define COAP_LOG_LEVEL LOG_LEVEL_DBG
```

Use Wireshark to capture traffic:
```bash
# Capture on 6LoWPAN interface
sudo wireshark -i tun0 -f "udp port 5683"
```

Enable CoAP dissector in Wireshark: Analyze → Decode As → UDP port 5683 → CoAP

## Limitations

Current implementation limitations:

- **Single transaction per resource**: One active request per resource at a time
- **Limited observers**: Default 3 observers (configurable)
- **No OSCORE**: No CoAP Object Security support yet
- **No multicast**: Multicast CoAP not fully implemented
- **No CoAP over TCP**: UDP transport only

## Migration Notes

### Changes from Contiki-NG 4.0 to 4.1+

- **REST_MAX_CHUNK_SIZE** → **COAP_MAX_CHUNK_SIZE**
- REST engine removed, use CoAP engine directly
- `rest_activate_resource()` → `coap_activate_resource()`
- TinyDTLS added as submodule for DTLS support

## Additional Resources

**Tutorials:**
- [CoAP Tutorial](../../tutorials/CoAP.md) - Step-by-step guide
- [LWM2M Tutorial](../../tutorials/LWM2M-and-IPSO-Objects.md) - LWM2M over CoAP

**Specifications:**
- [RFC 7252] - The Constrained Application Protocol (CoAP)
- [RFC 7959] - Block-Wise Transfers in the Constrained Application Protocol
- [RFC 7641] - Observing Resources in the Constrained Application Protocol
- [RFC 6690] - Constrained RESTful Environments (CoRE) Link Format

**Examples:**
- `examples/coap/coap-example-server/` - Complete CoAP server
- `examples/coap/coap-example-client/` - Complete CoAP client
- `examples/coap/coap-plugtest-server/` - Plugtest server for interoperability

## Summary

CoAP provides an efficient RESTful protocol for constrained IoT devices:

- **Use CoAP** for RESTful APIs on resource-constrained devices
- **Use Observe** instead of polling for efficient sensor monitoring
- **Use CON** for reliable delivery, **NON** for frequent unreliable updates
- **Implement error handling** for all requests and responses
- **Enable DTLS** (CoAPs) for secure communication when needed
- **Monitor memory** usage and tune configuration for your application
- **Follow best practices** to avoid common pitfalls

CoAP brings web-like RESTful architecture to IoT while maintaining efficiency for battery-powered, low-bandwidth wireless sensor networks.

[RFC 7252]: https://tools.ietf.org/html/rfc7252
[RFC 7959]: https://tools.ietf.org/html/rfc7959
[RFC 7641]: https://tools.ietf.org/html/rfc7641
[RFC 6690]: https://tools.ietf.org/html/rfc6690
