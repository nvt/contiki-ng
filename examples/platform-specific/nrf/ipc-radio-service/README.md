# IPC Radio Service

Radio service firmware for the nRF5340 **network core**. Provides
802.15.4 radio access to the application core via IPC shared memory.

This is a minimal Contiki-NG image (NULLNET/NULLMAC/NULLROUTING)
whose sole purpose is to receive commands from the application core,
call the nRF 802.15.4 radio driver, and return results. It also
forwards received frames and sends software ACKs.

## Building

```bash
make TARGET=nrf BOARD=nrf5340/dk/network
```

## Flashing

The network core must be flashed **before** the application core:

```bash
make TARGET=nrf BOARD=nrf5340/dk/network ipc-radio-service.upload
```

## Design Notes

- The network core runs a busy-poll loop for sub-100us command and
  frame detection latency, which is required for 802.15.4 software
  ACKs within the sender's CSMA ACK wait window.
- UARTE is disabled on the network core (`NRF_HAS_UARTE 0`). All
  debug output is redirected to a shared memory ring buffer, which
  the application core drains and prints with a `[NET]` prefix.
- The radio is configured in poll mode so that received frames are
  forwarded to the application core via IPC rather than consumed
  locally.
- TSCH is not supported. The IPC latency is too high for TSCH slot
  timing; use CSMA.

## Related

- `arch/cpu/nrf/net/nrf-ipc.h` -- IPC protocol definitions
- `arch/cpu/nrf/net/README.md` -- Full IPC architecture documentation
