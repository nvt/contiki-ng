CONTIKI_PROJECT = packet-injector
all: $(CONTIKI_PROJECT)

PLATFORM_ONLY = native
TARGET = native

MODULES += os/net/app-layer/coap
MODULES += os/net/mac/ble

# The injector feeds raw, often malformed, packets into the parsers. Build it
# with AddressSanitizer so that out-of-bounds accesses fail the test instead of
# corrupting memory silently. -fno-common gives uip_aligned_buf, a tentative
# definition, its own redzone, which ASan needs to catch overflows of uip_buf.
CFLAGS += -fsanitize=address -fno-common
LDFLAGS += -fsanitize=address

CONTIKI = ../../../
include $(CONTIKI)/Makefile.include
