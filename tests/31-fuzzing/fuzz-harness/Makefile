CONTIKI_PROJECT = fuzz-harness
all: $(CONTIKI_PROJECT)

PLATFORM_ONLY = native
TARGET = native

# Routing protocol under test. The packet injector in tests/20-packet-parsing
# uses the native default, which is RPL Lite, so this directory fuzzes RPL
# Classic by default in order to cover both. Override on the command line to
# fuzz the other one.
MAKE_ROUTING ?= MAKE_ROUTING_RPL_CLASSIC

# Application layer protocols to build into the harness. Each one links its
# module and enables the matching entry point. Keep the set as small as the
# campaign needs: code that is linked but not targeted still contributes to
# the coverage map that guides the fuzzer.
#
#   make FUZZ_PROTOCOLS="snmp coap"
#
# The build system does not rebuild on a change to this variable, so run
# "make distclean" when changing it.
FUZZ_PROTOCOLS ?=

ifneq ($(filter coap,$(FUZZ_PROTOCOLS)),)
  MODULES += os/net/app-layer/coap
  CFLAGS += -DFUZZ_WITH_COAP=1
endif

ifneq ($(filter snmp,$(FUZZ_PROTOCOLS)),)
  MODULES += os/net/app-layer/snmp
  CFLAGS += -DFUZZ_WITH_SNMP=1
endif

CONTIKI = ../../../
include $(CONTIKI)/Makefile.include
