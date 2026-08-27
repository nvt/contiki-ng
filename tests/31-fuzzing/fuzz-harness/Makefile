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

# Build for replaying the output of a campaign rather than for running one.
#
# A campaign runs without either of these, because both cost throughput. The
# fuzzer's output is replayed afterwards through a build that has them, which
# is where a memory error or an undefined operation is detected, and where the
# reach of the campaign is measured.
ifeq ($(FUZZ_SANITIZE),1)
  CFLAGS  += -fsanitize=address,undefined -fno-omit-frame-pointer -g
  LDFLAGS += -fsanitize=address,undefined
endif

ifeq ($(FUZZ_COVERAGE),1)
  CFLAGS  += --coverage -g
  LDFLAGS += --coverage
endif

CONTIKI = ../../../
include $(CONTIKI)/Makefile.include
