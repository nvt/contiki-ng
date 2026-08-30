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

# MQTT runs over TCP, which uipopt.h leaves out by default, and the module is
# built at the newest version of the protocol. Version 5 keeps the message
# parsing of the older versions and adds the properties that mqtt-prop.c
# decodes, so it is the version that reaches all of what the module links.
ifneq ($(filter mqtt,$(FUZZ_PROTOCOLS)),)
  MODULES += os/net/app-layer/mqtt
  CFLAGS += -DFUZZ_WITH_MQTT=1
  CFLAGS += -DUIP_CONF_TCP=1
  CFLAGS += -DMQTT_CONF_VERSION=5
endif

# Only the DNS64 translation of the NAT64 gateway is built. The rest of the
# module reaches the network through a platform layer that a campaign has no
# use for, and would need one written for it before it linked at all.
ifneq ($(filter nat64-dns64,$(FUZZ_PROTOCOLS)),)
  MODULES += os/services/nat64
  MODULES_SOURCES_EXCLUDES += nat64.c nat64-tcp.c
  CFLAGS += -DFUZZ_WITH_NAT64_DNS64=1
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
