CONTIKI_PROJECT = fuzz-harness
all: $(CONTIKI_PROJECT)

PLATFORM_ONLY = native
TARGET = native

# Routing protocol under test. The packet injector in tests/20-packet-parsing
# uses the native default, which is RPL Lite, so this directory fuzzes RPL
# Classic by default in order to cover both. Override on the command line to
# fuzz the other one.
MAKE_ROUTING ?= MAKE_ROUTING_RPL_CLASSIC

CONTIKI = ../../../
include $(CONTIKI)/Makefile.include
