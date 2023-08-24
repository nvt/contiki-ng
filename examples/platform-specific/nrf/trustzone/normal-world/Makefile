CONTIKI_PROJECT = normal-world-example
CONTIKI = ../../../../..

all: $(CONTIKI_PROJECT)

PLATFORMS_ONLY += nrf
BOARDS_ONLY = nrf5340/dk/application

TARGET ?= nrf
BOARD ?= nrf5340/dk/application

SECURE_WORLD_PATH ?= ../secure-world
CMSE_IMPORT_LIB ?= CMSE-import-lib.o

TRUSTZONE_SECURE_BUILD = 0

LDFLAGS += $(SECURE_WORLD_PATH)/build/nrf/nrf5340/dk/application/$(CMSE_IMPORT_LIB)

include $(CONTIKI)/Makefile.include
