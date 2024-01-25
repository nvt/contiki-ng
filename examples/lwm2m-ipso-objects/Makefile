CONTIKI_PROJECT = example-ipso-objects

CONTIKI_SOURCEFILES += example-ipso-temperature.c

PLATFORMS_EXCLUDE = sky z1

ifeq ($(MAKE_WITH_DTLS),1)
 # Exclude platforms with insufficient memory for DTLS support.
  PLATFORMS_EXCLUDE += zoul
endif

all: $(CONTIKI_PROJECT)

CONTIKI=../..

include $(CONTIKI)/Makefile.dir-variables
MODULES += $(CONTIKI_NG_APP_LAYER_DIR)/coap
MODULES += $(CONTIKI_NG_SERVICES_DIR)/lwm2m
MODULES += $(CONTIKI_NG_SERVICES_DIR)/ipso-objects
MODULES += $(CONTIKI_NG_SERVICES_DIR)/rpl-border-router

include $(CONTIKI)/Makefile.identify-target
MODULES_REL += $(TARGET)

include $(CONTIKI)/Makefile.include
