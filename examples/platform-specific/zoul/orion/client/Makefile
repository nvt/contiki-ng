CONTIKI_PROJECT = client ifttt-client
all: $(CONTIKI_PROJECT)

BOARD = orion

PLATFORMS_ONLY = zoul
BOARDS_ONLY = orion

CONTIKI = ../../../../..

include $(CONTIKI)/Makefile.dir-variables
MODULES += $(CONTIKI_NG_APP_LAYER_DIR)/http-socket

include $(CONTIKI)/Makefile.include
