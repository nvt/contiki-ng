APPS = tunslip6 serialdump
LIB_SRCS = tools-utils.c
DEPEND = tools-utils.h

# Select the platform-specific tunslip6 implementation by host OS.
UNAME := $(shell uname)
ifeq ($(UNAME),Linux)
TUNSLIP6_PLATFORM = tunslip6-linux.c
else ifeq ($(UNAME),Darwin)
TUNSLIP6_PLATFORM = tunslip6-macos.c
else
TUNSLIP6_PLATFORM = tunslip6-bsd.c
endif

all: $(APPS)

CFLAGS += -Wall -Werror -O2

serialdump: serialdump.c $(LIB_SRCS) $(DEPEND)
	$(CC) $(CFLAGS) $< $(LIB_SRCS) -o $@

tunslip6: tunslip6.c $(TUNSLIP6_PLATFORM) tunslip6.h $(LIB_SRCS) $(DEPEND)
	$(CC) $(CFLAGS) tunslip6.c $(TUNSLIP6_PLATFORM) $(LIB_SRCS) -o $@

clean:
	rm -f $(APPS)
