CONTIKI_PROJECT = udp-echo
all: $(CONTIKI_PROJECT)

# Enable Rust support
RUST_SUPPORT = 1

# Enable IPv6 networking
MAKE_MAC = MAKE_MAC_CSMA
MAKE_NET = MAKE_NET_IPV6

# Include simple-udp module
MODULES += os/net/ipv6

# Platforms that don't support Rust yet
PLATFORMS_EXCLUDE += sky z1

CONTIKI = ../../..

include $(CONTIKI)/Makefile.include
