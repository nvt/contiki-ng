CONTIKI_PROJECT = async-udp-echo
all: $(CONTIKI_PROJECT)

# Enable Rust support
RUST_SUPPORT = 1

# Rust source files are auto-detected
# The build system will find async_udp_echo_process.rs automatically

# Platforms that don't support Rust yet
PLATFORMS_EXCLUDE += sky z1

CONTIKI = ../../..

include $(CONTIKI)/Makefile.include
