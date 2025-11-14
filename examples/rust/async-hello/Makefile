CONTIKI_PROJECT = async-hello
all: $(CONTIKI_PROJECT)

# Enable Rust support
RUST_SUPPORT = 1

# Rust source files are auto-detected from the current directory
# The build system will find async_hello_process.rs automatically

# Platforms that don't support Rust yet
PLATFORMS_EXCLUDE += sky z1

CONTIKI = ../../..

include $(CONTIKI)/Makefile.include
