CONTIKI_PROJECT = hello-world
all: $(CONTIKI_PROJECT)

# Include Rust source files
PROJECT_SOURCEFILES += rust_module.rs

# Platforms that don't support Rust yet
PLATFORMS_EXCLUDE += sky z1

# Enable Rust support
RUST_SUPPORT = 1

CONTIKI = ../..

# Include Rust support before main Makefile
-include $(CONTIKI)/tools/rust-support/Makefile.rust

include $(CONTIKI)/Makefile.include