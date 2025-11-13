CONTIKI_PROJECT = hello-world
all: $(CONTIKI_PROJECT)

# Rust source files are auto-detected from the current directory
# No need to manually add them to PROJECT_SOURCEFILES anymore!
# (To disable auto-detection, set RUST_NO_AUTO_DETECT = 1)

# Platforms that don't support Rust yet
PLATFORMS_EXCLUDE += sky z1

# Enable Rust support
RUST_SUPPORT = 1

CONTIKI = ../..

# Include Rust support before main Makefile
-include $(CONTIKI)/tools/rust-support/Makefile.rust

include $(CONTIKI)/Makefile.include