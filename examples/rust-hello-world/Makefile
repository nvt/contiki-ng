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

# Makefile.rust is automatically included by Makefile.include when RUST_SUPPORT=1
# No need to include it explicitly here!

include $(CONTIKI)/Makefile.include