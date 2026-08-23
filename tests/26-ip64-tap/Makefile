# End-to-end test of the ip64 NAT64 service against host software over a TAP
# device.
#
# One check, reported via the summary/"TEST FAIL" convention that
# tests/check-test.sh expects: run a native node with ip64 on a TAP device,
# and check that an IPv4 echo server on the host exchanges UDP with it and
# that the host can ping the node. Needs CAP_NET_ADMIN, no Cooja or internet.
#
# Author: Nicolas Tsiftes <nicolas.tsiftes@ri.se>

SHELL := /bin/bash

CONTIKI ?= ../..

IP64_TAP_TEST := $(CURDIR)/test-ip64-tap.sh

.PHONY: all summary ip64-tap clean

all: summary

# A successful check leaves no summary line; the final rule then creates an
# empty summary so check-test.sh (which greps for "TEST FAIL") sees a pass.
summary: clean
	@$(MAKE) ip64-tap
	@echo "========== Summary =========="
	@([ ! -f summary ] && echo "All tests OK" && touch summary) || \
          (echo "Failures:" && cat summary && false)

ip64-tap:
	@echo ">> ip64 over a TAP device, against host software"
	@$(IP64_TAP_TEST) || echo "TEST FAIL: ip64-tap" >> summary

clean:
	@rm -f *.*log *.pid report summary
	@$(MAKE) -C code-ip64-tap TARGET=native clean >/dev/null 2>&1 || true
