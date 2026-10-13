# Check the harness and the seeds of every target, as check-seeds.sh
# describes. This is what running make in this directory does, which is how
# tests/Makefile and continuous integration run a test directory. Running a
# fuzzing campaign is left to fuzz.sh.

.PHONY: all summary clean

all: clean
	@$(MAKE) --no-print-directory summary

summary:
	@./check-seeds.sh
	@echo "========== Summary =========="
	@([ ! -f summary ] && echo "All tests OK" && touch summary) || \
	  (echo "Failures:" && cat summary && false)

clean:
	@rm -f summary
