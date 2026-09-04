# ePassport - an eMRTD viewer for the Proxmark3.
#
# Nothing here builds: the app is a Python script run in place.  These targets
# are the housekeeping around it.

PYTHON ?= python3
SAMPLEDIR ?= samples

.PHONY: help run test format samples clean distclean check

help:
	@echo "ePassport"
	@echo
	@echo "  make run        launch the app"
	@echo "  make test       run the test suite (no hardware needed)"
	@echo "  make samples    generate fabricated sample dumps into $(SAMPLEDIR)/"
	@echo "  make format     reformat with black"
	@echo "  make clean      remove __pycache__ and test caches"
	@echo "  make distclean  clean, plus the generated samples"
	@echo
	@echo "  PYTHON=$(PYTHON)  (override if your dependencies live in a venv)"

run:
	$(PYTHON) ./ePassport.py

test:
	$(PYTHON) -m pytest tests/ -q

check: test

format:
	$(PYTHON) -m black epassport tests tools_*.py

samples:
	$(PYTHON) tools_make_sample.py $(SAMPLEDIR)

# Byte-code and test caches only - never anything a person put here.
clean: _clean_pycache
	rm -rf .pytest_cache

_clean_pycache:
	find . -type d -name __pycache__ -exec rm -rf \{\} +

# Also drop the generated dumps.  They are rebuilt by `make samples`, and
# nothing derived from a document is kept in this tree.
distclean: clean
	rm -rf $(SAMPLEDIR)
