PYTHON ?= python

.PHONY: hooks test

# Turn on the pre-commit secret scan for this clone.
hooks:
	git config core.hooksPath hooks

test:
	$(PYTHON) -m pytest -q
