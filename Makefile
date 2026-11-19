# One command reproduces everything:   make all
# Use the project's Python:            make all PYTHON=/path/to/python
PYTHON ?= python

.PHONY: all hooks test data stats scrub sample splits bench bench-dev clean

all: test data stats scrub sample bench

# Turn on the pre-commit secret scan for this clone.
hooks:
	git config core.hooksPath hooks

test:
	$(PYTHON) -m pytest -q

# Part A: generate 2,000 synthetic traces, describe them, scrub them, sample them.
data:
	$(PYTHON) -m tracegen.generate --seed 20261118 --n 2000 --out data

stats: data
	$(PYTHON) -m scrubber.stats data/traces.jsonl

scrub: data
	$(PYTHON) -m scrubber.scrub --version v2 --in data/traces.jsonl --out outputs/traces.scrubbed.jsonl

sample: scrub
	$(PYTHON) -m scrubber.sample --in outputs/traces.scrubbed.jsonl --n 200 --seed 0 --out outputs/sample --scrubbed-with "scrubber v2 (regex + entropy)"

# Part B: rebuild the frozen splits, verify their checksums, score every scrubber.
splits:
	$(PYTHON) -m bench.build_splits

bench: splits
	$(PYTHON) -m bench.run

# For building a scrubber: scores on the dev split only, writes nothing that is published.
bench-dev: splits
	$(PYTHON) -m bench.run --split dev --skip-optional

clean:
	rm -rf data outputs bench/data bench/results_dev.json
