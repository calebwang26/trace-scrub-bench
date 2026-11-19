# Plan: trace-scrub-bench

**Question:** how much sensitive data do scrubbers miss in agent traces, which kinds slip through & how much useful content do they destroy along the way?

**Idea:** recall can't be measured on real traces, because nobody knows what is hidden in them. So this project generates synthetic traces with **planted** sensitive items (the ground truth is known), then scores any scrubber against that ground truth.

## Layout

```
trace-scrub-bench/
├── tracegen/            shared: makes the synthetic data
│   ├── marks.py         tracks where each planted item ends up in the text
│   ├── sensitive.py     builds FAKE-marked secrets & personal data from parts
│   ├── decoys.py        look-alikes that are NOT sensitive (UUIDs, commit hashes, example keys)
│   ├── content.py       ordinary agent work: files, pytest output, shell output
│   ├── carriers.py      realistic places a secret shows up, incl. the hard cases
│   └── generate.py      seeded trace generator, writes traces + ground truth
├── scrubber/            Part A: the scrubber & the delivery tools
│   ├── stats.py         dataset statistics
│   ├── sample.py        stratified sampler + sample card
│   ├── entropy.py       Shannon-entropy detector
│   └── scrub.py         v1 (regex only) & v2 (regex + entropy + fixes)
├── bench/               Part B: ScrubBench (never imports scrubber/)
│   ├── splits_v1.json   seeds, sizes & SHA-256 checksums of dev & test
│   ├── build_splits.py  regenerates the data & verifies the checksums
│   ├── adversarial.py   hand-written test-only traces
│   ├── align.py         which original characters survived scrubbing
│   ├── score.py         recall, precision, severity score, utility, speed
│   ├── plugins.py       loads scrubbers listed in scrubbers.yaml
│   ├── baselines.py     do-nothing & redact-everything
│   ├── adapters/        optional third-party entries (Presidio, Gitleaks)
│   ├── scrubbers.yaml   the registered entries
│   ├── run.py           scores every entry, writes LEADERBOARD.md + plots
│   └── plots/           small PNGs used in the README
└── tests/
```

One change from the spec: the generator sits in its own `tracegen/` folder, not in `scrubber/`. The benchmark needs the generator, & the benchmark must never import from `scrubber/`. A neutral third folder keeps that rule clean.

## Build order

1. Safety files (the only commit made directly on `main`), then the private GitHub repo.
2. `tracegen`: position tracking, sensitive-value factories, decoys.
3. `tracegen`: ordinary trace content, then planting with ground truth, then hard cases.
4. Generator determinism tests.
5. `stats.py`, then `sample.py` with its stratification test & sample card.
6. Benchmark: alignment & scorer, with exact-number tests on the two baselines & a hand-made example. The scorer is proven before it measures any real scrubber.
7. Benchmark: frozen dev & test splits with checksums, plus hand-written adversarial traces.
8. Plug-in loader, `scrubbers.yaml`, `run.py`, leaderboard & plots.
9. Scrubber v1 (regex only) → first leaderboard.
10. Error analysis on the **dev split only** → scrubber v2 (regex + entropy + fixes).
11. Optional entries: Presidio & Gitleaks, if they install cleanly.
12. README with real results, `EXPLAIN.md`, pre-publish checklist.

## Rules that hold throughout

- Every slice is a branch → PR → CI (pytest + gitleaks) → merge commit.
- Generated data is never committed. The generator & its seeds are.
- Every synthetic secret contains `FAKE` where its format allows, & is assembled at runtime from parts.
- v2 is tuned on dev only. Test-split numbers are computed once the scrubber is frozen.
- Results in the README come from real runs. Negative results are reported as they are.
