# EXPLAIN: a plain-language walkthrough of trace-scrub-bench

This file is for someone who knows neural networks & basic RL but is new to research code. Part 1 explains the idea. Part 2 walks through every file. Part 3 answers the "defend it" questions with this project's real numbers.

Every number below comes from `bench/LEADERBOARD.md` (the held-out test split) or `BUILDLOG.md` (the dev split), & is reproduced by `make all`.

---

## Part 1: the idea in five steps

1. **The problem.** Before a broker can show a buyer any agent trace, personal data & secrets must be removed. The tool that does this is a *scrubber*. The question is how good a scrubber is.
2. **Why that is hard to measure.** On real traces nobody knows what is hidden. If the scrubber finds 40 secrets, were there 40 or 400? Without the answer key, "how many did it miss" can't be computed.
3. **The fix: plant the answer key.** This project generates synthetic traces & hides a known set of fake secrets in them, writing down exactly where each one is. Now misses can be counted.
4. **Two parts, kept apart.** Part A is a scrubber (`scrubber/`), built in two versions. Part B is a benchmark (`bench/`) that scores *any* scrubber. The benchmark never imports the scrubber, so it can't quietly favour it.
5. **Two ways to fail.** A scrubber can miss secrets (bad recall) or destroy useful text (bad utility). A scrubber that deletes everything has perfect recall & is worthless. So the benchmark measures both, with two baselines as anchors: do-nothing & redact-everything.

If you remember one comparison from ML: this is a classifier evaluation. "Sensitive" is the positive class, recall & precision mean what they always mean, the dev split is the validation set you tune on, & the test split is the test set you touch once.

---

## Part 2: file by file

### Safety files (top level)

- **`.gitignore`**: tells git which files never to commit: `.env` files, generated data (`data/`, `bench/data/`, `outputs/`, every `*.jsonl`), caches.
- **`.gitleaks.toml`**: settings for gitleaks, a secret scanner. It keeps all default rules & allows exactly one exception: a finding that contains the marker `FAKE`.
- **`hooks/pre-commit`**: a script git runs before every commit. It runs gitleaks on the staged changes & blocks the commit if a secret is found. `make hooks` switches it on.
- **`.github/workflows/ci.yml`**: on every pull request GitHub runs the tests & gitleaks. A PR is merged only when both pass.
- **`requirements.txt`**: exact versions of the four packages used, so results are reproducible. `requirements-optional.txt` lists what the optional Presidio entry needs.
- **`Makefile`**: named commands. `make all` runs the whole project.

### `tracegen/`: the synthetic data generator

- **`marks.py`**: solves "where exactly did the secret end up?". While text is being written, each planted item is wrapped in invisible marker characters. At the end, `resolve` removes the markers & returns the clean text plus each item's start & end position. Nobody counts characters by hand, so the positions can't drift when a template changes.
- **`sensitive.py`**: small functions that each build one fake sensitive value: an AWS key, a GitHub token, an OpenAI-style key, a JWT, a private key, a database URL, an env secret, a name, an email, a phone number, an IP address. Every secret contains `FAKE` & is glued together from parts at runtime, so no real-looking key is ever written in the source code.
- **`decoys.py`**: builds harmless look-alikes: UUIDs, git commit hashes, checksums, example keys from documentation, `changeme` placeholders, `127.0.0.1`. A good scrubber leaves these alone.
- **`content.py`**: the ordinary bulk of a trace: reading a Python file, running pytest, editing code, grep, git status. It contains nothing sensitive, on purpose, so the answer key is complete.
- **`carriers.py`**: the places a secret realistically shows up: a `.env` file, a git log, a curl command, a log line. It also holds the **hard cases**: a secret split over two lines, a secret base64-encoded, a secret inside JSON with escaped quotes.
- **`generate.py`**: puts it together. For each trace it picks a model, harness & outcome, writes 4 to 40 turns of ordinary work, drops planted items & decoys into random turns, & writes four files: the traces, the ground truth (answer key), the decoys & the list of Python files. The same seed always gives byte-identical files.

### `scrubber/`: Part A

- **`stats.py`**: dataset statistics: how many traces, how long, success rate, share with a repo, mix by model & harness.
- **`sample.py`**: the stratified sampler. It picks N traces so that the mix of (model, outcome, has_repo) matches the full set, & writes a sample card: the one-page summary a buyer reads. The card also states the scrubber's measured miss rate, read from the benchmark's results file, so it never claims the data is clean.
- **`entropy.py`**: Shannon entropy, a number for "how random does this string look" in bits per character. `aaaaaaaa` scores 0. English identifiers score 3 to 4. Random base64 scores above 4.3. The detector flags long tokens above a threshold.
- **`scrub.py`**: the scrubber. Each *detector* looks at the text & proposes spans to remove. Overlaps are settled by priority. Each surviving span is replaced by a typed placeholder such as `[REDACTED_AWS_KEY]`.
  - **v1** is ten regexes, one per type.
  - **v2** adds what v1 missed on the dev split: secrets identified by their variable name, JSON read as JSON, split secrets rejoined, base64 decoded, names found through context, the entropy detector, & allowlists so harmless look-alikes survive.
  - **`scrub_v2_no_entropy`** is v2 with the entropy detector switched off. It exists only to measure what that one detector adds & costs (an *ablation*: remove one part, see what changes).

### `bench/`: Part B, ScrubBench

- **`splits_v1.json`**: the frozen definition of the benchmark data: seeds, sizes & a SHA-256 checksum of every generated file. A checksum is a fingerprint: if one byte changes, it changes.
- **`build_splits.py`**: regenerates the dev & test data from the seeds & checks the fingerprints. The data itself is never committed.
- **`adversarial.py`**: 15 hand-written traces in formats the generator never produces. They are scored with the test split, to check that a scrubber didn't just learn the generator's templates.
- **`align.py`**: a scrubber only returns new text. To score it, the benchmark lines up the text before & after (first line by line, then character by character) & marks each original character as SOLID (clearly still there), WEAK (a short match that may be a coincidence) or GONE.
- **`score.py`**: turns those marks into numbers: recall, the severity-weighted score, precision, utility kept, decoys kept, Python-still-parses & speed. It also puts a 95% confidence interval on the main scores with a *bootstrap*: pretend the test split had been a different random draw by redrawing its traces (with replacement) 2,000 times, rescore each time, & report the range holding the middle 95% of those scores. Few traces give a wide range; many give a narrow one.
- **`baselines.py`**: the two anchors: do-nothing & redact-everything.
- **`plugins.py`** & **`scrubbers.yaml`**: the plug-in interface. A scrubber is a Python function `scrub(text) -> str` or a command that reads stdin & writes stdout. Entries are listed in the YAML file & loaded by name.
- **`adapters/`**: wrappers that make two third-party tools fit that interface: Gitleaks (a secret scanner) & Microsoft Presidio (a personal-data detector).
- **`run.py`**: scores every registered scrubber & writes `LEADERBOARD.md`, `results_test.json` & the two plots.
- **`charts.py`**: draws the plots.
- **`misses.py`**: error analysis for building a scrubber: what it missed & what it broke. It only works on the dev split.

### `tests/`

Over 100 small checks. The most important ones:
- the generator gives identical bytes for the same seed;
- the two baselines score exactly 0% & 100% where they should;
- a hand-made example matches numbers computed by hand;
- an "oracle" scrubber that removes exactly the planted items scores a perfect 100% on everything;
- the benchmark folder contains no import of the scrubber.

### Other documents

- **`PLAN.md`**: the plan written before building.
- **`BUILDLOG.md`**: what was built in each step, each decision & why, & every problem hit.
- **`README.md`**: the question, method, results & limitations.

---

## Part 3: defend it

Short written answers to the hard questions, using this project's real numbers. Test-split numbers are from `bench/LEADERBOARD.md`; dev-split numbers are from `BUILDLOG.md`.

### Why can't recall be measured on real seller data, & why does planting fix that?

Recall is "of all the sensitive items that exist, what share did the scrubber remove". The numerator is easy: count what it removed. The denominator is the problem. In a real seller's traces nobody knows how many secrets there are, & the ones a scrubber misses are exactly the ones nobody has seen. You could have humans read a sample, but humans also miss a base64-encoded key, & reading millions of traces isn't possible.

Planting fixes the denominator. The generator puts 3,423 items into the test split & writes down the exact position of each one. After scrubbing, the scorer checks each position. v2 removed 3,359, so its recall is 98.1%, a number that can't be computed on real data.

The price is that the number describes synthetic traces. It is a measurement of the scrubber under known conditions, not a promise about a seller's real data.

### What's the difference between precision & recall here, & which matters more to a buyer? To a seller's legal team?

- **Recall:** of the sensitive items that exist, how many were removed. Low recall means leaks.
- **Precision:** of the characters removed, how many were sensitive. Low precision means harmless content was destroyed.

redact-everything shows why both are needed: 100% recall, 1.5% precision.

**The seller's legal team cares most about recall.** One leaked private key or customer email is a breach, a contract violation or a regulatory problem. Destroying some harmless text costs them nothing. They would accept v1's damage to decoys, but not v1's 68.1% recall.

**The buyer cares about both, & more about precision than a seller does.** A buyer wants no liability in the data (recall), but is paying for useful training data. A scrubber that replaces commit hashes, version numbers & half the code with placeholders hands them damaged goods. Presidio is the example: only 41.0% of Python files still parse after it runs. A buyer training a coding model would rather have v2's 100%.

So the same leaderboard is read differently by each side, which is why it reports the two numbers separately & doesn't hide them in one score.

### Why does the entropy detector raise recall but also false positives? Give one false positive it produced.

Entropy measures how random a string looks. Secrets are random on purpose, so high entropy catches secrets that have no recognizable prefix or name. But randomness is not the same as secrecy: a hash, a compressed image or a checksum encoded in base64 is exactly as random as an API key, & nothing inside the string says which one it is.

**A real false positive:** a test fixture line `PNG_1X1 = "<base64 of a tiny image>"`. v2 turns it into `PNG_1X1 = "[REDACTED_HIGH_ENTROPY]"`. On the test split v2 damages half of all public base64 blobs this way (50% of the `b64 blob` decoys kept). A test in `tests/test_scrub_v2.py` pins this behaviour.

**The honest surprise:** in this project the entropy detector raised recall very little. With it switched off (`v2-without-entropy`), test recall goes from 98.1% to 98.0%, & on dev it loses 9 items out of 6,637. Meanwhile precision goes from 95.9% to 100.0%. The rules that find a secret through its variable name (`SMTP_PASSWORD = ...`) or by decoding base64 & looking inside already catch what entropy catches. The one place it helped is unfamiliar formats: 17 of 29 adversarial items with it, 15 without. That is a difference of two items, & the two confidence intervals (37.9% to 78.6% & 31.0% to 70.4%) overlap almost completely, so it can't be called a real effect. The cost is measured; the benefit is not.

Two details of how the detector is built: hex strings are skipped, because 16 symbols can never exceed 4.0 bits per character & commit hashes aren't secrets; & the threshold of 4.3 bits was chosen on dev data, where it flagged 4 of 96,528 ordinary strings, against 6,505 at a threshold of 3.8.

### Why does the benchmark need a utility metric, & what do the two baselines show?

Without a utility metric, the best possible scrubber is one line of code: delete everything. It has 100% recall. A benchmark that ranks that first is measuring the wrong thing.

The two baselines mark the two ends:
- **do-nothing:** 0% recall, 100% utility. Perfectly useful, perfectly unsafe.
- **redact-everything:** 100% recall, 0% utility. Perfectly safe, perfectly useless.

Every real scrubber sits between them, & the job is to get close to both 100%s at once. The leaderboard's "balance" column (the harmonic mean of risk removed & utility kept) gives both baselines exactly 0 for that reason.

The baselines also test the benchmark itself: if the scorer didn't return exactly 0% & 100% for them, the scorer would be broken. Those are unit tests in this repo.

One lesson from the results: the plain character count is a weak utility metric. Every real scrubber keeps over 98.9% of characters, even Presidio while it breaks 59% of Python files. The sharper checks (decoys kept, Python still parses) are what tell scrubbers apart.

### Why keep a held-out test split & hand-written adversarial cases? What goes wrong without them?

Same reason as a test set in machine learning. v2 was built by looking at what v1 missed on the dev split & fixing it, one group at a time. After enough rounds, a scrubber fits the dev data, including its accidents. Scoring it on dev would then overstate how good it is. The test split has a different seed, so it has different secrets & different traces. v2 scores 98.6% on dev & 98.5% on the generated part of test, so the fixes carried over to new data from the same generator.

But the same generator is the weak point. Both splits come from the same few dozen templates. A scrubber can learn the templates instead of the problem. The 15 hand-written traces use formats the generator never produces, & there the picture changes: **v2 removes 17 of 29 items, 58.6%.** Without those traces, this README would report 98% & nobody would know the scrubber misses a token printed as hex or a phone number in a UK format. With only 29 items that 58.6% is itself rough: its 95% confidence interval runs from 37.9% to 78.6%. It is enough to say "far worse than 98%", not enough to say "59%" with a straight face.

Two rules keep the test honest: the adversarial traces were written before any scrubber existed, & the error-analysis tool (`bench/misses.py`) refuses to run on anything but dev. The moment you read individual test misses & fix them, the test split becomes a second dev split.

This project also shows the rule being followed when it hurt. After the test run, the ablation showed a variant with better precision. v2 was left unchanged, because picking the better variant after seeing test results is tuning on the test set.

### Why weight a leaked private key more than a leaked email?

Because the damage is different in kind. A private key or an AWS key gives direct access: someone can log into servers, read databases, run up costs, & the key has to be revoked & rotated everywhere it is used. A leaked email identifies a person & may have legal consequences, but it doesn't open any door by itself. A leaked internal IP address reveals little alone.

Plain recall treats all three the same. A scrubber that catches every IP address & misses every private key would look fine on recall & be dangerous in practice. The severity-weighted score counts each item by its weight (private key & AWS key 10; tokens & passwords 7; email, phone & name 3; IP 1), so it answers "what share of the *risk* was removed".

The gap shows up in the results. Gitleaks has 21.4% recall but a 37.5% severity-weighted score, because what it does catch is the high-weight secrets. Presidio is the reverse: 34.5% recall, 18.4% severity-weighted.

The weights themselves are a judgment call, not derived from data on real incidents. That is stated in the README's limitations.

### What does "stratified" mean, & why does a buyer care that the sample matches the full set?

A stratum is a group of traces that share some properties. Here a stratum is one combination of model, outcome (success or fail) & whether the trace has a repo: 24 groups in the 2,000-trace dataset. Stratified sampling takes the same share from every group. In the 2,000-trace dataset, 10.0% of traces are "atlas-4, success, with repo", so a 200-trace sample gets 20 of them. A share that isn't a whole number of traces is rounded, never by more than one trace.

A buyer decides whether to buy the whole dataset by looking at a sample. If the sample has more successes, more repos or more of the strong model than the full set, the buyer overpays. A plain random sample of 200 can easily be off by a few points by chance, & a seller could also cherry-pick. A stratified sample with a sample card removes both worries: the card shows the mix of the full set next to the mix of the sample.

In this project the 200-trace sample has a 52.0% success rate against 52.1% in the full set, 75.5% with a repo against 75.9%, & no stratum is off by more than 0.25 percentage points. A test also checks that the stratified sample's worst gap is smaller than the average gap of 30 plain random samples.

### Name two kinds of sensitive data this benchmark would still miss.

The benchmark only measures what it plants. It plants 11 types, so anything else is invisible to it. Two examples that matter in real traces:

1. **Sensitive business content that has no recognizable shape.** Proprietary source code, internal hostnames & URLs, customer names in a database dump, unreleased product names, pricing in a config file. None of it looks like a key or an email, so no pattern finds it, & this benchmark never plants it. A scrubber could score 100% here & still ship a company's core algorithm to a buyer.
2. **Personal data beyond the four planted kinds, & in other forms.** Street addresses, dates of birth, payment card numbers, government ids, account numbers, usernames in file paths (`/home/jsmith/`), names in non-Western formats or in other languages. The benchmark's names are two capitalized words in English text.

A third, more subtle gap: **identifying combinations**. A trace with no name in it can still identify a person through a job title, a small team & a timestamp together. No span-based benchmark can see that.
