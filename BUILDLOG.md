# Build log

What was built in each step, the decisions made & why, & the problems hit along the way.

## Step 0: one-time machine setup

- `gh` & `gitleaks` (8.30.1) were already installed, & `gh` was logged in.
- Global git email switched to the GitHub no-reply address, so the real email never appears in commits.
- Conda env `mlproj` (Python 3.11). **Problem:** conda's default Anaconda channel refused to install until its Terms of Service were accepted. **Fix:** built the env from the `conda-forge` channel instead, which has no such gate.

## Step 1: safety files (initial commit on `main`)

- `.gitignore` blocks `.env`, virtual envs, caches, zips & every generated-data folder (`data/`, `bench/data/`, `outputs/`, all `*.jsonl`).
- `.gitleaks.toml` keeps all default gitleaks rules & allows only findings that contain `FAKE`.
- `hooks/pre-commit` runs `gitleaks protect --staged`. **Decision:** the hook lives in a tracked `hooks/` folder & is switched on with `make hooks` (`git config core.hooksPath hooks`). A script in `.git/hooks/` would not be versioned, so a fresh clone would silently have no scan.
- **Checked that the hook really works:** staged a random real-shaped GitHub token → blocked (exit 1). Staged the same token with `FAKE` in it → allowed (exit 0). Both test files were deleted afterwards.
- CI (`.github/workflows/ci.yml`) runs `pytest` & the official gitleaks action on every pull request & on pushes to `main`.
- **Decision:** `tracegen/` holds the generator (see `PLAN.md`), so `bench/` never has to import `scrubber/`.

## Step 2: the trace generator (`tracegen/`)

- `marks.py`: planted items are wrapped in invisible marker characters while the text is written, then stripped to give exact character positions. **Why:** hand-counted offsets break the moment a template changes. It also handles JSON for free: the secret between the markers gets escaped by `json.dumps`, so the ground truth records the secret exactly as it appears in the trace.
- `sensitive.py`: 11 types. Every secret carries `FAKE` & is assembled from parts at runtime; a test scans the source to prove no key-shaped literal sits in it. Formats that can't carry the marker use reserved ranges: 555-01xx phone numbers, private & documentation IP ranges, `.example` / `.test` email domains.
- **Decision:** the module is called `sensitive.py`, not `secrets.py`, because Python's standard library already has a `secrets` module & a same-named file can shadow it.
- **Decision:** for a database URL the ground truth is the password only, not the whole URL. The host & database name are useful context, & the password is the secret.
- **Decision:** AWS credentials files plant two items, the key id (`AKIA...`) & the 40-character secret access key next to it, which has no fixed prefix. Both are type `aws_key`.
- **Decision:** `person_name` is an 11th type. The spec lists personal names among the hard cases; they are sensitive, so they belong in the ground truth, not among the decoys.
- `decoys.py`: 8 kinds of harmless look-alikes (documentation example keys, `.env.example` placeholders, UUIDs, commit hashes, SHA-256 digests, public base64 blobs, loopback IPs & version numbers, example emails).
- `content.py`: the ordinary bulk of a trace (reading files, pytest output, edits, grep, git, configs). It contains nothing sensitive-looking, so the ground truth is complete.
- `carriers.py`: 36 places where items get planted, including the hard cases: split over two lines (shell continuation, adjacent Python string literals, terminal wrap), base64 (Kubernetes Secret, `echo ... | base64 -d`) & escaped JSON (a `write_file` call, a quoted curl command, JSON inside JSON). 30% of planted secrets use a hard carrier.
- `generate.py`: each trace gets its own random stream seeded by `"{seed}:{index}"`, so trace 42 is the same no matter how many traces are generated.
- **Decision:** model & harness names are invented (`atlas-4`, `openllama-70b`, ...), & so are their success rates. Real model names next to made-up success rates would read like a claim about real systems.
- **Problem:** the first full run crashed with "a planted item got lost". **Cause:** one carrier built three alternative comment lines & then picked one, but building a line already registers its items, so two registered items never reached the text. **Fix:** pick the kind first, then build only that line. The assert that caught it stays in the generator.
- **Real output (seed 20261118, 2,000 traces):** 134,600 steps (mean 67 per trace, 27 tool calls), 6,637 planted sensitive items (5,826 plain, 343 escaped JSON, 247 base64, 221 split), 5,628 decoys, 12,263 whole-file Python steps that all parse.
- Tests: same seed → identical bytes, different seed → different data, positions exact, every Python step parses, & a sweep proves nothing sensitive-looking sits outside the labeled spans.
- **Problem:** on the first pull request the gitleaks CI job failed with `403 Resource not accessible by integration`. It was not a leak: the gitleaks action lists the PR's commits through the GitHub API, & the workflow only granted `contents: read`. **Fix:** added `pull-requests: read` to the workflow permissions.

## Step 3: dataset statistics & the stratified sampler (`scrubber/stats.py`, `scrubber/sample.py`)

- `stats.py` reports trace count, steps / tool calls / messages per trace (mean, median, p90), success rate, share with a repo & breakdowns by model & harness.
- `sample.py` stratifies by model × outcome × has_repo (24 strata in the 2,000-trace set). **Decision:** largest-remainder allocation. Each stratum's exact share is rarely a whole number; rounding each one separately can make the total miss N. Largest remainder always sums to exactly N & keeps every stratum within one trace of its exact share. A test checks both properties on 200 random cases.
- **Decision:** harness is reported on the sample card but is not a stratum. Adding it would create 120 strata, many with only a handful of traces. The card says so.
- **Real output (200 of 2,000, seed 0):** success rate 52.0% in the sample vs 52.1% in the full set, repo share 75.5% vs 75.9%, largest stratum gap 0.25 percentage points.
- A test also checks that the stratified sample's worst-stratum gap is smaller than the average gap of 30 simple random samples, which is the reason to stratify at all.

## Step 4: the scorer (`bench/align.py`, `bench/score.py`, `bench/baselines.py`)

Built & tested **before** any real scrubber exists, so the measuring tool can't be shaped around the thing it measures.

- `align.py`: a scrubber only returns a new string, so the benchmark has to work out which original characters survived. Two passes: line by line first, then character by character inside changed lines.
- **Decision:** in the character pass a matching run counts only if it is at least 4 characters long. **Why:** the placeholder `[REDACTED_AWS_KEY]` shares the letters `K` & `E` with almost any key, & a plain diff would report "2 characters of the key leaked".
- **Decision (the partial-redaction rule):** an item counts as removed only if at most `min(4, length // 4)` of its characters survive. That allows a kept public prefix (`ghp_`, `AKIA`) & nothing more. A test pins it: keeping `AKIA` passes, keeping `AKIAF` or the second half of the key is a miss.
- **Decision:** `redact_everything` returns a single block character `█`, which never occurs in a trace, so its utility is exactly 0 rather than "nearly 0 because a few letters happened to match".
- Severity weights: private key & AWS key 10; GitHub token, OpenAI-style key, JWT, database password, env secret 7; email, phone, name 3; IPv4 1.
- **Problem:** a test with a secret split over two lines showed utility below 100% although only the secret was removed. **Cause:** when two neighbouring lines both change, the diff treats them as one region, & the 2 characters between the halves (backslash + newline) formed a run shorter than 4, so they were counted as destroyed. **Fix:** when a changed region has the same number of lines before & after, pair the lines up one to one.
- **Problem:** two tests failed comparing a float with a `Fraction` (`0.3333333333333333 != Fraction(1, 3)`). The scorer was right, the test was wrong. **Fix:** compare with the same division written out (`1 / 3`).
- Tests (16): both baselines give exactly 0 / 1 on a hand-made dataset **and** on 60 generated traces; a hand-made example with a hand-computed answer (recall 1/3, severity 3/14, precision 31/35, utility 44/48) matches exactly.
- **Real timing:** scoring `redact_everything` over 2,000 traces (134,600 steps) takes about 3 seconds, so the alignment is not a bottleneck.
- **First surprise from real data:** a one-line email regex also "removed" database passwords & GitHub tokens, because `user:PASSWORD@host.example` & `token@github.com` look like emails. It scored 22.7% overall recall although emails are only 17% of the items.

## Step 5: frozen splits & adversarial traces (`bench/build_splits.py`, `bench/splits_v1.json`, `bench/adversarial.py`)

- `splits_v1.json` pins dev (seed 20261118, 2,000 traces) & test (seed 77191, 1,000 traces) plus a SHA-256 checksum of every generated file. `python -m bench.build_splits` regenerates the data & fails loudly if a single byte differs. CI runs this on Linux, so the checksums are verified on a second operating system on every pull request.
- **Real sizes:** dev has 6,637 planted items & 5,628 decoys; test has 3,394 & 2,705; the adversarial set adds 15 traces with 29 planted items & 10 decoys.
- `adversarial.py`: 15 hand-written traces in formats the generator never produces: a key in a URL query parameter, a token as plain hex, `github_pat_` & `gho_` tokens, temporary AWS credentials (`ASIA...` plus a session token), OpenSSH & PGP key headers, a JWT folded over three lines, database passwords outside a URL (`password=...` DSN, `mysql -p...`, JDBC), secrets under names like `passwd` & `clientSecret`, a Python dict in a traceback, double base64, obfuscated emails (`[at]`, `%40`), non-US phone formats, IPs in AWS hostnames & IPv6-mapped form, names in prose, & a trace of harmless look-alikes (`react@18.2.0`, the OID `2.5.29.17`, `PASSWORD_MIN_LENGTH=12`).
- **Decision:** the adversarial traces were written **before** either scrubber existed, & they are only ever scored, never used for tuning. Otherwise they would just become a second dev set.
- **Decision:** refactored the generator's file writer into `write_dataset` so the adversarial set uses the same on-disk format. Verified with checksums that the refactor did not change a single byte of the generated data.
- Tests: rebuilt data matches the checksums, a tampered checksum is detected, dev & test share no trace ids & no secret values, adversarial positions are exact.
- **Problem:** the pre-commit scan blocked the adversarial file: gitleaks' `generic-api-key` rule flagged the JWT header `eyJhbGciOi...`. That string is public (it is the base64 of `{"alg":"HS256","typ":"JWT"}`, the start of every HS256 token), not a secret. **Fix:** build the header at runtime from the JSON, exactly as the generator does, instead of writing the literal. The allowlist was **not** widened. The generated bytes & checksum stayed identical.

## Step 6: plug-in loader, runner, leaderboard & plots (`bench/plugins.py`, `bench/run.py`, `bench/charts.py`, `bench/scrubbers.yaml`)

- A scrubber is `scrub(text) -> str` (a Python function named in `scrubbers.yaml`) or a command that reads stdin & writes stdout. The runner loads entries by name with `importlib`, so `bench/` contains no `import scrubber` statement. A test scans the folder to keep it that way.
- **Decision:** an entry may also be an object with `scrub_many(texts)`, called once per trace. **Why:** a command-line scanner launched once per step would mean about 67,000 process launches for the test split. Every entry is still scored the same way, on the same texts.
- **Decision:** the leaderboard is sorted by "balance", the harmonic mean of the severity-weighted score & utility kept. **Why:** sorted by recall alone, redact-everything wins. With the harmonic mean, both baselines score exactly 0, & the spec's headline number (severity-weighted score) still has its own column.
- **Decision:** `--split dev` prints a table & writes `results_dev.json` only. `LEADERBOARD.md` & the plots come from the test split only, so the published numbers are always held-out numbers.
- `charts.py`: a recall heatmap (one blue ramp: darker means more removed, every cell also shows its number) & a risk-removed vs utility-kept scatter with a zoom panel, because real scrubbers all sit within a fraction of a percent of 100% utility.
- **First real leaderboard (baselines only, test split, 1,015 traces, 3,423 items):** do-nothing 0% recall / 100% utility; redact-everything 100% recall / 0% utility / 1.6% precision (only 1.6% of all characters are sensitive).

## Step 7: scrubber v1 & the benchmark bug it exposed (`scrubber/scrub.py`, `bench/misses.py`)

- `scrub.py`: detectors propose spans on the original text; overlaps are settled by priority; each surviving span becomes `[REDACTED_<LABEL>]`. **Why detect first & replace once:** replacing rule by rule lets a later rule match inside an earlier rule's placeholder.
- v1 is deliberately the obvious first attempt: one regex per type (10 rules), no entropy, no special cases.
- `bench/misses.py` lists what a scrubber missed & which decoys it damaged, grouped by type / variant / carrier. **Decision:** it only works on the dev split. Reading individual misses on the test split & then fixing them would make test a second dev set.
- **Problem (a bug in the benchmark, found by v1):** on dev, v1 replaced every private key with `[REDACTED_PRIVATE_KEY]`, yet the scorer counted all 134 of them as missed. **Cause:** the ground truth covered the whole PEM block including its `-----BEGIN RSA PRIVATE KEY-----` line, & the words `PRIVATE KEY` in the placeholder matched that header for 7 characters, which read as "7 characters survived". **Fix, in two parts:**
  1. The ground truth for a private key is now the base64 body only. The BEGIN/END lines are public format markers (every RSA key starts with the same line), so they are not the secret. Only `ground_truth.jsonl` changed; the checksums prove `traces.jsonl` is byte-identical.
  2. The alignment now gives every character one of three marks: SOLID (unchanged line, or a matching run of 4+ characters), WEAK (a shorter matching run) or GONE. For harmless text any match counts as kept; for a planted item only SOLID characters count as leaked. Before, short runs were simply dropped, which also undercounted utility by a couple of characters whenever two redactions sat close together (e.g. the ` <` in `NAME <EMAIL>`).
- **New test, the oracle scrubber:** a scrubber that redacts exactly the planted spans must score 100% recall, 100% precision, 100% utility & 100% decoys kept on generated data. It does now. This end-to-end check would have caught the bug above, so it stays.
- The frozen checksums were updated for the ground-truth files. This happened before any test-split score was published, so no published number changed.
- **v1 on dev (real numbers, corrected scorer):** recall 70.3%, severity-weighted score 68.7%, precision 85.2%, utility kept 99.79%, decoys kept 56.4%. By type: email, phone & IPv4 100%; private key 89.6%; GitHub token 84.1%; database password 83.7%; JWT 80.5%; AWS key 68.3%; OpenAI-style key 58.8%; env secret 34.6%; person name 0%. By variant: plain 75.4%, escaped JSON 79.0%, split 0%, base64 0%.
- **Decision:** v1 is not scored on the test split yet. The test split gets run once, at the end, with every scrubber frozen.
