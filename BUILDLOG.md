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

## Step 8: scrubber v2, tuned on the dev split only (`scrubber/scrub.py`, `scrubber/entropy.py`)

Method: run `python -m bench.misses --scrubber <name>` on dev, read the groups of misses & damaged decoys, fix the largest group, repeat. The test split & the adversarial traces were not scored at any point in this step.

Each fix & the dev evidence behind it:

| dev finding (v1) | fix in v2 |
|---|---|
| every `sk-proj-...` key missed (v1's pattern stopped at the `-`) | allow `-` & `_` inside OpenAI-style keys |
| AWS secret access key missed 63 of 63 (no fixed prefix) | secrets named by their variable: any `name = value` / `name: value` whose name contains secret, password, token, credential or ends in `_key` |
| env secrets missed in Python constants (52 of 52), compose files (49 of 49) & log lines (48 of 48): v1 required `NAME=value` at the start of a line | the same assignment rule, in two forms: rest-of-line & mid-line |
| env secrets inside JSON missed (63 of 63): escaped `\n` & `\"` defeat line-based regexes | if a text is valid JSON, decode each string, scrub it & re-encode it. Nested JSON is decoded again |
| every split secret missed (221 of 221) | `joined_view`: undo shell continuations, adjacent string literals & terminal wraps, run the rules on the joined text, map matches back to both fragments |
| every base64 secret missed (247 of 247) | decode base64 blobs & redact the blob if the decoded text contains a secret; plus the entropy detector |
| every person name missed (1,104 of 1,104) | context rules: `Author:`, `Name <email>`, git blame, `"name": "..."` |
| 44% of decoys damaged: example keys, `.env.example` placeholders, `user@example.com`, `127.0.0.1`, version numbers | `is_placeholder` (EXAMPLE, `changeme`, `xxxx`, `<...>`), an email allowlist, loopback & "name version" lines for IPs |

- **Entropy threshold, chosen from dev data:** among 104,559 candidate tokens (20+ base64-alphabet characters) on dev, a threshold of 4.3 bits per character flagged 4 of 96,528 harmless non-decoy strings; 4.0 flagged 128; 3.8 flagged 6,505 (long identifiers & paths). Pure-hex tokens are skipped, because hex can't exceed 4.0 bits & commit hashes are not secrets. `sha512-...` integrity hashes are skipped by prefix.
- **The entropy detector's known false positive:** public base64 such as a test image payload (`PNG_1X1 = "..."`). It is as random as a secret & nothing in the string says otherwise. v2 damages 278 of 562 base64 decoys on dev for this reason. A test pins this behaviour instead of hiding it.
- **Problem (a regression found on the first v2 run):** v2 caught 0 of 134 plain private-key files, although v1 caught them all. **Cause:** the new line-joining logic saw a PEM block (a header followed by lines of pure base64) as one long wrapped token & let the entropy rule redact it line by line, starting inside the header. **Fix:** the private-key rule now runs first, & the split-secret pass skips anything inside a `-----BEGIN ... END-----` block.
- **Problem:** `.env` lines such as `PORT=8000` right after a secret were glued onto the secret by the wrap logic & redacted with it. **Fix:** a wrapped continuation line may not contain `=` (except base64 padding at the end). A test covers it.
- **Problem:** a few random secrets without any digit (`FAKEDXXYymKAGIOcf`) slipped past the "must contain a digit" check. **Fix:** 12+ characters mixing upper & lower case also count as secret-shaped.
- **v2 keeps the BEGIN/END lines of a private key** & redacts only the body, so a reader still sees that a key of that kind was there.
- **What v2 still misses on dev (90 items, left as they are):** names in ordinary prose (72 of 158 user messages: "Sofia Costa wrote the original version"), which need a language model, not a regex; short or low-randomness secrets split across two Python string literals (11 of 20); passwords that contain a quote character inside a quoted shell command (7 of 19), which are ambiguous even to a shell.
- **v2 on dev (real numbers):** recall 98.6% (v1: 70.3%), severity-weighted score 98.9% (68.7%), precision 95.8% (85.2%), utility kept 99.93% (99.79%), decoys kept 95.1% (56.4%), Python still parses 100%, about 180 traces/sec (v1: about 600).
- **Honest caveat:** the same author wrote the generator, the adversarial traces & this scrubber. v2 was tuned only on dev output, but it can't be truly blind to the generator's design. The held-out seed, the adversarial traces & the third-party entries exist to bound that.
- `bench/misses.py` now also lists "collateral": harmless text that was destroyed, largest first.

## Step 9: optional third-party entries (`bench/adapters/`)

- **Gitleaks 8.30.1** was already installed (Homebrew). It is a scanner, not a scrubber, so the adapter scans & then replaces each reported secret with `[REDACTED_GITLEAKS]`. It uses gitleaks' default rules, not this repo's `.gitleaks.toml`, whose `FAKE` allowlist would hide every planted secret.
- **Decision:** one gitleaks process per trace (all steps written to a temporary folder), not one per step. Per step would mean about 68,000 process launches for the test split.
- **Problem:** gitleaks also decodes base64 & reports the *decoded* secret, which doesn't appear in the text. Its column numbers for the encoded text are off by one on every line but the first. **Fix:** the adapter tries both offsets & keeps the slice that really decodes to the reported secret.
- **Microsoft Presidio 2.2.366** installed cleanly with pip, with spaCy's small English model (`en_core_web_sm`). It is configured for the four kinds of personal data in this benchmark (email, phone, IP, person). It has no rules for API keys or passwords.
- Both entries are `optional: true` in `scrubbers.yaml`: a clone without them still runs, & the leaderboard notes what was skipped. Their tests skip themselves when the tool is missing (CI has neither).
- **Problem (found by running the full benchmark twice & comparing):** every score was identical between the two runs except Gitleaks, which differed by one item (a base64-encoded JWT). **Cause:** Gitleaks scans in parallel & lists its findings in a varying order, & the adapter applied them one after another, so an earlier replacement could shift the text a later finding pointed at. **Fix:** the adapter now locates every target on the original text first & replaces longest-first. Three consecutive runs then gave identical counts (732 items removed).
- **Side check on Presidio's emails:** Presidio removed 1 of 610 test-split emails (0.2%). With the reserved `.example` / `.test` endings swapped for `.com` / `.org` it removed 610 of 610. So that 0% is an artifact of this benchmark's safety choice, not a weakness of Presidio. The leaderboard carries this note, & `python -m bench.adapters.presidio_tld_check` reproduces it.

## Step 10: the single test-split run & what it showed

Every scrubber was frozen before this run. Nothing in `scrubber/` was changed afterwards.

- **Test split:** 1,015 traces (1,000 generated + 15 hand-written), 3,423 planted items, 2,715 decoys, 6,287 Python files, 12.3 million characters of which 1.5% are sensitive.
- **Results (see `bench/LEADERBOARD.md`):** v2 recall 98.1%, severity-weighted score 98.4%, precision 95.9%, decoys kept 95.0%. v1 recall 68.1%, severity-weighted 67.0%, decoys kept 56.5%. Gitleaks recall 21.4% (51.7% on secrets only, 0% on personal data by design). Presidio recall 34.5%, precision 13.3%, & only 41.0% of Python files still parse after it.
- **Dev vs test for v2:** 98.6% on dev, 98.5% on the generated part of test (52 of 3,394 missed). The fixes carried over to a new seed almost unchanged.
- **The adversarial traces are the sobering number:** v2 removed 17 of 29 hand-written items (58.6%), v1 5 of 29 (17.2%). v2 missed a token printed as hex, a PGP private key, a JWT folded over three lines, a password after `mysql -p`, both obfuscated emails, all three unusual phone formats, an IP inside an AWS hostname & two names in prose. It also damaged 2 of the 10 hand-written decoys: the OID `2.5.29.17` (taken for an IP) & a base64 image.
- **A result I did not expect (ablation):** on dev, switching the entropy detector off inside v2 lowers recall by only 9 items out of 6,637 (98.6% → 98.5%), while precision rises from 95.8% to 100.0% & decoys kept from 95.1% to 100.0%. The name-based & decode-based rules already catch almost everything the entropy detector catches. I added `v2-without-entropy` as a leaderboard entry to report the same comparison on the test split: recall 98.0% vs 98.1%, precision 100.0% vs 95.9%. Where entropy does help is the unfamiliar formats: 15 of 29 adversarial items without it, 17 of 29 with it (a `gho_` token & a double-base64 token). **v2 was not changed in response**: the test split had already been run, & choosing the better-looking variant afterwards would be tuning on the test set. The README reports both.
- **Decision:** `bench.run --only NAME --merge` scores one entry & merges it into the saved results, so adding a scrubber doesn't require re-running the slow ones.
- `make all` now runs the whole project: tests, Part A pipeline (generate → stats → scrub → stratified sample) & Part B (splits, checksums, leaderboard).
- **A small finding from the Part A pipeline:** in the 200-trace sample drawn from the v2-scrubbed dataset, 3 `FAKE`-marked strings survive. A delivered sample is only as clean as the scrubber's recall.

## Step 11: README, EXPLAIN & the pre-publish checklist

- `README.md` follows the required structure (question, why it matters, method, results, limitations, next steps, how to run). Every number in it is copied from `bench/LEADERBOARD.md`, `bench/results_test.json` or a command named next to it.
- `EXPLAIN.md` has the file-by-file walkthrough & a written answer to each "defend it" question.
- **Problem:** while writing an example for `EXPLAIN.md` I typed a share from memory (6.3%) & then checked it against the data: the real figure is 10.0%. Fixed before commit. Numbers in the docs are checked against output, not recalled.

### Pre-publish checklist (run on `main` after the last merge)

1. **Secret scan of the entire history: pass.** `gitleaks detect --source . --log-opts="--all"` reports no leaks. Run again with the default rules & *without* the `FAKE` allowlist, it reports 5 findings, all in test files & all containing `FAKE` (4 GitHub-token-shaped test values, 1 JWT-shaped one). Nothing without the marker.
2. **Commit emails: failed at first, then fixed in the git history.** The commits made on this machine always used the GitHub no-reply address. But the first 9 merge commits were created by GitHub when each pull request was merged, & GitHub wrote the account's primary email (a personal address) as their author. **Fix:** Caleb switched on "Keep my email addresses private" in GitHub's settings (the next merge commit then carried the no-reply address, which confirmed it), & with his explicit OK the author email of those 9 commits was rewritten & `main` was force-pushed. Checks afterwards: a backup bundle was taken first; the final file tree is identical before & after; all 47 commit messages, names & dates are unchanged; a fresh clone shows only the no-reply address on every ref.
   **What the rewrite can't fix:** GitHub still serves the 9 old merge commits to anyone who asks for them by their id, & each merged pull request page links to its old commit. So in *this* repository the personal address stays retrievable for as long as GitHub keeps those orphaned commits. **Caleb's decision:** publish the clean history as a fresh repository & keep the original one private (see "Publishing" below).
3. **Confidential terms: pass.** No company, seller, buyer or partner names, prices or deal terms in any tracked file. The README describes the context generically.
4. **Size: pass.** The largest tracked file is a 127 KB plot. No generated data, `.env` or `*.jsonl` file is tracked.
5. **CI & fresh clone: pass.** CI is green on `main`. A fresh `gh repo clone` into a temp folder, a new virtual environment with only `requirements.txt`, then `make all`: exit code 0 in 85 seconds, 115 tests passed (1 skipped: Presidio not installed), checksums verified, & every non-Presidio leaderboard number identical to the committed one.
6. **README review: approved by Caleb.**
7. **Switch to public: approved by Caleb**, by the route described below.

### Publishing

- The repository this project was built in (11 pull requests, with their CI runs) was renamed `trace-scrub-bench-dev` & stays private, because its pull-request pages link to the 9 orphaned commits that still carry a personal email address.
- The public repository `trace-scrub-bench` is a fresh one. It received exactly the rewritten `main` branch: every commit & every merge of the build, with only the no-reply address in it. It was created private, CI had to pass on it, & the old commit ids were confirmed absent from it before it was switched to public.
- What the public repository does not have: the 11 pull-request web pages & their descriptions. The merge commits in the history (`Merge pull request #N ...`) show where each one landed, & each step's reasoning is in this log.
- **Lesson for the next project:** switch on "Keep my email addresses private" *before* the first pull request is merged. Local git settings don't cover commits that GitHub creates itself.

### After publishing: repository settings

- **Branch protection on `main`:** changes need a pull request, & both CI checks (`tests`, `gitleaks`) must pass before it can merge. This applies to the owner too. Force pushes & deleting the branch are blocked. The rule was a habit during the build; now GitHub enforces it. (Branch protection isn't available on a free private repository, which is why it only starts here.)
- **GitHub secret scanning & push protection: on.**
- **Problem:** GitHub's scanner immediately raised one alert, "OpenAI API Key", on a hand-written test value in `tests/test_scrub.py` (`sk-FAKE...`). It was never a real key & carries the `FAKE` marker; the local gitleaks scan allows it for that reason, but GitHub's scanner doesn't know this repo's marker. **Fix:** the alert was closed as "used in tests", & the test value is now glued from two parts, like the secrets in the generator. **Lesson:** build key-shaped test values from parts too, not only the generator's.
- This change went through the protected flow (pull request, both checks, merge), which confirmed the protection works.

## Step 12: closing four gaps found in a final audit against the spec

- **Confidence intervals.** The README admitted there were none. `bootstrap_ci` in `bench/score.py` now puts a 95% interval on recall, the severity-weighted score & adversarial recall. **Decision:** resample whole traces, not single items, because items in the same trace aren't independent. **Real numbers:** v2's recall is 98.1% (97.6 to 98.6); its adversarial recall is 58.6% (37.9 to 78.6), which shows how little 29 items can say. v2 with & without entropy: 98.1% (97.6 to 98.6) vs 98.0% (97.4 to 98.5), so that 0.1-point gap is noise. Adding the intervals changed no score: every other number is identical to the earlier run.
- **Sample card.** The README said a card should state the scrubber's measured miss rate, but the card didn't. Now `sample.py` reads the scrubber's result from the benchmark's results file & writes "expect about 1.9% of sensitive items to remain ... scrubbed, not guaranteed clean". It reads a file; it does not import the benchmark.
- **`make all` without Presidio dropped Presidio's row** from the leaderboard, so a fresh clone always showed a diff. Now an optional tool that isn't installed keeps its saved row (only if the saved result was computed on the same data), including its case-by-case adversarial results, & the leaderboard says so. **Checked in a clean clone with only `requirements.txt`:** the regenerated leaderboard differs from the committed one only in the speed column & the skip note.
- **`python bench/run.py`** (the command as the spec writes it) now works, as well as `python -m bench.run`. A test runs it.
