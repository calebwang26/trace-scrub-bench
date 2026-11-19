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
