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
