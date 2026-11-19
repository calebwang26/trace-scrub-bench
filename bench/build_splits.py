"""Rebuild the benchmark's frozen data splits & verify them against checksums.

    python -m bench.build_splits            # rebuild & verify
    python -m bench.build_splits --update   # rebuild & write new checksums (only when freezing a new version)

The data itself is never committed. `splits_v1.json` pins the seeds, the
sizes & a SHA-256 checksum of every generated file, so anyone can rebuild
exactly the same bytes & scores stay comparable over time.

  dev          for building & tuning scrubbers
  test         held out: only for final scores (a different seed)
  adversarial  hand-written traces, scored together with test
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from bench import adversarial
from tracegen.generate import generate

HERE = Path(__file__).resolve().parent
SPEC_PATH = HERE / "splits_v1.json"
DATA_ROOT = HERE / "data"
CHECKED_FILES = ["traces.jsonl", "ground_truth.jsonl", "decoys.jsonl", "python_steps.jsonl"]


def load_spec() -> dict:
    return json.loads(SPEC_PATH.read_text(encoding="utf-8"))


def checksums(folder: Path) -> dict[str, str]:
    return {name: hashlib.sha256((folder / name).read_bytes()).hexdigest() for name in CHECKED_FILES}


def folders(split: str, root: Path = DATA_ROOT) -> list[Path]:
    """The data folders that make up a split. Test includes the adversarial traces."""
    if split == "dev":
        return [root / "dev"]
    if split == "test":
        return [root / "test", root / "adversarial"]
    raise ValueError(f"unknown split: {split}")


def build(root: Path = DATA_ROOT, spec: dict | None = None) -> dict[str, dict[str, str]]:
    """Regenerate every part into `root` & return the checksums found."""
    spec = spec or load_spec()
    found = {}
    for name in ("dev", "test"):
        part = spec["parts"][name]
        generate(part["seed"], part["n_traces"], root / name)
        found[name] = checksums(root / name)
    adversarial.write(root / "adversarial")
    found["adversarial"] = checksums(root / "adversarial")
    return found


def verify(found: dict, spec: dict | None = None) -> list[str]:
    """Return a list of mismatches (empty when everything matches)."""
    spec = spec or load_spec()
    problems = []
    for name, sums in found.items():
        for file, digest in sums.items():
            expected = spec["parts"][name]["sha256"].get(file)
            if digest != expected:
                problems.append(f"{name}/{file}: expected {expected}, got {digest}")
    return problems


def ensure(root: Path = DATA_ROOT) -> None:
    """Rebuild the data if it is missing or does not match the frozen checksums."""
    spec = load_spec()
    try:
        found = {name: checksums(root / name) for name in spec["parts"]}
        if not verify(found, spec):
            return
    except FileNotFoundError:
        pass
    problems = verify(build(root, spec), spec)
    if problems:
        raise SystemExit("Split checksums do not match splits_v1.json:\n  " + "\n  ".join(problems))


def main() -> None:
    parser = argparse.ArgumentParser(description="Rebuild & verify the benchmark splits.")
    parser.add_argument("--update", action="store_true", help="write the new checksums into splits_v1.json")
    args = parser.parse_args()
    spec = load_spec()
    found = build(DATA_ROOT, spec)
    if args.update:
        for name, sums in found.items():
            spec["parts"][name]["sha256"] = sums
        SPEC_PATH.write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote new checksums to {SPEC_PATH.name}")
        return
    problems = verify(found, spec)
    if problems:
        raise SystemExit("MISMATCH\n  " + "\n  ".join(problems))
    for name in found:
        manifest = json.loads((DATA_ROOT / name / "manifest.json").read_text())
        print(f"{name:12s} ok  {manifest['n_traces']:>5} traces  {manifest['n_sensitive']:>5} planted items  {manifest['n_decoys']:>5} decoys")


if __name__ == "__main__":
    main()
