"""Fetch (or verify) the pinned SigmaHQ rule subset used for the compile-coverage report.

The subset is committed under third_party/sigmahq/ so `make check` works offline; this script
documents and reproduces how it was chosen.

  uv run python scripts/fetch_sigmahq.py --select   # choose paths from the pinned tree (network)
  uv run python scripts/fetch_sigmahq.py            # download listed files, verify SHA-256

Selection is deterministic: for each source directory, the sorted list of .yml paths is sampled
at evenly spaced indices up to that directory's quota. No rule is picked or dropped by hand.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEST = ROOT / "third_party" / "sigmahq"
MANIFEST = DEST / "MANIFEST.json"
RELEASE_TAG = "r2026-07-01"
COMMIT = "552f3fee420ef232a8e5790c4fae591847e32347"
TREE_URL = f"https://api.github.com/repos/SigmaHQ/sigma/git/trees/{COMMIT}?recursive=1"
RAW_URL = f"https://raw.githubusercontent.com/SigmaHQ/sigma/{COMMIT}/{{path}}"
QUOTAS = {
    "rules/windows/process_creation/": 70,
    "rules/windows/builtin/": 25,
    "rules/windows/registry/": 15,
    "rules/windows/powershell/": 10,
    "rules/windows/file/": 10,
    "rules/windows/network_connection/": 10,
    "rules/windows/image_load/": 10,
    "rules/linux/": 20,
    "rules/cloud/aws/": 10,
    "rules/network/": 5,
    "rules/web/": 5,
    "rules/macos/": 5,
    "rules/application/": 5,
}


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "sigmaforge-fetch"})  # noqa: S310
    # Only the fixed https:// URLs defined above are ever opened.
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
        data: bytes = response.read()
        return data


def select() -> list[str]:
    tree: dict[str, Any] = json.loads(fetch(TREE_URL))
    if tree.get("truncated"):
        sys.exit("tree listing truncated; cannot select deterministically")
    paths = sorted(e["path"] for e in tree["tree"] if e["path"].endswith(".yml"))
    chosen: list[str] = []
    for prefix, quota in QUOTAS.items():
        pool = [p for p in paths if p.startswith(prefix)]
        step = len(pool) / quota
        chosen.extend(pool[int(i * step)] for i in range(min(quota, len(pool))))
    return chosen


def download(paths: list[str], expected: dict[str, str] | None) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in [*paths, "LICENSE"]:
        data = fetch(RAW_URL.format(path=path))
        digest = hashlib.sha256(data).hexdigest()
        if expected is not None and expected.get(path) != digest:
            sys.exit(f"checksum mismatch for {path}: got {digest}, manifest {expected.get(path)}")
        target = DEST / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        hashes[path] = digest
    return hashes


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--select", action="store_true", help="re-select paths and rewrite manifest"
    )
    args = parser.parse_args()
    if args.select:
        paths = select()
        hashes = download(paths, None)
        manifest = {
            "source": "https://github.com/SigmaHQ/sigma",
            "release": RELEASE_TAG,
            "commit": COMMIT,
            "license": "Detection Rule License (DRL) 1.1 - see LICENSE in this directory",
            "selection": {"method": "evenly spaced over sorted paths", "quotas": QUOTAS},
            "files": hashes,
        }
        MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        print(f"selected and downloaded {len(paths)} rules")
        return
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    files: dict[str, str] = manifest["files"]
    download([p for p in files if p != "LICENSE"], files)
    print(f"verified {len(files)} files against {MANIFEST.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
