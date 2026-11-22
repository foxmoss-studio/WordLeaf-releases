#!/usr/bin/env python3
"""Fail publication if the public installer repository contains private-project assets.

This checks the tracked Git inventory. It does not inspect past Git history,
public releases, external clones, or caches; history is reviewed separately.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess
import sys

BANNED_SUFFIXES = (".wlw", ".typ", ".typst", ".pem", ".key", ".p12", ".pfx")
TEXT_SUFFIXES = {".md", ".txt", ".json", ".yaml", ".yml", ".ps1", ".nsi", ".py", ".sh"}
PEM_HEADER = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
)
GITHUB_TOKEN = re.compile(r"\\b(?:ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)[A-Za-z0-9_]{20,}\\b")

def denied_path(raw: str) -> bool:
    path = raw.replace("\\\\", "/").lower().lstrip("./")
    name = path.rsplit("/", 1)[-1]
    return (
        path.startswith("projects/")
        or path.endswith(BANNED_SUFFIXES)
        or name == ".env"
        or name.startswith(".env.")
    )

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe-path", help="Validate one artificial path (test mode)")
    args = parser.parse_args()

    if args.probe_path is not None:
        if denied_path(args.probe_path):
            print("Rejected prohibited release path", file=sys.stderr)
            return 1
        print("Allowed path")
        return 0

    proc = subprocess.run(
        ["git", "ls-files", "-z"], stdout=subprocess.PIPE, check=True
    )
    paths = [
        item.decode("utf-8", "surrogateescape")
        for item in proc.stdout.split(b"\\x00") if item
    ]
    offenders = []
    for rel in paths:
        if denied_path(rel):
            offenders.append(rel + " (prohibited public source/project path)")
            continue

        file = Path(rel)
        if not file.is_file() or file.stat().st_size > 2_000_000:
            continue
        if file.suffix.lower() not in TEXT_SUFFIXES:
            continue
        text = file.read_text(encoding="utf-8", errors="replace")
        if PEM_HEADER.search(text):
            offenders.append(rel + " (private key header)")
        if GITHUB_TOKEN.search(text):
            offenders.append(rel + " (token signature)")

    if offenders:
        print("Public release inventory rejected:", file=sys.stderr)
        for item in offenders:
            print(" - " + item, file=sys.stderr)
        return 1

    print(f"Public release inventory check passed: {len(paths)} tracked paths.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
