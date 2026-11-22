#!/usr/bin/env python3
"""Block unpublished source and obvious credentials from public release HEAD.

This audits tracked paths and selected text blobs only, not past Git history,
GitHub Release attachments, external forks, historical pull refs, or caches.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess
import sys

BANNED_SUFFIXES = (".wlw", ".typ", ".typst", ".pem", ".key", ".p12", ".pfx")
TEXT_SUFFIXES = {
    ".md", ".txt", ".json", ".yaml", ".yml", ".ps1", ".nsi", ".py",
    ".sh", ".toml", ".conf", ".ini", ".xml",
}
PEM_HEADER = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")
GITHUB_TOKEN = re.compile(
    r"\b(?:ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)[A-Za-z0-9_]{20,}\b"
)

def denied_path(raw: str) -> bool:
    path = raw.replace("\\", "/").lower()
    while path.startswith("./"):
        path = path[2:]
    name = path.rsplit("/", 1)[-1]
    return (
        not path
        or path.startswith("/")
        or ".." in path.split("/")
        or path.startswith("projects/")
        or path.endswith(BANNED_SUFFIXES)
        or name == ".env"
        or name.startswith(".env.")
    )

def tracked_paths() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        stdout=subprocess.PIPE,
        check=True,
    )
    return [
        part.decode("utf-8", "surrogateescape")
        for part in result.stdout.split(b"\x00")
        if part
    ]

def audit(paths: list[str]) -> list[str]:
    offenders = []
    for relative in paths:
        if denied_path(relative):
            offenders.append(relative + " (prohibited public source/project path)")
            continue

        file = Path(relative)
        if file.is_symlink():
            offenders.append(relative + " (symlinks are not public release files)")
            continue
        if not file.is_file():
            offenders.append(relative + " (tracked path is missing)")
            continue
        if file.suffix.lower() not in TEXT_SUFFIXES:
            continue
        if file.stat().st_size > 2_000_000:
            offenders.append(relative + " (text file exceeds inspection limit)")
            continue
        body = file.read_text(encoding="utf-8", errors="replace")
        if PEM_HEADER.search(body):
            offenders.append(relative + " (private key header)")
        if GITHUB_TOKEN.search(body):
            offenders.append(relative + " (token signature)")
    return offenders

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe-path", help="Check one artificial path for tests")
    args = parser.parse_args()

    if args.probe_path is not None:
        if denied_path(args.probe_path):
            print("Rejected prohibited release path", file=sys.stderr)
            return 1
        print("Allowed path")
        return 0

    paths = tracked_paths()
    problems = audit(paths)
    if problems:
        print("Public release inventory rejected:", file=sys.stderr)
        for item in problems:
            print(" - " + item, file=sys.stderr)
        return 1

    print(f"Public release inventory check passed: {len(paths)} tracked paths.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
