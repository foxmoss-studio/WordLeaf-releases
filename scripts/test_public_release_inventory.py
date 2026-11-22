#!/usr/bin/env python3
"""Safety regression tests for the public Wordleaf release inventory."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

module_path = Path(__file__).with_name("check-public-release-inventory.py")
spec = importlib.util.spec_from_file_location("release_guard", module_path)
guard = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(guard)

class ReleaseGuardTests(unittest.TestCase):
    def test_rejects_unpublished_paths(self):
        for value in (
            "projects/Finding-the-Artist.WLW",
            "PROJECTS/private.WLW",
            r"projects\private.wlw",
            "./projects/private.typ",
            ".env",
            "./.env.production",
            "config/.env.local",
            "signing-private.key",
            "/outside/installer.exe",
            "../secret.txt",
            "private-notes.txt",
            "src-tauri/src/lib.rs",
            "installer/report.docx",
            "scripts/private.ts",
            "models/local-model.gguf",
            "docs/notes.txt",
        ):
            with self.subTest(value=value):
                self.assertTrue(guard.denied_path(value))

    def test_allows_expected_public_release_files(self):
        for value in (
            "windows/WordleafSetup.exe",
            "windows/Wordleaf_0.2.4_x64-setup.exe",
            "installers.json",
            "latest.json",
            "macos/WordleafInstaller.pkg",
            "installer/corrected.nsi",
            ".github/workflows/publish-windows-release.yml",
            "scripts/check-public-release-inventory.py",
        ):
            with self.subTest(value=value):
                self.assertFalse(guard.denied_path(value))

    def test_nul_delimited_git_listing(self):
        fake = SimpleNamespace(stdout=b"installers.json\x00windows/file.exe\x00")
        with patch.object(guard.subprocess, "run", return_value=fake):
            self.assertEqual(
                guard.tracked_paths(), ["installers.json", "windows/file.exe"]
            )

    def test_rejects_fabricated_secrets_and_oversize_text(self):
        previous = Path.cwd()
        with tempfile.TemporaryDirectory() as tmp:
            try:
                os.chdir(tmp)
                Path("installer").mkdir()
                Path("installer/good.txt").write_text("A public installer description.\n")
                Path("installer/token.txt").write_text("ghp_" + "A" * 36)
                Path("installer/private.txt").write_text(
                    "-----BEGIN " + "OPENSSH PRIVATE KEY-----\n"
                )
                Path("installer/large.txt").write_text("X" * 2_000_001)
                problems = guard.audit(
                    ["installer/good.txt", "installer/token.txt",
                     "installer/private.txt", "installer/large.txt"]
                )
                self.assertEqual(len(problems), 3, problems)
                self.assertTrue(any("token signature" in x for x in problems))
                self.assertTrue(any("private key header" in x for x in problems))
                self.assertTrue(any("inspection limit" in x for x in problems))
            finally:
                os.chdir(previous)

    def test_missing_file_fails_closed(self):
        previous = Path.cwd()
        with tempfile.TemporaryDirectory() as tmp:
            try:
                os.chdir(tmp)
                self.assertIn("missing", guard.audit(["missing.txt"])[0])
            finally:
                os.chdir(previous)

if __name__ == "__main__":
    unittest.main()
