"""Shared set-up: a fake AerolVM server whose sandbox is this machine, and a
workspace root in a fresh temp folder."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

# The fake AerolVM client is shared by every package in integrations/.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "testing"))

from aerolvm_deepagents import AerolVMSandbox  # noqa: E402
from fake_microvm import FakeMicroVM, assert_fake_matches_sdk  # noqa: E402,F401

IMAGE = "python:3.12-slim"


class BackendTestCase(unittest.TestCase):
    def setUp(self) -> None:
        # realpath: on macOS the temp folder is behind a symlink.
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(prefix="aerolvm-da-")))
        self.root = self.tmp / "workspace"
        self.fake = FakeMicroVM(self.root)

    def tearDown(self) -> None:
        self.fake.cleanup()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def backend(self, **kwargs: Any) -> AerolVMSandbox:
        return AerolVMSandbox.create(self.fake, root_dir=str(self.root), image=IMAGE, **kwargs)  # type: ignore[arg-type]

    def exec_requests(self) -> list[dict]:
        return [call[1][1] for call in self.fake.calls_to("exec")]
