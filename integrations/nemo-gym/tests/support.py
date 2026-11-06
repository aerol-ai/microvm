"""Shared set-up: a fake AerolVM server whose sandbox is this machine, and a
work folder in a fresh temp folder."""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
import tempfile
import time
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any

# The fake AerolVM client is shared by every package in integrations/.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "testing"))

from aerolvm_nemo_gym import AerolVMProvider  # noqa: E402
from fake_microvm import FakeMicroVM, assert_fake_matches_sdk  # noqa: E402,F401


class ProviderTestCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        # realpath: on macOS the temp folder is behind a symlink.
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(prefix="aerolvm-nemo-")))
        self.work = self.tmp / "work"
        self.fake = FakeMicroVM(self.work)

    def tearDown(self) -> None:
        self.fake.cleanup()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def provider(self, **kwargs: Any) -> AerolVMProvider:
        return AerolVMProvider(client=self.fake, **kwargs)  # type: ignore[arg-type]

    async def eventually(self, check: Callable[[], object], timeout: float = 5.0) -> None:
        """Wait for ``check()`` to hold: for work a worker thread finishes
        after the awaiting task has gone."""
        deadline = time.monotonic() + timeout
        while not check():
            if time.monotonic() > deadline:
                self.fail("the background work did not finish in time")
            await asyncio.sleep(0.01)

    def create_request(self) -> dict:
        return self.fake.calls_to("create")[-1][1][0]

    def exec_requests(self) -> list[dict]:
        return [call[1][1] for call in self.fake.calls_to("exec")]
