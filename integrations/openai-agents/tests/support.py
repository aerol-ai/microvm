"""Shared set-up for the provider tests: a fake AerolVM server whose sandbox
is this machine, and a workspace root in a fresh temp folder."""

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

from agents.sandbox.manifest import Manifest  # noqa: E402

from aerolvm_openai_agents import AerolVMSandboxClient, AerolVMSandboxClientOptions  # noqa: E402
from fake_microvm import FakeMicroVM, assert_fake_matches_sdk  # noqa: E402,F401

IMAGE = "python:3.12-slim"


class ProviderTestCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        # realpath: on macOS the temp folder is behind a symlink, and the
        # SDK's path checks compare resolved paths.
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(prefix="aerolvm-oa-")))
        self.workspace = self.tmp / "workspace"
        self.fake = FakeMicroVM(self.workspace)
        self.client = AerolVMSandboxClient(self.fake)  # type: ignore[arg-type]

    def tearDown(self) -> None:
        self.fake.cleanup()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def options(self, **overrides: Any) -> AerolVMSandboxClientOptions:
        return AerolVMSandboxClientOptions(image=IMAGE, **overrides)

    def manifest(self, **overrides: Any) -> Manifest:
        return Manifest(root=str(self.workspace), **overrides)

    async def create(self, **option_overrides: Any):
        manifest = option_overrides.pop("manifest", None) or self.manifest()
        snapshot = option_overrides.pop("snapshot", None)
        return await self.client.create(manifest=manifest, snapshot=snapshot, options=self.options(**option_overrides))

    async def eventually(self, check: Callable[[], object], timeout: float = 5.0) -> None:
        """Wait for ``check()`` to hold: for work a worker thread finishes
        after the awaiting task has gone."""
        deadline = time.monotonic() + timeout
        while not check():
            if time.monotonic() > deadline:
                self.fail("the background work did not finish in time")
            await asyncio.sleep(0.01)

    def exec_requests(self) -> list[dict]:
        return [call[1][1] for call in self.fake.calls_to("exec")]
