"""Shared set-up: a fake AerolVM server whose sandbox is this machine, and a
work folder in a fresh temp folder."""

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

from aerolvm_gymnasium import SandboxEnv  # noqa: E402
from fake_microvm import FakeMicroVM, assert_fake_matches_sdk  # noqa: E402,F401

IMAGE = "python:3.12-slim"


class EnvTestCase(unittest.TestCase):
    def setUp(self) -> None:
        # realpath: on macOS the temp folder is behind a symlink.
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(prefix="aerolvm-gym-")))
        self.work = self.tmp / "workspace"
        self.fake = FakeMicroVM(self.work)
        self.envs: list[SandboxEnv] = []

    def tearDown(self) -> None:
        for env in self.envs:
            env.close()
        self.fake.cleanup()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def env(self, **kwargs: Any) -> SandboxEnv:
        env = SandboxEnv(kwargs.pop("image", IMAGE), client=self.fake, work_dir=str(self.work), **kwargs)  # type: ignore[arg-type]
        self.envs.append(env)
        return env

    def canned_exec(self) -> None:
        """Answer every command without running it. check_env sends random
        printable strings as actions; they must never reach a real shell."""

        def exec_(sandbox_id: str, request: dict) -> dict:
            self.fake._record("exec", sandbox_id, request)
            return {"stdout": "ok\n", "stderr": "", "exitCode": 0, "timedOut": False}

        self.fake.exec = exec_  # type: ignore[method-assign]
