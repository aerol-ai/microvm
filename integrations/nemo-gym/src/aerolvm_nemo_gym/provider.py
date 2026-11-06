"""NeMo Gym sandbox provider backed by AerolVM.

NeMo Gym's own Daytona provider also works against AerolVM's Daytona layer.
This provider talks to AerolVM with its own Python SDK instead, for
AerolVM's own create options (tags, a self-delete age, the runtime; see the
docs page "NVIDIA NeMo Gym"). NeMo Gym finds it through the
``nemo_gym.sandbox_providers`` entry point, under the name ``aerolvm``.

The AerolVM SDK is synchronous; every call runs in a worker thread, so a
long command never blocks NeMo Gym's event loop.
"""

from __future__ import annotations

import asyncio
import logging
import math
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, TypeVar

from microvm import MicroVM, MicroVMError, MicroVMHTTPError
from nemo_gym.sandbox.providers.base import (
    SandboxCreateError,
    SandboxCreateVerificationError,
    SandboxExecResult,
    SandboxHandle,
    SandboxResources,
    SandboxSpec,
    SandboxStatus,
)

LOGGER = logging.getLogger(__name__)
_T = TypeVar("_T")

PROVIDER_NAME = "aerolvm"
# Tag every sandbox this provider makes, so leaked ones are easy to find with
# MicroVM.list(tags={"integration": "nemo-gym"}).
INTEGRATION_TAG = {"integration": "nemo-gym"}
# The exit code a shell reports for a command stopped by its timeout.
TIMEOUT_RETURN_CODE = 124
_ROOT_USERS = ("root", "0", 0)

# AerolVM status -> NeMo Gym's provider-neutral status.
_STATUSES = {
    "creating": SandboxStatus.STARTING,
    "started": SandboxStatus.RUNNING,
    "stopped": SandboxStatus.STOPPED,
    "passivated": SandboxStatus.PAUSED,
    "destroyed": SandboxStatus.STOPPED,
    "error": SandboxStatus.ERROR,
}


class AerolVMCreateError(SandboxCreateError):
    """AerolVM could not create a sandbox."""


class AerolVMCreateVerificationError(SandboxCreateVerificationError):
    """A new sandbox did not answer its readiness probe in time."""


class AerolVMProvider:
    """Each NeMo Gym sandbox is one AerolVM sandbox.

    Config (the mapping under ``sandbox: aerolvm:`` in a NeMo Gym config):

    - ``api_url``, ``api_token``, ``team``: where the server is. Default to
      ``SB_API_URL``, ``SB_PAT_TOKEN`` and ``SB_TEAM``.
    - ``default_image``: image when the agent's spec names none.
    - ``create_options``: other ``MicroVM.create`` fields for every sandbox,
      such as ``runtime`` or ``networkBlockAll``.
    - ``exec_timeout_s``: command time limit when the agent gives none.
    - ``probe_deadline_s``: how long a new sandbox may take to run its first
      command. 0 skips the probe.
    """

    name = PROVIDER_NAME

    def __init__(
        self,
        api_url: str | None = None,
        api_token: str | None = None,
        team: str | None = None,
        default_image: str = "python:3.12-slim",
        create_options: Mapping[str, Any] | None = None,
        exec_timeout_s: float = 180,
        probe_deadline_s: float = 60,
        client: MicroVM | None = None,
    ) -> None:
        if exec_timeout_s <= 0:
            raise ValueError("exec_timeout_s must be positive")
        self._client = client if client is not None else MicroVM(api_url=api_url, pat_token=api_token, team=team)
        self._default_image = default_image
        self._create_options = dict(create_options or {})
        self._exec_timeout_s = exec_timeout_s
        self._probe_deadline_s = probe_deadline_s
        # The working folder each sandbox's spec named, by sandbox id: a
        # command given no cwd runs there.
        self._workdirs: dict[str, str] = {}

    async def _call(self, fn: Callable[..., _T], *args: Any, **kwargs: Any) -> _T:
        return await asyncio.to_thread(fn, *args, **kwargs)

    # -- lifecycle -----------------------------------------------------------

    async def create(self, spec: SandboxSpec) -> SandboxHandle:
        """Create a sandbox and return once it runs commands.

        A failure after the sandbox exists (the probe, the working folder)
        destroys it before raising, so a failed create leaves nothing
        behind. ``spec.files`` are not written here: NeMo Gym's sandbox API
        uploads them itself, through :meth:`upload_file`, right after.
        """
        request = self._create_request(spec)
        try:
            sandbox = await self._call(self._client.create, request)
        except (MicroVMError, OSError) as e:
            raise AerolVMCreateError(f"AerolVM could not create a sandbox from {request['image']!r}: {e}") from e
        handle = SandboxHandle(sandbox_id=sandbox.id, provider_name=self.name, raw=sandbox)
        try:
            await self._probe(handle)
            if spec.workdir:
                # NeMo Gym runs commands with cwd=workdir; it must exist.
                await self._call(self._client.make_dir, sandbox.id, spec.workdir, parents=True)
                self._workdirs[sandbox.id] = spec.workdir
        except BaseException:
            await self._destroy_quietly(sandbox.id)
            raise
        return handle

    async def status(self, handle: SandboxHandle) -> SandboxStatus:
        try:
            sandbox = await self._call(self._client.get, handle.sandbox_id)
        except MicroVMHTTPError as e:
            if e.status_code == 404:
                return SandboxStatus.STOPPED
            raise
        return _STATUSES.get(str(sandbox.to_dict().get("status")), SandboxStatus.UNKNOWN)

    async def close(self, handle: SandboxHandle) -> None:
        """Destroy the sandbox. One that is already gone is not an error."""
        self._workdirs.pop(handle.sandbox_id, None)
        try:
            await self._call(self._client.destroy, handle.sandbox_id)
        except MicroVMHTTPError as e:
            if e.status_code != 404:
                raise

    async def aclose(self) -> None:
        # The AerolVM SDK opens a connection per request; nothing to close.
        return None

    # -- commands and files ----------------------------------------------------

    async def exec(
        self,
        handle: SandboxHandle,
        command: str,
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout_s: int | float | None = None,
        user: str | int | None = None,
    ) -> SandboxExecResult:
        """Run a shell command. A request that fails raises: it says nothing
        about how the command ended."""
        if user is not None and user not in _ROOT_USERS:
            # Sandboxes run commands as their own user; a silent run as
            # another user would be worse than a clear refusal.
            raise NotImplementedError(
                f"AerolVM provider cannot run a command as {user!r}; set create_options.osUser to choose the "
                "sandbox's user"
            )
        budget = self._exec_timeout_s if timeout_s is None or timeout_s <= 0 else timeout_s
        # toolboxd counts whole seconds and reads 0 as its 5 minute default.
        request: dict[str, Any] = {"command": command, "timeoutSeconds": max(1, math.ceil(budget))}
        workdir = cwd or self._workdirs.get(handle.sandbox_id)
        if workdir:
            request["workDir"] = workdir
        if env:
            request["env"] = dict(env)
        result = await self._call(self._client.exec, handle.sandbox_id, request)
        if result.get("timedOut"):
            return SandboxExecResult(
                stdout=result.get("stdout") or "",
                stderr=(result.get("stderr") or "") + f"\ncommand timed out after {budget:g}s",
                return_code=TIMEOUT_RETURN_CODE,
                error_type="timeout",
            )
        return SandboxExecResult(
            stdout=result.get("stdout") or "",
            stderr=result.get("stderr") or "",
            return_code=int(result.get("exitCode") or 0),
        )

    async def upload_file(self, handle: SandboxHandle, source_path: Path, target_path: str) -> None:
        # Buffered, not streamed: the SDK retries a buffered upload on a
        # dropped connection and never a stream. Missing folders are made.
        data = await self._call(Path(source_path).read_bytes)
        await self._call(self._client.upload_file, handle.sandbox_id, target_path, data)

    async def download_file(self, handle: SandboxHandle, source_path: str, target_path: Path) -> None:
        target = Path(target_path)
        target.parent.mkdir(parents=True, exist_ok=True)

        def copy() -> None:
            with open(target, "wb") as out:
                self._client.download_file_to(handle.sandbox_id, source_path, out)

        await self._call(copy)

    async def write_file(self, handle: SandboxHandle, target_path: str, data: str | bytes) -> None:
        """Write bytes (or text, as UTF-8) to a file in the sandbox."""
        payload = data.encode("utf-8") if isinstance(data, str) else data
        await self._call(self._client.upload_file, handle.sandbox_id, target_path, payload)

    async def read_file(self, handle: SandboxHandle, source_path: str) -> bytes:
        return await self._call(self._client.download_file, handle.sandbox_id, source_path)

    # -- helpers ---------------------------------------------------------------

    def _create_request(self, spec: SandboxSpec) -> dict[str, Any]:
        if spec.sidecars:
            raise NotImplementedError("AerolVM provider does not support sidecars")
        fields = dict(self._create_options)
        fields["image"] = spec.image or self._default_image
        if spec.env:
            fields["env"] = {**dict(fields.get("env") or {}), **spec.env}
        # NeMo Gym's metadata becomes tags, so sandboxes are found by them.
        fields["tags"] = {**INTEGRATION_TAG, **dict(fields.get("tags") or {}), **spec.metadata}
        if spec.entrypoint:
            fields["containerCommand"] = list(spec.entrypoint)
        if spec.user is not None and spec.user not in _ROOT_USERS:
            fields["osUser"] = str(spec.user)
        resources = spec.resources if isinstance(spec.resources, SandboxResources) else SandboxResources.from_mapping(spec.resources)
        if resources.gpu:
            raise NotImplementedError("AerolVM provider does not map GPU requests; set create_options.gpus")
        if resources.cpu is not None:
            fields["cpu"] = resources.cpu
        if resources.memory_mib is not None:
            fields["memoryMB"] = int(resources.memory_mib)
        if resources.disk_gib is not None:
            fields["diskGB"] = int(resources.disk_gib)
        if spec.ttl_s:
            # The crash-safety net: the server deletes the sandbox at this
            # age even if the training process dies without closing it.
            lifecycle = dict(fields.get("lifecycle") or {})
            lifecycle["destroyAtAge"] = int(spec.ttl_s * 1_000_000_000)
            fields["lifecycle"] = lifecycle
        return fields

    async def _probe(self, handle: SandboxHandle) -> None:
        if self._probe_deadline_s <= 0:
            return
        deadline = time.monotonic() + self._probe_deadline_s
        last: BaseException | None = None
        while True:
            try:
                result = await self._call(
                    self._client.exec, handle.sandbox_id, {"command": "true", "timeoutSeconds": 10}
                )
                if result.get("exitCode") == 0:
                    return
                last = RuntimeError(f"probe exited {result.get('exitCode')}: {result.get('stderr')}")
            except MicroVMError as e:
                last = e
            if time.monotonic() >= deadline:
                raise AerolVMCreateVerificationError(
                    f"AerolVM sandbox {handle.sandbox_id} did not run a command within {self._probe_deadline_s:g}s"
                ) from last
            await asyncio.sleep(0.5)

    async def _destroy_quietly(self, sandbox_id: str) -> None:
        try:
            await self._call(self._client.destroy, sandbox_id)
        except Exception as e:
            if not (isinstance(e, MicroVMHTTPError) and e.status_code == 404):
                LOGGER.warning("could not destroy AerolVM sandbox %s after a failed create: %s", sandbox_id, e)
