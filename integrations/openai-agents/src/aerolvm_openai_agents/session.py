"""``BaseSandboxSession`` backed by an AerolVM sandbox.

The Agents SDK leaves six methods of ``BaseSandboxSession`` abstract: exec,
read, write, running, persist_workspace and hydrate_workspace. Everything
else (rm, mkdir, mv, extract, apply_patch, manifest materialization, snapshot
fingerprints) runs on top of them unchanged. This module fills them in with
the AerolVM Python SDK, and also replaces ``ls`` with the SDK's structured
folder listing.

The AerolVM SDK is synchronous. Every call runs in a worker thread through
``asyncio.to_thread``, so a long command never blocks the event loop and the
SDK's parallel tool calls really run in parallel.
"""

from __future__ import annotations

import asyncio
import io
import json
import logging
import math
import shlex
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar
from urllib.parse import urlsplit

from agents.sandbox.errors import (
    ExecTimeoutError,
    ExecTransportError,
    ExposedPortUnavailableError,
    WorkspaceArchiveReadError,
    WorkspaceArchiveWriteError,
    WorkspaceReadNotFoundError,
    WorkspaceStartError,
)
from agents.sandbox.files import EntryKind, FileEntry
from agents.sandbox.session.base_sandbox_session import BaseSandboxSession
from agents.sandbox.session.runtime_helpers import (
    RESOLVE_WORKSPACE_PATH_HELPER,
    RuntimeHelperScript,
)
from agents.sandbox.session.workspace_payloads import coerce_write_payload
from agents.sandbox.types import ExecResult, ExposedPortEndpoint, Permissions, User
from agents.sandbox.util.tar_utils import UnsafeTarMemberError, validate_tar_bytes
from agents.sandbox.workspace_paths import posix_path_for_error, sandbox_path_str
from microvm import (
    DEFAULT_LIST_LIMIT,
    MicroVM,
    MicroVMFileTooLargeError,
    MicroVMHTTPError,
    MicroVMUnsupportedFeatureError,
)

from ._owned import create_sandbox, run_owned
from .options import AerolVMSandboxSessionState

logger = logging.getLogger(__name__)

_T = TypeVar("_T")

# Archives are staged here, outside the workspace, so a staged tar is never
# packed into the next snapshot of the workspace.
STAGING_DIR = "/tmp/aerolvm-openai-agents"

# Tag every sandbox this package makes, so leaked ones are easy to find with
# MicroVM.list(tags={"integration": "openai-agents"}).
INTEGRATION_TAG = {"integration": "openai-agents"}

_SNAPSHOT_REF_KEY = "aerolvm_snapshot"
# A reference is about 80 bytes. Anything far larger is a tar, so it is never
# parsed as JSON.
_MAX_REF_BYTES = 4096

_EXEC_ARGV_FEATURE = "exec.argv"


def create_request(state: AerolVMSandboxSessionState, *, image: str | None = None) -> dict[str, Any]:
    """The ``MicroVM.create`` fields for this session's sandbox.

    ``image`` replaces the state's image when a sandbox is booted from a
    snapshot. The integration tag goes under the caller's own tags, so a
    caller can still set ``integration`` to something else.
    """
    fields = dict(state.create_options)
    fields["image"] = image or state.image
    fields["tags"] = {**INTEGRATION_TAG, **dict(fields.get("tags") or {})}
    return fields


def encode_snapshot_ref(name: str) -> bytes:
    return json.dumps({_SNAPSHOT_REF_KEY: name}, separators=(",", ":")).encode("utf-8")


def decode_snapshot_ref(raw: bytes) -> str | None:
    """The snapshot name in a reference, or None when ``raw`` is a tar.

    A tar made by this package starts with a "./" member name, never "{", so
    the two can not be confused. A tar from elsewhere that happens to start
    with "{" fails to parse as JSON and is treated as a tar too.
    """
    if len(raw) > _MAX_REF_BYTES or not raw.lstrip().startswith(b"{"):
        return None
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    name = decoded.get(_SNAPSHOT_REF_KEY) if isinstance(decoded, dict) else None
    return name if isinstance(name, str) and name else None


def is_not_found(err: BaseException) -> bool:
    return isinstance(err, MicroVMHTTPError) and err.status_code == 404


def _retryable(err: BaseException) -> bool | None:
    """Whether the Agents SDK may retry an operation that failed with ``err``.

    The AerolVM SDK has already retried what is safe to retry, so a status
    that says "overloaded, try later" is the only one worth another go. A
    4xx is the caller's mistake and never heals by itself. Anything else
    (a dropped connection mid-command) is unknown.
    """
    if isinstance(err, MicroVMHTTPError):
        if err.status_code in (429, 502, 503, 504):
            return True
        if 400 <= err.status_code < 500:
            return False
    return None


def _exec_retryable(err: BaseException) -> bool | None:
    """Like ``_retryable``, but a command must not run twice: only 429 and
    503 say the server turned it away before starting it. After a 502 or
    504 it may have run, so whether a retry is safe is unknown."""
    if isinstance(err, MicroVMHTTPError) and err.status_code in (502, 504):
        return None
    return _retryable(err)


class _PrefixFull(Exception):
    """Raised inside a download once the bounded read has its prefix."""


class _PrefixBuffer:
    """A ``download_file_to`` destination that keeps only the first bytes.

    Raising from ``write`` ends the download: the SDK closes the response
    and does not retry once the body has started. At most one more chunk
    (1 MiB) is read than the caller asked for.
    """

    def __init__(self, max_bytes: int) -> None:
        self._max = max_bytes
        self.data = bytearray()

    def write(self, chunk: bytes) -> int:
        self.data.extend(chunk[: self._max - len(self.data)])
        if len(self.data) >= self._max:
            raise _PrefixFull()
        return len(chunk)


class AerolVMSandboxSession(BaseSandboxSession):
    state: AerolVMSandboxSessionState

    def __init__(
        self,
        *,
        client: MicroVM,
        state: AerolVMSandboxSessionState,
        booted_from_snapshot: str | None = None,
    ) -> None:
        self._client = client
        self.state = state
        # Exec runs in the workspace root only once it exists; a working
        # directory that is missing makes every command fail.
        self._workspace_root_ready = state.workspace_root_ready
        # The snapshot this sandbox was just created from by resume(). Its
        # workspace already is that snapshot's, so start() need not restore
        # it again. Never saved: it describes this process's sandbox only.
        self._booted_from_snapshot = booted_from_snapshot
        # False once the sandbox's agent turned down argv; None until known.
        self._argv_supported: bool | None = None
        # The AerolVM snapshot persist_workspace() made in the current stop(),
        # until the SDK's snapshot store has kept the reference to it.
        self._pending_snapshot: str | None = None
        self._destroyed = False

    @property
    def client(self) -> MicroVM:
        return self._client

    @property
    def sandbox_id(self) -> str:
        return self.state.sandbox_id

    async def _call(self, fn: Callable[..., _T], *args: Any, **kwargs: Any) -> _T:
        return await asyncio.to_thread(fn, *args, **kwargs)

    # -- capabilities ------------------------------------------------------

    def supports_pty(self) -> bool:
        # The provider runs commands with buffered exec. AerolVM's exec
        # stream has a TTY and stdin, which is the way to turn this on later.
        return False

    def _runtime_helpers(self) -> tuple[RuntimeHelperScript, ...]:
        return (RESOLVE_WORKSPACE_PATH_HELPER,)

    def _current_runtime_helper_cache_key(self) -> object | None:
        # A restore from a snapshot swaps the sandbox, and the helpers must
        # then be checked again in the new one.
        return self.state.sandbox_id

    async def _validate_path_access(self, path: Path | str, *, for_write: bool = False) -> Path:
        # The checks must run inside the sandbox: only it can resolve its
        # symlinks.
        return await self._validate_remote_path_access(path, for_write=for_write)

    # -- start and stop ----------------------------------------------------

    async def _prepare_backend_workspace(self) -> None:
        root = self._workspace_root_path()
        try:
            await self._call(self._client.make_dir, self.sandbox_id, sandbox_path_str(root), parents=True)
        except Exception as e:
            raise WorkspaceStartError(path=root, cause=e, retryable=_retryable(e)) from e
        self._workspace_root_ready = True

    async def _after_start(self) -> None:
        # A restore from a snapshot can swap the sandbox during start();
        # install the helpers in the new one before the agent needs them.
        if self._runtime_helper_cache_key != self._current_runtime_helper_cache_key():
            await self._ensure_runtime_helpers()

    async def _shutdown_backend(self) -> None:
        action = self.state.on_shutdown
        if action == "keep":
            return
        if action == "stop":
            try:
                await self._call(self._client.stop, self.sandbox_id)
            except Exception as e:
                # Already gone (a lifecycle timer, say): nothing left to stop.
                if not is_not_found(e):
                    raise
            return
        await self.destroy_sandbox()

    async def destroy_sandbox(self) -> None:
        """Destroy the sandbox. A sandbox that is already gone is not an error."""
        if self._destroyed:
            return
        try:
            await self._call(self._client.destroy, self.sandbox_id)
        except Exception as e:
            if not is_not_found(e):
                raise
        self._destroyed = True

    async def running(self) -> bool:
        try:
            sandbox = await self._call(self._client.get, self.sandbox_id)
        except Exception:
            return False
        return sandbox.to_dict().get("status") == "started"

    # -- exec --------------------------------------------------------------

    async def _exec_internal(self, *command: str | Path, timeout: float | None = None) -> ExecResult:
        argv = [str(part) for part in command]
        budget = self.state.exec_timeout_s if timeout is None else timeout
        # toolboxd counts whole seconds and reads 0 as "use the 5 minute
        # default", so a sub-second budget rounds up to one second.
        request: dict[str, Any] = {"timeoutSeconds": max(1, math.ceil(budget))}
        if self._workspace_root_ready:
            request["workDir"] = self.state.manifest.root
        env = await self.state.manifest.environment.resolve()
        if env:
            request["env"] = dict(env)
        if self.state.max_output_bytes:
            request["maxStdoutBytes"] = self.state.max_output_bytes
            request["maxStderrBytes"] = self.state.max_output_bytes

        try:
            result = await self._run_exec(argv, request)
        except Exception as e:
            raise ExecTransportError(command=argv, cause=e, retryable=_exec_retryable(e)) from e

        if result.get("timedOut"):
            raise ExecTimeoutError(command=argv, timeout_s=budget)
        return ExecResult(
            stdout=str(result.get("stdout") or "").encode("utf-8"),
            stderr=str(result.get("stderr") or "").encode("utf-8"),
            exit_code=int(result.get("exitCode") or 0),
        )

    async def _run_exec(self, argv: list[str], request: dict[str, Any]) -> dict[str, Any]:
        if self._argv_supported is not False:
            try:
                result = await self._call(self._client.exec, self.sandbox_id, {**request, "argv": argv})
            except MicroVMUnsupportedFeatureError as e:
                # Only an older agent on a container or Firecracker sandbox
                # falls back. A missing output cap is not something to work
                # around: the caller asked for it, so the call fails closed.
                if e.runtime or e.features != [_EXEC_ARGV_FEATURE]:
                    raise
                self._argv_supported = False
            else:
                self._argv_supported = True
                return dict(result)
        # An agent that predates argv gets the same words as one command
        # line. Its shell splits them back exactly as shlex.join quoted them.
        result = await self._call(self._client.exec, self.sandbox_id, {**request, "command": shlex.join(argv)})
        return dict(result)

    # -- exposed ports -----------------------------------------------------

    async def _resolve_exposed_port(self, port: int) -> ExposedPortEndpoint:
        try:
            exposed = await self._call(self._client.expose_port, self.sandbox_id, port)
            endpoint = _endpoint_from_url(exposed.url)
        except Exception as e:
            raise ExposedPortUnavailableError(
                port=port,
                exposed_ports=self.state.exposed_ports,
                reason="backend_unavailable",
                context={"backend": "aerolvm"},
                cause=e,
                retryable=_retryable(e),
            ) from e
        return endpoint

    # -- files -------------------------------------------------------------

    async def read(self, path: Path, *, user: str | User | None = None) -> io.IOBase:
        if user is not None:
            # The download runs as the sandbox agent, so check first that
            # the user may read the file at all.
            await self._check_read_with_exec(path, user=user)
        workspace_path = await self._validate_path_access(path)
        try:
            data = await self._call(self._client.download_file, self.sandbox_id, sandbox_path_str(workspace_path))
        except Exception as e:
            raise self._read_error(path, e) from e
        return io.BytesIO(data)

    async def _read_bounded(self, path: Path, *, max_bytes: int) -> bytes:
        workspace_path = await self._validate_path_access(path)
        buffer = _PrefixBuffer(max_bytes)
        try:
            await self._call(self._client.download_file_to, self.sandbox_id, sandbox_path_str(workspace_path), buffer)
        except _PrefixFull:
            pass
        except Exception as e:
            raise self._read_error(path, e) from e
        return bytes(buffer.data)

    def _read_error(self, path: Path, err: Exception) -> Exception:
        if is_not_found(err):
            return WorkspaceReadNotFoundError(path=path, cause=err)
        return WorkspaceArchiveReadError(path=path, cause=err, retryable=_retryable(err))

    async def write(self, path: Path, data: io.IOBase, *, user: str | User | None = None) -> None:
        if user is not None:
            await self._check_write_with_exec(path, user=user)
        payload = coerce_write_payload(path=path, data=data).stream.read()
        workspace_path = await self._validate_path_access(path, for_write=True)
        try:
            # A buffered upload, not a streamed one: the AerolVM SDK retries
            # a buffered upload on a dropped connection, and never a stream.
            # toolboxd makes any missing parent folders.
            await self._call(self._client.upload_file, self.sandbox_id, sandbox_path_str(workspace_path), payload)
        except Exception as e:
            raise WorkspaceArchiveWriteError(path=workspace_path, cause=e, retryable=_retryable(e)) from e

    async def ls(self, path: Path | str, *, user: str | User | None = None) -> list[FileEntry]:
        """List a folder with the SDK's structured listing.

        The SDK's default parses ``ls -la`` output, which breaks on names
        with newlines and differs between GNU and BusyBox ``ls``. Every case
        this listing can not answer exactly (a user, a truncated listing, an
        older agent, any error) goes to that default, so its errors and
        edge cases stay exactly the SDK's.
        """
        if user is not None:
            return await super().ls(path, user=user)
        workspace_path = await self._validate_path_access(path)
        try:
            listing = await self._call(
                self._client.list_files,
                self.sandbox_id,
                sandbox_path_str(workspace_path),
                depth=1,
                limit=DEFAULT_LIST_LIMIT,
            )
        except Exception:
            return await super().ls(path)
        if listing.get("truncated"):
            return await super().ls(path)
        return [_file_entry(info) for info in listing.get("entries", [])]

    # -- workspace snapshots -----------------------------------------------

    async def persist_workspace(self) -> io.IOBase:
        if self.state.workspace_persistence == "snapshot" and self._can_use_native_snapshot():
            return await self._persist_workspace_via_snapshot()
        return await self._persist_workspace_via_tar()

    def _can_use_native_snapshot(self) -> bool:
        if self._native_snapshot_requires_tar_fallback():
            return False
        # An AerolVM snapshot copies the whole sandbox and can not leave a
        # path out. Mounted folders are left out anyway (their files are not
        # on the sandbox's own disk), but any other path the manifest wants
        # skipped needs the tar, which can exclude it.
        root = self._workspace_root_path()
        mounts: set[Path] = set()
        for _entry, mount_path in self.state.manifest.ephemeral_mount_targets():
            try:
                mounts.add(mount_path.relative_to(root))
            except ValueError:
                continue
        return not (self._persist_workspace_skip_relpaths() - mounts)

    async def _persist_workspace_via_snapshot(self) -> io.IOBase:
        error_root = posix_path_for_error(self._workspace_root_path())
        name = f"{self.state.snapshot_name_prefix}-{self.state.session_id.hex[:12]}-{uuid.uuid4().hex[:12]}"
        try:
            # A running sandbox pauses for about a second while it is copied.
            # The name is new on every save, so a retried request finds the
            # snapshot its first attempt made instead of failing. A save
            # cancelled midway deletes its snapshot once it is made: its
            # reference never reaches the snapshot store.
            sandbox_id = self.sandbox_id
            await run_owned(
                lambda: self._client.create_snapshot(sandbox_id, name),
                lambda _: _delete_abandoned_snapshot(self._client, name),
            )
        except Exception as e:
            raise WorkspaceArchiveReadError(
                path=error_root, context={"reason": "snapshot_failed"}, cause=e, retryable=_retryable(e)
            ) from e
        self._pending_snapshot = name
        return io.BytesIO(encode_snapshot_ref(name))

    async def _persist_snapshot(self) -> None:
        previous = self.state.last_snapshot
        self._pending_snapshot = None
        try:
            await super()._persist_snapshot()
        except BaseException:
            # Rollback rule: a snapshot whose reference never reached the
            # store can not be found again, so it is deleted rather than
            # left to fill the server's disk.
            if self._pending_snapshot is not None:
                await self._delete_snapshot_quietly(self._pending_snapshot)
                self._pending_snapshot = None
            raise
        name, self._pending_snapshot = self._pending_snapshot, None
        if name is None:
            return
        self.state.last_snapshot = name
        if self.state.delete_superseded_snapshots and previous and previous != name:
            await self._delete_snapshot_quietly(previous)

    async def _delete_snapshot_quietly(self, name: str) -> None:
        try:
            await self._call(self._client.delete_snapshot, name)
        except Exception as e:
            if not is_not_found(e):
                logger.warning("could not delete AerolVM snapshot %s: %s", name, e)

    async def _persist_workspace_via_tar(self) -> io.IOBase:
        root = self._workspace_root_path()
        error_root = posix_path_for_error(root)
        staging = f"{STAGING_DIR}/{uuid.uuid4().hex}.tar"
        limit = self._max_archive_bytes()
        excludes = [
            f"--exclude=./{rel.as_posix()}"
            for rel in sorted(self._persist_workspace_skip_relpaths(), key=lambda p: p.as_posix())
            if rel.as_posix() not in ("", ".")
        ]
        try:
            await self._call(self._client.make_dir, self.sandbox_id, STAGING_DIR, parents=True)
            # Pack inside the sandbox, then download over the file channel:
            # exec output is text, which would corrupt a tar.
            result = await self.exec(
                "tar", "-cf", staging, "-C", sandbox_path_str(root), *excludes, ".", shell=False
            )
            if not result.ok():
                raise WorkspaceArchiveReadError(
                    path=error_root,
                    context={
                        "reason": "tar_failed",
                        "exit_code": result.exit_code,
                        "stderr": result.stderr.decode("utf-8", errors="replace"),
                    },
                )
            # max_bytes refuses an oversized archive from its stated size,
            # before any of it is read into this process.
            data = await self._call(self._client.download_file, self.sandbox_id, staging, max_bytes=limit)
        except WorkspaceArchiveReadError:
            raise
        except MicroVMFileTooLargeError as e:
            raise WorkspaceArchiveReadError(
                path=error_root, context={"reason": "archive size exceeds limit", "limit": limit}, cause=e
            ) from e
        except Exception as e:
            raise WorkspaceArchiveReadError(path=error_root, cause=e, retryable=_retryable(e)) from e
        finally:
            await self._delete_quietly(staging)
        return io.BytesIO(data)

    async def hydrate_workspace(self, data: io.IOBase) -> None:
        root = self._workspace_root_path()
        error_root = posix_path_for_error(root)
        raw = _drain(data, error_path=error_root, max_bytes=self._max_archive_bytes())
        name = decode_snapshot_ref(raw)
        if name is not None:
            await self._replace_sandbox_from_snapshot(name)
            return

        try:
            validate_tar_bytes(raw, allow_external_symlink_targets=False)
        except UnsafeTarMemberError as e:
            raise WorkspaceArchiveWriteError(
                path=error_root, context={"reason": "unsafe_or_invalid_tar", "member": e.member}, cause=e
            ) from e

        staging = f"{STAGING_DIR}/{uuid.uuid4().hex}.tar"
        try:
            await self._call(self._client.make_dir, self.sandbox_id, STAGING_DIR, parents=True)
            await self._call(self._client.make_dir, self.sandbox_id, sandbox_path_str(root), parents=True)
            await self._call(self._client.upload_file, self.sandbox_id, staging, raw)
            result = await self.exec("tar", "-xf", staging, "-C", sandbox_path_str(root), shell=False)
            if not result.ok():
                raise WorkspaceArchiveWriteError(
                    path=error_root,
                    context={
                        "reason": "untar_failed",
                        "exit_code": result.exit_code,
                        "stderr": result.stderr.decode("utf-8", errors="replace"),
                    },
                )
        except WorkspaceArchiveWriteError:
            raise
        except Exception as e:
            raise WorkspaceArchiveWriteError(path=error_root, cause=e, retryable=_retryable(e)) from e
        finally:
            await self._delete_quietly(staging)
        self._workspace_root_ready = True

    async def _restore_snapshot_into_workspace_on_resume(self) -> None:
        # The SDK clears the workspace and then hydrates it. An AerolVM
        # snapshot replaces the whole sandbox, so clearing the old one first
        # is wasted work, and when resume() already booted the replacement
        # from this very snapshot, clearing would delete what it restored.
        # So the reference is read first, and only a tar takes the SDK path.
        archive = await self.state.snapshot.restore(dependencies=self.dependencies)
        try:
            raw = _drain(
                archive,
                error_path=posix_path_for_error(self._workspace_root_path()),
                max_bytes=self._max_archive_bytes(),
            )
        finally:
            _close_quietly(archive)
        name = decode_snapshot_ref(raw)
        if name is None:
            await self._clear_workspace_root_on_resume()
            await self.hydrate_workspace(io.BytesIO(raw))
            return
        if name == self._booted_from_snapshot:
            return
        await self._replace_sandbox_from_snapshot(name)

    async def _replace_sandbox_from_snapshot(self, name: str) -> None:
        root = self._workspace_root_path()
        old_id = self.state.sandbox_id
        # Rollback rule: the new sandbox is made before the old one goes. A
        # failed create leaves the session on its old sandbox, still usable.
        try:
            sandbox = await create_sandbox(self._client, create_request(self.state, image=name))
        except Exception as e:
            raise WorkspaceArchiveWriteError(
                path=posix_path_for_error(root),
                context={"reason": "snapshot_restore_failed", "snapshot": name},
                cause=e,
                retryable=_retryable(e),
            ) from e
        self.state.sandbox_id = sandbox.id
        self._booted_from_snapshot = name
        self._destroyed = False
        try:
            await self._call(self._client.destroy, old_id)
        except Exception as e:
            if not is_not_found(e):
                # The restore worked; the old sandbox is only a leak, which
                # its lifecycle timers (if set) will end.
                logger.warning("restored from snapshot %s but could not destroy old sandbox %s: %s", name, old_id, e)
        # A snapshot taken before the root existed boots without it, and exec
        # runs in the root.
        await self._call(self._client.make_dir, self.sandbox_id, sandbox_path_str(root), parents=True)
        self._workspace_root_ready = True

    # -- helpers -------------------------------------------------------------

    def _max_archive_bytes(self) -> int | None:
        # None (until a run sets SandboxArchiveLimits) means no limit.
        limits = self._archive_limits
        return limits.max_input_bytes if limits is not None else None

    async def _delete_quietly(self, path: str) -> None:
        """Delete a staged archive while another result or error is on its
        way out. That one is what the caller needs, so a failed cleanup is
        logged, never raised in its place. Staging sits outside the
        workspace, so a leftover file never reaches a snapshot."""
        try:
            await self._call(self._client.delete_file, self.sandbox_id, path)
        except Exception as e:
            if not is_not_found(e):
                logger.warning("could not delete staged archive %s in sandbox %s: %s", path, self.sandbox_id, e)


def _delete_abandoned_snapshot(client: MicroVM, name: str) -> None:
    try:
        client.delete_snapshot(name)
    except Exception as e:
        if not is_not_found(e):
            logger.warning("could not delete AerolVM snapshot %s, whose save was cancelled: %s", name, e)


def _file_entry(info: dict[str, Any]) -> FileEntry:
    # toolboxd's mode is Go's FileMode string: "drwxr-xr-x", "Lrwxrwxrwx" for
    # a symlink, and extra letters in front for setuid and the like. The
    # octal permissions field is the reliable source for the bits.
    mode = str(info.get("mode") or "")
    is_dir = bool(info.get("isDir"))
    if is_dir:
        kind = EntryKind.DIRECTORY
    elif info.get("symlinkTarget") is not None or mode.startswith("L"):
        kind = EntryKind.SYMLINK
    elif mode.startswith("-"):
        kind = EntryKind.FILE
    else:
        kind = EntryKind.OTHER
    try:
        bits = int(str(info.get("permissions") or "0"), 8)
    except ValueError:
        bits = 0
    return FileEntry(
        path=str(info.get("path") or ""),
        permissions=Permissions(owner=(bits >> 6) & 7, group=(bits >> 3) & 7, other=bits & 7, directory=is_dir),
        owner=str(info.get("owner") or ""),
        group=str(info.get("group") or ""),
        size=int(info.get("size") or 0),
        kind=kind,
    )


def _endpoint_from_url(url: str) -> ExposedPortEndpoint:
    parts = urlsplit(url)
    if not parts.hostname:
        raise ValueError(f"expose_port returned a URL without a host: {url!r}")
    tls = parts.scheme == "https"
    port = parts.port or (443 if tls else 80)
    return ExposedPortEndpoint(host=parts.hostname, port=port, tls=tls, query=parts.query)


def _drain(data: io.IOBase, *, error_path: Path, max_bytes: int | None) -> bytes:
    """Read a whole archive, refusing it as soon as it passes ``max_bytes``,
    so an oversized stream is never fully held in memory first."""
    buf = bytearray()
    while True:
        chunk = data.read(io.DEFAULT_BUFFER_SIZE)
        if not chunk:
            return bytes(buf)
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8")
        buf.extend(chunk)
        if max_bytes is not None and len(buf) > max_bytes:
            raise WorkspaceArchiveWriteError(
                path=error_path,
                context={"reason": "archive input size exceeds limit", "limit": max_bytes},
            )


def _close_quietly(stream: io.IOBase) -> None:
    try:
        stream.close()
    except Exception:
        pass
