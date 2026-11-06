"""DeepAgents backend that runs an agent's tools in an AerolVM sandbox.

DeepAgents' ``BaseSandbox`` needs three things from a provider: ``execute``,
``upload_files`` and ``download_files``. Everything else (read, write, edit,
grep, glob) it builds on those, by running small scripts through
``execute``. This backend fills in the three with the AerolVM Python SDK,
and also answers ``ls`` and ``delete`` with the SDK's file calls, which need
no Python in the sandbox and no output parsing.
"""

from __future__ import annotations

import asyncio
import posixpath
import threading
from typing import Any

from deepagents.backends.protocol import (
    FILE_NOT_FOUND,
    INVALID_PATH,
    IS_DIRECTORY,
    PERMISSION_DENIED,
    DeleteResult,
    ExecuteResponse,
    FileDownloadResponse,
    FileInfo,
    FileOperationError,
    FileUploadResponse,
    LsResult,
    WriteResult,
)
from deepagents.backends.sandbox import BaseSandbox
from microvm import DEFAULT_LIST_LIMIT, MicroVM, MicroVMHTTPError, MicroVMUnsupportedFeatureError
from microvm.client import Sandbox

# Tag every sandbox this package makes, so leaked ones are easy to find with
# MicroVM.list(tags={"integration": "deepagents"}).
INTEGRATION_TAG = {"integration": "deepagents"}

DEFAULT_ROOT_DIR = "/workspace"
# DeepAgents' own default for a sandbox command.
DEFAULT_TIMEOUT_S = 30 * 60
# Matches DeepAgents' LocalShellBackend: a command that ran out of time
# reports the shell's usual "timed out" status.
TIMEOUT_EXIT_CODE = 124


class AerolVMSandbox(BaseSandbox):
    """A DeepAgents sandbox backend backed by one AerolVM sandbox.

    Wrap a sandbox you made yourself with ``AerolVMSandbox(sandbox)``, or let
    the backend make one with :meth:`create` (destroyed by :meth:`close`) or
    find-or-make a named one with :meth:`for_name` (kept, for reuse across
    runs of the same thread).

    Commands run in ``root_dir``, which is made on first use. Relative file
    paths are taken as relative to it too, so ``execute("cat a.txt")`` and
    ``download_files(["a.txt"])`` name the same file.
    """

    def __init__(
        self,
        sandbox: Sandbox,
        *,
        root_dir: str = DEFAULT_ROOT_DIR,
        default_timeout: int = DEFAULT_TIMEOUT_S,
        max_output_bytes: int | None = None,
        owns_sandbox: bool = False,
    ) -> None:
        """
        Args:
            sandbox: The AerolVM sandbox (``MicroVM.create`` or ``get``).
            root_dir: Folder commands run in. Made on first use.
            default_timeout: Seconds a command may run when the agent sets
                no timeout, or sets 0.
            max_output_bytes: Keep at most this many bytes of a command's
                stdout and of its stderr; the rest is dropped inside the
                sandbox and the response says ``truncated``. ``None`` keeps
                all of it.
            owns_sandbox: Destroy the sandbox on :meth:`close`.
        """
        if not posixpath.isabs(root_dir):
            raise ValueError(f"root_dir must be an absolute path, got {root_dir!r}")
        if default_timeout <= 0:
            raise ValueError(f"default_timeout must be positive, got {default_timeout}")
        self._sandbox = sandbox
        self._root_dir = root_dir
        self._default_timeout = default_timeout
        self._max_output_bytes = max_output_bytes
        self._owns_sandbox = owns_sandbox
        # DeepAgents runs tools in worker threads, so two can arrive at once.
        self._root_lock = threading.Lock()
        self._root_ready = False

    # -- making and finding sandboxes ---------------------------------------

    @classmethod
    def create(
        cls,
        client: MicroVM | None = None,
        *,
        root_dir: str = DEFAULT_ROOT_DIR,
        default_timeout: int = DEFAULT_TIMEOUT_S,
        max_output_bytes: int | None = None,
        **create_fields: Any,
    ) -> AerolVMSandbox:
        """Make a new sandbox for this backend; :meth:`close` destroys it.

        ``create_fields`` are ``MicroVM.create`` fields, such as ``image``,
        ``cpu`` or ``lifecycle``. ``client`` defaults to ``MicroVM()``,
        which reads ``SB_API_URL`` and ``SB_PAT_TOKEN``.
        """
        client = client if client is not None else MicroVM()
        sandbox = client.create(_with_integration_tag(create_fields))
        return cls(
            sandbox,
            root_dir=root_dir,
            default_timeout=default_timeout,
            max_output_bytes=max_output_bytes,
            owns_sandbox=True,
        )

    @classmethod
    def for_name(
        cls,
        name: str,
        client: MicroVM | None = None,
        *,
        root_dir: str = DEFAULT_ROOT_DIR,
        default_timeout: int = DEFAULT_TIMEOUT_S,
        max_output_bytes: int | None = None,
        **create_fields: Any,
    ) -> AerolVMSandbox:
        """Use the sandbox called ``name``, making it the first time.

        Sandbox names are unique per account, so a graph that calls this with
        one name per conversation thread gets the same sandbox, and the same
        files, on every run of that thread. A stopped sandbox is started.
        :meth:`close` keeps the sandbox; give it a lifecycle (for example
        ``lifecycle={"destroyIfIdleFor": ...}``) so an old thread's sandbox
        does not live forever.
        """
        client = client if client is not None else MicroVM()
        sandbox = client.get_by_name(name)
        if sandbox is None:
            try:
                sandbox = client.create(_with_integration_tag({**create_fields, "name": name}))
            except MicroVMHTTPError as e:
                # Two runs of one thread raced to make it. The name is the
                # lock: the loser reads the winner's sandbox.
                if e.status_code != 409:
                    raise
                sandbox = client.get_by_name(name)
                if sandbox is None:
                    raise
        if sandbox.to_dict().get("status") == "stopped":
            sandbox = client.start(sandbox.id)
        return cls(
            sandbox,
            root_dir=root_dir,
            default_timeout=default_timeout,
            max_output_bytes=max_output_bytes,
            owns_sandbox=False,
        )

    def close(self) -> None:
        """Destroy the sandbox if this backend made it with :meth:`create`.
        A sandbox that is already gone is not an error."""
        if not self._owns_sandbox:
            return
        try:
            self._sandbox.destroy()
        except MicroVMHTTPError as e:
            if e.status_code != 404:
                raise
        self._owns_sandbox = False

    def __enter__(self) -> AerolVMSandbox:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def id(self) -> str:
        return self._sandbox.id

    @property
    def sandbox(self) -> Sandbox:
        """The AerolVM sandbox, for calls this backend does not cover."""
        return self._sandbox

    @property
    def root_dir(self) -> str:
        return self._root_dir

    # -- commands ------------------------------------------------------------

    def execute(self, command: str, *, timeout: int | None = None) -> ExecuteResponse:
        """Run a shell command in ``root_dir``.

        The output is stdout, then each stderr line prefixed ``[stderr]``,
        then ``Exit code: N`` when it is not 0: the same layout as
        DeepAgents' local shell backend, so a model reads both alike.
        A failed request (the server unreachable, the sandbox gone) raises,
        because it says nothing about how the command ended.
        """
        if not isinstance(command, str) or not command.strip():
            return ExecuteResponse(output="Error: Command must be a non-empty string.", exit_code=1)
        # toolboxd reads 0 as "use its 5 minute default", and has no "no
        # limit". DeepAgents allows 0 to mean "no limit" where a backend has
        # one; here it means the backend's default.
        budget = timeout if timeout is not None and timeout > 0 else self._default_timeout
        self._ensure_root()
        request: dict[str, Any] = {"command": command, "workDir": self._root_dir, "timeoutSeconds": budget}
        if self._max_output_bytes:
            request["maxStdoutBytes"] = self._max_output_bytes
            request["maxStderrBytes"] = self._max_output_bytes
        result = self._sandbox.exec(request)

        if result.get("timedOut"):
            hint = " (custom timeout)" if timeout else ". For long-running commands, re-run using the timeout parameter"
            return ExecuteResponse(
                output=f"Error: Command timed out after {budget} seconds{hint}.",
                exit_code=TIMEOUT_EXIT_CODE,
            )
        exit_code = int(result.get("exitCode") or 0)
        truncated = bool(result.get("stdoutTruncated") or result.get("stderrTruncated"))
        return ExecuteResponse(
            output=_combine_output(result.get("stdout") or "", result.get("stderr") or "", exit_code, truncated),
            exit_code=exit_code,
            truncated=truncated,
        )

    def _ensure_root(self) -> None:
        if self._root_ready:
            return
        with self._root_lock:
            if not self._root_ready:
                # parents=True is idempotent and needs no newer agent.
                self._sandbox.make_dir(self._root_dir, parents=True)
                self._root_ready = True

    # -- files ---------------------------------------------------------------

    def upload_files(self, files: list[tuple[str, bytes]]) -> list[FileUploadResponse]:
        """Write each file, making missing folders. One failure does not
        stop the others; it is reported in that file's response."""
        responses = []
        for path, content in files:
            error: FileOperationError | str | None = None
            target = self._resolve(path)
            if target is None:
                error = INVALID_PATH
            else:
                try:
                    self._sandbox.upload_file(target, content)
                except Exception as e:
                    error = _file_error(e)
            responses.append(FileUploadResponse(path=path, error=error))
        return responses

    def download_files(self, paths: list[str]) -> list[FileDownloadResponse]:
        """Read each file whole. One failure does not stop the others."""
        responses = []
        for path in paths:
            target = self._resolve(path)
            if target is None:
                responses.append(FileDownloadResponse(path=path, error=INVALID_PATH))
                continue
            try:
                content = self._sandbox.download_file(target)
            except Exception as e:
                responses.append(FileDownloadResponse(path=path, error=_file_error(e)))
            else:
                responses.append(FileDownloadResponse(path=path, content=content))
        return responses

    def _write_preflight(self, file_path: str) -> WriteResult | None:
        # BaseSandbox.write makes the parent folders with a Python script
        # before uploading. toolboxd's upload makes them itself, so the
        # script (and Python in the image, for writes) is not needed.
        return None

    async def _awrite_preflight(self, file_path: str) -> WriteResult | None:
        return None

    def ls(self, path: str) -> LsResult:
        """List a folder with the SDK's structured listing.

        BaseSandbox lists with a Python script run through execute. Anything
        the listing can not answer exactly (a truncated listing, an agent
        older than the file verbs) goes to that script instead, so its
        results stay the same.
        """
        target = self._resolve(path)
        if target is None:
            return LsResult(error=f"Path '{path}': invalid_path")
        try:
            listing = self._sandbox.list_files(target, depth=1, limit=DEFAULT_LIST_LIMIT)
        except MicroVMUnsupportedFeatureError:
            return super().ls(target)
        except MicroVMHTTPError as e:
            return LsResult(error=f"Path '{path}': {_ls_error(e)}")
        if listing.get("truncated"):
            return super().ls(target)
        entries: list[FileInfo] = []
        for info in listing.get("entries", []):
            entry: FileInfo = {"path": str(info.get("path")), "is_dir": bool(info.get("isDir"))}
            if not entry["is_dir"]:
                entry["size"] = int(info.get("size") or 0)
            if info.get("modTime"):
                entry["modified_at"] = str(info["modTime"])
            entries.append(entry)
        return LsResult(entries=entries)

    async def als(self, path: str) -> LsResult:
        # BaseSandbox's als runs its script through aexecute; this listing
        # is one SDK call, made off the event loop.
        return await asyncio.to_thread(self.ls, path)

    def delete(self, file_path: str) -> DeleteResult:
        """Delete a file, or a folder and everything in it."""
        target = self._resolve(file_path)
        if target is None:
            return DeleteResult(error=f"Error: '{file_path}' is not a valid path")
        try:
            self._sandbox.delete_file(target, recursive=True)
        except MicroVMHTTPError as e:
            if e.status_code == 404:
                return DeleteResult(error=f"Error: '{file_path}' not found")
            return DeleteResult(error=f"Error deleting file '{file_path}': {e}")
        return DeleteResult(path=file_path)

    def _resolve(self, path: str) -> str | None:
        """An absolute sandbox path, or None for one DeepAgents can not use."""
        if not isinstance(path, str) or not path or "\x00" in path:
            return None
        return posixpath.normpath(posixpath.join(self._root_dir, path))


def _with_integration_tag(fields: dict[str, Any]) -> dict[str, Any]:
    return {**fields, "tags": {**INTEGRATION_TAG, **dict(fields.get("tags") or {})}}


def _combine_output(stdout: str, stderr: str, exit_code: int, truncated: bool) -> str:
    parts = []
    if stdout:
        parts.append(stdout)
    if stderr:
        parts.extend(f"[stderr] {line}" for line in stderr.strip().split("\n"))
    output = "\n".join(parts) if parts else "<no output>"
    if truncated:
        output += "\n\n... Output truncated inside the sandbox."
    if exit_code != 0:
        output = f"{output.rstrip()}\n\nExit code: {exit_code}"
    return output


def _file_error(err: Exception) -> FileOperationError | str:
    """Map an SDK failure to DeepAgents' error codes, which a model can act
    on. toolboxd answers a missing file 404, no permission 403 (or 500 with
    the OS error on a download), and a folder 409 (500 on a download)."""
    if isinstance(err, MicroVMHTTPError):
        message = str(err).lower()
        if err.status_code == 404:
            return FILE_NOT_FOUND
        if err.status_code == 403 or message.endswith("permission denied"):
            return PERMISSION_DENIED
        if message.endswith("is a directory"):
            return IS_DIRECTORY
    return str(err)


def _ls_error(err: MicroVMHTTPError) -> str:
    # The words BaseSandbox's own listing reports, so callers see one set.
    if err.status_code == 404:
        return "path_not_found"
    if err.status_code == 403 or str(err).lower().endswith("permission denied"):
        return "permission_denied"
    if err.status_code == 409:
        return "not_a_directory"
    return str(err)
