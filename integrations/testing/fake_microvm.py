"""A stand-in for ``microvm.MicroVM`` where the sandbox is this machine.

Shared by the tests of every package in integrations/. exec runs real local
processes and the file calls touch real local paths, so each framework's own
machinery (the Agents SDK's shell helpers and tar archives, the DeepAgents
read and edit scripts) runs for real against the integration.

A snapshot copies the workspace folder aside; booting a sandbox from it puts
that copy back. That is the part of an AerolVM snapshot the integrations rely
on: the workspace comes back exactly as it was saved.

Every method has the real SDK method's signature, which
assert_fake_matches_sdk checks, so an integration can not call the fake in a
way the real client would reject. The per-call ``timeout`` is accepted and
ignored: nothing here waits on a network.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from microvm import (
    DEFAULT_LIST_LIMIT,
    ExposeResult,
    MicroVMError,
    MicroVMFileTooLargeError,
    MicroVMHTTPError,
    MicroVMUnsupportedFeatureError,
)
from microvm import MicroVM
from microvm.client import Sandbox

ALL_FEATURES = frozenset({"exec.argv", "exec.max_output_bytes", "files.verbs", "files.write_options", "files.extract"})


def _go_mode(st: os.stat_result) -> str:
    """The mode string toolboxd sends: Go's FileMode.String()."""
    perm = stat.filemode(st.st_mode)[1:]
    if stat.S_ISDIR(st.st_mode):
        return "d" + perm
    if stat.S_ISLNK(st.st_mode):
        return "L" + perm
    if stat.S_ISREG(st.st_mode):
        return "-" + perm
    return "p" + perm


class FakeMicroVM:
    """Records every call in ``calls`` as (method, args, kwargs)."""

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace
        self.calls: List[tuple] = []
        self.sandboxes: Dict[str, Dict[str, Any]] = {}
        self.snapshots: Dict[str, Path] = {}
        self.features = set(ALL_FEATURES)
        # Method name -> exception raised by the next call to it.
        self.fail_next: Dict[str, BaseException] = {}
        self._stash = Path(tempfile.mkdtemp(prefix="fake-microvm-snapshots-"))
        self._lock = threading.Lock()

    def cleanup(self) -> None:
        shutil.rmtree(self._stash, ignore_errors=True)

    def calls_to(self, method: str) -> List[tuple]:
        return [c for c in self.calls if c[0] == method]

    def _record(self, method: str, *args: Any, **kwargs: Any) -> None:
        with self._lock:
            self.calls.append((method, args, kwargs))
            err = self.fail_next.pop(method, None)
        if err is not None:
            raise err

    def _sandbox(self, sandbox_id: str) -> Dict[str, Any]:
        data = self.sandboxes.get(sandbox_id)
        if data is None:
            raise MicroVMHTTPError(404, "sandbox not found")
        return data

    def _require(self, sandbox_id: str, *features: str) -> None:
        missing = [f for f in features if f not in self.features]
        if missing:
            raise MicroVMUnsupportedFeatureError(sandbox_id, missing, "v0.0.1")

    # -- sandboxes ---------------------------------------------------------

    def create(self, options: Optional[dict] = None, *, timeout: Optional[float] = None, **fields: Any) -> Sandbox:
        self._record("create", options, **fields)
        opts = {**(options or {}), **fields}
        image = opts.get("image", "")
        if image in self.snapshots:
            shutil.rmtree(self.workspace, ignore_errors=True)
            shutil.copytree(self.snapshots[image], self.workspace, symlinks=True)
        elif str(image).startswith("missing-"):
            raise MicroVMHTTPError(404, f"image {image} not found")
        name = opts.get("name")
        if name and any(d.get("name") == name for d in self.sandboxes.values()):
            raise MicroVMHTTPError(409, f"sandbox name {name} is already in use")
        sandbox_id = f"sb-{uuid.uuid4().hex[:16]}"
        data = {"id": sandbox_id, "status": "started", "image": image, "tags": dict(opts.get("tags") or {})}
        if name:
            data["name"] = name
        self.sandboxes[sandbox_id] = data
        return Sandbox(self, dict(data))  # type: ignore[arg-type]

    def get(self, sandbox_id: str, *, include_env: bool = False, timeout: Optional[float] = None) -> Sandbox:
        self._record("get", sandbox_id, include_env=include_env)
        return Sandbox(self, dict(self._sandbox(sandbox_id)))  # type: ignore[arg-type]

    def get_by_name(self, name: str, *, include_env: bool = False, timeout: Optional[float] = None) -> Optional[Sandbox]:
        self._record("get_by_name", name, include_env=include_env)
        for data in self.sandboxes.values():
            if data.get("name") == name:
                return Sandbox(self, dict(data))  # type: ignore[arg-type]
        return None

    def start(self, sandbox_id: str, *, timeout: Optional[float] = None) -> Sandbox:
        self._record("start", sandbox_id)
        self._sandbox(sandbox_id)["status"] = "started"
        return Sandbox(self, dict(self._sandbox(sandbox_id)))  # type: ignore[arg-type]

    def stop(self, sandbox_id: str, *, timeout: Optional[float] = None) -> Sandbox:
        self._record("stop", sandbox_id)
        self._sandbox(sandbox_id)["status"] = "stopped"
        return Sandbox(self, dict(self._sandbox(sandbox_id)))  # type: ignore[arg-type]

    def destroy(self, sandbox_id: str, *, timeout: Optional[float] = None) -> None:
        self._record("destroy", sandbox_id)
        self._sandbox(sandbox_id)
        del self.sandboxes[sandbox_id]

    def create_snapshot(self, sandbox_id: str, name: str, *, allow_pause: Optional[bool] = None, timeout: Optional[float] = None) -> dict:
        self._record("create_snapshot", sandbox_id, name, allow_pause=allow_pause)
        self._sandbox(sandbox_id)
        target = self._stash / name
        shutil.copytree(self.workspace, target, symlinks=True)
        self.snapshots[name] = target
        return {"name": name, "image": f"aerolvm-snapshot/{name}", "sourceSandboxID": sandbox_id}

    def delete_snapshot(self, name: str, *, timeout: Optional[float] = None) -> None:
        self._record("delete_snapshot", name)
        path = self.snapshots.pop(name, None)
        if path is None:
            raise MicroVMHTTPError(404, "snapshot not found")
        shutil.rmtree(path, ignore_errors=True)

    def expose_port(self, sandbox_id: str, port: int, *, protocol: str = "http", visibility: Optional[str] = None, timeout: Optional[float] = None) -> ExposeResult:
        self._record("expose_port", sandbox_id, port, protocol=protocol, visibility=visibility)
        self._sandbox(sandbox_id)
        return ExposeResult(protocol="http", url=f"https://{sandbox_id}-{port}.sandbox.test")

    # -- exec --------------------------------------------------------------

    def exec(self, sandbox_id: str, request: dict, *, timeout: Optional[float] = None) -> dict:
        self._record("exec", sandbox_id, request)
        self._sandbox(sandbox_id)
        features = []
        if request.get("argv"):
            features.append("exec.argv")
        if request.get("maxStdoutBytes") or request.get("maxStderrBytes"):
            features.append("exec.max_output_bytes")
        self._require(sandbox_id, *features)
        argv = request.get("argv") or ["/bin/sh", "-c", request["command"]]
        env = {**os.environ, **(request.get("env") or {})}
        cwd = request.get("workDir") or None
        if cwd is not None and not os.path.isdir(cwd):
            raise MicroVMHTTPError(400, f"workdir {cwd} does not exist")
        try:
            proc = subprocess.run(
                argv, cwd=cwd, env=env, capture_output=True, timeout=request.get("timeoutSeconds") or 300
            )
        except subprocess.TimeoutExpired as e:
            return {
                "stdout": (e.stdout or b"").decode("utf-8", "replace"),
                "stderr": (e.stderr or b"").decode("utf-8", "replace"),
                "exitCode": -1,
                "durationMS": 0,
                "timedOut": True,
                "stdoutTruncated": False,
                "stderrTruncated": False,
                "signal": "SIGKILL",
            }
        except FileNotFoundError:
            return {"stdout": "", "stderr": f"{argv[0]}: not found", "exitCode": 127, "durationMS": 0,
                    "timedOut": False, "stdoutTruncated": False, "stderrTruncated": False, "signal": ""}
        out, err = proc.stdout, proc.stderr
        cap_out, cap_err = request.get("maxStdoutBytes"), request.get("maxStderrBytes")
        return {
            "stdout": (out[:cap_out] if cap_out else out).decode("utf-8", "replace"),
            "stderr": (err[:cap_err] if cap_err else err).decode("utf-8", "replace"),
            "exitCode": proc.returncode,
            "durationMS": 1,
            "timedOut": False,
            "stdoutTruncated": bool(cap_out and len(out) > cap_out),
            "stderrTruncated": bool(cap_err and len(err) > cap_err),
            "signal": "",
        }

    # -- files -------------------------------------------------------------

    @staticmethod
    def _missing(path: str) -> MicroVMHTTPError:
        return MicroVMHTTPError(404, f"stat {path}: no such file or directory", code="file_not_found")

    def upload_file(
        self,
        sandbox_id: str,
        target_path: str,
        data: bytes,
        *,
        append: bool = False,
        create_only: bool = False,
        atomic: bool = False,
        mode: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> None:
        self._record("upload_file", sandbox_id, target_path, len(data), append=append)
        self._sandbox(sandbox_id)
        try:
            Path(target_path).parent.mkdir(parents=True, exist_ok=True)
            with open(target_path, "ab" if append else "wb") as f:
                f.write(data)
        except IsADirectoryError as e:
            raise MicroVMHTTPError(409, f"open {target_path}: is a directory") from e
        except PermissionError as e:
            raise MicroVMHTTPError(403, f"open {target_path}: permission denied") from e

    def _check_readable(self, target_path: str) -> None:
        # toolboxd's download answers these as it does (main.go handleDownload).
        if not os.path.exists(target_path):
            raise self._missing(target_path)
        if os.path.isdir(target_path):
            raise MicroVMHTTPError(500, f"read {target_path}: is a directory")
        if not os.access(target_path, os.R_OK):
            raise MicroVMHTTPError(500, f"open {target_path}: permission denied")

    def download_file(self, sandbox_id: str, target_path: str, *, max_bytes: Optional[int] = None, timeout: Optional[float] = None) -> bytes:
        self._record("download_file", sandbox_id, target_path, max_bytes=max_bytes)
        self._sandbox(sandbox_id)
        self._check_readable(target_path)
        if max_bytes is not None and os.path.getsize(target_path) > max_bytes:
            raise MicroVMFileTooLargeError(target_path, max_bytes)
        return Path(target_path).read_bytes()

    def download_file_to(
        self, sandbox_id: str, target_path: str, dest: Any, *, max_bytes: Optional[int] = None, chunk_size: int = 4,
        timeout: Optional[float] = None,
    ) -> int:
        self._record("download_file_to", sandbox_id, target_path, max_bytes=max_bytes)
        self._sandbox(sandbox_id)
        self._check_readable(target_path)
        written = 0
        with open(target_path, "rb") as f:
            # Small chunks by default, so a bounded read is seen to stop early.
            while chunk := f.read(chunk_size):
                dest.write(chunk)
                written += len(chunk)
        return written

    def list_files(self, sandbox_id: str, path: str, *, depth: int = 1, limit: int = DEFAULT_LIST_LIMIT, timeout: Optional[float] = None) -> dict:
        self._record("list_files", sandbox_id, path, depth=depth, limit=limit)
        self._sandbox(sandbox_id)
        self._require(sandbox_id, "files.verbs")
        if not os.path.isdir(path):
            raise self._missing(path)
        entries = []
        for name in sorted(os.listdir(path)):
            full = os.path.join(path, name)
            st = os.lstat(full)
            info = {
                "name": name,
                "path": full,
                "isDir": stat.S_ISDIR(st.st_mode),
                "size": st.st_size,
                "mode": _go_mode(st),
                "permissions": "%04o" % stat.S_IMODE(st.st_mode),
                "owner": "root",
                "group": "root",
                "modTime": "2026-11-06T00:00:00Z",
            }
            if stat.S_ISLNK(st.st_mode):
                info["symlinkTarget"] = os.readlink(full)
            entries.append(info)
        return {"entries": entries[:limit], "truncated": len(entries) > limit}

    def get_file_info(self, sandbox_id: str, path: str, *, timeout: Optional[float] = None) -> dict:
        self._record("get_file_info", sandbox_id, path)
        self._sandbox(sandbox_id)
        if not os.path.exists(path):
            raise self._missing(path)
        st = os.stat(path)
        return {
            "name": os.path.basename(path),
            "path": path,
            "isDir": stat.S_ISDIR(st.st_mode),
            "size": st.st_size,
            "mode": _go_mode(st),
            "permissions": "%04o" % stat.S_IMODE(st.st_mode),
        }

    def delete_file(self, sandbox_id: str, path: str, *, recursive: bool = False, timeout: Optional[float] = None) -> None:
        self._record("delete_file", sandbox_id, path, recursive=recursive)
        self._sandbox(sandbox_id)
        if not os.path.lexists(path):
            raise self._missing(path)
        if os.path.isdir(path) and not os.path.islink(path):
            if not recursive:
                raise MicroVMHTTPError(409, f"{path} is a folder")
            shutil.rmtree(path)
        else:
            os.remove(path)

    def make_dir(self, sandbox_id: str, path: str, *, parents: bool = False, mode: Optional[int] = None, timeout: Optional[float] = None) -> None:
        self._record("make_dir", sandbox_id, path, parents=parents, mode=mode)
        self._sandbox(sandbox_id)
        if parents:
            os.makedirs(path, exist_ok=True)
            return
        self._require(sandbox_id, "files.verbs")
        try:
            os.mkdir(path)
        except FileExistsError as e:
            raise MicroVMHTTPError(409, "folder exists", code="folder_exists") from e

    def upload_dir(self, sandbox_id: str, local_dir: str, remote_dir: str, *, timeout: Optional[float] = None) -> None:
        self._record("upload_dir", sandbox_id, local_dir, remote_dir)
        self._sandbox(sandbox_id)
        self._require(sandbox_id, "files.extract")
        if not os.path.isdir(local_dir):
            raise MicroVMError(f"{local_dir} is not a folder")
        shutil.copytree(local_dir, remote_dir, symlinks=True, dirs_exist_ok=True)


_HELPERS = {"cleanup", "calls_to"}


def assert_fake_matches_sdk(test) -> None:
    """Fail ``test`` (a unittest.TestCase) when a fake method's parameters
    differ from the real ``MicroVM`` method's in name, order or kind."""
    import inspect

    for name, method in vars(FakeMicroVM).items():
        if name.startswith("_") or not callable(method) or name in _HELPERS:
            continue
        fake = [(p.name, p.kind) for p in inspect.signature(method).parameters.values()]
        real = [(p.name, p.kind) for p in inspect.signature(getattr(MicroVM, name)).parameters.values()]
        test.assertEqual(fake, real, f"FakeMicroVM.{name} does not match MicroVM.{name}")
