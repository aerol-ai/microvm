from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
import uuid
from io import BytesIO
from typing import Any, Dict, Iterable, List, Optional

from .types import (
    CreateOptions,
    ExecRequest,
    ExecResult,
    HealthStatus,
    ResizeOptions,
    SandboxData,
)


def _normalize_url(value: str) -> str:
    return value.rstrip("/")


def _read_env(name: str) -> Optional[str]:
    value = os.environ.get(name)
    return value if value not in (None, "") else None


class MicroVMError(Exception):
    pass


class Sandbox:
    def __init__(self, client: "MicroVM", data: SandboxData) -> None:
        self._client = client
        self._data = data

    def to_dict(self) -> SandboxData:
        return self._data

    def refresh(self) -> "Sandbox":
        updated = self._client.get(self.id)
        self._data = updated.to_dict()
        return self

    def exec(self, request: ExecRequest) -> ExecResult:
        return self._client.exec(self.id, request)

    def exec_command(self, command: str) -> ExecResult:
        return self._client.exec(self.id, {"command": command})

    def upload_file(self, target_path: str, data: bytes) -> None:
        self._client.upload_file(self.id, target_path, data)

    def download_file(self, target_path: str) -> bytes:
        return self._client.download_file(self.id, target_path)

    def expose_port(self, port: int) -> str:
        return self._client.expose_port(self.id, port)

    def unexpose_port(self, port: int) -> None:
        self._client.unexpose_port(self.id, port)

    def start(self) -> "Sandbox":
        updated = self._client.start(self.id)
        self._data = updated.to_dict()
        return self

    def stop(self) -> "Sandbox":
        updated = self._client.stop(self.id)
        self._data = updated.to_dict()
        return self

    def destroy(self) -> None:
        self._client.destroy(self.id)

    def resize(self, options: ResizeOptions) -> "Sandbox":
        updated = self._client.resize(self.id, options)
        self._data = updated.to_dict()
        return self

    @property
    def id(self) -> str:
        return self._data.get("id", "")

    def __getattr__(self, name: str) -> Any:
        if name in self._data:
            return self._data[name]
        raise AttributeError(f"Sandbox object has no attribute {name}")


class MicroVM:
    default_api_url = "http://127.0.0.1:8080"
    auth_required_error_message = "PAT token is required. Set pat_token or SB_PAT_TOKEN."

    def __init__(self, api_url: Optional[str] = None, pat_token: Optional[str] = None) -> None:
        self.api_url = _normalize_url(api_url or _read_env("SB_API_URL") or self.default_api_url)
        self.pat_token = pat_token or _read_env("SB_PAT_TOKEN") or ""

        if not self.pat_token:
            raise MicroVMError(self.auth_required_error_message)

    def create(self, options: CreateOptions) -> Sandbox:
        sandbox = self._do_json("POST", "/v1/sandboxes", options)
        return self._wrap_sandbox(sandbox)

    def list(self) -> List[Sandbox]:
        sandboxes = self._do_json("GET", "/v1/sandboxes", None)
        return [self._wrap_sandbox(item) for item in sandboxes]

    def get(self, sandbox_id: str) -> Sandbox:
        sandbox = self._do_json("GET", f"/v1/sandboxes/{sandbox_id}", None)
        return self._wrap_sandbox(sandbox)

    def start(self, sandbox_id: str) -> Sandbox:
        sandbox = self._do_json("POST", f"/v1/sandboxes/{sandbox_id}/start", None)
        return self._wrap_sandbox(sandbox)

    def stop(self, sandbox_id: str) -> Sandbox:
        sandbox = self._do_json("POST", f"/v1/sandboxes/{sandbox_id}/stop", None)
        return self._wrap_sandbox(sandbox)

    def destroy(self, sandbox_id: str) -> None:
        self._do_json("DELETE", f"/v1/sandboxes/{sandbox_id}", None)

    def resize(self, sandbox_id: str, options: ResizeOptions) -> Sandbox:
        sandbox = self._do_json("POST", f"/v1/sandboxes/{sandbox_id}/resize", options)
        return self._wrap_sandbox(sandbox)

    def health(self) -> HealthStatus:
        return self._do_json("GET", "/health", None)

    def exec(self, sandbox_id: str, request: ExecRequest) -> ExecResult:
        return self._do_json("POST", f"/v1/sandboxes/{sandbox_id}/toolbox/process/execute", request)

    def upload_file(self, sandbox_id: str, target_path: str, data: bytes) -> None:
        self._do_multipart(
            f"/v1/sandboxes/{sandbox_id}/toolbox/files/upload",
            {"path": target_path},
            "file",
            target_path,
            data,
        )

    def download_file(self, sandbox_id: str, target_path: str) -> bytes:
        url = self._url(f"/v1/sandboxes/{sandbox_id}/toolbox/files/download?path={urllib.parse.quote(target_path, safe='')}" )
        response = self._request("GET", url)
        return response

    def expose_port(self, sandbox_id: str, port: int) -> str:
        response = self._do_json("POST", f"/v1/sandboxes/{sandbox_id}/ports/{port}", None)
        return response["public_url"]

    def unexpose_port(self, sandbox_id: str, port: int) -> None:
        self._do_json("DELETE", f"/v1/sandboxes/{sandbox_id}/ports/{port}", None)

    def _wrap_sandbox(self, response: SandboxData) -> Sandbox:
        return Sandbox(self, response)

    def _url(self, path: str) -> str:
        return f"{self.api_url}{path}"

    def _request(self, method: str, url: str, body: Optional[bytes] = None, content_type: Optional[str] = None) -> bytes:
        request = urllib.request.Request(url, data=body, method=method)
        request.add_header("Authorization", f"Bearer {self.pat_token}")
        if content_type is not None:
            request.add_header("Content-Type", content_type)

        try:
            with urllib.request.urlopen(request) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            try:
                data = json.loads(payload.decode("utf-8"))
                raise MicroVMError(data.get("error", exc.reason)) from exc
            except (ValueError, TypeError):
                raise MicroVMError(exc.reason) from exc

    def _do_json(self, method: str, path: str, payload: Optional[Dict[str, Any]]) -> Any:
        body = None
        content_type = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            content_type = "application/json"
        raw = self._request(method, self._url(path), body, content_type)
        if raw == b"":
            return {}
        return json.loads(raw.decode("utf-8"))

    def _do_multipart(
        self,
        path: str,
        fields: Dict[str, str],
        file_field: str,
        filename: str,
        data: bytes,
    ) -> None:
        boundary = uuid.uuid4().hex
        body = BytesIO()
        encoder = body.write

        for name, value in fields.items():
            encoder(f"--{boundary}\r\n".encode("utf-8"))
            encoder(f"Content-Disposition: form-data; name=\"{name}\"\r\n\r\n".encode("utf-8"))
            encoder(value.encode("utf-8"))
            encoder(b"\r\n")

        encoder(f"--{boundary}\r\n".encode("utf-8"))
        encoder(
            f"Content-Disposition: form-data; name=\"{file_field}\"; filename=\"{os.path.basename(filename)}\"\r\n"
            .encode("utf-8"),
        )
        encoder(b"Content-Type: application/octet-stream\r\n\r\n")
        encoder(data)
        encoder(b"\r\n")
        encoder(f"--{boundary}--\r\n".encode("utf-8"))

        self._request(
            "POST",
            self._url(path),
            body.getvalue(),
            f"multipart/form-data; boundary={boundary}",
        )
