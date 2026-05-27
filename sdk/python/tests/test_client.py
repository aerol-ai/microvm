import json
import unittest

from microvm import Image
from microvm import client as client_module
from microvm.client import MicroVM


class RecordingMicroVM(MicroVM):
    def __init__(self) -> None:
        super().__init__(api_url="https://sandbox.example.com", pat_token="pat-token")
        self.calls = []
        self.raw_calls = []

    def _do_json(self, method, path, payload):  # type: ignore[override]
        self.calls.append((method, path, payload))
        if method == "POST" and path == "/v1/images/build":
            return {"image": "aerolvm-build/abc123:latest"}
        if method == "POST" and path == "/v1/sandboxes":
            return {
                "id": "sb-1",
                "image": "ubuntu:22.04",
                "status": "started",
                "public_url": "https://sb-1.example.com",
                "cpu": 2,
                "memory_mb": 2048,
                "disk_gb": 20,
                "os_user": "root",
                "network_block_all": True,
                "toolbox_enabled": True,
                "ssh_public_key": "ssh-ed25519 AAAA sandbox",
                "ssh_private_key": "PRIVATE",
                "exposed_ports": [],
                "created_at": "2026-05-07T10:00:00Z",
                "updated_at": "2026-05-07T10:00:00Z",
                "last_active_at": "2026-05-07T10:00:00Z",
                "lifecycle": payload.get("lifecycle", {}),
                "failover": payload.get("failover"),
            }
        if method == "PUT" and path == "/v1/sandboxes/sb-1/lifecycle":
            return {
                "id": "sb-1",
                "image": "ubuntu:22.04",
                "status": "started",
                "public_url": "https://sb-1.example.com",
                "cpu": 2,
                "memory_mb": 2048,
                "disk_gb": 20,
                "os_user": "root",
                "network_block_all": True,
                "toolbox_enabled": True,
                "ssh_public_key": "ssh-ed25519 AAAA sandbox",
                "exposed_ports": [],
                "created_at": "2026-05-07T10:00:00Z",
                "updated_at": "2026-05-07T11:00:00Z",
                "last_active_at": "2026-05-07T10:30:00Z",
                "lifecycle": payload,
            }
        if method == "POST" and path == "/v1/sandboxes/sb-1/snapshot":
            return {
                "name": payload.get("name", "snapshots/default:v1"),
                "image": payload.get("name", "snapshots/default:v1"),
                "image_id": "sha256:snap-1",
                "source_sandbox_id": "sb-1",
                "created_at": "2026-05-14T10:00:00Z",
            }
        if method == "POST" and path == "/v1/snapshots":
            return {
                "name": payload.get("name", "snapshots/default:v1"),
                "image": payload.get("image") or "snapshots/built:resolved",
                "image_id": "sha256:snap-2",
                "source_sandbox_id": "",
                "created_at": "2026-05-15T10:00:00Z",
                "entrypoint": payload.get("entrypoint") or [],
                "region_id": payload.get("region_id", ""),
                "cpu": payload.get("cpu", 0),
                "gpu": payload.get("gpu", 0),
                "memory_mb": payload.get("memory_mb", 0),
                "disk_gb": payload.get("disk_gb", 0),
            }
        if method == "GET" and path == "/v1/sandboxes/sb-1/network/usage":
            return {
                "sandbox_id": "sb-1",
                "bytes_in": 1024,
                "bytes_out": 2048,
                "bytes_in_limit": 1048576,
                "bytes_out_limit": 0,
                "quota_exceeded": False,
                "last_sampled_at": "2026-05-15T10:00:00Z",
            }
        if method == "PATCH" and path == "/v1/sandboxes/sb-1/network/limits":
            return {
                "sandbox_id": "sb-1",
                "bytes_in": 1024,
                "bytes_out": 2048,
                "bytes_in_limit": payload.get("network_bytes_in_limit", 0) if payload else 0,
                "bytes_out_limit": payload.get("network_bytes_out_limit", 0) if payload else 0,
                "quota_exceeded": False,
                "quota_exceeded_at": "2026-05-15T09:00:00Z",
                "last_sampled_at": "2026-05-15T10:00:00Z",
            }
        if method == "GET" and path == "/v1/sandboxes/sb-1/mounts":
            return {
                "mounts": [
                    {
                        "type": "s3",
                        "target": "/workspace",
                        "source": "s3://bucket/prefix",
                        "options": {"region": "us-east-1"},
                        "read_only": True,
                        "has_credentials": True,
                    }
                ]
            }
        if method == "POST" and path == "/v1/sandboxes/sb-1/sessions":
            return {
                "id": "ses-1",
                "name": payload.get("name", "default"),
                "argv": payload.get("argv") or ["sh", "-c", payload.get("command", "")],
                "workdir": payload.get("workdir"),
                "pty": bool(payload.get("pty", False)),
                "status": "running",
                "exit_code": 0,
                "created_at": "2026-05-07T10:05:00Z",
                "started_at": "2026-05-07T10:05:01Z",
                "recording": True,
                "bytes": 0,
                "attached": 1,
            }
        if method == "GET" and path == "/v1/sandboxes/sb-1/sessions":
            return {
                "sessions": [
                    {
                        "id": "ses-1",
                        "name": "default",
                        "argv": ["bash"],
                        "pty": True,
                        "status": "running",
                        "exit_code": 0,
                        "created_at": "2026-05-07T10:05:00Z",
                        "started_at": "2026-05-07T10:05:01Z",
                        "recording": True,
                        "bytes": 12,
                        "attached": 1,
                    }
                ]
            }
        if method == "GET" and path == "/v1/sandboxes/sb-1/sessions/ses-1":
            return {
                "id": "ses-1",
                "name": "default",
                "argv": ["bash"],
                "workdir": "/workspace",
                "pty": True,
                "status": "running",
                "exit_code": 0,
                "created_at": "2026-05-07T10:05:00Z",
                "started_at": "2026-05-07T10:05:01Z",
                "recording": True,
                "bytes": 99,
                "attached": 2,
            }
        if method == "POST" and path == "/v1/sandboxes/sb-1/sessions/ses-1/signal":
            return {}
        if method == "POST" and path == "/v1/sandboxes/sb-1/sessions/ses-1/resize":
            return {}
        if method == "DELETE" and path == "/v1/sandboxes/sb-1/sessions/ses-1":
            return {}
        if method == "POST" and path.endswith("/process/execute"):
            return {
                "stdout": "ok",
                "stderr": "",
                "exit_code": 0,
                "duration_ms": 5,
            }
        if method == "GET" and path == "/health":
            return {
                "status": "ok",
                "sandboxes": 1,
                "docker": "ok",
                "caddy": "ok",
                "ssh_gateway": "disabled",
                "version": "dev",
            }
        raise AssertionError(f"unexpected call: {method} {path} {payload}")

    def _request(self, method, url, body=None, content_type=None):  # type: ignore[override]
        path = url.replace(self.api_url, "")
        self.raw_calls.append((method, path, body, content_type))
        if method == "GET" and path == "/v1/sandboxes/sb-1/sessions/ses-1/log":
            return b"session log"
        if method == "GET" and path == "/v1/sandboxes/sb-1/sessions/ses-1/recording":
            return b'{"version":2}'
        raise AssertionError(f"unexpected raw call: {method} {path}")


class FakeABNF:
    OPCODE_BINARY = 2


class FakeWebSocket:
    def __init__(self, responses):
        self.responses = list(responses)
        self.sent = []
        self.closed = False

    def send(self, payload, opcode=None):
        self.sent.append((payload, opcode))

    def recv(self):
        if not self.responses:
            raise RuntimeError("socket exhausted")
        return self.responses.pop(0)

    def close(self):
        self.closed = True


class FakeWebSocketModule:
    ABNF = FakeABNF

    def __init__(self, ws):
        self.ws = ws
        self.calls = []

    def create_connection(self, url, header, enable_multithread):
        self.calls.append((url, header, enable_multithread))
        return self.ws


class ClientTests(unittest.TestCase):
    def test_create_with_image_builds_before_create(self):
        client = RecordingMicroVM()

        sandbox = client.create(
            {
                "image": Image.base("ubuntu:22.04").run_commands("apt-get update", "apt-get install -y curl"),
            }
        )

        self.assertEqual(
            client.calls[0],
            (
                "POST",
                "/v1/images/build",
                {
                    "dockerfile_content": "FROM ubuntu:22.04\nRUN apt-get update\nRUN apt-get install -y curl\n",
                },
            ),
        )
        self.assertEqual(client.calls[1][0], "POST")
        self.assertEqual(client.calls[1][1], "/v1/sandboxes")
        self.assertEqual(client.calls[1][2]["image"], "aerolvm-build/abc123:latest")
        self.assertEqual(sandbox.id, "sb-1")

    def test_build_image_with_push_forwards_push_options(self):
        class PushRecordingMicroVM(RecordingMicroVM):
            def _do_json(self, method, path, payload):  # type: ignore[override]
                self.calls.append((method, path, payload))
                if method == "POST" and path == "/v1/images/build":
                    return {
                        "image": "aerolvm-build/abc123:latest",
                        "pushed": "ghcr.io/x/y:v1",
                    }
                return super()._do_json(method, path, payload)

        client = PushRecordingMicroVM()
        result = client.build_image_with_push(
            Image.base("alpine"),
            push={
                "registry": "ghcr.io/x/y",
                "tag": "v1",
                "server": "ghcr.io",
                "username": "u",
                "password": "p",
            },
        )

        self.assertEqual(result.image, "aerolvm-build/abc123:latest")
        self.assertEqual(result.pushed, "ghcr.io/x/y:v1")
        self.assertEqual(
            client.calls[-1],
            (
                "POST",
                "/v1/images/build",
                {
                    "dockerfile_content": "FROM alpine\n",
                    "push": {
                        "registry": "ghcr.io/x/y",
                        "username": "u",
                        "password": "p",
                        "tag": "v1",
                        "server": "ghcr.io",
                    },
                },
            ),
        )

    def test_build_image_with_push_rejects_missing_credentials(self):
        client = RecordingMicroVM()
        with self.assertRaisesRegex(ValueError, "push.registry is required"):
            client.build_image_with_push(
                Image.base("alpine"),
                push={"username": "u", "password": "p"},
            )
        with self.assertRaisesRegex(ValueError, r"push\.username and push\.password"):
            client.build_image_with_push(
                Image.base("alpine"),
                push={"registry": "ghcr.io/x/y", "password": "p"},
            )
        with self.assertRaisesRegex(ValueError, r"push\.username and push\.password"):
            client.build_image_with_push(
                Image.base("alpine"),
                push={"registry": "ghcr.io/x/y", "username": "u"},
            )

    def test_build_image_maps_404_to_actionable_error(self):
        class NotFoundBuildMicroVM(RecordingMicroVM):
            def _do_json(self, method, path, payload):  # type: ignore[override]
                if method == "POST" and path == "/v1/images/build":
                    raise client_module.MicroVMHTTPError(404, "Not Found")
                return super()._do_json(method, path, payload)

        client = NotFoundBuildMicroVM()

        with self.assertRaisesRegex(client_module.MicroVMError, "does not support Image builds"):
            client.build_image(Image.base("alpine"))

    def test_create_maps_request_and_response_shapes(self):
        client = RecordingMicroVM()
        sandbox = client.create(
            {
                "image": "ubuntu:22.04",
                "memoryMB": 2048,
                "diskGB": 20,
                "networkBlockAll": True,
                "containerCommand": ["bash", "-lc", "echo hi"],
                "mounts": [
                    {
                        "type": "s3",
                        "target": "/workspace",
                        "source": "s3://bucket/prefix",
                        "options": {"region": "us-east-1"},
                        "credentials": {"access_key_id": "AKIA", "secret_access_key": "SECRET"},
                        "readOnly": True,
                    }
                ],
                "lifecycle": {
                    "stopIfIdleFor": 3_600_000_000_000,
                    "destroyAtAge": 86_400_000_000_000,
                },
                "failover": {"policy": "recreate"},
            }
        )

        self.assertEqual(
            client.calls[0],
            (
                "POST",
                "/v1/sandboxes",
                {
                    "image": "ubuntu:22.04",
                    "memory_mb": 2048,
                    "disk_gb": 20,
                    "network_block_all": True,
                    "container_command": ["bash", "-lc", "echo hi"],
                    "mounts": [
                        {
                            "type": "s3",
                            "target": "/workspace",
                            "source": "s3://bucket/prefix",
                            "options": {"region": "us-east-1"},
                            "credentials": {"access_key_id": "AKIA", "secret_access_key": "SECRET"},
                            "read_only": True,
                        }
                    ],
                    "lifecycle": {
                        "stop_if_idle_for": 3_600_000_000_000,
                        "destroy_at_age": 86_400_000_000_000,
                    },
                    "failover": {"policy": "recreate"},
                },
            ),
        )
        self.assertEqual(sandbox.publicURL, "https://sb-1.example.com")
        self.assertEqual(sandbox.memoryMB, 2048)
        self.assertTrue(sandbox.networkBlockAll)
        self.assertEqual(sandbox.sshPublicKey, "ssh-ed25519 AAAA sandbox")
        self.assertEqual(sandbox.sshPrivateKey, "PRIVATE")
        self.assertEqual(
            sandbox.lifecycle,
            {
                "stopIfIdleFor": 3_600_000_000_000,
                "destroyAtAge": 86_400_000_000_000,
            },
        )
        self.assertEqual(sandbox.failover, {"policy": "recreate"})

    def test_update_lifecycle_maps_request_and_updates_sandbox_state(self):
        client = RecordingMicroVM()

        sandbox = client.create({"image": "ubuntu:22.04"})
        updated = client.update_lifecycle(
            "sb-1",
            {
                "stopIfIdleFor": 7_200_000_000_000,
                "destroyAtAge": 172_800_000_000_000,
            },
        )
        sandbox.update_lifecycle(
            {
                "stopIfIdleFor": 10_800_000_000_000,
                "destroyIfIdleFor": 14_400_000_000_000,
            }
        )

        self.assertEqual(
            client.calls[1],
            (
                "PUT",
                "/v1/sandboxes/sb-1/lifecycle",
                {
                    "stop_if_idle_for": 7_200_000_000_000,
                    "destroy_at_age": 172_800_000_000_000,
                },
            ),
        )
        self.assertEqual(
            client.calls[2],
            (
                "PUT",
                "/v1/sandboxes/sb-1/lifecycle",
                {
                    "stop_if_idle_for": 10_800_000_000_000,
                    "destroy_if_idle_for": 14_400_000_000_000,
                },
            ),
        )
        self.assertEqual(
            updated.lifecycle,
            {
                "stopIfIdleFor": 7_200_000_000_000,
                "destroyAtAge": 172_800_000_000_000,
            },
        )
        self.assertEqual(
            sandbox.lifecycle,
            {
                "stopIfIdleFor": 10_800_000_000_000,
                "destroyIfIdleFor": 14_400_000_000_000,
            },
        )

    def test_create_round_trips_serverless_lifecycle_flag(self):
        client = RecordingMicroVM()
        sandbox = client.create(
            {
                "image": "ubuntu:22.04",
                "lifecycle": {
                    "stopIfIdleFor": 300_000_000_000,
                    "serverless": True,
                },
            }
        )

        self.assertEqual(
            client.calls[0],
            (
                "POST",
                "/v1/sandboxes",
                {
                    "image": "ubuntu:22.04",
                    "mounts": [],
                    "lifecycle": {
                        "stop_if_idle_for": 300_000_000_000,
                        "serverless": True,
                    },
                },
            ),
        )
        self.assertEqual(
            sandbox.lifecycle,
            {
                "stopIfIdleFor": 300_000_000_000,
                "serverless": True,
            },
        )

    def test_create_snapshot_maps_request_and_response_shapes(self):
        client = RecordingMicroVM()
        snapshot = client.create_snapshot("sb-1", "snapshots/demo:v1")
        sandbox = client.create({"image": "ubuntu:22.04"})
        sandbox_snapshot = sandbox.create_snapshot("snapshots/from-sandbox:v1")

        self.assertEqual(
            client.calls[0],
            (
                "POST",
                "/v1/sandboxes/sb-1/snapshot",
                {"name": "snapshots/demo:v1"},
            ),
        )
        self.assertEqual(snapshot["imageID"], "sha256:snap-1")
        self.assertEqual(snapshot["sourceSandboxID"], "sb-1")
        self.assertEqual(sandbox_snapshot["name"], "snapshots/from-sandbox:v1")

    def test_register_snapshot_maps_request_and_response_shapes(self):
        client = RecordingMicroVM()

        snapshot = client.register_snapshot(
            {
                "name": "py-base",
                "image": "python:3.12-slim",
                "regionID": "us",
                "cpu": 2,
                "gpu": 1,
                "memoryMB": 4096,
                "diskGB": 10,
            }
        )

        self.assertEqual(
            client.calls[0],
            (
                "POST",
                "/v1/snapshots",
                {
                    "name": "py-base",
                    "image": "python:3.12-slim",
                    "region_id": "us",
                    "cpu": 2,
                    "gpu": 1,
                    "memory_mb": 4096,
                    "disk_gb": 10,
                },
            ),
        )
        self.assertEqual(snapshot["imageID"], "sha256:snap-2")
        self.assertEqual(snapshot["regionID"], "us")
        self.assertEqual(snapshot["cpu"], 2.0)
        self.assertEqual(snapshot["gpu"], 1.0)
        self.assertEqual(snapshot["memoryMB"], 4096)
        self.assertEqual(snapshot["diskGB"], 10)

    def test_register_snapshot_from_image_uses_dockerfile_content(self):
        client = RecordingMicroVM()

        snapshot = client.register_snapshot_from_image(
            "built",
            Image.base("debian:bookworm-slim").run_commands("apt-get update"),
            {"entrypoint": ["/bin/sh", "-c", "echo hi"]},
        )

        method, path, payload = client.calls[0]
        self.assertEqual((method, path), ("POST", "/v1/snapshots"))
        self.assertEqual(payload["name"], "built")
        self.assertNotIn("image", payload)
        self.assertIn("dockerfile_content", payload)
        self.assertIn("FROM debian:bookworm-slim", payload["dockerfile_content"])
        self.assertIn("RUN apt-get update", payload["dockerfile_content"])
        self.assertEqual(payload["entrypoint"], ["/bin/sh", "-c", "echo hi"])
        self.assertEqual(snapshot["image"], "snapshots/built:resolved")
        self.assertEqual(snapshot["entrypoint"], ["/bin/sh", "-c", "echo hi"])

    def test_register_snapshot_validates_input_before_sending(self):
        client = RecordingMicroVM()

        with self.assertRaisesRegex(client_module.MicroVMError, "name is required"):
            client.register_snapshot({"image": "alpine"})

        with self.assertRaisesRegex(client_module.MicroVMError, "image or dockerfile_content is required"):
            client.register_snapshot({"name": "x"})

        with self.assertRaisesRegex(client_module.MicroVMError, "mutually exclusive"):
            client.register_snapshot({"name": "x", "image": "alpine", "dockerfileContent": "FROM busybox"})

        self.assertEqual(client.calls, [])

    def test_exec_and_health_map_api_shapes(self):
        client = RecordingMicroVM()

        result = client.exec("sb-1", {"command": "echo ok", "workDir": "/workspace", "timeoutSeconds": 2})
        health = client.health()

        self.assertEqual(
            client.calls[0],
            (
                "POST",
                "/v1/sandboxes/sb-1/toolbox/process/execute",
                {"command": "echo ok", "workdir": "/workspace", "timeout_seconds": 2},
            ),
        )
        self.assertEqual(result["exitCode"], 0)
        self.assertEqual(result["durationMS"], 5)
        self.assertEqual(health["status"], "ok")
        self.assertEqual(health["sshGateway"], "disabled")

    def test_mounts_maps_redacted_mount_shapes(self):
        client = RecordingMicroVM()

        mounts = client.mounts("sb-1")

        self.assertEqual(client.calls[0], ("GET", "/v1/sandboxes/sb-1/mounts", None))
        self.assertEqual(
            mounts,
            [
                {
                    "type": "s3",
                    "target": "/workspace",
                    "source": "s3://bucket/prefix",
                    "options": {"region": "us-east-1"},
                    "readOnly": True,
                    "hasCredentials": True,
                }
            ],
        )

    def test_create_with_network_byte_limits_maps_snake_case_fields(self):
        client = RecordingMicroVM()
        client.create(
            {
                "image": "ubuntu:22.04",
                "networkBytesInLimit": 1048576,
                "networkBytesOutLimit": 524288,
            }
        )
        self.assertEqual(
            client.calls[0],
            (
                "POST",
                "/v1/sandboxes",
                {
                    "image": "ubuntu:22.04",
                    "network_bytes_in_limit": 1048576,
                    "network_bytes_out_limit": 524288,
                    "mounts": [],
                },
            ),
        )

    def test_get_network_usage_maps_response_shape(self):
        client = RecordingMicroVM()

        usage = client.get_network_usage("sb-1")

        self.assertEqual(client.calls[0], ("GET", "/v1/sandboxes/sb-1/network/usage", None))
        self.assertEqual(
            usage,
            {
                "sandboxID": "sb-1",
                "bytesIn": 1024,
                "bytesOut": 2048,
                "bytesInLimit": 1048576,
                "bytesOutLimit": 0,
                "quotaExceeded": False,
                "lastSampledAt": "2026-05-15T10:00:00Z",
            },
        )

    def test_set_network_limits_sends_patch_and_returns_usage(self):
        client = RecordingMicroVM()
        sandbox = client.create({"image": "ubuntu:22.04"})

        usage = sandbox.set_network_limits({"networkBytesInLimit": 2097152})

        self.assertEqual(
            client.calls[1],
            (
                "PATCH",
                "/v1/sandboxes/sb-1/network/limits",
                {"network_bytes_in_limit": 2097152},
            ),
        )
        self.assertEqual(usage["bytesInLimit"], 2097152)
        self.assertEqual(usage["quotaExceededAt"], "2026-05-15T09:00:00Z")

    def test_exec_stream_sends_handshake_and_control_frames(self):
        stdout_chunks = []
        stderr_chunks = []
        errors = []
        fake_ws = FakeWebSocket(
            [
                bytes([1]) + b"hello",
                bytes([2]) + b"warn",
                json.dumps({"type": "exit", "code": 0}),
            ]
        )
        fake_module = FakeWebSocketModule(fake_ws)
        original_loader = client_module._load_websocket_module
        client_module._load_websocket_module = lambda: fake_module
        try:
            client = RecordingMicroVM()
            handle = client.exec_stream(
                "sb-1",
                {
                    "command": "bash",
                    "tty": True,
                    "cols": 120,
                    "rows": 40,
                    "onStdout": stdout_chunks.append,
                    "onStderr": stderr_chunks.append,
                    "onError": errors.append,
                },
            )

            handle.write("pwd\n")
            handle.resize(120, 40)
            handle.signal("INT")
            result = handle.wait(1)

            self.assertEqual(result["code"], 0)
            self.assertEqual(stdout_chunks, [b"hello"])
            self.assertEqual(stderr_chunks, [b"warn"])
            self.assertEqual(errors, [])
            self.assertEqual(fake_module.calls[0][0], "wss://sandbox.example.com/v1/sandboxes/sb-1/toolbox/process/exec/stream")
            self.assertEqual(fake_module.calls[0][1], ["Authorization: Bearer pat-token"])
            self.assertTrue(fake_module.calls[0][2])
            self.assertEqual(json.loads(fake_ws.sent[0][0]), {"command": "bash", "tty": True, "cols": 120, "rows": 40})
            self.assertEqual(fake_ws.sent[1], (b"pwd\n", 2))
            self.assertEqual(json.loads(fake_ws.sent[2][0]), {"type": "resize", "cols": 120, "rows": 40})
            self.assertEqual(json.loads(fake_ws.sent[3][0]), {"type": "signal", "signal": "INT"})
        finally:
            client_module._load_websocket_module = original_loader

    def test_session_methods_map_api_shapes(self):
        client = RecordingMicroVM()
        sandbox = client.create({"image": "ubuntu:22.04"})

        created = sandbox.create_session(
            {"name": "default", "command": "bash", "workDir": "/workspace", "pty": True, "cols": 120, "rows": 40}
        )
        listed = sandbox.list_sessions()
        loaded = sandbox.get_session("ses-1")
        sandbox.signal_session("ses-1", "TERM")
        sandbox.resize_session("ses-1", 120, 40)
        log = sandbox.session_log("ses-1")
        recording = sandbox.session_recording("ses-1")
        sandbox.delete_session("ses-1")

        self.assertEqual(
            client.calls[1],
            (
                "POST",
                "/v1/sandboxes/sb-1/sessions",
                {
                    "name": "default",
                    "command": "bash",
                    "workdir": "/workspace",
                    "pty": True,
                    "cols": 120,
                    "rows": 40,
                },
            ),
        )
        self.assertEqual(client.calls[2], ("GET", "/v1/sandboxes/sb-1/sessions", None))
        self.assertEqual(client.calls[3], ("GET", "/v1/sandboxes/sb-1/sessions/ses-1", None))
        self.assertEqual(client.calls[4], ("POST", "/v1/sandboxes/sb-1/sessions/ses-1/signal", {"signal": "TERM"}))
        self.assertEqual(client.calls[5], ("POST", "/v1/sandboxes/sb-1/sessions/ses-1/resize", {"cols": 120, "rows": 40}))
        self.assertEqual(client.calls[6], ("DELETE", "/v1/sandboxes/sb-1/sessions/ses-1", None))
        self.assertEqual(client.raw_calls[0][:2], ("GET", "/v1/sandboxes/sb-1/sessions/ses-1/log"))
        self.assertEqual(client.raw_calls[1][:2], ("GET", "/v1/sandboxes/sb-1/sessions/ses-1/recording"))

        self.assertEqual(created["argv"], ["sh", "-c", "bash"])
        self.assertEqual(listed[0]["status"], "running")
        self.assertEqual(loaded["bytes"], 99)
        self.assertEqual(log, b"session log")
        self.assertEqual(recording, b'{"version":2}')

    def test_attach_session_sends_control_frames_and_waits_for_exit(self):
        stdout_chunks = []
        stderr_chunks = []
        errors = []
        exits = []
        fake_ws = FakeWebSocket(
            [
                bytes([1]) + b"hello",
                bytes([2]) + b"warn",
                json.dumps({"type": "exit", "code": 0, "signal": "TERM"}),
            ]
        )
        fake_module = FakeWebSocketModule(fake_ws)
        original_loader = client_module._load_websocket_module
        client_module._load_websocket_module = lambda: fake_module
        try:
            client = RecordingMicroVM()
            handle = client.attach_session(
                "sb-1",
                "ses-1",
                {
                    "cols": 120,
                    "rows": 40,
                    "onStdout": stdout_chunks.append,
                    "onStderr": stderr_chunks.append,
                    "onError": errors.append,
                    "onExit": exits.append,
                },
            )

            handle.write("pwd\n")
            handle.resize(100, 30)
            handle.signal("INT")
            result = handle.wait(1)

            self.assertEqual(result, {"code": 0, "signal": "TERM"})
            self.assertEqual(stdout_chunks, [b"hello"])
            self.assertEqual(stderr_chunks, [b"warn"])
            self.assertEqual(errors, [])
            self.assertEqual(exits, [{"code": 0, "signal": "TERM"}])
            self.assertEqual(fake_module.calls[0][0], "wss://sandbox.example.com/v1/sandboxes/sb-1/sessions/ses-1/attach")
            self.assertEqual(fake_module.calls[0][1], ["Authorization: Bearer pat-token"])
            self.assertTrue(fake_module.calls[0][2])
            self.assertEqual(json.loads(fake_ws.sent[0][0]), {"type": "resize", "cols": 120, "rows": 40})
            self.assertEqual(fake_ws.sent[1], (b"pwd\n", 2))
            self.assertEqual(json.loads(fake_ws.sent[2][0]), {"type": "resize", "cols": 100, "rows": 30})
            self.assertEqual(json.loads(fake_ws.sent[3][0]), {"type": "signal", "signal": "INT"})
        finally:
            client_module._load_websocket_module = original_loader


class ListFilterTests(unittest.TestCase):
    """Mirrors pkg/api/v1/list_filter_test.go: a tag-filter list call must
    render every tag as `?tag.<k>=<v>` on the wire, since that is the prefix
    the server's parseTagFilter inspects. A bare list() call must produce the
    pre-filter URL byte-for-byte so existing callers and fixtures don't see a
    stray trailing "?".
    """

    def _client_capturing(self):
        captured = {"paths": []}

        class CapturingClient(MicroVM):
            def __init__(self) -> None:
                super().__init__(api_url="https://sandbox.example.com", pat_token="pat-token")

            def _do_json(self, method, path, payload):  # type: ignore[override]
                captured["paths"].append((method, path, payload))
                return []

        return CapturingClient(), captured

    def test_list_with_tags_renders_tag_prefix(self):
        client, captured = self._client_capturing()
        client.list(tags={"user_id": "alice", "project_id": "p1"})
        method, path, _ = captured["paths"][0]
        self.assertEqual(method, "GET")
        # Dict iteration is insertion-ordered on every supported Python; assert
        # both pairs are present without depending on a stable join order.
        self.assertTrue(path.startswith("/v1/sandboxes?"))
        self.assertIn("tag.user_id=alice", path)
        self.assertIn("tag.project_id=p1", path)

    def test_list_with_tags_url_encodes_keys_and_values(self):
        client, captured = self._client_capturing()
        client.list(tags={"user/id": "alice bob", "needs=encode": "v&v"})
        _, path, _ = captured["paths"][0]
        self.assertIn("tag.user%2Fid=alice%20bob", path)
        self.assertIn("tag.needs%3Dencode=v%26v", path)

    def test_list_without_tags_omits_query_string(self):
        client, captured = self._client_capturing()
        client.list()
        client.list(tags=None)
        client.list(tags={})
        for _, path, _ in captured["paths"]:
            self.assertEqual(path, "/v1/sandboxes")


class CustomDomainsTests(unittest.TestCase):
    """Mirrors the wire shape of the custom-domains endpoints
    (POST/GET/DELETE /v1/sandboxes/{id}/custom-domains[...]).
    """

    def _client(self, *, post_status=201, post_body=None, get_body=None, delete_status=204):
        captured = {"calls": []}

        class FakeMicroVM(MicroVM):
            def __init__(self) -> None:
                super().__init__(api_url="https://sandbox.example.com", pat_token="pat-token")

            def _do_json(self, method, path, payload):  # type: ignore[override]
                captured["calls"].append((method, path, payload))
                if method == "POST" and path.endswith("/custom-domains"):
                    if post_status >= 400:
                        raise client_module.MicroVMHTTPError(post_status, "boom")
                    return post_body or {"custom_domains": []}
                if method == "GET" and path.endswith("/custom-domains"):
                    return get_body or {"custom_domains": []}
                if method == "DELETE" and "/custom-domains/" in path:
                    if delete_status >= 400:
                        raise client_module.MicroVMHTTPError(delete_status, "boom")
                    return {}
                raise AssertionError(f"unexpected call: {method} {path}")

        return FakeMicroVM(), captured

    def test_add_custom_domain_returns_list_and_sends_body(self):
        client, captured = self._client(
            post_body={
                "custom_domains": [
                    {
                        "hostname": "api.acme.com",
                        "status": "pending_dns",
                        "created_at": "2026-05-25T10:00:00Z",
                        "updated_at": "2026-05-25T10:00:00Z",
                    }
                ]
            },
        )

        domains = client.add_custom_domain("sb-1", "api.acme.com")

        self.assertEqual(
            captured["calls"][0],
            ("POST", "/v1/sandboxes/sb-1/custom-domains", {"hostname": "api.acme.com"}),
        )
        self.assertEqual(len(domains), 1)
        self.assertEqual(domains[0]["hostname"], "api.acme.com")
        self.assertEqual(domains[0]["status"], "pending_dns")
        self.assertEqual(domains[0]["createdAt"], "2026-05-25T10:00:00Z")
        self.assertNotIn("lastError", domains[0])

    def test_add_custom_domain_preserves_hostname_case(self):
        # Case is forwarded as-passed; the server normalizes. The SDK must not
        # lowercase locally or the wire payload diverges from caller intent.
        client, captured = self._client(post_body={"custom_domains": []})
        client.add_custom_domain("sb-1", "API.AcMe.COM")
        self.assertEqual(captured["calls"][0][2], {"hostname": "API.AcMe.COM"})

    def test_list_custom_domains_maps_response_shape(self):
        client, captured = self._client(
            get_body={
                "custom_domains": [
                    {
                        "hostname": "a.acme.com",
                        "status": "ready",
                        "created_at": "2026-05-24T10:00:00Z",
                        "updated_at": "2026-05-25T10:00:00Z",
                    },
                    {
                        "hostname": "b.acme.com",
                        "status": "failed",
                        "last_error": "challenge timeout",
                        "created_at": "2026-05-24T10:00:00Z",
                        "updated_at": "2026-05-25T10:01:00Z",
                    },
                ]
            },
        )

        domains = client.list_custom_domains("sb-1")

        self.assertEqual(captured["calls"][0], ("GET", "/v1/sandboxes/sb-1/custom-domains", None))
        self.assertEqual(len(domains), 2)
        self.assertEqual(domains[0]["status"], "ready")
        self.assertNotIn("lastError", domains[0])
        self.assertEqual(domains[1]["status"], "failed")
        self.assertEqual(domains[1]["lastError"], "challenge timeout")

    def test_remove_custom_domain_returns_none_and_url_encodes_host(self):
        client, captured = self._client()
        # Hostname with characters that require percent-encoding to round-trip.
        result = client.remove_custom_domain("sb-1", "weird host/.example.com")
        self.assertIsNone(result)
        method, path, payload = captured["calls"][0]
        self.assertEqual(method, "DELETE")
        self.assertEqual(payload, None)
        self.assertEqual(
            path,
            "/v1/sandboxes/sb-1/custom-domains/weird%20host%2F.example.com",
        )

    def test_add_custom_domain_propagates_409_protocol_conflict(self):
        client, _ = self._client(post_status=409)
        with self.assertRaises(client_module.MicroVMHTTPError) as ctx:
            client.add_custom_domain("sb-1", "api.acme.com")
        self.assertEqual(ctx.exception.status_code, 409)

    def test_add_custom_domain_propagates_412_not_supported(self):
        client, _ = self._client(post_status=412)
        with self.assertRaises(client_module.MicroVMHTTPError) as ctx:
            client.add_custom_domain("sb-1", "api.acme.com")
        self.assertEqual(ctx.exception.status_code, 412)

    def test_sandbox_methods_delegate_to_client(self):
        client, captured = self._client(
            post_body={
                "custom_domains": [
                    {
                        "hostname": "api.acme.com",
                        "status": "pending_dns",
                        "created_at": "2026-05-25T10:00:00Z",
                        "updated_at": "2026-05-25T10:00:00Z",
                    }
                ]
            },
        )
        # Construct a Sandbox without a create roundtrip.
        sandbox = client_module.Sandbox(client, {"id": "sb-1"})

        sandbox.add_custom_domain("api.acme.com")
        sandbox.list_custom_domains()
        sandbox.remove_custom_domain("api.acme.com")

        self.assertEqual(
            [(m, p) for (m, p, _) in captured["calls"]],
            [
                ("POST", "/v1/sandboxes/sb-1/custom-domains"),
                ("GET", "/v1/sandboxes/sb-1/custom-domains"),
                ("DELETE", "/v1/sandboxes/sb-1/custom-domains/api.acme.com"),
            ],
        )

    def test_create_forwards_custom_domains_list(self):
        client = RecordingMicroVM()
        client.create(
            {
                "image": "ubuntu:22.04",
                "customDomains": ["api.acme.com", "edge.acme.com"],
            }
        )
        method, path, payload = client.calls[0]
        self.assertEqual((method, path), ("POST", "/v1/sandboxes"))
        self.assertEqual(payload["custom_domains"], ["api.acme.com", "edge.acme.com"])


class DNSRecordsTests(unittest.TestCase):
    """Covers the two DNS helper endpoints:

    - ``GET /v1/ingress/dns``                                 → ``dns_target``
    - ``GET /v1/sandboxes/{id}/custom-domains/dns``           → ``custom_domain_dns``
    """

    def _client(self, *, body=None):
        captured = {"calls": []}

        class FakeMicroVM(MicroVM):
            def __init__(self) -> None:
                super().__init__(api_url="https://sandbox.example.com", pat_token="pat-token")

            def _do_json(self, method, path, payload):  # type: ignore[override]
                captured["calls"].append((method, path, payload))
                return body or {}

        return FakeMicroVM(), captured

    def test_dns_target_hostname_source(self):
        client, captured = self._client(body={"hostname": "ingress.example.com", "source": "hostname"})

        target = client.dns_target()

        self.assertEqual(captured["calls"][0], ("GET", "/v1/ingress/dns", None))
        self.assertEqual(target["hostname"], "ingress.example.com")
        self.assertEqual(target["source"], "hostname")
        self.assertNotIn("ips", target)

    def test_dns_target_ips_source(self):
        client, _ = self._client(body={"ips": ["198.51.100.10", "198.51.100.11"], "source": "ips"})

        target = client.dns_target()

        self.assertEqual(target["ips"], ["198.51.100.10", "198.51.100.11"])
        self.assertEqual(target["source"], "ips")
        self.assertNotIn("hostname", target)

    def test_dns_target_empty_payload_yields_unknown_source(self):
        # Daemon must still answer; absent fields decode to a minimal target
        # with source="unknown" so callers can branch on the documented enum
        # without seeing "" or server typos.
        client, _ = self._client(body={})

        target = client.dns_target()

        self.assertEqual(target, {"source": "unknown"})

    def test_dns_target_unknown_source_value_normalises_to_unknown(self):
        # Daemon advertises source ∈ {hostname, ips, mixed, unknown}.
        # Defensive: any out-of-contract value collapses to "unknown" so
        # callers' branching stays exhaustive.
        client, _ = self._client(body={"source": "some-future-value"})

        target = client.dns_target()

        self.assertEqual(target["source"], "unknown")

    def test_custom_domain_dns_maps_records_and_target(self):
        client, captured = self._client(
            body={
                "records": [
                    {
                        "hostname": "api.acme.com",
                        "type": "CNAME",
                        "name": "api.acme.com",
                        "value": "ingress.example.com",
                        "notes": "use proxied=false if behind Cloudflare",
                    },
                    {
                        "hostname": "edge.acme.com",
                        "type": "A",
                        "name": "edge.acme.com",
                        "value": "198.51.100.10",
                    },
                ],
                "target": {"hostname": "ingress.example.com", "source": "hostname"},
            },
        )

        bundle = client.custom_domain_dns("sb-1")

        self.assertEqual(captured["calls"][0], ("GET", "/v1/sandboxes/sb-1/custom-domains/dns", None))
        self.assertEqual(len(bundle["records"]), 2)
        self.assertEqual(bundle["records"][0]["type"], "CNAME")
        self.assertEqual(bundle["records"][0]["value"], "ingress.example.com")
        self.assertEqual(bundle["records"][0]["notes"], "use proxied=false if behind Cloudflare")
        self.assertEqual(bundle["records"][1]["type"], "A")
        self.assertNotIn("notes", bundle["records"][1])
        self.assertEqual(bundle["target"]["hostname"], "ingress.example.com")
        self.assertEqual(bundle["target"]["source"], "hostname")

    def test_custom_domain_dns_empty_records_list(self):
        client, _ = self._client(body={"records": [], "target": {"ips": ["198.51.100.10"], "source": "ips"}})

        bundle = client.custom_domain_dns("sb-1")

        self.assertEqual(bundle["records"], [])
        self.assertEqual(bundle["target"]["ips"], ["198.51.100.10"])

    def test_sandbox_custom_domain_dns_delegates_to_client(self):
        client, captured = self._client(
            body={
                "records": [
                    {"hostname": "api.acme.com", "type": "CNAME", "name": "api.acme.com", "value": "ingress.example.com"},
                ],
                "target": {"hostname": "ingress.example.com", "source": "hostname"},
            },
        )
        sandbox = client_module.Sandbox(client, {"id": "sb-1"})

        bundle = sandbox.custom_domain_dns()

        self.assertEqual(captured["calls"][0], ("GET", "/v1/sandboxes/sb-1/custom-domains/dns", None))
        self.assertEqual(bundle["records"][0]["hostname"], "api.acme.com")
        self.assertEqual(bundle["target"]["source"], "hostname")


if __name__ == "__main__":
    unittest.main()


class TemplateLifecycleTests(unittest.TestCase):
    """Cover the Firecracker rootfs-template surface:
    POST/GET/DELETE /v1/templates[/{id}] and the operator-triggered
    POST /v1/templates/{id}/rebuild. Validates that the SDK maps
    snake_case wire fields to the camelCase Template dict, sends the
    right method/path, and surfaces 412 errors as MicroVMHTTPError.
    """

    def _client(self, *, response=None):
        captured = {"calls": []}

        class FakeMicroVM(MicroVM):
            def __init__(self) -> None:
                super().__init__(api_url="https://sandbox.example.com", pat_token="pat-token")

            def _do_json(self, method, path, payload):  # type: ignore[override]
                captured["calls"].append((method, path, payload))
                # Each individual test installs its own response, so we
                # consume from a shared mailbox here.
                if isinstance(response, Exception):
                    raise response
                return response

        return FakeMicroVM(), captured

    def test_create_template_sends_request_and_maps_response(self):
        api_response = {
            "id": "tpl-create",
            "image": "docker://python:3.11",
            "status": "pending",
            "min_size_mib": 512,
            "created_at": "2026-05-27T10:00:00Z",
            "updated_at": "2026-05-27T10:00:00Z",
            "has_snapshot": False,
            "has_overlay": False,
        }
        client, captured = self._client(response=api_response)
        tpl = client.create_template({"id": "tpl-create", "image": "docker://python:3.11", "minSizeMiB": 512})
        self.assertEqual(captured["calls"][0][0], "POST")
        self.assertEqual(captured["calls"][0][1], "/v1/templates")
        self.assertEqual(captured["calls"][0][2], {"id": "tpl-create", "image": "docker://python:3.11", "min_size_mib": 512})
        self.assertEqual(tpl["id"], "tpl-create")
        self.assertEqual(tpl["status"], "pending")
        self.assertEqual(tpl["minSizeMiB"], 512)
        self.assertEqual(tpl["hasSnapshot"], False)

    def test_create_template_requires_image(self):
        client, _ = self._client(response={})
        with self.assertRaises(client_module.MicroVMError):
            client.create_template({"id": "tpl-x", "image": ""})

    def test_list_templates_normalizes_null_to_empty(self):
        client, _ = self._client(response=None)
        rows = client.list_templates()
        self.assertEqual(rows, [])

    def test_list_templates_maps_each_row(self):
        api_response = [
            {
                "id": "tpl-1",
                "image": "docker://alpine:3.19",
                "status": "ready",
                "created_at": "2026-05-27T10:00:00Z",
                "updated_at": "2026-05-27T10:05:00Z",
                "ready_at": "2026-05-27T10:04:00Z",
                "has_snapshot": True,
                "has_overlay": False,
                "push_state": "active",
            },
        ]
        client, _ = self._client(response=api_response)
        rows = client.list_templates()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], "tpl-1")
        self.assertEqual(rows[0]["status"], "ready")
        self.assertEqual(rows[0]["hasSnapshot"], True)
        self.assertEqual(rows[0]["readyAt"], "2026-05-27T10:04:00Z")
        self.assertEqual(rows[0]["pushState"], "active")

    def test_get_template_targets_per_id_path(self):
        client, captured = self._client(response={
            "id": "tpl-x",
            "image": "docker://alpine:3.19",
            "status": "ready",
            "created_at": "2026-05-27T10:00:00Z",
            "updated_at": "2026-05-27T10:00:00Z",
            "has_snapshot": True,
            "has_overlay": False,
        })
        tpl = client.get_template("tpl-x")
        self.assertEqual(captured["calls"][0], ("GET", "/v1/templates/tpl-x", None))
        self.assertEqual(tpl["id"], "tpl-x")

    def test_delete_template_sends_delete(self):
        client, captured = self._client(response=None)
        client.delete_template("tpl-x")
        self.assertEqual(captured["calls"][0], ("DELETE", "/v1/templates/tpl-x", None))

    def test_rebuild_template_posts_and_maps_unhealthy_response(self):
        api_response = {
            "id": "tpl-rebuild",
            "image": "docker://alpine:3.19",
            "status": "unhealthy",
            "created_at": "2026-05-27T10:00:00Z",
            "updated_at": "2026-05-27T10:10:00Z",
            "has_snapshot": True,
            "has_overlay": False,
        }
        client, captured = self._client(response=api_response)
        tpl = client.rebuild_template("tpl-rebuild")
        self.assertEqual(captured["calls"][0], ("POST", "/v1/templates/tpl-rebuild/rebuild", None))
        self.assertEqual(tpl["status"], "unhealthy")

    def test_rebuild_template_surfaces_412_as_http_error(self):
        client, _ = self._client(response=client_module.MicroVMHTTPError(412, "template not eligible for rebuild: current status=pending"))
        with self.assertRaises(client_module.MicroVMHTTPError) as ctx:
            client.rebuild_template("tpl-pending")
        self.assertEqual(ctx.exception.status_code, 412)
