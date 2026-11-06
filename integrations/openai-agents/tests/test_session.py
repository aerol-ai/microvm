"""Commands, files, listings and ports, through the real SDK session."""

from __future__ import annotations

import io
import os
import unittest
from pathlib import Path

from agents.sandbox.errors import (
    ExecTimeoutError,
    ExecTransportError,
    ExposedPortUnavailableError,
    WorkspaceReadNotFoundError,
)
from agents.sandbox.files import EntryKind
from agents.sandbox.manifest import Environment
from microvm import MicroVMHTTPError

from aerolvm_openai_agents import AerolVMSandboxClient, DEFAULT_EXEC_TIMEOUT_S
from support import IMAGE, ProviderTestCase, assert_fake_matches_sdk


class FakeMatchesSDKTest(unittest.TestCase):
    def test_fake_matches_sdk(self) -> None:
        # The provider is tested against the fake, so the fake must take
        # exactly the arguments the real client takes.
        assert_fake_matches_sdk(self)


class ExecTest(ProviderTestCase):
    async def test_commands_run_in_the_workspace_with_argv(self) -> None:
        session = await self.create()
        async with session:
            result = await session.exec("pwd")
            self.assertTrue(result.ok())
            self.assertEqual(result.stdout.decode().strip(), str(self.workspace))
            # Words with spaces and quotes reach the program unchanged.
            result = await session.exec("printf", "%s|", "a b", "it's", shell=False)
            self.assertEqual(result.stdout, b"a b|it's|")

        request = self.exec_requests()[-1]
        self.assertEqual(request["argv"], ["printf", "%s|", "a b", "it's"])
        self.assertNotIn("command", request)
        self.assertEqual(request["workDir"], str(self.workspace))
        # The agent set no timeout, so the provider's default goes out.
        self.assertEqual(request["timeoutSeconds"], int(DEFAULT_EXEC_TIMEOUT_S))

    async def test_create_sends_image_options_and_integration_tag(self) -> None:
        await self.create(create_options={"cpu": 0.5, "tags": {"team": "ml"}})
        (call,) = self.fake.calls_to("create")
        request = call[1][0]
        self.assertEqual(request["image"], IMAGE)
        self.assertEqual(request["cpu"], 0.5)
        self.assertEqual(request["tags"], {"integration": "openai-agents", "team": "ml"})

    async def test_manifest_environment_reaches_every_command(self) -> None:
        session = await self.create(manifest=self.manifest(environment=Environment(value={"GREETING": "hello"})))
        async with session:
            result = await session.exec("echo $GREETING")
        self.assertEqual(result.stdout.strip(), b"hello")

    async def test_older_agent_without_argv_gets_one_command_line(self) -> None:
        self.fake.features.discard("exec.argv")
        session = await self.create()
        async with session:
            result = await session.exec("printf", "%s|", "a b", "it's", shell=False)
            self.assertEqual(result.stdout, b"a b|it's|")
            before = len(self.exec_requests())
            await session.exec("true", shell=False)
        # Once refused, argv is not tried again for this sandbox.
        self.assertEqual(len(self.exec_requests()), before + 1)
        self.assertEqual(self.exec_requests()[-1]["command"], "true")

    async def test_timeout_is_an_exec_timeout_error(self) -> None:
        session = await self.create()
        async with session:
            with self.assertRaises(ExecTimeoutError) as caught:
                await session.exec("sleep", "5", shell=False, timeout=0.2)
        self.assertEqual(caught.exception.timeout_s, 0.2)
        # toolboxd counts whole seconds; a fraction rounds up, never to 0
        # (which would mean its 5 minute default).
        self.assertEqual(self.exec_requests()[-1]["timeoutSeconds"], 1)

    async def test_output_cap_is_sent_and_honoured(self) -> None:
        session = await self.create(max_output_bytes=4)
        async with session:
            result = await session.exec("printf", "abcdefgh", shell=False)
        self.assertEqual(result.stdout, b"abcd")
        self.assertEqual(self.exec_requests()[-1]["maxStdoutBytes"], 4)
        self.assertEqual(self.exec_requests()[-1]["maxStderrBytes"], 4)

    async def test_output_cap_on_an_older_agent_fails_closed(self) -> None:
        session = await self.create()
        async with session:
            # Turn the feature off after start, so start() itself still works.
            self.fake.features.discard("exec.max_output_bytes")
            session._inner.state.max_output_bytes = 4
            with self.assertRaises(ExecTransportError) as caught:
                await session.exec("echo", "hi", shell=False)
        self.assertIn("exec.max_output_bytes", str(caught.exception.cause))

    async def test_transport_errors_say_whether_a_retry_is_safe(self) -> None:
        session = await self.create()
        cases = [(503, True), (429, True), (502, None), (504, None), (400, False)]
        async with session:
            for status, retryable in cases:
                with self.subTest(status=status):
                    self.fake.fail_next["exec"] = MicroVMHTTPError(status, "boom")
                    with self.assertRaises(ExecTransportError) as caught:
                        await session.exec("true", shell=False)
                    self.assertIs(caught.exception.retryable, retryable)

    async def test_running_follows_the_sandbox_status(self) -> None:
        session = await self.create(on_shutdown="keep")
        sandbox_id = session.state.sandbox_id
        self.assertTrue(await session.running())
        self.fake.stop(sandbox_id)
        self.assertFalse(await session.running())
        self.fake.fail_next["get"] = MicroVMHTTPError(500, "down")
        self.assertFalse(await session.running())


class FilesTest(ProviderTestCase):
    async def test_binary_round_trip_through_the_file_channel(self) -> None:
        payload = bytes(range(256)) * 4
        session = await self.create()
        async with session:
            await session.write(Path("data/blob.bin"), io.BytesIO(payload))
            read = await session.read(Path("data/blob.bin"))
            self.assertEqual(read.read(), payload)
        self.assertEqual((self.workspace / "data" / "blob.bin").read_bytes(), payload)
        upload = self.fake.calls_to("upload_file")[-1]
        # An absolute path reaches the sandbox, not one relative to its cwd.
        self.assertEqual(upload[1][1], str(self.workspace / "data" / "blob.bin"))

    async def test_missing_file_is_not_found(self) -> None:
        session = await self.create()
        async with session:
            with self.assertRaises(WorkspaceReadNotFoundError):
                await session.read(Path("nope.txt"))

    async def test_bounded_read_stops_at_the_limit(self) -> None:
        session = await self.create()
        async with session:
            await session.write(Path("big.txt"), io.BytesIO(b"x" * 100))
            prefix = await session.read_bounded(Path("big.txt"), max_bytes=10)
            whole = await session.read_bounded(Path("big.txt"), max_bytes=1000)
            with self.assertRaises(WorkspaceReadNotFoundError):
                await session.read_bounded(Path("nope.txt"), max_bytes=10)
        self.assertEqual(prefix, b"x" * 10)
        self.assertEqual(whole, b"x" * 100)

    async def test_ls_uses_the_structured_listing(self) -> None:
        session = await self.create()
        async with session:
            await session.write(Path("a.txt"), io.BytesIO(b"hello"))
            await session.mkdir(Path("sub"))
            os.chmod(self.workspace / "a.txt", 0o640)
            os.symlink("a.txt", self.workspace / "link")
            before = len(self.exec_requests())
            entries = {Path(e.path).name: e for e in await session.ls(Path("."))}
            # The path check runs one helper command; the listing itself none.
            listing_execs = [r for r in self.exec_requests()[before:] if (r.get("argv") or [""])[0] == "ls"]
        self.assertEqual(listing_execs, [])
        self.assertEqual(entries["a.txt"].kind, EntryKind.FILE)
        self.assertEqual(entries["a.txt"].size, 5)
        self.assertEqual(entries["a.txt"].permissions.to_mode() & 0o777, 0o640)
        self.assertEqual(entries["sub"].kind, EntryKind.DIRECTORY)
        self.assertTrue(entries["sub"].is_dir())
        self.assertEqual(entries["link"].kind, EntryKind.SYMLINK)
        self.assertEqual(entries["a.txt"].path, str(self.workspace / "a.txt"))

    async def _ls_names_after(self, breaker) -> list[str]:
        session = await self.create()
        async with session:
            await session.write(Path("a.txt"), io.BytesIO(b"hello"))
            breaker()
            return sorted(Path(e.path).name for e in await session.ls(Path(".")))

    async def test_ls_on_an_older_agent_falls_back_to_the_sdk(self) -> None:
        names = await self._ls_names_after(lambda: self.fake.features.discard("files.verbs"))
        self.assertEqual(names, ["a.txt"])

    async def test_truncated_listing_falls_back_to_the_sdk(self) -> None:
        def truncate() -> None:
            self.fake.list_files = lambda *a, **k: {"entries": [], "truncated": True}

        self.assertEqual(await self._ls_names_after(truncate), ["a.txt"])


class ExposedPortTest(ProviderTestCase):
    async def test_configured_port_resolves_to_its_public_url(self) -> None:
        session = await self.create(exposed_ports=(8080,))
        endpoint = await session.resolve_exposed_port(8080)
        self.assertEqual((endpoint.host, endpoint.port, endpoint.tls), (f"{session.state.sandbox_id}-8080.sandbox.test", 443, True))
        self.assertEqual(self.fake.calls_to("expose_port")[-1][1][1], 8080)

    async def test_unconfigured_port_is_refused_without_exposing_it(self) -> None:
        session = await self.create(exposed_ports=(8080,))
        with self.assertRaises(ExposedPortUnavailableError) as caught:
            await session.resolve_exposed_port(9090)
        self.assertEqual(caught.exception.context["reason"], "not_configured")
        self.assertEqual(self.fake.calls_to("expose_port"), [])

    async def test_expose_failure_is_backend_unavailable(self) -> None:
        session = await self.create(exposed_ports=(8080,))
        self.fake.fail_next["expose_port"] = MicroVMHTTPError(503, "busy")
        with self.assertRaises(ExposedPortUnavailableError) as caught:
            await session.resolve_exposed_port(8080)
        self.assertEqual(caught.exception.context["reason"], "backend_unavailable")
        self.assertTrue(caught.exception.retryable)


class LifecycleTest(ProviderTestCase):
    async def test_close_destroys_the_sandbox_by_default(self) -> None:
        session = await self.create()
        sandbox_id = session.state.sandbox_id
        async with session:
            pass
        self.assertNotIn(sandbox_id, self.fake.sandboxes)
        # delete() after a clean shutdown has nothing left to do.
        await self.client.delete(session)
        self.assertEqual(len(self.fake.calls_to("destroy")), 1)

    async def test_delete_destroys_a_session_that_was_never_closed(self) -> None:
        session = await self.create()
        await self.client.delete(session)
        self.assertEqual(self.fake.sandboxes, {})
        # Already gone is fine.
        await self.client.delete(session)

    async def test_stop_and_keep_leave_the_sandbox(self) -> None:
        for action, status in (("stop", "stopped"), ("keep", "started")):
            with self.subTest(action):
                session = await self.create(on_shutdown=action)
                async with session:
                    pass
                await self.client.delete(session)
                self.assertEqual(self.fake.sandboxes[session.state.sandbox_id]["status"], status)

    async def test_destroy_failure_is_raised_not_swallowed(self) -> None:
        session = await self.create()
        await session.start()
        self.fake.fail_next["destroy"] = MicroVMHTTPError(500, "disk on fire")
        with self.assertRaises(MicroVMHTTPError):
            await session.aclose()
        # delete() gets a second chance at it.
        await self.client.delete(session)
        self.assertEqual(self.fake.sandboxes, {})

    async def test_shutdown_of_a_vanished_sandbox_is_quiet(self) -> None:
        for action in ("destroy", "stop"):
            with self.subTest(action):
                session = await self.create(on_shutdown=action)
                await session.start()
                self.fake.destroy(session.state.sandbox_id)
                await session.aclose()

    async def test_delete_refuses_foreign_sessions(self) -> None:
        with self.assertRaises(TypeError):
            await self.client.delete(object())  # type: ignore[arg-type]

    async def test_start_failure_on_the_workspace_root_is_a_start_error(self) -> None:
        from agents.sandbox.errors import WorkspaceStartError

        session = await self.create()
        self.fake.fail_next["make_dir"] = MicroVMHTTPError(403, "read-only disk")
        with self.assertRaises(WorkspaceStartError) as caught:
            await session.start()
        self.assertFalse(caught.exception.retryable)

    def test_snapshot_prefix_must_work_as_an_image_name(self) -> None:
        from pydantic import ValidationError

        self.assertEqual(self.options(snapshot_name_prefix="team-a1").snapshot_name_prefix, "team-a1")
        for bad in ("Team", "a/b", "-x", ""):
            with self.subTest(bad), self.assertRaises(ValidationError):
                self.options(snapshot_name_prefix=bad)

    def test_default_client_reads_the_environment(self) -> None:
        old = {k: os.environ.get(k) for k in ("SB_API_URL", "SB_PAT_TOKEN")}
        os.environ.update({"SB_API_URL": "https://aerolvm.example", "SB_PAT_TOKEN": "pat"})
        try:
            client = AerolVMSandboxClient()
        finally:
            for key, value in old.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        self.assertEqual(client.client.api_url, "https://aerolvm.example")


if __name__ == "__main__":
    unittest.main()
