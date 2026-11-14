"""The NeMo Gym provider: the protocol, sandbox creation, commands, files,
status, and a run through NeMo Gym's own AsyncSandbox."""

from __future__ import annotations

import asyncio
import inspect
import threading
import unittest
from unittest import mock

from microvm import MicroVMHTTPError
from nemo_gym.sandbox.api import AsyncSandbox
from nemo_gym.sandbox.providers.base import SandboxProvider, SandboxSpec, SandboxStatus
from nemo_gym.sandbox.providers.registry import create_provider, get_provider_class

from aerolvm_nemo_gym import AerolVMCreateError, AerolVMCreateVerificationError, AerolVMProvider, _owned
from aerolvm_nemo_gym._owned import CREATE_OP_TAG
from support import ProviderTestCase, assert_fake_matches_sdk


class ContractTest(unittest.TestCase):
    def test_fake_matches_sdk(self) -> None:
        assert_fake_matches_sdk(self)

    def test_every_protocol_method_matches(self) -> None:
        for name, member in vars(SandboxProvider).items():
            if name.startswith("_") or not callable(member):
                continue
            with self.subTest(name):
                want = [(p.name, p.kind) for p in inspect.signature(member).parameters.values()]
                got = [(p.name, p.kind) for p in inspect.signature(getattr(AerolVMProvider, name)).parameters.values()]
                self.assertEqual(got, want)
                self.assertTrue(inspect.iscoroutinefunction(getattr(AerolVMProvider, name)))
        self.assertEqual(AerolVMProvider.name, "aerolvm")

    def test_nemo_gym_finds_it_by_entry_point(self) -> None:
        self.assertIs(get_provider_class("aerolvm"), AerolVMProvider)


class CreateTest(ProviderTestCase):
    async def test_spec_maps_onto_create(self) -> None:
        provider = self.provider(default_image="ubuntu:24.04", create_options={"runtime": "gvisor", "tags": {"team": "rl"}})
        spec = SandboxSpec(
            image="python:3.12",
            ttl_s=90,
            workdir=str(self.work),
            env={"TASK": "1"},
            metadata={"sandbox-api": "aerolvm", "episode": "7"},
            resources={"cpu": 2, "memory_mib": 4096, "disk_gib": 20},
            entrypoint=["sleep", "infinity"],
            user="coder",
        )
        handle = await provider.create(spec)
        request = self.create_request()
        self.assertEqual(request["image"], "python:3.12")
        self.assertEqual(request["runtime"], "gvisor")
        self.assertEqual(request["env"], {"TASK": "1"})
        tags = dict(request["tags"])
        self.assertRegex(tags.pop(CREATE_OP_TAG), r"^[0-9a-f]{32}$")
        self.assertEqual(tags, {"integration": "nemo-gym", "team": "rl", "sandbox-api": "aerolvm", "episode": "7"})
        self.assertEqual((request["cpu"], request["memoryMB"], request["diskGB"]), (2, 4096, 20))
        self.assertEqual(request["containerCommand"], ["sleep", "infinity"])
        self.assertEqual(request["osUser"], "coder")
        # ttl_s is the crash-safety net: the server deletes the sandbox then.
        self.assertEqual(request["lifecycle"], {"destroyAtAge": 90_000_000_000})
        self.assertEqual(handle.provider_name, "aerolvm")
        self.assertIn(handle.sandbox_id, self.fake.sandboxes)
        self.assertTrue(self.work.is_dir())
        # It answered a probe command before create returned.
        self.assertEqual(self.exec_requests()[0]["command"], "true")

    async def test_defaults(self) -> None:
        await self.provider(default_image="ubuntu:24.04").create(SandboxSpec())
        request = self.create_request()
        self.assertEqual(request["image"], "ubuntu:24.04")
        self.assertNotIn("lifecycle", request)
        self.assertNotIn("osUser", request)
        await self.provider().create(SandboxSpec(user="root"))
        self.assertNotIn("osUser", self.create_request())
        # Each create has its own operation tag.
        ops = {call[1][0]["tags"][CREATE_OP_TAG] for call in self.fake.calls_to("create")}
        self.assertEqual(len(ops), 2)

    async def test_create_failure_is_a_create_error(self) -> None:
        self.fake.fail_next["create"] = MicroVMHTTPError(503, "no capacity")
        with self.assertRaises(AerolVMCreateError):
            await self.provider().create(SandboxSpec())

    async def test_a_sandbox_that_never_answers_is_destroyed(self) -> None:
        def never_ready(sandbox_id, request):
            self.fake._record("exec", sandbox_id, request)
            return {"stdout": "", "stderr": "agent starting", "exitCode": 1}

        self.fake.exec = never_ready
        with self.assertRaises(AerolVMCreateVerificationError):
            await self.provider(probe_deadline_s=0.6).create(SandboxSpec())
        self.assertEqual(self.fake.sandboxes, {})

    async def test_probe_retries_until_the_agent_answers(self) -> None:
        self.fake.fail_next["exec"] = MicroVMHTTPError(502, "toolbox not up yet")
        await self.provider().create(SandboxSpec())
        self.assertEqual(len(self.exec_requests()), 2)

    async def test_probe_can_be_skipped(self) -> None:
        await self.provider(probe_deadline_s=0).create(SandboxSpec())
        self.assertEqual(self.exec_requests(), [])

    async def test_unsupported_requests_are_refused_before_creating(self) -> None:
        for spec in (SandboxSpec(resources={"gpu": 1}), SandboxSpec(sidecars=[{"name": "db", "image": "postgres"}])):
            with self.subTest(spec=spec), self.assertRaises(NotImplementedError):
                await self.provider().create(spec)
        self.assertEqual(self.fake.calls_to("create"), [])

    def test_bad_settings_are_refused(self) -> None:
        with self.assertRaises(ValueError):
            self.provider(exec_timeout_s=0)


class CancelledCreateTest(ProviderTestCase):
    """Cancelling create while its request is out. The worker thread runs on
    and the server makes the sandbox, so its result must not be dropped
    before something destroys it."""

    def setUp(self) -> None:
        super().setUp()
        # Which thread destroyed each sandbox: the worker thread, when the
        # create ends after the task stopped waiting, or a release thread,
        # when the worker had already handed the sandbox over.
        self.destroyed_on: list[str] = []
        real = self.fake.destroy

        def destroy(sandbox_id, *, timeout=None):
            self.destroyed_on.append(threading.current_thread().name)
            return real(sandbox_id, timeout=timeout)

        self.fake.destroy = destroy

    async def start_held_create(self, spec: SandboxSpec | None = None):
        entered, release = self.fake.hold("create")
        task = asyncio.create_task(self.provider().create(spec or SandboxSpec()))
        self.assertTrue(await asyncio.to_thread(entered.wait, 5))
        return task, release

    async def test_cancel_during_create_destroys_the_sandbox(self) -> None:
        task, release = await self.start_held_create()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(self.fake.sandboxes, {})  # not made yet
        release.set()
        await self.eventually(lambda: self.destroyed_on)
        self.assertEqual(self.fake.sandboxes, {})
        self.assertEqual(len(self.fake.calls_to("create")), 1)
        self.assertNotEqual(self.destroyed_on, ["aerolvm-release"])
        # Nothing ran in it: no probe, no workdir.
        self.assertEqual(self.exec_requests(), [])

    async def test_cancel_as_create_returns_destroys_the_sandbox(self) -> None:
        handed = threading.Event()

        class Observed(_owned._Handoff):
            def run(self):
                try:
                    return super().run()
                finally:
                    handed.set()

        with mock.patch.object(_owned, "_Handoff", Observed):
            task, release = await self.start_held_create()
            release.set()
            # Blocks the event loop on purpose: the worker hands the sandbox
            # over, and the task is cancelled before it can take it.
            self.assertTrue(handed.wait(5))
            self.assertEqual(len(self.fake.sandboxes), 1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        await self.eventually(lambda: self.destroyed_on)
        self.assertEqual(self.fake.sandboxes, {})
        self.assertEqual(self.destroyed_on, ["aerolvm-release"])

    async def test_nemo_gym_timeout_on_start_leaves_nothing_behind(self) -> None:
        # The way it happens in a run: NeMo Gym's own AsyncSandbox, given up
        # on by a timeout while the server is still making the sandbox.
        entered, release = self.fake.hold("create")
        with self.assertRaises(TimeoutError):
            async with asyncio.timeout(0.2):
                await AsyncSandbox(self.provider(), SandboxSpec()).start()
        self.assertTrue(entered.is_set())
        release.set()
        await self.eventually(lambda: self.destroyed_on)
        self.assertEqual(self.fake.sandboxes, {})

    async def test_cancel_after_create_is_cleaned_up_by_create_itself(self) -> None:
        # Once the sandbox is made, a cancel during the probe goes through
        # create's own failure path, which destroys it before re-raising.
        entered, release = self.fake.hold("exec")
        task = asyncio.create_task(self.provider().create(SandboxSpec()))
        self.assertTrue(await asyncio.to_thread(entered.wait, 5))
        self.assertEqual(len(self.fake.sandboxes), 1)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(self.fake.sandboxes, {})
        release.set()

    async def test_a_create_whose_reply_is_lost_is_found_by_its_tag(self) -> None:
        for err in (MicroVMHTTPError(502, "bad gateway"), ConnectionResetError("reset by peer")):
            with self.subTest(err=err):
                self.fake.lose_reply("create", err)
                with self.assertLogs("aerolvm_nemo_gym._owned", level="WARNING"):
                    with self.assertRaises(AerolVMCreateError):
                        await self.provider().create(SandboxSpec())
                self.assertEqual(self.fake.sandboxes, {})
                op = self.create_request()["tags"][CREATE_OP_TAG]
                self.assertEqual(self.fake.calls_to("destroy_all")[-1][2]["tags"], {CREATE_OP_TAG: op})

    async def test_a_cancelled_create_whose_reply_is_lost_is_found_by_its_tag(self) -> None:
        self.fake.lose_reply("create", MicroVMHTTPError(504, "gateway timeout"))
        task, release = await self.start_held_create()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        release.set()
        await self.eventually(lambda: self.fake.calls_to("destroy_all") and self.destroyed_on)
        self.assertEqual(self.fake.sandboxes, {})

    async def test_a_refused_create_is_not_searched_for(self) -> None:
        for status in (400, 409, 503):
            with self.subTest(status=status):
                self.fake.fail_next["create"] = MicroVMHTTPError(status, "no")
                with self.assertRaises(AerolVMCreateError):
                    await self.provider().create(SandboxSpec())
        self.assertEqual(self.fake.calls_to("list"), [])
        self.assertEqual(self.fake.calls_to("destroy_all"), [])

    async def test_a_failed_search_is_logged_with_the_tag(self) -> None:
        self.fake.fail_next["create"] = ConnectionResetError("reset by peer")
        self.fake.fail_next["list"] = MicroVMHTTPError(502, "still down")
        with self.assertLogs("aerolvm_nemo_gym._owned", level="WARNING") as logs:
            with self.assertRaises(AerolVMCreateError):
                await self.provider().create(SandboxSpec())
        op = self.create_request()["tags"][CREATE_OP_TAG]
        self.assertIn(op, logs.output[0])
        self.assertIn("destroy_all", logs.output[0])


class ExecTest(ProviderTestCase):
    async def asyncSetUp(self) -> None:
        self.provider_ = self.provider(exec_timeout_s=30)
        self.handle = await self.provider_.create(SandboxSpec(workdir=str(self.work)))

    async def test_runs_in_the_workdir_with_env(self) -> None:
        result = await self.provider_.exec(self.handle, 'echo "$X"; pwd; echo e >&2; exit 4', env={"X": "y"})
        self.assertEqual((result.stdout, result.stderr, result.return_code), (f"y\n{self.work}\n", "e\n", 4))
        other = self.tmp / "other"
        other.mkdir()
        result = await self.provider_.exec(self.handle, "pwd", cwd=str(other))
        self.assertEqual(result.stdout.strip(), str(other))

    async def test_timeouts(self) -> None:
        for given, sent in ((None, 30), (0, 30), (2.5, 3), (0.1, 1)):
            with self.subTest(given=given):
                await self.provider_.exec(self.handle, "true", timeout_s=given)
                self.assertEqual(self.exec_requests()[-1]["timeoutSeconds"], sent)
        result = await self.provider_.exec(self.handle, "sleep 5", timeout_s=1)
        self.assertEqual((result.return_code, result.error_type), (124, "timeout"))
        self.assertIn("timed out", result.stderr)

    async def test_users(self) -> None:
        for user in (None, "root", 0):
            await self.provider_.exec(self.handle, "true", user=user)
        with self.assertRaises(NotImplementedError):
            await self.provider_.exec(self.handle, "true", user="coder")

    async def test_a_failed_request_raises(self) -> None:
        self.fake.fail_next["exec"] = MicroVMHTTPError(500, "boom")
        with self.assertRaises(MicroVMHTTPError):
            await self.provider_.exec(self.handle, "true")


class FilesAndStatusTest(ProviderTestCase):
    async def asyncSetUp(self) -> None:
        self.provider_ = self.provider()
        self.handle = await self.provider_.create(SandboxSpec())

    async def test_upload_download_round_trip(self) -> None:
        source = self.tmp / "in.bin"
        source.write_bytes(bytes(range(256)))
        await self.provider_.upload_file(self.handle, source, str(self.work / "a" / "in.bin"))
        target = self.tmp / "out" / "nested" / "copy.bin"
        await self.provider_.download_file(self.handle, str(self.work / "a" / "in.bin"), target)
        self.assertEqual(target.read_bytes(), bytes(range(256)))

    async def test_write_and_read_file(self) -> None:
        await self.provider_.write_file(self.handle, str(self.work / "t.txt"), "text")
        await self.provider_.write_file(self.handle, str(self.work / "b.bin"), b"\x00\x01")
        self.assertEqual(await self.provider_.read_file(self.handle, str(self.work / "t.txt")), b"text")
        self.assertEqual(await self.provider_.read_file(self.handle, str(self.work / "b.bin")), b"\x00\x01")

    async def test_status(self) -> None:
        sandbox = self.fake.sandboxes[self.handle.sandbox_id]
        for status, want in (("started", SandboxStatus.RUNNING), ("stopped", SandboxStatus.STOPPED),
                             ("error", SandboxStatus.ERROR), ("creating", SandboxStatus.STARTING),
                             ("awaiting_runtime", SandboxStatus.UNKNOWN)):
            with self.subTest(status):
                sandbox["status"] = status
                self.assertEqual(await self.provider_.status(self.handle), want)
        self.fake.fail_next["get"] = MicroVMHTTPError(500, "down")
        with self.assertRaises(MicroVMHTTPError):
            await self.provider_.status(self.handle)
        await self.provider_.close(self.handle)
        self.assertEqual(await self.provider_.status(self.handle), SandboxStatus.STOPPED)

    async def test_close(self) -> None:
        await self.provider_.close(self.handle)
        self.assertEqual(self.fake.sandboxes, {})
        await self.provider_.close(self.handle)  # already gone
        handle = await self.provider_.create(SandboxSpec())
        self.fake.fail_next["destroy"] = MicroVMHTTPError(500, "stuck")
        with self.assertRaises(MicroVMHTTPError):
            await self.provider_.close(handle)
        await self.provider_.aclose()


class NeMoGymAPITest(ProviderTestCase):
    async def test_async_sandbox_from_a_config_mapping(self) -> None:
        # The way NeMo Gym builds it: a one-key config naming the provider.
        spec = SandboxSpec(workdir=str(self.work), files={str(self.work / "task.txt"): "solve me"})
        async with await AsyncSandbox({"aerolvm": {"client": self.fake, "exec_timeout_s": 20}}, spec).start() as sandbox:
            self.assertEqual(sandbox.provider_name, "aerolvm")
            result = await sandbox.exec("cat task.txt && pwd")
            self.assertEqual(result.stdout, f"solve me{self.work}\n")
            sandbox_id = sandbox.sandbox_id
        self.assertNotIn(sandbox_id, self.fake.sandboxes)
        # The spec's file was written once, by NeMo Gym's upload, not twice.
        self.assertEqual(len(self.fake.calls_to("upload_file")), 1)

    def test_create_provider_passes_the_config(self) -> None:
        provider = create_provider({"aerolvm": {"client": self.fake, "default_image": "alpine:3"}})
        self.assertIsInstance(provider, AerolVMProvider)
        self.assertEqual(provider._default_image, "alpine:3")


if __name__ == "__main__":
    unittest.main()
