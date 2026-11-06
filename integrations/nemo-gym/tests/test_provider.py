"""The NeMo Gym provider: the protocol, sandbox creation, commands, files,
status, and a run through NeMo Gym's own AsyncSandbox."""

from __future__ import annotations

import inspect
import unittest

from microvm import MicroVMHTTPError
from nemo_gym.sandbox.api import AsyncSandbox
from nemo_gym.sandbox.providers.base import SandboxProvider, SandboxSpec, SandboxStatus
from nemo_gym.sandbox.providers.registry import create_provider, get_provider_class

from aerolvm_nemo_gym import AerolVMCreateError, AerolVMCreateVerificationError, AerolVMProvider
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
        self.assertEqual(request["tags"], {"integration": "nemo-gym", "team": "rl", "sandbox-api": "aerolvm", "episode": "7"})
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
