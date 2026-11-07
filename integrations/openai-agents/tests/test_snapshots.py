"""Saving and restoring the workspace, and resuming a saved session."""

from __future__ import annotations

import asyncio
import io
import json
import os
import shutil
import tarfile
import unittest
from pathlib import Path

from agents.sandbox import SandboxArchiveLimits
from agents.sandbox.entries import File
from agents.sandbox.errors import WorkspaceArchiveReadError, WorkspaceArchiveWriteError
from agents.sandbox.snapshot import LocalSnapshotSpec
from microvm import MicroVMHTTPError

from aerolvm_openai_agents import AerolVMSandboxSessionState
from aerolvm_openai_agents.session import STAGING_DIR, decode_snapshot_ref, encode_snapshot_ref
from support import IMAGE, ProviderTestCase


class SnapshotRefTest(unittest.TestCase):
    def test_round_trip_and_rejects(self) -> None:
        self.assertEqual(decode_snapshot_ref(encode_snapshot_ref("snap-1")), "snap-1")
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo("./a.txt")
            info.size = 1
            tar.addfile(info, io.BytesIO(b"a"))
        for raw in (buf.getvalue(), b'{"other": "x"}', b"{not json", b'{"aerolvm_snapshot": ""}',
                    b'{"aerolvm_snapshot": 3}', b"[1]", b"{" + b" " * 5000 + b"}"):
            with self.subTest(raw=raw[:20]):
                self.assertIsNone(decode_snapshot_ref(raw))


class SnapshotTestCase(ProviderTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.store = self.tmp / "snapshots"

    def spec(self) -> LocalSnapshotSpec:
        return LocalSnapshotSpec(base_path=self.store)

    def stored(self, session) -> bytes:
        return (self.store / f"{session.state.session_id}.tar").read_bytes()

    def reload(self, session) -> AerolVMSandboxSessionState:
        # Through JSON, the way a saved RunState comes back in a new process.
        payload = json.loads(json.dumps(self.client.serialize_session_state(session.state)))
        state = self.client.deserialize_session_state(payload)
        assert isinstance(state, AerolVMSandboxSessionState)
        return state

    async def run_and_save(self, **options) -> object:
        session = await self.create(snapshot=self.spec(), **options)
        async with session:
            await session.write(Path("notes/a.txt"), io.BytesIO(b"saved"))
        return session

    def lose_the_machine(self) -> None:
        # The replacement sandbox must get its files from the snapshot, not
        # from what the old one left on this host.
        shutil.rmtree(self.workspace, ignore_errors=True)


class NativeSnapshotTest(SnapshotTestCase):
    async def test_close_saves_an_aerolvm_snapshot_and_a_small_reference(self) -> None:
        session = await self.run_and_save()
        name = decode_snapshot_ref(self.stored(session))
        self.assertIsNotNone(name)
        self.assertTrue(name.startswith(f"openai-agents-{session.state.session_id.hex[:12]}-"))
        self.assertIn(name, self.fake.snapshots)
        self.assertEqual(session.state.last_snapshot, name)
        self.assertEqual(self.fake.sandboxes, {})

    async def test_resume_boots_straight_from_the_last_snapshot(self) -> None:
        session = await self.run_and_save()
        name = session.state.last_snapshot
        state = self.reload(session)
        self.lose_the_machine()
        creates_before = len(self.fake.calls_to("create"))

        resumed = await self.client.resume(state)
        async with resumed:
            data = (await resumed.read(Path("notes/a.txt"))).read()

        self.assertEqual(data, b"saved")
        creates = self.fake.calls_to("create")[creates_before:]
        # One create, from the snapshot. start() had nothing left to restore,
        # so no second sandbox was made and nothing was cleared.
        self.assertEqual([c[1][0]["image"] for c in creates], [name])

    async def test_resume_without_a_bootable_snapshot_restores_in_start(self) -> None:
        for last in (None, "missing-snapshot"):
            with self.subTest(last_snapshot=last):
                session = await self.run_and_save()
                name = session.state.last_snapshot
                state = self.reload(session)
                state.last_snapshot = last
                self.lose_the_machine()
                creates_before = len(self.fake.calls_to("create"))

                resumed = await self.client.resume(state)
                async with resumed:
                    data = (await resumed.read(Path("notes/a.txt"))).read()
                    live = set(self.fake.sandboxes)

                self.assertEqual(data, b"saved")
                images = [c[1][0]["image"] for c in self.fake.calls_to("create")[creates_before:]]
                expected = [IMAGE, name] if last is None else [last, IMAGE, name]
                self.assertEqual(images, expected)
                # The plain sandbox made first was destroyed once the
                # snapshot's replaced it.
                self.assertEqual(len(live), 1)

    async def test_ephemeral_paths_make_it_fall_back_to_tar(self) -> None:
        manifest = self.manifest(
            entries={"cache.txt": File(content=b"tmp", ephemeral=True), "keep.txt": File(content=b"keep")}
        )
        session = await self.create(snapshot=self.spec(), manifest=manifest)
        async with session:
            pass
        with tarfile.open(fileobj=io.BytesIO(self.stored(session))) as tar:
            names = tar.getnames()
        self.assertIn("./keep.txt", names)
        self.assertNotIn("./cache.txt", names)
        self.assertEqual(self.fake.calls_to("create_snapshot"), [])

    async def test_superseded_snapshots_are_kept_unless_asked(self) -> None:
        for delete in (False, True):
            with self.subTest(delete_superseded_snapshots=delete):
                session = await self.create(
                    snapshot=self.spec(), on_shutdown="keep", delete_superseded_snapshots=delete
                )
                await session.start()
                await session.stop()
                first = session.state.last_snapshot
                await session.stop()
                second = session.state.last_snapshot
                self.assertNotEqual(first, second)
                self.assertIn(second, self.fake.snapshots)
                self.assertEqual(first in self.fake.snapshots, not delete)

    async def test_snapshot_the_store_did_not_keep_is_deleted(self) -> None:
        # A file where the store wants a folder makes its persist fail after
        # the AerolVM snapshot was made.
        self.store.parent.mkdir(parents=True, exist_ok=True)
        self.store.write_text("not a folder")
        session = await self.create(snapshot=self.spec(), on_shutdown="keep")
        await session.start()
        with self.assertRaises(Exception):
            await session.stop()
        (made,) = self.fake.calls_to("create_snapshot")
        self.assertEqual(self.fake.calls_to("delete_snapshot")[-1][1][0], made[1][1])
        self.assertEqual(self.fake.snapshots, {})
        self.assertIsNone(session.state.last_snapshot)

    async def test_a_cancelled_save_deletes_its_snapshot(self) -> None:
        # The snapshot's reference never reaches the store, so nothing could
        # find the snapshot again: it is deleted once the server has made it.
        session = await self.create(snapshot=self.spec(), on_shutdown="keep")
        await session.start()
        entered, release = self.fake.hold("create_snapshot")
        task = asyncio.create_task(session.stop())
        self.assertTrue(await asyncio.to_thread(entered.wait, 5))
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        release.set()
        await self.eventually(lambda: self.fake.calls_to("delete_snapshot"))
        (made,) = self.fake.calls_to("create_snapshot")
        self.assertEqual(self.fake.calls_to("delete_snapshot")[0][1][0], made[1][1])
        self.assertEqual(self.fake.snapshots, {})
        self.assertIsNone(session.state.last_snapshot)

    async def test_snapshot_failure_is_an_archive_read_error(self) -> None:
        session = await self.create(snapshot=self.spec(), on_shutdown="keep")
        await session.start()
        self.fake.fail_next["create_snapshot"] = MicroVMHTTPError(503, "busy")
        with self.assertRaises(WorkspaceArchiveReadError) as caught:
            await session.stop()
        self.assertTrue(caught.exception.retryable)
        self.assertEqual(caught.exception.context["reason"], "snapshot_failed")

    async def test_failed_restore_keeps_the_old_sandbox(self) -> None:
        session = await self.create(on_shutdown="keep")
        await session.start()
        old_id = session.state.sandbox_id
        self.fake.fail_next["create"] = MicroVMHTTPError(500, "no capacity")
        with self.assertRaises(WorkspaceArchiveWriteError):
            await session.hydrate_workspace(io.BytesIO(encode_snapshot_ref("whatever")))
        self.assertEqual(session.state.sandbox_id, old_id)
        self.assertIn(old_id, self.fake.sandboxes)
        self.assertTrue((await session.exec("true")).ok())

    async def test_restore_survives_an_old_sandbox_that_will_not_die(self) -> None:
        session = await self.run_and_save(on_shutdown="keep")
        name = session.state.last_snapshot
        old_id = session.state.sandbox_id
        self.fake.fail_next["destroy"] = MicroVMHTTPError(500, "stuck")
        with self.assertLogs("aerolvm_openai_agents.session", level="WARNING"):
            await session.hydrate_workspace(io.BytesIO(encode_snapshot_ref(name)))
        self.assertNotEqual(session.state.sandbox_id, old_id)
        self.assertEqual((await session.read(Path("notes/a.txt"))).read(), b"saved")


class TarPersistenceTest(SnapshotTestCase):
    async def test_tar_round_trip_through_a_new_sandbox(self) -> None:
        session = await self.run_and_save(workspace_persistence="tar")
        with tarfile.open(fileobj=io.BytesIO(self.stored(session))) as tar:
            self.assertIn("./notes/a.txt", tar.getnames())
        self.assertEqual(self.fake.calls_to("create_snapshot"), [])
        self.assertIsNone(session.state.last_snapshot)
        # The staged archive was cleaned up.
        staged = [c[1][1] for c in self.fake.calls_to("download_file")]
        self.assertTrue(staged and all(p.startswith(STAGING_DIR) and not os.path.exists(p) for p in staged))

        state = self.reload(session)
        self.lose_the_machine()
        resumed = await self.client.resume(state)
        async with resumed:
            data = (await resumed.read(Path("notes/a.txt"))).read()
        self.assertEqual(data, b"saved")
        self.assertEqual(self.fake.calls_to("create")[-1][1][0]["image"], IMAGE)

    async def test_archive_over_the_limit_is_refused_before_download(self) -> None:
        session = await self.create(snapshot=self.spec(), workspace_persistence="tar", on_shutdown="keep")
        await session.start()
        await session.write(Path("big.bin"), io.BytesIO(b"x" * 50_000))
        session._inner._set_archive_limits(SandboxArchiveLimits(max_input_bytes=1_000))
        with self.assertRaises(WorkspaceArchiveReadError) as caught:
            await session.stop()
        self.assertEqual(caught.exception.context["reason"], "archive size exceeds limit")

    async def test_failed_tar_is_reported(self) -> None:
        session = await self.create(snapshot=self.spec(), workspace_persistence="tar", on_shutdown="keep")
        await session.start()
        real_exec = self.fake.exec

        def tar_fails(sandbox_id, request):
            if (request.get("argv") or [""])[0] == "tar":
                return {"stdout": "", "stderr": "tar: disk full", "exitCode": 2}
            return real_exec(sandbox_id, request)

        self.fake.exec = tar_fails
        with self.assertRaises(WorkspaceArchiveReadError) as caught:
            await session.stop()
        self.assertEqual(caught.exception.context["reason"], "tar_failed")
        self.assertIn("disk full", caught.exception.context["stderr"])

    def small_tar(self, name: str = "./a.txt", size: int = 1) -> bytes:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name)
            info.size = size
            tar.addfile(info, io.BytesIO(b"x" * size))
        return buf.getvalue()

    async def test_failed_untar_is_reported_and_staging_removed(self) -> None:
        session = await self.create(on_shutdown="keep")
        await session.start()
        real_exec = self.fake.exec

        def tar_fails(sandbox_id, request):
            if (request.get("argv") or [""])[0] == "tar":
                return {"stdout": "", "stderr": "tar: no space", "exitCode": 2}
            return real_exec(sandbox_id, request)

        self.fake.exec = tar_fails
        with self.assertRaises(WorkspaceArchiveWriteError) as caught:
            await session.hydrate_workspace(io.BytesIO(self.small_tar()))
        self.assertEqual(caught.exception.context["reason"], "untar_failed")
        staged = self.fake.calls_to("upload_file")[-1][1][1]
        self.assertFalse(os.path.exists(staged))

    async def test_restore_input_over_the_limit_is_refused_while_reading(self) -> None:
        session = await self.create(on_shutdown="keep")
        await session.start()
        session._inner._set_archive_limits(SandboxArchiveLimits(max_input_bytes=100))
        with self.assertRaises(WorkspaceArchiveWriteError) as caught:
            await session.hydrate_workspace(io.BytesIO(self.small_tar(size=10_000)))
        self.assertEqual(caught.exception.context["reason"], "archive input size exceeds limit")
        self.assertEqual(self.fake.calls_to("upload_file"), [])

    async def test_unsafe_archive_is_refused(self) -> None:
        session = await self.create(on_shutdown="keep")
        await session.start()
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo("../escape.txt")
            info.size = 1
            tar.addfile(info, io.BytesIO(b"x"))
        with self.assertRaises(WorkspaceArchiveWriteError) as caught:
            await session.hydrate_workspace(io.BytesIO(buf.getvalue()))
        self.assertEqual(caught.exception.context["reason"], "unsafe_or_invalid_tar")
        self.assertFalse((self.tmp / "escape.txt").exists())
        self.assertEqual(self.fake.calls_to("upload_file"), [])


class ResumeTest(SnapshotTestCase):
    async def test_stopped_sandbox_is_started_and_reused(self) -> None:
        session = await self.run_and_save(on_shutdown="stop")
        sandbox_id = session.state.sandbox_id
        self.assertEqual(self.fake.sandboxes[sandbox_id]["status"], "stopped")
        creates_before = len(self.fake.calls_to("create"))

        resumed = await self.client.resume(self.reload(session))
        async with resumed:
            data = (await resumed.read(Path("notes/a.txt"))).read()
        self.assertEqual(data, b"saved")
        self.assertEqual(resumed.state.sandbox_id, sandbox_id)
        self.assertEqual(self.fake.calls_to("start")[-1][1][0], sandbox_id)
        self.assertEqual(len(self.fake.calls_to("create")), creates_before)

    async def test_kept_sandbox_is_reattached(self) -> None:
        session = await self.run_and_save(on_shutdown="keep")
        resumed = await self.client.resume(self.reload(session))
        self.assertEqual(resumed.state.sandbox_id, session.state.sandbox_id)
        self.assertEqual(self.fake.calls_to("start"), [])

    async def test_unexpected_lookup_failure_is_not_a_reason_to_replace(self) -> None:
        session = await self.run_and_save(on_shutdown="keep")
        creates_before = len(self.fake.calls_to("create"))
        self.fake.fail_next["get"] = MicroVMHTTPError(503, "down")
        with self.assertRaises(MicroVMHTTPError):
            await self.client.resume(self.reload(session))
        self.assertEqual(len(self.fake.calls_to("create")), creates_before)

    async def test_a_cancelled_resume_destroys_the_replacement(self) -> None:
        session = await self.run_and_save()
        state = self.reload(session)
        self.assertEqual(self.fake.sandboxes, {})
        entered, release = self.fake.hold("create")
        task = asyncio.create_task(self.client.resume(state))
        self.assertTrue(await asyncio.to_thread(entered.wait, 5))
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        release.set()
        await self.eventually(lambda: len(self.fake.calls_to("destroy")) == 2)
        self.assertEqual(self.fake.sandboxes, {})

    async def test_a_cancelled_restore_destroys_the_new_sandbox_and_keeps_the_old(self) -> None:
        session = await self.run_and_save(on_shutdown="keep")
        name = session.state.last_snapshot
        old_id = session.state.sandbox_id
        entered, release = self.fake.hold("create")
        task = asyncio.create_task(session.hydrate_workspace(io.BytesIO(encode_snapshot_ref(name))))
        self.assertTrue(await asyncio.to_thread(entered.wait, 5))
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        release.set()
        await self.eventually(lambda: self.fake.calls_to("destroy"))
        self.assertEqual(list(self.fake.sandboxes), [old_id])
        self.assertEqual(session.state.sandbox_id, old_id)

    async def test_failed_sandbox_is_destroyed_and_replaced(self) -> None:
        session = await self.run_and_save(on_shutdown="keep")
        old_id = session.state.sandbox_id
        self.fake.sandboxes[old_id]["status"] = "error"
        resumed = await self.client.resume(self.reload(session))
        self.assertNotEqual(resumed.state.sandbox_id, old_id)
        self.assertNotIn(old_id, self.fake.sandboxes)

    async def test_snapshot_boot_failure_that_may_have_made_a_sandbox_is_raised(self) -> None:
        session = await self.run_and_save()
        state = self.reload(session)
        self.fake.fail_next["create"] = MicroVMHTTPError(504, "gateway timeout")
        with self.assertRaises(MicroVMHTTPError):
            await self.client.resume(state)
        # No second create from the image, which could leave two sandboxes.
        self.assertEqual(self.fake.calls_to("create")[-1][1][0]["image"], session.state.last_snapshot)
        # The one it may have made was searched for by its tag.
        self.assertEqual(len(self.fake.calls_to("destroy_all")), 1)

    async def test_resume_refuses_foreign_state(self) -> None:
        with self.assertRaises(TypeError):
            await self.client.resume(object())  # type: ignore[arg-type]

    async def test_state_from_an_earlier_version_still_loads(self) -> None:
        session = await self.create()
        payload = json.loads(json.dumps(self.client.serialize_session_state(session.state)))
        for key in ("last_snapshot", "on_shutdown", "max_output_bytes", "create_options", "workspace_persistence"):
            payload.pop(key)
        state = self.client.deserialize_session_state(payload)
        self.assertEqual(state.on_shutdown, "destroy")
        self.assertEqual(state.workspace_persistence, "snapshot")


if __name__ == "__main__":
    unittest.main()
