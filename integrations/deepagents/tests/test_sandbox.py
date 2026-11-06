"""The DeepAgents backend: commands, file transfer, listing, delete, and the
BaseSandbox tools (read, write, edit, grep, glob) running through it."""

from __future__ import annotations

import asyncio
import os
import unittest

from deepagents.backends.protocol import FILE_NOT_FOUND, INVALID_PATH, IS_DIRECTORY, PERMISSION_DENIED
from microvm import MicroVMHTTPError

from aerolvm_deepagents import DEFAULT_TIMEOUT_S, AerolVMSandbox
from support import IMAGE, BackendTestCase, assert_fake_matches_sdk


class FakeMatchesSDKTest(unittest.TestCase):
    def test_fake_matches_sdk(self) -> None:
        assert_fake_matches_sdk(self)


class ExecuteTest(BackendTestCase):
    def test_commands_run_in_the_root_dir_made_once(self) -> None:
        backend = self.backend()
        self.assertEqual(backend.execute("pwd").output.strip(), str(self.root))
        backend.execute("true")
        self.assertEqual(len(self.fake.calls_to("make_dir")), 1)
        request = self.exec_requests()[-1]
        self.assertEqual(request["workDir"], str(self.root))
        self.assertEqual(request["timeoutSeconds"], DEFAULT_TIMEOUT_S)
        self.assertNotIn("maxStdoutBytes", request)

    def test_output_layout_matches_the_local_shell_backend(self) -> None:
        backend = self.backend()
        cases = [
            ("echo out", "out\n", 0),
            ("echo out; echo bad >&2; exit 3", "out\n\n[stderr] bad\n\nExit code: 3", 3),
            ("true", "<no output>", 0),
        ]
        for command, output, code in cases:
            with self.subTest(command):
                result = backend.execute(command)
                self.assertEqual((result.output, result.exit_code, result.truncated), (output, code, False))

    def test_timeouts(self) -> None:
        backend = self.backend(default_timeout=7)
        backend.execute("true", timeout=0)
        self.assertEqual(self.exec_requests()[-1]["timeoutSeconds"], 7)
        backend.execute("true", timeout=42)
        self.assertEqual(self.exec_requests()[-1]["timeoutSeconds"], 42)
        result = backend.execute("sleep 5", timeout=1)
        self.assertEqual(result.exit_code, 124)
        self.assertIn("timed out after 1 seconds", result.output)

    def test_output_cap_marks_the_result_truncated(self) -> None:
        backend = self.backend(max_output_bytes=3)
        result = backend.execute("printf abcdef")
        self.assertTrue(result.truncated)
        self.assertTrue(result.output.startswith("abc\n"))
        self.assertEqual(self.exec_requests()[-1]["maxStdoutBytes"], 3)

    def test_empty_command_is_refused_without_a_call(self) -> None:
        backend = self.backend()
        self.assertEqual(backend.execute("  ").exit_code, 1)
        self.assertEqual(self.exec_requests(), [])

    def test_failed_request_raises(self) -> None:
        backend = self.backend()
        self.fake.fail_next["exec"] = MicroVMHTTPError(502, "bad gateway")
        with self.assertRaises(MicroVMHTTPError):
            backend.execute("echo hi")

    def test_async_execute(self) -> None:
        backend = self.backend()
        result = asyncio.run(backend.aexecute("echo async", timeout=5))
        self.assertEqual(result.output, "async\n")

    def test_bad_settings_are_refused(self) -> None:
        sandbox = self.fake.create(image=IMAGE)
        with self.assertRaises(ValueError):
            AerolVMSandbox(sandbox, root_dir="workspace")
        with self.assertRaises(ValueError):
            AerolVMSandbox(sandbox, default_timeout=0)


class FileTransferTest(BackendTestCase):
    def test_binary_round_trip_and_relative_paths(self) -> None:
        backend = self.backend()
        payload = bytes(range(256))
        responses = backend.upload_files([(str(self.root / "a" / "blob.bin"), payload), ("rel.txt", b"relative")])
        self.assertEqual([r.error for r in responses], [None, None])
        self.assertEqual((self.root / "rel.txt").read_bytes(), b"relative")
        downloads = backend.download_files([str(self.root / "a" / "blob.bin"), "rel.txt"])
        self.assertEqual([d.content for d in downloads], [payload, b"relative"])
        self.assertEqual(downloads[1].path, "rel.txt")

    def test_errors_are_mapped_per_file(self) -> None:
        backend = self.backend()
        backend.upload_files([("ok.txt", b"ok")])
        (self.root / "folder").mkdir()
        downloads = backend.download_files(["ok.txt", "missing.txt", "folder", ""])
        self.assertEqual(
            [(d.content, d.error) for d in downloads],
            [(b"ok", None), (None, FILE_NOT_FOUND), (None, IS_DIRECTORY), (None, INVALID_PATH)],
        )
        uploads = backend.upload_files([("folder", b"x"), ("ok2.txt", b"y")])
        self.assertEqual([u.error for u in uploads], [IS_DIRECTORY, None])

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root reads every file")
    def test_permission_denied_is_mapped(self) -> None:
        backend = self.backend()
        backend.upload_files([("secret.txt", b"x")])
        os.chmod(self.root / "secret.txt", 0)
        try:
            (download,) = backend.download_files(["secret.txt"])
        finally:
            os.chmod(self.root / "secret.txt", 0o600)
        self.assertEqual(download.error, PERMISSION_DENIED)
        self.fake.fail_next["upload_file"] = MicroVMHTTPError(403, "open x: permission denied")
        self.assertEqual(backend.upload_files([("x", b"x")])[0].error, PERMISSION_DENIED)

    def test_other_failures_keep_their_message(self) -> None:
        backend = self.backend()
        self.fake.fail_next["upload_file"] = MicroVMHTTPError(507, "sandbox disk is full")
        self.assertEqual(backend.upload_files([("x", b"x")])[0].error, "sandbox disk is full")


class ListAndDeleteTest(BackendTestCase):
    def test_ls_uses_the_structured_listing(self) -> None:
        backend = self.backend()
        backend.upload_files([("a.txt", b"hello"), ("sub/b.txt", b"x")])
        before = len(self.exec_requests())
        result = backend.ls(str(self.root))
        self.assertIsNone(result.error)
        entries = {e["path"]: e for e in result.entries}
        self.assertEqual(entries[str(self.root / "a.txt")]["size"], 5)
        self.assertFalse(entries[str(self.root / "a.txt")]["is_dir"])
        self.assertTrue(entries[str(self.root / "sub")]["is_dir"])
        self.assertIn("modified_at", entries[str(self.root / "a.txt")])
        # No Python script ran in the sandbox.
        self.assertEqual(len(self.exec_requests()), before)

    def test_ls_errors_use_base_sandbox_words(self) -> None:
        backend = self.backend()
        self.assertEqual(backend.ls("nope").error, "Path 'nope': path_not_found")
        self.fake.fail_next["list_files"] = MicroVMHTTPError(409, "not a folder")
        self.assertEqual(backend.ls("x").error, "Path 'x': not_a_directory")
        self.fake.fail_next["list_files"] = MicroVMHTTPError(403, "denied")
        self.assertEqual(backend.ls("x").error, "Path 'x': permission_denied")
        self.assertEqual(backend.ls("").error, "Path '': invalid_path")

    def test_ls_falls_back_to_base_sandbox(self) -> None:
        backend = self.backend()
        backend.upload_files([("a.txt", b"hello")])
        expected = [str(self.root / "a.txt")]
        for label, breaker in (
            ("older agent", lambda: self.fake.features.discard("files.verbs")),
            ("truncated", lambda: setattr(self.fake, "list_files", lambda *a, **k: {"entries": [], "truncated": True})),
        ):
            with self.subTest(label):
                breaker()
                result = backend.ls(str(self.root))
                self.assertEqual([e["path"] for e in result.entries], expected)

    def test_async_ls(self) -> None:
        backend = self.backend()
        backend.upload_files([("a.txt", b"hello")])
        result = asyncio.run(backend.als(str(self.root)))
        self.assertEqual([e["path"] for e in result.entries], [str(self.root / "a.txt")])

    def test_delete_files_and_folders(self) -> None:
        backend = self.backend()
        backend.upload_files([("a.txt", b"x"), ("dir/b.txt", b"y")])
        self.assertEqual(backend.delete("a.txt").path, "a.txt")
        self.assertEqual(backend.delete(str(self.root / "dir")).path, str(self.root / "dir"))
        self.assertFalse((self.root / "dir").exists())
        self.assertEqual(backend.delete("a.txt").error, "Error: 'a.txt' not found")
        self.assertIn("not a valid path", backend.delete("").error)
        self.fake.fail_next["delete_file"] = MicroVMHTTPError(403, "denied")
        backend.upload_files([("c.txt", b"x")])
        self.assertIn("denied", backend.delete("c.txt").error)


class BaseSandboxToolsTest(BackendTestCase):
    """DeepAgents' own file tools, running their scripts through execute."""

    def test_write_read_edit_grep_glob(self) -> None:
        backend = self.backend()
        path = str(self.root / "src" / "app.py")
        before = len(self.exec_requests())
        self.assertIsNone(backend.write(path, "print('hello')\n").error)
        # write() made the folder through the upload, with no script.
        self.assertEqual(len(self.exec_requests()), before)

        read = backend.read(path)
        self.assertIsNone(read.error)
        self.assertIn("print('hello')", str(read.file_data["content"]))

        self.assertIsNone(backend.edit(path, "hello", "world").error)
        self.assertEqual((self.root / "src" / "app.py").read_text(), "print('world')\n")

        grep = backend.grep("world", str(self.root))
        self.assertEqual([m["path"] for m in grep.matches], [path])
        glob = backend.glob("**/*.py", str(self.root))
        self.assertEqual([m["path"] for m in glob.matches], [path])

    def test_async_write_and_read(self) -> None:
        backend = self.backend()
        path = str(self.root / "notes.txt")

        async def run():
            await backend.awrite(path, "async note")
            return await backend.aread(path)

        self.assertIn("async note", str(asyncio.run(run()).file_data["content"]))


class LifecycleTest(BackendTestCase):
    def test_create_tags_and_close_destroys(self) -> None:
        backend = self.backend(cpu=1)
        (call,) = self.fake.calls_to("create")
        self.assertEqual(call[1][0]["image"], IMAGE)
        self.assertEqual(call[1][0]["cpu"], 1)
        self.assertEqual(call[1][0]["tags"], {"integration": "deepagents"})
        self.assertEqual(backend.id, backend.sandbox.id)
        with backend:
            pass
        self.assertEqual(self.fake.sandboxes, {})
        backend.close()  # nothing left to do

    def test_close_of_a_vanished_sandbox_is_quiet_but_other_errors_raise(self) -> None:
        backend = self.backend()
        self.fake.destroy(backend.id)
        backend.close()
        backend = self.backend()
        self.fake.fail_next["destroy"] = MicroVMHTTPError(500, "stuck")
        with self.assertRaises(MicroVMHTTPError):
            backend.close()

    def test_a_wrapped_sandbox_is_never_destroyed(self) -> None:
        sandbox = self.fake.create(image=IMAGE)
        with AerolVMSandbox(sandbox, root_dir=str(self.root)):
            pass
        self.assertIn(sandbox.id, self.fake.sandboxes)

    def test_default_client_reads_the_environment(self) -> None:
        old = {k: os.environ.get(k) for k in ("SB_API_URL", "SB_PAT_TOKEN")}
        os.environ.update({"SB_API_URL": "http://127.0.0.1:9", "SB_PAT_TOKEN": "pat"})
        try:
            with self.assertRaises(Exception) as caught:
                AerolVMSandbox.create(image=IMAGE)
        finally:
            for key, value in old.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        # It got as far as calling the server named in the environment.
        self.assertNotIn("PAT token is required", str(caught.exception))


class ForNameTest(BackendTestCase):
    def for_name(self, **kwargs):
        return AerolVMSandbox.for_name("thread-1", self.fake, root_dir=str(self.root), image=IMAGE, **kwargs)

    def test_makes_once_then_reuses_and_keeps_it(self) -> None:
        first = self.for_name()
        first.upload_files([("state.txt", b"kept")])
        first.close()
        second = self.for_name()
        self.assertEqual(second.id, first.id)
        self.assertEqual(len(self.fake.calls_to("create")), 1)
        self.assertEqual(self.fake.calls_to("create")[0][1][0]["name"], "thread-1")
        self.assertEqual(second.download_files(["state.txt"])[0].content, b"kept")

    def test_stopped_sandbox_is_started(self) -> None:
        first = self.for_name()
        self.fake.stop(first.id)
        self.for_name()
        self.assertEqual(self.fake.sandboxes[first.id]["status"], "started")

    def test_losing_a_create_race_reads_the_winner(self) -> None:
        winner = self.fake.create(image=IMAGE, name="thread-1")
        real_get_by_name = self.fake.get_by_name
        looks = []

        def get_by_name(name, *, include_env=False):
            # The first look happens before the winner's create lands.
            looks.append(name)
            return None if len(looks) == 1 else real_get_by_name(name, include_env=include_env)

        self.fake.get_by_name = get_by_name
        self.assertEqual(self.for_name().id, winner.id)
        self.assertEqual(len(looks), 2)
        # Our create was refused (409) and made nothing.
        self.assertEqual(len(self.fake.calls_to("create")), 2)
        self.assertEqual(len(self.fake.sandboxes), 1)

    def test_other_create_failures_raise(self) -> None:
        self.fake.fail_next["create"] = MicroVMHTTPError(403, "forbidden")
        with self.assertRaises(MicroVMHTTPError):
            self.for_name()


if __name__ == "__main__":
    unittest.main()
