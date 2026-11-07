"""SandboxEnv: Gymnasium API conformance, episodes, rewards and snapshots."""

from __future__ import annotations

import unittest
import warnings

import gymnasium as gym
from gymnasium.utils.env_checker import check_env
from microvm import MicroVMHTTPError

from aerolvm_gymnasium import ENV_ID, CommandReward, CommandTermination, SandboxEnv, Step, make_snapshot
from support import IMAGE, EnvTestCase, assert_fake_matches_sdk


class FakeMatchesSDKTest(unittest.TestCase):
    def test_fake_matches_sdk(self) -> None:
        assert_fake_matches_sdk(self)


class GymnasiumAPITest(EnvTestCase):
    def test_check_env_passes_on_the_registered_env(self) -> None:
        self.canned_exec()
        env = gym.make(ENV_ID, image=IMAGE, client=self.fake, work_dir=str(self.work))
        self.envs.append(env.unwrapped)  # type: ignore[arg-type]
        with warnings.catch_warnings():
            # Any warning from the checker is a finding, not noise.
            warnings.simplefilter("error")
            check_env(env.unwrapped)
        env.close()
        self.assertEqual(self.fake.sandboxes, {})

    def test_spec_is_nondeterministic_and_spaces_are_text(self) -> None:
        self.assertTrue(gym.spec(ENV_ID).nondeterministic)
        env = self.env(max_obs_length=100, max_action_length=50)
        self.assertIsInstance(env.observation_space, gym.spaces.Text)
        self.assertEqual(env.observation_space.max_length, 100)
        self.assertEqual(env.observation_space.min_length, 0)
        self.assertEqual(env.action_space.max_length, 50)

    def test_random_agent_through_the_wrappers(self) -> None:
        # gym.make adds the passive checker and order enforcing; a short
        # random rollout through them must run cleanly for two episodes.
        self.canned_exec()
        env = gym.make(ENV_ID, image=IMAGE, client=self.fake, work_dir=str(self.work), max_episode_steps=3)
        env.action_space.seed(0)
        for _ in range(2):
            env.reset(seed=1)
            done = False
            steps = 0
            while not done:
                _, _, terminated, truncated, _ = env.step(env.action_space.sample())
                done = terminated or truncated
                steps += 1
            self.assertEqual(steps, 3)
        env.close()
        self.assertEqual(len(self.fake.calls_to("create")), 2)
        self.assertEqual(self.fake.sandboxes, {})

    def test_vector_env_batches_text(self) -> None:
        envs = gym.make_vec(ENV_ID, num_envs=2, image=IMAGE, client=self.fake, work_dir=str(self.work))
        obs, _ = envs.reset(options={"task": "t"})
        self.assertEqual(obs, ("t", "t"))
        obs, rewards, *_ = envs.step(("echo a", "echo b"))
        self.assertEqual(obs, ("a\n", "b\n"))
        self.assertEqual(list(rewards), [1.0, 1.0])
        envs.close()
        self.assertEqual(self.fake.sandboxes, {})

    def test_step_before_reset_is_refused(self) -> None:
        with self.assertRaises(RuntimeError):
            self.env().step("true")

    def test_bad_settings_are_refused(self) -> None:
        cases = [
            ({"image": ""}, ValueError),
            ({"reward_fn": 3}, TypeError),
            ({"termination_fn": "x"}, TypeError),
            ({"step_timeout": 0}, ValueError),
        ]
        for kwargs, error in cases:
            with self.subTest(kwargs=kwargs), self.assertRaises(error):
                self.env(**kwargs)


class EpisodeTest(EnvTestCase):
    def test_commands_run_in_the_episode_sandbox(self) -> None:
        env = self.env()
        obs, info = env.reset(options={"task": "make a.txt"})
        self.assertEqual(obs, "make a.txt")
        self.assertEqual(info["task"], "make a.txt")
        self.assertEqual(info["image"], IMAGE)
        first_id = info["sandbox_id"]
        self.assertTrue(self.work.is_dir())

        obs, reward, terminated, truncated, info = env.step("echo hi > a.txt && cat a.txt")
        self.assertEqual((obs, reward, terminated, truncated), ("hi\n", 1.0, False, False))
        self.assertEqual(info["exit_code"], 0)
        self.assertEqual(info["step"], 1)
        request = self.fake.calls_to("exec")[-1][1][1]
        self.assertEqual((request["workDir"], request["timeoutSeconds"]), (str(self.work), 60))

        obs, reward, *_ = env.step("echo oops >&2; exit 3")
        self.assertEqual(obs, "[stderr]\noops\n")
        self.assertEqual(reward, 0.0)

        _, info = env.reset()
        self.assertNotEqual(info["sandbox_id"], first_id)
        env.close()
        # The old episode's sandbox went in the background; close waited.
        self.assertEqual(self.fake.sandboxes, {})
        create = self.fake.calls_to("create")[0][1][0]
        self.assertEqual(create["tags"], {"integration": "gymnasium"})

    def test_truncation_at_max_steps(self) -> None:
        env = self.env(max_episode_steps=2)
        env.reset()
        self.assertFalse(env.step("true")[3])
        self.assertTrue(env.step("true")[3])

    def test_timeout_and_environment_errors_do_not_raise(self) -> None:
        env = self.env(step_timeout=1)
        env.reset()
        _, reward, _, _, info = env.step("sleep 5")
        self.assertTrue(info["timed_out"])
        self.assertEqual(reward, 0.0)

        self.fake.fail_next["exec"] = MicroVMHTTPError(502, "bad gateway")
        with self.assertLogs("aerolvm_gymnasium.env", level="WARNING"):
            obs, reward, _, _, info = env.step("true")
        self.assertTrue(info["env_error"])
        self.assertEqual((info["exit_code"], reward), (-1, 0.0))
        self.assertIn("bad gateway", obs)

    def test_a_check_that_hits_a_server_error_does_not_raise(self) -> None:
        env = self.env(reward_fn=CommandReward("test -f done.txt", success=5.0, failure=-1.0),
                       termination_fn=CommandTermination("test -f done.txt"))
        env.reset()
        real_exec = self.fake.exec
        calls = {"n": 0}

        def exec_failing_on_the_check(sandbox_id, request, **kwargs):
            calls["n"] += 1
            if calls["n"] == 2:  # the action is call 1; the reward check is call 2
                raise MicroVMHTTPError(502, "bad gateway")
            return real_exec(sandbox_id, request, **kwargs)

        self.fake.exec = exec_failing_on_the_check
        with self.assertLogs("aerolvm_gymnasium.env", level="WARNING"):
            _, reward, terminated, _, info = env.step("touch done.txt")
        self.assertEqual((reward, terminated, info["env_error"]), (0.0, False, True))
        self.assertEqual(info["exit_code"], 0)

    def test_observation_always_fits_its_space(self) -> None:
        env = self.env(max_obs_length=8)
        env.reset()
        obs, *_ = env.step("printf 'h\\303\\251llo\\033 world'")
        self.assertEqual(obs, "h?llo? w")
        self.assertIn(obs, env.observation_space)

    def test_output_cap_is_sent_and_reported(self) -> None:
        env = self.env(max_output_bytes=3)
        env.reset()
        obs, _, _, _, info = env.step("printf abcdef")
        self.assertEqual(obs, "abc")
        self.assertTrue(info["output_truncated"])
        self.assertEqual(self.fake.calls_to("exec")[-1][1][1]["maxStdoutBytes"], 3)

    def test_failed_reset_retires_the_new_sandbox(self) -> None:
        env = self.env()
        self.fake.fail_next["make_dir"] = MicroVMHTTPError(500, "disk")
        with self.assertRaises(MicroVMHTTPError):
            env.reset()
        self.assertIsNone(env.sandbox)
        env.close()
        self.assertEqual(self.fake.sandboxes, {})

    def test_close_is_idempotent_and_a_vanished_sandbox_is_fine(self) -> None:
        env = self.env()
        env.reset()
        self.fake.destroy(env.sandbox.id)
        env.close()
        env.close()


class RewardTest(EnvTestCase):
    def test_command_reward_and_termination_check_the_sandbox(self) -> None:
        env = self.env(reward_fn=CommandReward("test -f done.txt", success=5.0, failure=-1.0),
                       termination_fn=CommandTermination("test -f done.txt"))
        env.reset()
        _, reward, terminated, _, _ = env.step("echo working")
        self.assertEqual((reward, terminated), (-1.0, False))
        _, reward, terminated, truncated, _ = env.step("touch done.txt")
        self.assertEqual((reward, terminated, truncated), (5.0, True, False))

    def test_custom_functions_get_the_step_and_a_reset_hook(self) -> None:
        seen: list[Step] = []
        tasks: list[str] = []

        class Recorder:
            def reset(self, task: str) -> None:
                tasks.append(task)

            def __call__(self, step: Step) -> float:
                seen.append(step)
                return float(step.step)

        env = self.env(reward_fn=Recorder())
        env.reset(options={"task": "t1"})
        _, reward, *_ = env.step("echo out; echo err >&2")
        self.assertEqual(reward, 1.0)
        self.assertEqual(tasks, ["t1"])
        step = seen[0]
        self.assertEqual((step.stdout, step.stderr, step.exit_code, step.task), ("out\n", "err\n", 0, "t1"))
        self.assertEqual(step.run("echo from-check")["stdout"], "from-check\n")

    def test_empty_check_commands_are_refused(self) -> None:
        for cls in (CommandReward, CommandTermination):
            with self.subTest(cls.__name__), self.assertRaises(ValueError):
                cls("  ")


class SnapshotTest(EnvTestCase):
    def task_folder(self):
        folder = self.tmp / "task"
        folder.mkdir()
        (folder / "README.txt").write_text("fix the bug")
        return folder

    def test_setup_runs_once_and_every_episode_starts_from_it(self) -> None:
        env = self.env(workspace_dir=str(self.task_folder()), setup_commands=["echo built > setup.txt"])
        _, info = env.reset()
        snapshot = env.base_snapshot
        self.assertEqual(info["image"], snapshot)
        self.assertEqual((self.work / "README.txt").read_text(), "fix the bug")
        self.assertEqual((self.work / "setup.txt").read_text(), "built\n")

        env.step("echo junk > junk.txt")
        env.reset()
        # The new episode starts from the snapshot, not from the last one.
        self.assertFalse((self.work / "junk.txt").exists())
        self.assertEqual(len(self.fake.calls_to("create_snapshot")), 1)
        self.assertEqual(len(self.fake.calls_to("upload_dir")), 1)
        images = [c[1][0]["image"] for c in self.fake.calls_to("create")]
        self.assertEqual(images, [IMAGE, snapshot, snapshot])

        env.close()
        self.assertNotIn(snapshot, self.fake.snapshots)
        self.assertEqual(self.fake.sandboxes, {})

    def test_make_snapshot_for_many_environments(self) -> None:
        name = make_snapshot(IMAGE, "shared-start", client=self.fake, setup_commands=["echo ready > r.txt"],
                             work_dir=str(self.work))  # type: ignore[arg-type]
        envs = [self.env(image=name) for _ in range(2)]
        for env in envs:
            _, info = env.reset()
            self.assertEqual(info["image"], "shared-start")
        for env in envs:
            env.close()
        # An environment never deletes a snapshot it did not build.
        self.assertIn("shared-start", self.fake.snapshots)

    def test_failed_setup_names_the_command_and_cleans_up(self) -> None:
        with self.assertRaises(RuntimeError) as caught:
            make_snapshot(IMAGE, "broken", client=self.fake, setup_commands=["true", "echo nope >&2; exit 2"],
                          work_dir=str(self.work))  # type: ignore[arg-type]
        self.assertIn("exit 2", str(caught.exception))
        self.assertIn("nope", str(caught.exception))
        self.assertEqual(self.fake.sandboxes, {})
        self.assertEqual(self.fake.snapshots, {})

    def test_snapshot_delete_failure_on_close_is_logged(self) -> None:
        env = self.env(setup_commands=["true"])
        env.reset()
        self.fake.fail_next["delete_snapshot"] = MicroVMHTTPError(500, "busy")
        with self.assertLogs("aerolvm_gymnasium.env", level="WARNING"):
            env.close()


if __name__ == "__main__":
    unittest.main()
