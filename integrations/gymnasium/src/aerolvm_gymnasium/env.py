"""A Gymnasium environment where each episode is a fresh AerolVM sandbox.

The agent acts by sending shell commands and observes their output. A
reward function scores each step, and may run its own checks in the
sandbox. ``reset()`` makes a new sandbox and ``close()`` destroys it, so no
episode sees what the one before it did.
"""

from __future__ import annotations

import logging
import string
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any

import gymnasium as gym
from gymnasium import spaces
from microvm import MicroVM, MicroVMError, MicroVMHTTPError
from microvm.client import Sandbox

from .rewards import RewardFn, Step, TerminationFn, exit_code_reward, reset_hook

logger = logging.getLogger(__name__)

# Tag every sandbox and snapshot this package makes, so leaked ones are easy
# to find with MicroVM.list(tags={"integration": "gymnasium"}).
INTEGRATION_TAG = {"integration": "gymnasium"}

DEFAULT_WORK_DIR = "/workspace"
CHARSET = string.printable
# Shown in place of a character the observation space can not hold (any
# non-printable or non-ASCII one), so an observation is always valid.
REPLACEMENT_CHAR = "?"


def make_snapshot(
    image: str,
    name: str,
    *,
    client: MicroVM | None = None,
    workspace_dir: str | None = None,
    setup_commands: list[str] | tuple[str, ...] = (),
    work_dir: str = DEFAULT_WORK_DIR,
    create_options: dict[str, Any] | None = None,
    setup_timeout: int = 600,
) -> str:
    """Build the start state every episode should begin from, once.

    Makes a sandbox from ``image``, copies the local ``workspace_dir`` into
    ``work_dir``, runs ``setup_commands`` there, saves the result as the
    AerolVM snapshot ``name`` and destroys the sandbox. Pass the returned
    name as ``image`` to any number of environments: each reset then boots
    straight into the prepared state instead of repeating the setup.

    Raises ``RuntimeError`` naming the command when a setup command fails.
    The sandbox is destroyed either way.
    """
    client = client if client is not None else MicroVM()
    sandbox = client.create(_create_request(create_options, image))
    try:
        sandbox.make_dir(work_dir, parents=True)
        if workspace_dir is not None:
            sandbox.upload_dir(workspace_dir, work_dir)
        for command in setup_commands:
            result = sandbox.exec({"command": command, "workDir": work_dir, "timeoutSeconds": setup_timeout})
            if result.get("exitCode") != 0 or result.get("timedOut"):
                raise RuntimeError(
                    f"setup command {command!r} failed with exit code {result.get('exitCode')}: "
                    f"{(result.get('stderr') or result.get('stdout') or '').strip()[-2000:]}"
                )
        sandbox.create_snapshot(name)
    finally:
        _destroy_quietly(sandbox)
    return name


class SandboxEnv(gym.Env[str, str]):
    """Shell commands in, command output out, one fresh sandbox per episode.

    Args:
        image: Image or AerolVM snapshot name each episode's sandbox starts
            from. A snapshot made by :func:`make_snapshot` starts episodes in
            a prepared state.
        reward_fn: Scores each step from a :class:`~aerolvm_gymnasium.Step`.
            Defaults to 1.0 when the command exits 0.
        termination_fn: Says from a ``Step`` when the task is done. ``None``
            (the default) never ends an episode early; ``max_episode_steps``
            truncates it.
        client: A ``microvm.MicroVM``. Defaults to one built from
            ``SB_API_URL`` and ``SB_PAT_TOKEN``.
        create_options: Other ``MicroVM.create`` fields, such as ``cpu``,
            ``memoryMB``, ``runtime`` or ``networkBlockAll``.
        workspace_dir, setup_commands: When given, the first ``reset()``
            builds a snapshot from them with :func:`make_snapshot` and every
            episode starts from it. ``close()`` deletes that snapshot.
        work_dir: Folder commands run in.
        step_timeout: Seconds one command may run.
        max_episode_steps: Steps before an episode is truncated.
        max_obs_length: Characters kept from each command's output.
        max_action_length: Longest command the action space allows.
        max_output_bytes: Cap each command's stdout and stderr inside the
            sandbox, so a command that prints gigabytes costs nothing to
            ship. ``None`` sends everything and clips it here.
    """

    metadata = {"render_modes": []}

    def __init__(
        self,
        image: str,
        *,
        reward_fn: RewardFn = exit_code_reward,
        termination_fn: TerminationFn | None = None,
        client: MicroVM | None = None,
        create_options: dict[str, Any] | None = None,
        workspace_dir: str | None = None,
        setup_commands: list[str] | tuple[str, ...] = (),
        work_dir: str = DEFAULT_WORK_DIR,
        step_timeout: int = 60,
        max_episode_steps: int = 20,
        max_obs_length: int = 4096,
        max_action_length: int = 4096,
        max_output_bytes: int | None = None,
    ) -> None:
        super().__init__()
        if not image:
            raise ValueError("image is required")
        if not callable(reward_fn):
            raise TypeError("reward_fn must be callable")
        if termination_fn is not None and not callable(termination_fn):
            raise TypeError("termination_fn must be callable")
        if step_timeout <= 0 or max_episode_steps <= 0 or max_obs_length <= 0:
            raise ValueError("step_timeout, max_episode_steps and max_obs_length must be positive")
        self.image = image
        self.reward_fn = reward_fn
        self.termination_fn = termination_fn
        self.work_dir = work_dir
        self.step_timeout = step_timeout
        self.max_episode_steps = max_episode_steps
        self.max_obs_length = max_obs_length
        self.max_output_bytes = max_output_bytes
        self._client = client if client is not None else MicroVM()
        self._create_options = dict(create_options or {})
        self._workspace_dir = workspace_dir
        self._setup_commands = tuple(setup_commands)
        self._base_snapshot: str | None = None

        self.observation_space = spaces.Text(max_length=max_obs_length, min_length=0, charset=CHARSET)
        self.action_space = spaces.Text(max_length=max_action_length, min_length=1, charset=CHARSET)

        self._sandbox: Sandbox | None = None
        self._task = ""
        self._steps = 0
        # A finished episode's sandbox is destroyed in the background, so
        # reset() waits only for the new sandbox, not for the old one to go.
        self._reaper = ThreadPoolExecutor(max_workers=2, thread_name_prefix="aerolvm-gym-destroy")
        self._pending: list[Future[None]] = []

    # -- Gymnasium API -------------------------------------------------------

    def reset(self, *, seed: int | None = None, options: dict[str, Any] | None = None) -> tuple[str, dict[str, Any]]:
        """Start an episode in a new sandbox.

        ``options["task"]`` (a string) is passed to the reward and
        termination functions, and is the first observation, so an agent
        reads its task from it. The sandbox itself does not use ``seed``:
        it only seeds ``self.np_random``, as Gymnasium requires.
        """
        super().reset(seed=seed)
        options = options or {}
        self._retire_sandbox()

        started = time.monotonic()
        image = self._episode_image()
        sandbox = self._client.create(_create_request(self._create_options, image))
        self._sandbox = sandbox
        try:
            sandbox.make_dir(self.work_dir, parents=True)
        except Exception:
            self._retire_sandbox()
            raise

        self._task = str(options.get("task", ""))
        self._steps = 0
        reset_hook(self.reward_fn, self._task)
        reset_hook(self.termination_fn, self._task)
        info = {
            "sandbox_id": sandbox.id,
            "image": image,
            "task": self._task,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
        }
        return self._observation(self._task), info

    def step(self, action: str) -> tuple[str, float, bool, bool, dict[str, Any]]:
        if self._sandbox is None:
            raise RuntimeError("call reset() before step()")
        self._steps += 1
        started = time.monotonic()
        env_error = False
        try:
            result = self._run(str(action), self.step_timeout)
        except MicroVMError as e:
            # The command never ran or its result is lost. The agent sees
            # why, and info says it was the environment, not the command.
            logger.warning("step %d failed in sandbox %s: %s", self._steps, self._sandbox.id, e)
            result = {"stdout": "", "stderr": str(e), "exitCode": -1, "timedOut": False}
            env_error = True
        elapsed_ms = int((time.monotonic() - started) * 1000)

        stdout = str(result.get("stdout") or "")
        stderr = str(result.get("stderr") or "")
        observation = self._observation(stdout + (f"[stderr]\n{stderr}" if stderr else ""))
        record = Step(
            action=str(action),
            observation=observation,
            exit_code=int(result.get("exitCode") if result.get("exitCode") is not None else -1),
            stdout=stdout,
            stderr=stderr,
            timed_out=bool(result.get("timedOut")),
            env_error=env_error,
            step=self._steps,
            task=self._task,
            run=self._run_check,
        )
        try:
            reward = float(self.reward_fn(record))
            terminated = bool(self.termination_fn(record)) if self.termination_fn is not None else False
        except MicroVMError as e:
            # A check that runs a command (CommandReward, CommandTermination,
            # Step.run) can meet the same server failure as the action. The
            # step still does not raise: no reward, the episode goes on, and
            # info says it was the environment.
            logger.warning("step %d check failed in sandbox %s: %s", self._steps, self._sandbox.id, e)
            reward, terminated, env_error = 0.0, False, True
        truncated = not terminated and self._steps >= self.max_episode_steps
        info = {
            "exit_code": record.exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": record.timed_out,
            "output_truncated": bool(result.get("stdoutTruncated") or result.get("stderrTruncated")),
            "env_error": env_error,
            "elapsed_ms": elapsed_ms,
            "step": self._steps,
            "sandbox_id": self._sandbox.id,
        }
        return observation, reward, terminated, truncated, info

    def close(self) -> None:
        """Destroy the episode's sandbox and any snapshot this environment
        built. Safe to call more than once."""
        self._retire_sandbox()
        for future in self._pending:
            future.result()
        self._pending.clear()
        self._reaper.shutdown(wait=True)
        if self._base_snapshot is not None:
            name, self._base_snapshot = self._base_snapshot, None
            try:
                self._client.delete_snapshot(name)
            except MicroVMHTTPError as e:
                if e.status_code != 404:
                    logger.warning("could not delete snapshot %s: %s", name, e)
        super().close()

    # -- helpers ---------------------------------------------------------------

    @property
    def sandbox(self) -> Sandbox | None:
        """The current episode's sandbox, for calls the environment does not
        make itself (uploading task files, reading results)."""
        return self._sandbox

    @property
    def base_snapshot(self) -> str | None:
        """The snapshot built from ``workspace_dir`` and ``setup_commands``,
        once the first reset has made it."""
        return self._base_snapshot

    def _episode_image(self) -> str:
        if not (self._workspace_dir or self._setup_commands):
            return self.image
        if self._base_snapshot is None:
            name = f"gymnasium-{uuid.uuid4().hex}"
            make_snapshot(
                self.image,
                name,
                client=self._client,
                workspace_dir=self._workspace_dir,
                setup_commands=self._setup_commands,
                work_dir=self.work_dir,
                create_options=self._create_options,
            )
            self._base_snapshot = name
        return self._base_snapshot

    def _run(self, command: str, timeout: int) -> dict[str, Any]:
        assert self._sandbox is not None
        request: dict[str, Any] = {"command": command, "workDir": self.work_dir, "timeoutSeconds": timeout}
        if self.max_output_bytes:
            request["maxStdoutBytes"] = self.max_output_bytes
            request["maxStderrBytes"] = self.max_output_bytes
        return dict(self._sandbox.exec(request))

    def _run_check(self, command: str) -> dict[str, Any]:
        return self._run(command, self.step_timeout)

    def _observation(self, text: str) -> str:
        # Text spaces hold only their charset; anything else would make the
        # observation invalid for the space (and fail check_env).
        clipped = text[: self.max_obs_length]
        return "".join(c if c in CHARSET else REPLACEMENT_CHAR for c in clipped)

    def _retire_sandbox(self) -> None:
        sandbox, self._sandbox = self._sandbox, None
        if sandbox is None:
            return
        self._pending = [f for f in self._pending if not f.done()]
        try:
            self._pending.append(self._reaper.submit(_destroy_quietly, sandbox))
        except RuntimeError:
            # The reaper is shut down (close() ran before); destroy inline.
            _destroy_quietly(sandbox)


def _create_request(create_options: dict[str, Any] | None, image: str) -> dict[str, Any]:
    fields = dict(create_options or {})
    fields["image"] = image
    fields["tags"] = {**INTEGRATION_TAG, **dict(fields.get("tags") or {})}
    return fields


def _destroy_quietly(sandbox: Sandbox) -> None:
    try:
        sandbox.destroy()
    except MicroVMHTTPError as e:
        if e.status_code != 404:
            logger.warning("could not destroy sandbox %s: %s", sandbox.id, e)
    except Exception as e:
        # A finished episode's sandbox that will not go away is a leak, not
        # a reason to stop training; its lifecycle timers can end it.
        logger.warning("could not destroy sandbox %s: %s", sandbox.id, e)
