"""Reward and termination functions for :class:`~aerolvm_gymnasium.SandboxEnv`.

Both are plain callables that take one :class:`Step` and return a float (a
reward) or a bool (whether the episode is over). An object with a
``reset(task)`` method has it called at the start of every episode, which is
where a stateful function clears what it remembered.

``Step.run`` runs another command in the episode's sandbox. That is how a
reward checks the work itself, for example by running the task's tests, and
not only the agent's own output.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class Step:
    """What one ``env.step(action)`` did, as reward and termination
    functions see it."""

    action: str
    """The shell command the agent sent."""
    observation: str
    """What the agent sees: the output, clipped to the observation space."""
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    """The command ran past ``step_timeout`` and was stopped."""
    env_error: bool
    """The command could not be run at all (the sandbox or server failed)."""
    step: int
    """1 for the first step of an episode."""
    task: str
    """The task given to ``reset(options={"task": ...})``."""
    run: Callable[[str], dict[str, Any]] = field(repr=False, compare=False)
    """Run another command in the episode's sandbox, in the work folder.
    Returns the AerolVM SDK's ``ExecResult`` (``exitCode``, ``stdout``,
    ``stderr``, ...)."""


RewardFn = Callable[[Step], float]
TerminationFn = Callable[[Step], bool]


class Resettable(Protocol):
    def reset(self, task: str) -> None: ...


def exit_code_reward(step: Step) -> float:
    """1.0 when the command exits 0, else 0.0. The default reward."""
    return 1.0 if step.exit_code == 0 and not step.timed_out and not step.env_error else 0.0


class CommandReward:
    """Runs a check command in the sandbox after every step and gives
    ``success`` when it exits 0, else ``failure``.

    For a coding task the check is usually the task's tests, so the reward
    says whether the work is done, not whether the agent's last command
    happened to succeed. The check runs in the same sandbox, after the
    agent's command, so it sees every file the agent changed.
    """

    def __init__(self, command: str, *, success: float = 1.0, failure: float = 0.0) -> None:
        if not command.strip():
            raise ValueError("command must not be empty")
        self.command = command
        self.success = success
        self.failure = failure

    def __call__(self, step: Step) -> float:
        result = step.run(self.command)
        return self.success if result.get("exitCode") == 0 and not result.get("timedOut") else self.failure


class CommandTermination:
    """Ends the episode once a check command exits 0 in the sandbox."""

    def __init__(self, command: str) -> None:
        if not command.strip():
            raise ValueError("command must not be empty")
        self.command = command

    def __call__(self, step: Step) -> bool:
        result = step.run(self.command)
        return result.get("exitCode") == 0 and not result.get("timedOut")


def reset_hook(fn: object, task: str) -> None:
    """Call ``fn.reset(task)`` when ``fn`` has one."""
    reset = getattr(fn, "reset", None)
    if callable(reset):
        reset(task)
