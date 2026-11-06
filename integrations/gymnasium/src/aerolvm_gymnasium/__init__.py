"""Gymnasium environment backed by AerolVM sandboxes.

Importing the package registers ``AerolVM/ShellSandbox-v0``, so
``gymnasium.make("AerolVM/ShellSandbox-v0", image=...)`` works, and so do
Gymnasium's vector environments built from that id.
"""

import gymnasium as gym

from .env import DEFAULT_WORK_DIR, INTEGRATION_TAG, SandboxEnv, make_snapshot
from .rewards import CommandReward, CommandTermination, RewardFn, Step, TerminationFn, exit_code_reward

ENV_ID = "AerolVM/ShellSandbox-v0"

# Marked nondeterministic: a real sandbox (clocks, networks, process
# scheduling) can not promise the same output for the same seed, and
# check_env would otherwise demand that it does.
if ENV_ID not in gym.registry:
    gym.register(id=ENV_ID, entry_point="aerolvm_gymnasium.env:SandboxEnv", nondeterministic=True)

__all__ = [
    "DEFAULT_WORK_DIR",
    "ENV_ID",
    "INTEGRATION_TAG",
    "CommandReward",
    "CommandTermination",
    "RewardFn",
    "SandboxEnv",
    "Step",
    "TerminationFn",
    "exit_code_reward",
    "make_snapshot",
]
