# aerolvm-gymnasium

A [Gymnasium](https://gymnasium.farama.org/) environment where every episode
runs in a fresh AerolVM sandbox. The agent acts by sending shell commands,
sees their output, and earns a reward from a function you choose.

Use it to train or test agents that work in a terminal: fix a bug, set up a
project, pass a test suite. Each episode starts clean, so one episode never
sees another's files.

## Install

The package is not on PyPI yet. Install it from this repository:

```bash
pip install "git+https://github.com/aerol-ai/microvm.git#subdirectory=integrations/gymnasium"
```

It needs `gymnasium` 1.4 and the AerolVM Python SDK (`aerolvm-sdk`). Set
`SB_API_URL` and `SB_PAT_TOKEN` so the SDK can reach your AerolVM server.

## Use it

```python
import gymnasium as gym
import aerolvm_gymnasium  # registers AerolVM/ShellSandbox-v0
from aerolvm_gymnasium import CommandReward, CommandTermination

env = gym.make(
    "AerolVM/ShellSandbox-v0",
    image="python:3.12-slim",
    reward_fn=CommandReward("test -f hello.txt"),
    termination_fn=CommandTermination("test -f hello.txt"),
    max_episode_steps=10,
)

obs, info = env.reset(options={"task": "Create a file called hello.txt"})
print(obs)  # the task is the first observation

obs, reward, terminated, truncated, info = env.step("touch hello.txt")
print(reward, terminated)  # 1.0 True

env.close()  # destroys the sandbox
```

You can also build it directly: `aerolvm_gymnasium.SandboxEnv(image=...)`.

## What it does

| Gymnasium call | AerolVM does |
| --- | --- |
| `reset()` | Makes a new sandbox (the old one is destroyed in the background) and makes the work folder |
| `step(command)` | Runs the command in the work folder with a time limit |
| `close()` | Destroys the sandbox, and the snapshot it built (if any) |

- **Actions** are shell commands (a `Text` space of printable characters).
- **Observations** are the command's stdout, then `[stderr]` and its stderr,
  clipped to `max_obs_length`. Characters the space can not hold become `?`.
- **`info`** has `exit_code`, `stdout`, `stderr`, `timed_out`,
  `output_truncated`, `env_error`, `elapsed_ms`, `step` and `sandbox_id`.
- **Truncation** happens after `max_episode_steps` steps.
- If the server fails during a step, the step does not raise: the
  observation says why, `info["env_error"]` is `True` and the exit code is -1.
  If it fails during a reward or termination check that runs a command, the
  step gets reward 0, the episode goes on, and `info["env_error"]` is `True`.

## Rewards

A reward function takes a `Step` and returns a float. A termination function
takes a `Step` and returns `True` when the task is done. A `Step` has the
action, observation, exit code, stdout, stderr, step number and task, and
`step.run(command)` runs a check in the same sandbox.

| Function | What it does |
| --- | --- |
| `exit_code_reward` (default) | 1.0 when the command exits 0 |
| `CommandReward(cmd, success=1.0, failure=0.0)` | Runs `cmd` after each step; `success` when it exits 0 |
| `CommandTermination(cmd)` | Ends the episode when `cmd` exits 0 |

Write your own as any callable. If it has a `reset(task)` method, that runs at
the start of each episode:

```python
class FewerStepsIsBetter:
    def reset(self, task):
        pass

    def __call__(self, step):
        return 1.0 - 0.1 * step.step if step.exit_code == 0 else 0.0
```

## Fast resets

Each reset makes a new sandbox, so resets are as fast as sandbox creation.
Three things make them faster:

1. **Start from a snapshot.** Pass `workspace_dir` (a local folder copied into
   the work folder) and `setup_commands` (run once). The first reset builds a
   snapshot from them, and every episode boots straight into that state. To
   share one snapshot across many environments (a vector env), build it once
   with `make_snapshot(...)` and pass its name as `image`.
2. **Use a warm pool.** Ask your admin to set a warm pool for the image (or
   snapshot). A create from it then takes a ready sandbox.
3. **The old sandbox goes in the background**, so a reset waits only for the
   new one.

## Settings

| Setting | Default | What it does |
| --- | --- | --- |
| `image` | (required) | Image or snapshot name each episode starts from |
| `reward_fn` | `exit_code_reward` | Scores each step |
| `termination_fn` | `None` | Ends an episode early when it returns `True` |
| `client` | from env vars | A `microvm.MicroVM` |
| `create_options` | `{}` | Other create fields, such as `cpu`, `memoryMB` or `networkBlockAll` |
| `workspace_dir`, `setup_commands` | none | Build a start snapshot on the first reset |
| `work_dir` | `/workspace` | Folder commands run in |
| `step_timeout` | `60` | Seconds one command may run |
| `max_episode_steps` | `20` | Steps before truncation |
| `max_obs_length` | `4096` | Characters kept from each output |
| `max_action_length` | `4096` | Longest command allowed |
| `max_output_bytes` | `None` | Cap stdout and stderr inside the sandbox |

## Limits

- The sandbox does not use the seed. `reset(seed=...)` seeds only
  `env.np_random`, so the environment is registered as nondeterministic.
- Container and Firecracker sandboxes only. WebAssembly and V8 isolate
  sandboxes have no shell.
- A `CommandReward` and a `CommandTermination` each run their check, so
  using both runs it twice per step.

## Tests

The tests run offline, including Gymnasium's own `check_env`. A fake AerolVM
client runs commands on your own machine.

```bash
cd integrations/gymnasium
python -m pip install -e ../../sdk/python -e .
python -m unittest discover -s tests -v
```
