# aerolvm-openai-agents

Run [OpenAI Agents SDK](https://github.com/openai/openai-agents-python)
sandbox agents (`SandboxAgent`) in AerolVM sandboxes.

Your agent stays the same. You only change the run config to name the
AerolVM client. Each run gets its own sandbox. When the run ends, the
workspace can be saved as an AerolVM snapshot, and a later run can pick it
up again.

## Install

The package is not on PyPI yet. Install it from this repository:

```bash
pip install "git+https://github.com/aerol-ai/microvm.git#subdirectory=integrations/openai-agents"
```

It needs `openai-agents` 0.24.x (installed for you) and the AerolVM Python
SDK (`aerolvm-sdk`). Set `SB_API_URL` and `SB_PAT_TOKEN` so the SDK can reach
your AerolVM server.

## Use it

```python
import asyncio

from agents import Runner
from agents.run import RunConfig
from agents.sandbox import SandboxAgent, SandboxRunConfig
from agents.sandbox.capabilities import Shell
from agents.sandbox.snapshot import LocalSnapshotSpec

from aerolvm_openai_agents import AerolVMSandboxClient, AerolVMSandboxClientOptions

agent = SandboxAgent(
    name="builder",
    instructions="Build the project in the workspace.",
    capabilities=[Shell()],
)

run_config = RunConfig(
    sandbox=SandboxRunConfig(
        client=AerolVMSandboxClient(),  # reads SB_API_URL and SB_PAT_TOKEN
        options=AerolVMSandboxClientOptions(image="python:3.12-slim"),
        # Optional: save the workspace when the run ends.
        snapshot=LocalSnapshotSpec(base_path="./agent-snapshots"),
    ),
)

result = asyncio.run(Runner.run(agent, "Make a hello.py and run it", run_config=run_config))
print(result.final_output)
```

## Options

`AerolVMSandboxClientOptions` takes:

| Option | Default | What it does |
| --- | --- | --- |
| `image` | (required) | The image, or AerolVM snapshot name, the sandbox starts from. It needs `sh`, `find` and `readlink`, plus `tar` for `workspace_persistence="tar"`. |
| `create_options` | `{}` | Any other `MicroVM.create` fields, such as `cpu`, `memoryMB`, `runtime`, `env`, `networkAllowOut` or `lifecycle`. |
| `exposed_ports` | `()` | Ports the agent may publish. They are made public the first time the agent asks for one. |
| `workspace_persistence` | `"snapshot"` | How the workspace is saved: `"snapshot"` (an AerolVM snapshot) or `"tar"` (a tar file kept by the SDK). |
| `on_shutdown` | `"destroy"` | What happens to the sandbox when the run ends: `"destroy"`, `"stop"` or `"keep"`. |
| `exec_timeout_s` | `3600` | Time limit for a command the agent runs without one. |
| `max_output_bytes` | `None` | Keep at most this many bytes of each command's stdout and stderr. |
| `snapshot_name_prefix` | `"openai-agents"` | Start of every snapshot name this package makes. |
| `delete_superseded_snapshots` | `False` | Delete the older snapshot once a newer one is saved. |

Settings in `create_options` are saved with the session state, so a resume
can make the same kind of sandbox again. Do not put secrets there that you
would not store with your run state.

## How it works

| Agents SDK asks for | AerolVM does |
| --- | --- |
| `create` | `MicroVM.create`, tagged `integration=openai-agents` and with an `aerolvm-create-op` tag of its own (it finds the sandbox when a create fails with no clear answer); a create cancelled while the sandbox is being made destroys it once it exists |
| a command | `exec` with the command as a list (`argv`), run in the workspace folder |
| read and write a file | `download_file` and `upload_file` (bytes stay exact) |
| list a folder | `list_files` |
| save the workspace | `create_snapshot`, then the SDK stores a small reference to it |
| restore the workspace | a new sandbox from that snapshot, then the old one is destroyed |
| `resume` | reuse the sandbox if it still exists (start it if it was stopped); otherwise make a new one, from the last snapshot when there is one |
| a public port | `expose_port` |

### Saving the workspace

You choose where the SDK keeps saved state with `SandboxRunConfig(snapshot=...)`.
With the default `workspace_persistence="snapshot"`, the SDK keeps only a
small reference. The files themselves stay on the AerolVM server, as a
snapshot of the whole sandbox, so installed packages come back too.

Snapshots are not deleted for you, because a saved run state may still point
at one. Each snapshot name starts with `snapshot_name_prefix`, so you can find
and delete old ones with `MicroVM.list_snapshots` and `MicroVM.delete_snapshot`.
Or set `delete_superseded_snapshots=True` when you never go back to an older
state.

Use `workspace_persistence="tar"` when the saved state must live outside the
AerolVM server. The package also uses a tar by itself when the manifest marks
paths as ephemeral, because a snapshot can not leave paths out.

## Limits

- Commands run with buffered exec, so there is no terminal (PTY). The
  `write_stdin` tool is not offered.
- Container and Firecracker sandboxes only. WebAssembly and V8 isolate
  sandboxes have no shell.
- Command output is text. Binary files go through the file calls, never
  through command output.
- A file read or write holds the whole file in memory.

## Tests

The tests run offline. A fake AerolVM client runs commands on your own
machine, so the real Agents SDK session code runs against the provider.

```bash
cd integrations/openai-agents
python -m pip install -e ../../sdk/python -e .
python -m unittest discover -s tests -v
```
