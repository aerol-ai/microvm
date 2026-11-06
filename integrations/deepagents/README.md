# aerolvm-deepagents

A [LangChain DeepAgents](https://github.com/langchain-ai/deepagents) backend
that runs the agent's tools in an AerolVM sandbox.

The agent's shell commands and file tools (`execute`, `ls`, `read_file`,
`write_file`, `edit_file`, `grep`, `glob`) all work inside the sandbox, not
on your machine.

## Install

The package is not on PyPI yet. Install it from this repository:

```bash
pip install "git+https://github.com/aerol-ai/microvm.git#subdirectory=integrations/deepagents"
```

It needs `deepagents` 0.7.x (0.7.34 or newer; installed for you) and the
AerolVM Python SDK (`aerolvm-sdk`). Set `SB_API_URL` and `SB_PAT_TOKEN` so
the SDK can reach your AerolVM server.

## Use it

```python
from deepagents import create_deep_agent
from aerolvm_deepagents import AerolVMSandbox

with AerolVMSandbox.create(image="python:3.12-slim") as backend:
    agent = create_deep_agent(model="anthropic:claude-sonnet-4-5", backend=backend)
    result = agent.invoke(
        {"messages": [{"role": "user", "content": "Write hello.py, run it, and tell me what it printed."}]}
    )
    print(result["messages"][-1].content)
# Leaving the "with" block destroys the sandbox.
```

### Three ways to get a sandbox

| Call | Makes a sandbox? | `close()` destroys it? |
| --- | --- | --- |
| `AerolVMSandbox.create(image=..., **fields)` | Yes, every time | Yes |
| `AerolVMSandbox.for_name("thread-42", image=..., **fields)` | Only the first time; later calls reuse it (and start it if it was stopped) | No |
| `AerolVMSandbox(sandbox)` | No, you pass one from `MicroVM.create` or `get` | No |

`for_name` fits a LangGraph graph factory: use one name per conversation
thread and every run of that thread gets the same sandbox and files. Give it
a lifecycle so old threads' sandboxes go away, for example
`lifecycle={"destroyIfIdleFor": 24 * 3600 * 10**9}` (one day, in nanoseconds).

Extra keyword arguments to `create` and `for_name` are `MicroVM.create`
fields, such as `cpu`, `memoryMB`, `env` or `networkAllowOut`.

### Settings

| Setting | Default | What it does |
| --- | --- | --- |
| `root_dir` | `/workspace` | Folder commands run in, made on first use. Relative file paths are taken from here too. |
| `default_timeout` | `1800` | Seconds a command may run when the agent sets no timeout (or 0). |
| `max_output_bytes` | `None` | Keep at most this many bytes of a command's stdout and of its stderr. The response then says `truncated`. |

## How it works

| DeepAgents calls | AerolVM does |
| --- | --- |
| `execute` | `exec` in `root_dir`, with the timeout and output caps |
| `upload_files` and `write` | `upload_file` (missing folders are made) |
| `download_files` | `download_file` |
| `ls` | `list_files` |
| `delete` | `delete_file` (folders too) |
| `read`, `edit`, `grep`, `glob` | DeepAgents' own scripts, run through `execute` |

Command output has the same layout as DeepAgents' local shell backend:
stdout, then each stderr line marked `[stderr]`, then `Exit code: N` when it
is not 0. A command that runs out of time returns exit code 124.

File errors come back as DeepAgents' codes (`file_not_found`,
`permission_denied`, `is_directory`, `invalid_path`), one per file, so one
bad path does not fail the others.

## Limits

- `read`, `edit` and `glob` run Python scripts, and `grep` runs `grep`, so
  the image needs `python3` and `grep`. `ls`, `write`, `delete`, upload and
  download do not.
- Container and Firecracker sandboxes only. WebAssembly and V8 isolate
  sandboxes have no shell.
- Each upload or download holds the whole file in memory.
- A request that fails (the server cannot be reached, the sandbox is gone)
  raises an error instead of returning an output, because it says nothing
  about how the command ended.

## Tests

The tests run offline. A fake AerolVM client runs commands on your own
machine, so DeepAgents' own scripts run for real against the backend.

```bash
cd integrations/deepagents
python -m pip install -e ../../sdk/python -e .
python -m unittest discover -s tests -v
```
