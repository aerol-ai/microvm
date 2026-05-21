# Aerol.ai MicroVM Python SDK

A lightweight Python SDK for the Aerol.ai MicroVM sandbox API.

## Install

```bash
pip install aerolvm-sdk
```

For local development from this repository:

```bash
cd sdk/python
pip install .
```

## Usage

```python
from microvm import MicroVM

client = MicroVM(pat_token="${SB_PAT_TOKEN}", api_url="https://sandbox.example.com")
health = client.health()
print(health)
print(health["sshGateway"])

sandbox = client.create(
	{
		"image": "ghcr.io/aerol-ai/ubuntu:22.04",
		"lifecycle": {
			"stopIfIdleFor": 3_600_000_000_000,
			"destroyAtAge": 86_400_000_000_000,
		},
		"failover": {"policy": "recreate"},
		"mounts": [
			{
				"type": "s3",
				"target": "/workspace",
				"source": "s3://bucket/prefix",
				"credentials": {"access_key_id": "AKIA...", "secret_access_key": "SECRET"},
			}
		],
	}
)
print(sandbox.sshPublicKey)
print(sandbox.sshPrivateKey)  # only returned by create()
print(client.mounts(sandbox.id))

sandbox.update_lifecycle(
	{
		"stopIfIdleFor": 7_200_000_000_000,
		"destroyAtAge": 172_800_000_000_000,
	}
)
print(sandbox.lifecycle)
```

## Build Images

```python
from microvm import Image, MicroVM

client = MicroVM(pat_token="${SB_PAT_TOKEN}", api_url="https://sandbox.example.com")
image = Image.base("ubuntu:22.04").run_commands("apt-get update", "apt-get install -y curl")

# create() accepts an Image directly
sandbox = client.create({"image": image})

# or build it explicitly and reuse the content-addressed tag
tag = client.build_image(image)
print(tag)
```

## Example

```bash
python examples/create_sandbox.py --api-url http://127.0.0.1:21212 --pat-token test --image ghcr.io/aerol-ai/ubuntu:22.04
```

## Streaming exec
```python
import sys

handle = sandbox.exec_stream(
	{
		"command": "bash",
		"tty": True,
		"cols": 120,
		"rows": 40,
		"onStdout": lambda chunk: sys.stdout.buffer.write(chunk),
	}
)

handle.write("echo hello\n")
result = handle.wait()
print(result)
```

## Sessions

```python
import sys

session = sandbox.create_session(
	{
		"name": "shell",
		"command": "bash",
		"workDir": "/workspace",
		"pty": True,
		"cols": 120,
		"rows": 40,
	}
)

print(session)
print(sandbox.list_sessions())
print(sandbox.session_log(session["id"]).decode("utf-8"))

handle = sandbox.attach_session(
	session["id"],
	{
		"cols": 120,
		"rows": 40,
		"onStdout": lambda chunk: sys.stdout.buffer.write(chunk),
	}
)
handle.write("echo attached\n")
print(handle.wait())
```
