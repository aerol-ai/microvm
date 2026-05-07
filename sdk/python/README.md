# Aerol.ai MicroVM Python SDK

A lightweight Python SDK for the Aerol.ai MicroVM sandbox API.

## Install

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
```

## Example

```bash
python examples/create_sandbox.py --api-url http://127.0.0.1:8080 --pat-token test --image ghcr.io/aerol-ai/ubuntu:22.04
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
