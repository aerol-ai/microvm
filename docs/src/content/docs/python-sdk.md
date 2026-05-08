---
title: Python SDK
description: Use the Python client for synchronous sandbox lifecycle, exec streaming, file transfer, and sessions.
---

The Python SDK lives under `sdk/python`, publishes as `aerol-ai-microvm-sdk`, and is imported as `microvm`.

## Install

```bash
pip install aerol-ai-microvm-sdk
```

For local development from this repository, `cd sdk/python && pip install .` also works.

## Create A Client

```python
from microvm import MicroVM

client = MicroVM(
    api_url='https://sandbox.example.com',
    pat_token='your-token',
)
```

If you omit either field, the client falls back to `SB_API_URL`, `SB_PAT_TOKEN`, and then `http://127.0.0.1:8080` for the base URL.

## Create And Use A Sandbox

```python
from microvm import MicroVM

client = MicroVM(api_url='https://sandbox.example.com', pat_token='your-token')

sandbox = client.create(
    {
        'image': 'ghcr.io/aerol-ai/ubuntu:22.04',
        'cpu': 1.0,
        'memoryMB': 1024,
        'diskGB': 10,
        'lifecycle': {
            'stopIfIdleFor': 3_600_000_000_000,
            'destroyAtAge': 86_400_000_000_000,
        },
    }
)

result = sandbox.exec_command('echo hello from python')

print(result['stdout'])
print(sandbox.publicURL)
print(sandbox.sshPublicKey)
print(sandbox.sshPrivateKey)  # returned only by create()
```

The `Sandbox` wrapper exposes response fields as attributes and also provides `to_dict()` if you need the raw payload back.

## Streaming Exec And Sessions

```python
import sys

handle = sandbox.exec_stream(
    {
        'command': 'bash',
        'tty': True,
        'cols': 120,
        'rows': 40,
        'onStdout': lambda chunk: sys.stdout.buffer.write(chunk),
    }
)

handle.write('echo streamed\n')
print(handle.wait())
```

```python
session = sandbox.create_session(
    {
        'name': 'shell',
        'command': 'bash',
        'workDir': '/workspace',
        'pty': True,
        'cols': 120,
        'rows': 40,
    }
)

attached = sandbox.attach_session(
    session['id'],
    {
        'cols': 120,
        'rows': 40,
        'onStdout': lambda chunk: sys.stdout.buffer.write(chunk),
    },
)

attached.write('echo attached\n')
print(attached.wait())
```

## Additional Helpers

- `client.health()` returns the daemon status payload, including `sshGateway`.
- `client.mounts(sandbox_id)` returns redacted mount information.
- `sandbox.upload_file()` and `sandbox.download_file()` move bytes through `toolboxd`.
- `sandbox.expose_port()` and `sandbox.unexpose_port()` manage public URLs.
- `sandbox.session_log()` and `sandbox.session_recording()` return raw `bytes`.

Lifecycle fields use integer nanoseconds in Python to match the JSON API.