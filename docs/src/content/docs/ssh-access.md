title: SSH Access

AerolVM runs an SSH gateway on port `2220` (configurable via `SB_SSH_LISTEN_ADDR`). Each sandbox is provisioned with a unique Ed25519 key pair on creation. The private key is returned **only** in the create response and is not stored by the server.

## Key Provisioning

When a sandbox is created, the API response includes:

```json
{
  "id": "sandbox_abc123",
  "ssh_public_key": "ssh-ed25519 AAAA...",
  "ssh_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n..."
}
```

Save `ssh_private_key` - it is not retrievable later. The `ssh_public_key` field is returned by the get and list endpoints.

## Connecting

The SSH username encodes the sandbox ID and an optional session name:

| Username format | Behavior |
|---|---|
| `<sandbox-id>` | Attach to the default session |
| `<sandbox-id>+<name>` | Attach to the named session |

```bash
# Save the private key from the create response
echo "$SSH_PRIVATE_KEY" > ~/.ssh/sandbox_key
chmod 600 ~/.ssh/sandbox_key

# Connect to the default session
ssh -i ~/.ssh/sandbox_key -p 2220 sandbox_abc123@<host>

# Connect to a named session
ssh -i ~/.ssh/sandbox_key -p 2220 sandbox_abc123+myshell@<host>
```

## Configuration

| Environment Variable | Default | Description |
|---|---|---|
| `SB_ENABLE_SSH_GATEWAY` | `true` | Enable or disable the SSH gateway. |
| `SB_SSH_LISTEN_ADDR` | `0.0.0.0:2220` | Address and port for the SSH server. |
| `SB_SSH_HOST_KEY_PATH` | `/var/lib/aerolvm/ssh_host_ed25519_key` | Host key path. Generated on first start if absent. |

## SDK Usage

```ts
// TypeScript - retrieve public key after creation
const sandbox = await client.create({ image: 'ubuntu:22.04' })
console.log(sandbox.sshPrivateKey)  // save this
console.log(sandbox.sshPublicKey)   // available later via get()
```

```python
# Python
sandbox = client.create(image='ubuntu:22.04')
private_key = sandbox['ssh_private_key']  # save - only returned on create
```

```go
// Go
sandbox, err := client.Create(ctx, microvm.CreateOptions{
    Image: "ubuntu:22.04",
})
privateKey := sandbox.SSHPrivateKey // save - only returned on create
```

```java
// Java
Sandbox sandbox = client.create(new CreateOptions().setImage("ubuntu:22.04"));
String privateKey = sandbox.sshPrivateKey; // save - only returned on create
```

## How the Gateway Works

The gateway listens on `SB_SSH_LISTEN_ADDR`. On each connection it:

1. Parses the SSH username to extract the sandbox ID and session name.
2. Looks up the sandbox and retrieves the stored public key.
3. Validates the client's public key against the sandbox-specific key (public key auth only; password auth is disabled).
4. Bridges the SSH channel into a terminal session inside the sandbox.

Each sandbox accepts exactly one authorized key. There is no shared host-level access.
