---
title: File System
description: Upload files into a sandbox and download files from a sandbox using the HTTP API.
---

The sandbox API exposes two endpoints for transferring files between your application and the sandbox. All file operations use the same bearer token as the rest of the API.

## Upload

Send a file into the sandbox:

```http
POST /v1/sandboxes/{id}/toolbox/files/upload?path=/workspace/hello.py
Authorization: Bearer <token>
Content-Type: application/octet-stream

<file bytes>
```

The `path` query parameter specifies the absolute path inside the sandbox. Parent directories are created automatically if they do not exist.

### SDK Usage

```ts
// TypeScript
const content = Buffer.from('print("hello")')
await sandbox.uploadFile('/workspace/hello.py', content)
```

```python
# Python
content = b'print("hello")'
sandbox.upload_file('/workspace/hello.py', content)
```

```go
// Go
content := []byte(`print("hello")`)
err := sandbox.UploadFile(ctx, "/workspace/hello.py", content)
```

```java
// Java
byte[] content = "print(\"hello\")".getBytes();
sandbox.uploadFile("/workspace/hello.py", content);
```

```rust
// Rust
let content = b"print(\"hello\")";
sandbox.upload_file("/workspace/hello.py", content).await?;
```

## Download

Retrieve a file from the sandbox:

```http
GET /v1/sandboxes/{id}/toolbox/files/download?path=/workspace/output.txt
Authorization: Bearer <token>
```

The response body is the raw file bytes.

### SDK Usage

```ts
// TypeScript
const bytes = await sandbox.downloadFile('/workspace/output.txt')
console.log(bytes.toString())
```

```python
# Python
data = sandbox.download_file('/workspace/output.txt')
print(data.decode())
```

```go
// Go
data, err := sandbox.DownloadFile(ctx, "/workspace/output.txt")
```

```java
// Java
byte[] data = sandbox.downloadFile("/workspace/output.txt");
```

```rust
// Rust
let data = sandbox.download_file("/workspace/output.txt").await?;
```

## Common Patterns

### Run a Script

```ts
await sandbox.uploadFile('/run.sh', Buffer.from('#!/bin/bash\necho hello'))
const result = await sandbox.exec({ command: 'bash /run.sh' })
console.log(result.stdout)
```

### Retrieve Generated Output

```ts
await sandbox.exec({ command: 'python3 -c "import json; json.dump({\'x\': 1}, open(\'/out.json\', \'w\'))"' })
const bytes = await sandbox.downloadFile('/out.json')
const data = JSON.parse(bytes.toString())
```

## Limits

File uploads are limited to 256 MB by default. For larger transfers, use [External Storage](/external-storage) to mount an S3 bucket or NFS share directly into the sandbox.
