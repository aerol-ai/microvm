---
title: Go SDK
---

The Go SDK lives under `sdk/go` and is imported as `github.com/aerol-ai/microvm/sdk/go/pkg/microvm`.

## Install

```bash
go get github.com/aerol-ai/microvm/sdk/go/pkg/microvm@latest
```

To pin a specific release, use the repository tag, for example:

```bash
go get github.com/aerol-ai/microvm/sdk/go/pkg/microvm@v0.1.1
```

The Go SDK does not have a separate package manifest version under `sdk/go`. Its version comes from repository tags because it is part of the root Go module.

The request and response types are re-exported from `github.com/aerol-ai/microvm/sdk/go/pkg/types`.

## Create A Client

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

func main() {
	client, err := microvm.NewClientWithConfig(&sdktypes.MicroVMConfig{
		APIUrl:   os.Getenv("SB_API_URL"),
		PATToken: os.Getenv("SB_PAT_TOKEN"),
	})
	if err != nil {
		log.Fatal(err)
	}

	sandbox, err := client.Create(context.Background(), sdktypes.CreateSandboxOptions{
		Image:    "ghcr.io/aerol-ai/ubuntu:22.04",
		CPU:      1,
		MemoryMB: 1024,
		DiskGB:   10,
		Lifecycle: &sdktypes.Lifecycle{
			StopIfIdleFor: time.Hour,
			DestroyAtAge:  24 * time.Hour,
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(sandbox.ID, sandbox.PublicURL)
	fmt.Println(sandbox.SSHPublicKey)
	fmt.Println(sandbox.SSHPrivateKey) // returned only by Create
}
```

`microvm.NewClient()` is also available and reads `SB_PAT_TOKEN` and `SB_API_URL` from the environment.

## Run Commands

```go
result, err := sandbox.ExecCommand(context.Background(), "echo hello")
if err != nil {
	log.Fatal(err)
}

fmt.Println(result.Stdout)
```

You can also call `sandbox.Exec()` with a full request object when you need `Workdir`, `Env`, or `TimeoutSeconds`.

## Streaming Exec And Sessions

```go
handle, err := sandbox.ExecStream(context.Background(), sdktypes.ExecStreamOptions{
	Command: "bash",
	TTY:     true,
	Cols:    120,
	Rows:    40,
	OnStdout: func(chunk []byte) {
		fmt.Print(string(chunk))
	},
})
if err != nil {
	log.Fatal(err)
}

if err := handle.WriteString("echo streamed\n"); err != nil {
	log.Fatal(err)
}

exit, err := handle.Wait()
if err != nil {
	log.Fatal(err)
}

fmt.Println(exit.Code, exit.Signal)
```

```go
session, err := sandbox.CreateSession(context.Background(), sdktypes.CreateSessionOptions{
	Name:    "shell",
	Command: "bash",
	Workdir: "/workspace",
	Pty:     true,
	Cols:    120,
	Rows:    40,
})
if err != nil {
	log.Fatal(err)
}

attached, err := sandbox.AttachSession(context.Background(), session.ID, microvm.SessionAttachOptions{
	Cols: 120,
	Rows: 40,
	OnStdout: func(chunk []byte) {
		fmt.Print(string(chunk))
	},
})
if err != nil {
	log.Fatal(err)
}

_ = attached.WriteString("echo attached\n")
code, signal, err := attached.Wait()
fmt.Println(code, signal, err)
```

## Additional Helpers

- `client.Mounts()` returns redacted mount config for a sandbox.
- `sandbox.UploadFile()` and `sandbox.DownloadFile()` transfer files to and from the sandbox.
- `sandbox.ExposePort()` and `sandbox.UnexposePort()` manage public URLs.
- `sandbox.SessionLog()` and `sandbox.SessionRecording()` return raw bytes.

Because the Go SDK reuses the server models, lifecycle values are plain `time.Duration` fields instead of raw nanosecond integers.