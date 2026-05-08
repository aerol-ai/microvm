---
title: Java SDK
description: Use the Java client for sandbox lifecycle management, exec streaming, file transfer, and persistent sessions.
---

The Java SDK lives under `sdk/java` and publishes to GitHub Packages as `ai.aerol:aerolvm-sdk`.

## Install

Add the GitHub Packages repository and the dependency to your `pom.xml`:

```xml
<repositories>
  <repository>
    <id>github</id>
    <url>https://maven.pkg.github.com/aerol-ai/microvm</url>
  </repository>
</repositories>

<dependencies>
  <dependency>
    <groupId>ai.aerol</groupId>
    <artifactId>aerolvm-sdk</artifactId>
    <version>0.1.1</version>
  </dependency>
</dependencies>
```

GitHub Packages requires credentials. Add a GitHub token with `read:packages` to your Maven `settings.xml`:

```xml
<servers>
  <server>
    <id>github</id>
    <username>YOUR_GITHUB_USERNAME</username>
    <password>YOUR_GITHUB_TOKEN</password>
  </server>
</servers>
```

## Create a Client

```java
import ai.aerol.microvm.MicroVMClient;
import ai.aerol.microvm.MicroVMConfig;

MicroVMClient client = new MicroVMClient(
    new MicroVMConfig()
        .setApiUrl("https://sandbox.example.com")
        .setPatToken(System.getenv("SB_PAT_TOKEN"))
);
```

## Sandbox Lifecycle

```java
import ai.aerol.microvm.Sandbox;
import ai.aerol.microvm.model.CreateOptions;
import ai.aerol.microvm.model.Lifecycle;

Sandbox sandbox = client.create(
    new CreateOptions()
        .setImage("ubuntu:22.04")
        .setLifecycle(new Lifecycle()
            .setStopIfIdleFor(3_600_000_000_000L)
            .setDestroyAtAge(86_400_000_000_000L))
);

System.out.println(sandbox.id);
System.out.println(sandbox.publicUrl);
System.out.println(sandbox.sshPrivateKey); // only returned by create()

// Update lifecycle parameters
sandbox.updateLifecycle(
    new Lifecycle()
        .setStopIfIdleFor(7_200_000_000_000L)
        .setDestroyAtAge(172_800_000_000_000L)
);

sandbox.stop();
sandbox.start();
sandbox.destroy();
```

## Execute a Command

```java
import ai.aerol.microvm.model.ExecOptions;
import ai.aerol.microvm.model.ExecResult;

ExecResult result = sandbox.exec(
    new ExecOptions().setCommand("echo hello")
);

System.out.println(result.stdout); // "hello\n"
System.out.println(result.exitCode); // 0
```

## Streaming Exec

Open a WebSocket connection that streams stdout/stderr live and accepts stdin:

```java
import ai.aerol.microvm.ExecStreamHandle;
import ai.aerol.microvm.model.ExecExitInfo;
import ai.aerol.microvm.model.ExecStreamOptions;

ExecStreamHandle handle = sandbox.execStream(
    new ExecStreamOptions()
        .setCommand("bash")
        .setTty(true)
        .setCols(120)
        .setRows(40)
        .setOnStdout(chunk ->
            System.out.print(new String(chunk, java.nio.charset.StandardCharsets.UTF_8)))
);

handle.write("echo hello\n");
ExecExitInfo exit = handle.waitForExit();
System.out.println(exit.code);
```

## File Transfer

```java
// Upload
byte[] content = "print(\"hello\")".getBytes();
sandbox.uploadFile("/workspace/hello.py", content);

// Download
byte[] data = sandbox.downloadFile("/workspace/hello.py");
System.out.println(new String(data));
```

## Sessions

Sessions are persistent processes that survive WebSocket disconnects:

```java
import ai.aerol.microvm.SessionAttachHandle;
import ai.aerol.microvm.model.CreateSessionOptions;
import ai.aerol.microvm.model.Session;
import ai.aerol.microvm.model.SessionAttachOptions;

Session session = sandbox.createSession(
    new CreateSessionOptions()
        .setName("shell")
        .setCommand("bash")
        .setWorkDir("/workspace")
        .setPty(true)
        .setCols(120)
        .setRows(40)
);

System.out.println(session.id);

// Retrieve buffered output without attaching
byte[] log = sandbox.sessionLog(session.id);
System.out.println(new String(log));

// Attach and interact
SessionAttachHandle attach = sandbox.attachSession(
    session.id,
    new SessionAttachOptions()
        .setCols(120)
        .setRows(40)
        .setOnStdout(chunk ->
            System.out.print(new String(chunk, java.nio.charset.StandardCharsets.UTF_8)))
);

attach.write("echo attached\n");
attach.waitForExit();
```

## Port Exposure

```java
var result = sandbox.exposePort(3000);
System.out.println(result.url);

sandbox.unexposePort(3000);
```

## External Storage

```java
import ai.aerol.microvm.model.MountSpec;

Sandbox sandbox = client.create(
    new CreateOptions()
        .setImage("ubuntu:22.04")
        .setMounts(java.util.List.of(
            new MountSpec()
                .setType("s3")
                .setTarget("/workspace")
                .setSource("s3://my-bucket/prefix")
        ))
);
```

## Health Check

```java
var health = client.health();
System.out.println(health.sshGateway); // true if SSH gateway is up
```
