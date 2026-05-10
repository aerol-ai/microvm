# AerolVM Java SDK

A Java client for the Aerol.ai MicroVM sandbox API.

## Build

```bash
mvn -f sdk/java/pom.xml test
```

## Install

The release workflow publishes the package to GitHub Packages as `ai.aerol:aerolvm-sdk`.

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
    <version>0.1.5</version>
  </dependency>
</dependencies>
```

GitHub Packages requires credentials to consume Maven artifacts. Use a GitHub token with `read:packages` and configure it in your Maven `settings.xml` under the `github` server id.

## Usage

```java
import ai.aerol.microvm.MicroVMClient;
import ai.aerol.microvm.MicroVMConfig;
import ai.aerol.microvm.Sandbox;
import ai.aerol.microvm.model.CreateOptions;
import ai.aerol.microvm.model.Lifecycle;
import ai.aerol.microvm.model.MountSpec;

MicroVMClient client = new MicroVMClient(
    new MicroVMConfig()
        .setApiUrl("https://sandbox.example.com")
        .setPatToken(System.getenv("SB_PAT_TOKEN"))
);

Sandbox sandbox = client.create(
    new CreateOptions()
        .setImage("ghcr.io/aerol-ai/ubuntu:22.04")
        .setLifecycle(new Lifecycle()
            .setStopIfIdleFor(3_600_000_000_000L)
            .setDestroyAtAge(86_400_000_000_000L))
        .setMounts(java.util.List.of(
            new MountSpec()
                .setType("s3")
                .setTarget("/workspace")
                .setSource("s3://bucket/prefix")
        ))
);

System.out.println(sandbox.publicUrl);
System.out.println(sandbox.sshPublicKey);
System.out.println(sandbox.sshPrivateKey); // only returned by create()
System.out.println(client.health().sshGateway);

sandbox.updateLifecycle(
    new Lifecycle()
        .setStopIfIdleFor(7_200_000_000_000L)
        .setDestroyAtAge(172_800_000_000_000L)
);
```

## Streaming Exec

```java
import ai.aerol.microvm.model.ExecExitInfo;
import ai.aerol.microvm.model.ExecStreamOptions;

var handle = sandbox.execStream(
    new ExecStreamOptions()
        .setCommand("bash")
        .setTty(true)
        .setCols(120)
        .setRows(40)
        .setOnStdout(chunk -> System.out.print(new String(chunk, java.nio.charset.StandardCharsets.UTF_8)))
);

handle.write("echo hello\n");
ExecExitInfo exit = handle.waitForExit();
System.out.println(exit.code);
```

## Sessions

```java
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
System.out.println(new String(sandbox.sessionLog(session.id), java.nio.charset.StandardCharsets.UTF_8));

var attach = sandbox.attachSession(
    session.id,
    new SessionAttachOptions()
        .setCols(120)
        .setRows(40)
        .setOnStdout(chunk -> System.out.print(new String(chunk, java.nio.charset.StandardCharsets.UTF_8)))
);

attach.write("echo attached\n");
attach.waitForExit();
```