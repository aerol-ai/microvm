package ai.aerol.microvm;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import ai.aerol.microvm.internal.JsonSupport;
import ai.aerol.microvm.internal.StreamingWebSocket;
import ai.aerol.microvm.internal.StreamingWebSocketListener;
import ai.aerol.microvm.internal.WebSocketConnector;
import ai.aerol.microvm.model.CreateOptions;
import ai.aerol.microvm.model.CreateSessionOptions;
import ai.aerol.microvm.model.CustomDomain;
import ai.aerol.microvm.model.CustomDomainDnsRecords;
import ai.aerol.microvm.model.CustomDomainStatus;
import ai.aerol.microvm.model.DnsRecord;
import ai.aerol.microvm.model.IngressTarget;
import ai.aerol.microvm.model.ExecExitInfo;
import ai.aerol.microvm.model.ExecRequest;
import ai.aerol.microvm.model.ExecResult;
import ai.aerol.microvm.model.ExecStreamOptions;
import ai.aerol.microvm.model.Failover;
import ai.aerol.microvm.model.Lifecycle;
import ai.aerol.microvm.model.MountSpec;
import ai.aerol.microvm.model.MountSpecRedacted;
import ai.aerol.microvm.model.PlatformVolumeMount;
import ai.aerol.microvm.model.NetworkUsage;
import ai.aerol.microvm.model.RegisterSnapshotOptions;
import ai.aerol.microvm.model.SandboxData;
import ai.aerol.microvm.model.SandboxSnapshot;
import ai.aerol.microvm.model.Session;
import ai.aerol.microvm.model.CreateTemplateOptions;
import ai.aerol.microvm.model.CreateWasmModuleOptions;
import ai.aerol.microvm.model.SessionAttachOptions;
import ai.aerol.microvm.model.SetNetworkLimitsOptions;
import ai.aerol.microvm.model.Template;
import ai.aerol.microvm.model.TemplateStatus;
import ai.aerol.microvm.model.WasmModule;
import ai.aerol.microvm.model.WasmModuleStatus;

class MicroVMClientTest {
    @Test
    void createWithImageBuildsThenCreatesSandbox() throws Exception {
        AtomicReference<Map<String, Object>> buildPayload = new AtomicReference<>();
        AtomicReference<Map<String, Object>> createPayload = new AtomicReference<>();
        HttpServer server = startServer(exchange -> {
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod();
            if ("POST".equals(method) && "/v1/images/build".equals(path)) {
                buildPayload.set(castMap(JsonSupport.read(exchange.getRequestBody().readAllBytes(), Map.class)));
                writeJson(exchange, 200, mapOf("image", "aerolvm-build/abc123:latest"));
                return;
            }
            if ("POST".equals(method) && "/v1/sandboxes".equals(path)) {
                createPayload.set(castMap(JsonSupport.read(exchange.getRequestBody().readAllBytes(), Map.class)));
                writeJson(exchange, 200, mapOf(
                    "id", "sb-from-image",
                    "image", "aerolvm-build/abc123:latest",
                    "status", "started",
                    "public_url", "https://sb-from-image.example.com",
                    "cpu", 2,
                    "memory_mb", 2048,
                    "disk_gb", 20,
                    "os_user", "root",
                    "network_block_all", false,
                    "toolbox_enabled", true,
                    "exposed_ports", List.of(),
                    "created_at", "2026-05-07T10:00:00Z",
                    "updated_at", "2026-05-07T10:00:00Z",
                    "last_active_at", "2026-05-07T10:00:00Z"
                ));
                return;
            }
            throw new AssertionError("unexpected request: " + method + " " + path);
        });

        try {
            MicroVMClient client = clientFor(server);
            Sandbox sandbox = client.createWithImage(
                Image.base("ubuntu:22.04").runCommands("apt-get update", "apt-get install -y curl"),
                new CreateOptions()
            );

            assertEquals(
                mapOf("dockerfile_content", "FROM ubuntu:22.04\nRUN apt-get update\nRUN apt-get install -y curl\n"),
                buildPayload.get()
            );
            assertEquals("aerolvm-build/abc123:latest", createPayload.get().get("image"));
            assertEquals("sb-from-image", sandbox.id);
        } finally {
            server.stop(0);
        }
    }

    @Test
    void buildImageMaps404ToActionableError() throws Exception {
        HttpServer server = startServer(exchange -> {
            writeResponse(exchange, 404, "text/plain", "404 page not found\n".getBytes(StandardCharsets.UTF_8));
        });

        try {
            MicroVMClient client = clientFor(server);
            MicroVMException error = assertThrows(MicroVMException.class, () -> client.buildImage(Image.base("alpine")));
            assertTrue(error.getMessage().contains("does not support Image builds"));
            assertTrue(error.getMessage().contains("string image reference"));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void buildImageWithPushForwardsPushOptionsAndReturnsPushedRef() throws Exception {
        AtomicReference<Map<String, Object>> seenBody = new AtomicReference<>();
        HttpServer server = startServer(exchange -> {
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod();
            if ("POST".equals(method) && "/v1/images/build".equals(path)) {
                seenBody.set(castMap(JsonSupport.read(exchange.getRequestBody().readAllBytes(), Map.class)));
                writeJson(exchange, 200, mapOf(
                    "image", "aerolvm-build/abc123:latest",
                    "pushed", "ghcr.io/x/y:v1"
                ));
                return;
            }
            throw new AssertionError("unexpected request: " + method + " " + path);
        });

        try {
            MicroVMClient client = clientFor(server);
            ai.aerol.microvm.model.BuildImageResult result = client.buildImage(
                Image.base("alpine"),
                new ai.aerol.microvm.model.BuildImageOptions().setPush(
                    new ai.aerol.microvm.model.BuildImagePushOptions()
                        .setRegistry("ghcr.io/x/y")
                        .setTag("v1")
                        .setServer("ghcr.io")
                        .setUsername("u")
                        .setPassword("p")
                )
            );

            assertEquals("aerolvm-build/abc123:latest", result.image);
            assertEquals("ghcr.io/x/y:v1", result.pushed);

            Map<String, Object> body = seenBody.get();
            assertEquals("FROM alpine\n", body.get("dockerfile_content"));
            Map<?, ?> push = (Map<?, ?>) body.get("push");
            assertNotNull(push);
            assertEquals("ghcr.io/x/y", push.get("registry"));
            assertEquals("v1", push.get("tag"));
            assertEquals("ghcr.io", push.get("server"));
            assertEquals("u", push.get("username"));
            assertEquals("p", push.get("password"));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void cloneGenerationReadsTokenViaToolboxProxy() throws Exception {
        AtomicReference<String> seenPath = new AtomicReference<>();
        AtomicReference<String> seenMethod = new AtomicReference<>();
        HttpServer server = startServer(exchange -> {
            seenMethod.set(exchange.getRequestMethod());
            seenPath.set(exchange.getRequestURI().getPath());
            writeJson(exchange, 200, mapOf(
                "generation", "2d0d8c69",
                "resumed_at", 1700000000000000000L
            ));
        });

        try {
            MicroVMClient client = clientFor(server);
            ai.aerol.microvm.model.CloneGeneration gen = client.cloneGeneration("sb-clone");

            assertEquals("GET", seenMethod.get());
            assertEquals("/v1/sandboxes/sb-clone/toolbox/clone-generation", seenPath.get());
            assertEquals("2d0d8c69", gen.generation);
            assertEquals(1700000000000000000L, gen.resumedAt);
        } finally {
            server.stop(0);
        }
    }

    @Test
    void buildImageWithPushRejectsMissingCredentialsClientSide() throws Exception {
        // No HTTP server: validation must throw before any wire call. If a
        // request leaks out, the HttpClient will fail with a connect error
        // and the test will surface that instead of the expected message.
        HttpServer server = startServer(exchange -> {
            throw new AssertionError("must not call daemon: " + exchange.getRequestURI());
        });

        try {
            MicroVMClient client = clientFor(server);

            MicroVMException missingRegistry = assertThrows(MicroVMException.class, () -> client.buildImage(
                Image.base("alpine"),
                new ai.aerol.microvm.model.BuildImageOptions().setPush(
                    new ai.aerol.microvm.model.BuildImagePushOptions()
                        .setUsername("u").setPassword("p")
                )
            ));
            assertTrue(missingRegistry.getMessage().contains("registry"));

            MicroVMException missingUser = assertThrows(MicroVMException.class, () -> client.buildImage(
                Image.base("alpine"),
                new ai.aerol.microvm.model.BuildImageOptions().setPush(
                    new ai.aerol.microvm.model.BuildImagePushOptions()
                        .setRegistry("ghcr.io/x/y").setPassword("p")
                )
            ));
            assertTrue(missingUser.getMessage().contains("username"));

            MicroVMException missingPass = assertThrows(MicroVMException.class, () -> client.buildImage(
                Image.base("alpine"),
                new ai.aerol.microvm.model.BuildImageOptions().setPush(
                    new ai.aerol.microvm.model.BuildImagePushOptions()
                        .setRegistry("ghcr.io/x/y").setUsername("u")
                )
            ));
            assertTrue(missingPass.getMessage().contains("password"));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void newClientUsesEnvironmentConfig() throws Exception {
        AtomicReference<String> authorization = new AtomicReference<>();
        HttpServer server = startServer(exchange -> {
            authorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            writeResponse(exchange, 200, "application/json", "[]".getBytes(StandardCharsets.UTF_8));
        });

        try {
            String apiUrl = serverUrl(server);
            Map<String, String> environment = Map.of(
                "SB_PAT_TOKEN", "env-pat",
                "SB_API_URL", apiUrl
            );
            MicroVMClient client = new MicroVMClient(new MicroVMConfig(), HttpClient.newHttpClient(), new FakeWebSocketConnector(), environment::get);

            assertEquals(apiUrl, client.getApiUrl());
            client.list();
            assertEquals("Bearer env-pat", authorization.get());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void getAndListIncludeEnvQuery() throws Exception {
        AtomicReference<String> seenPath = new AtomicReference<>();
        AtomicReference<String> seenQuery = new AtomicReference<>();
        HttpServer server = startServer(exchange -> {
            seenPath.set(exchange.getRequestURI().getPath());
            seenQuery.set(exchange.getRequestURI().getRawQuery());
            if (exchange.getRequestURI().getPath().endsWith("/sandboxes")) {
                writeResponse(exchange, 200, "application/json", "[]".getBytes(StandardCharsets.UTF_8));
                return;
            }
            writeJson(exchange, 200, mapOf("id", "sb-1"));
        });
        try {
            MicroVMClient client = clientFor(server);
            client.get("sb-1", true);
            assertEquals("/v1/sandboxes/sb-1", seenPath.get());
            assertEquals("include_env=true", seenQuery.get());

            Map<String, String> tags = new HashMap<>();
            tags.put("team", "a");
            client.list(tags, true);
            assertEquals("/v1/sandboxes", seenPath.get());
            assertTrue(seenQuery.get().contains("include_env=true"));
            assertTrue(seenQuery.get().contains("tag.team=a"));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void createMapsRequestAndResponseShapes() throws Exception {
        AtomicReference<Map<String, Object>> requestBody = new AtomicReference<>();
        HttpServer server = startServer(exchange -> {
            assertEquals("POST", exchange.getRequestMethod());
            assertEquals("/v1/sandboxes", exchange.getRequestURI().getPath());
            requestBody.set(castMap(JsonSupport.read(exchange.getRequestBody().readAllBytes(), Map.class)));
            writeJson(exchange, 200, mapOf(
                "id", "sb-create",
                "image", "ubuntu:22.04",
                "status", "started",
                "public_url", "https://sb-create.example.com",
                "container_id", "container-sb-create",
                "container_ip", "10.0.0.10",
                "cpu", 2,
                "memory_mb", 2048,
                "disk_gb", 20,
                "os_user", "root",
                "env", mapOf("KEY", "VALUE"),
                "network_block_all", true,
                "toolbox_enabled", true,
                "ssh_public_key", "ssh-ed25519 AAAA sandbox",
                "ssh_private_key", "PRIVATE",
                "exposed_ports", List.of(),
                "created_at", "2026-05-07T10:00:00Z",
                "updated_at", "2026-05-07T10:00:00Z",
                "last_active_at", "2026-05-07T10:00:00Z",
                "lifecycle", mapOf(
                    "stop_if_idle_for", 3_600_000_000_000L,
                    "destroy_at_age", 86_400_000_000_000L
                ),
                "failover", mapOf("policy", "recreate")
            ));
        });

        try {
            MicroVMClient client = clientFor(server);
            Sandbox sandbox = client.create(
                new CreateOptions()
                    .setImage("ubuntu:22.04")
                    .setMemoryMb(2048)
                    .setNetworkBlockAll(true)
                    .setNetworkAllowOut(List.of("1.1.1.0/24", "8.8.8.8/32"))
                    .setAllowPublicTraffic(false)
                    .setMaskRequestHost("localhost")
                    .setMounts(List.of(
                        new MountSpec()
                            .setType("s3")
                            .setTarget("/workspace")
                            .setSource("s3://bucket/prefix")
                    ))
                    .setPlatformVolumes(List.of(
                        new PlatformVolumeMount().setName("data").setPath("/workspace"),
                        new PlatformVolumeMount().setName("cache").setPath("/cache").setReadOnly(true)
                    ))
                    .setLifecycle(new Lifecycle()
                        .setStopIfIdleFor(3_600_000_000_000L)
                        .setDestroyAtAge(86_400_000_000_000L))
                    .setFailover(new Failover().setPolicy("recreate"))
            );

            assertEquals("sb-create", sandbox.id);
            assertEquals("PRIVATE", sandbox.sshPrivateKey);
            assertEquals("ssh-ed25519 AAAA sandbox", sandbox.sshPublicKey);
            assertEquals(2048, sandbox.memoryMb);
            assertEquals(3_600_000_000_000L, sandbox.lifecycle.stopIfIdleFor);
            assertEquals(86_400_000_000_000L, sandbox.lifecycle.destroyAtAge);
            assertNotNull(sandbox.failover);
            assertEquals("recreate", sandbox.failover.policy);

            Map<String, Object> payload = requestBody.get();
            assertEquals("ubuntu:22.04", payload.get("image"));
            assertEquals(2048, ((Number) payload.get("memory_mb")).intValue());
            assertEquals(Boolean.TRUE, payload.get("network_block_all"));
            assertEquals(List.of("1.1.1.0/24", "8.8.8.8/32"), payload.get("network_allow_out"));
            assertEquals(Boolean.FALSE, payload.get("allow_public_traffic"));
            assertEquals("localhost", payload.get("mask_request_host"));
            Map<String, Object> lifecycle = castMap(payload.get("lifecycle"));
            assertEquals(3_600_000_000_000L, ((Number) lifecycle.get("stop_if_idle_for")).longValue());
            assertEquals(86_400_000_000_000L, ((Number) lifecycle.get("destroy_at_age")).longValue());
            Map<String, Object> failover = castMap(payload.get("failover"));
            assertEquals("recreate", failover.get("policy"));
            List<?> platformVolumes = (List<?>) payload.get("platform_volumes");
            assertEquals(2, platformVolumes.size());
            Map<String, Object> firstVolume = castMap(platformVolumes.get(0));
            assertEquals("data", firstVolume.get("name"));
            assertEquals("/workspace", firstVolume.get("path"));
            assertNull(firstVolume.get("read_only"));
            Map<String, Object> secondVolume = castMap(platformVolumes.get(1));
            assertEquals(Boolean.TRUE, secondVolume.get("read_only"));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void createOmitsAllowPublicTrafficWhenUnset() throws Exception {
        AtomicReference<Map<String, Object>> requestBody = new AtomicReference<>();
        HttpServer server = startServer(exchange -> {
            requestBody.set(castMap(JsonSupport.read(exchange.getRequestBody().readAllBytes(), Map.class)));
            writeJson(exchange, 200, mapOf(
                "id", "sb-private-default",
                "image", "ubuntu:22.04",
                "status", "started",
                "public_url", "",
                "cpu", 1,
                "memory_mb", 1024,
                "disk_gb", 10,
                "os_user", "root",
                "network_block_all", false,
                "toolbox_enabled", true,
                "exposed_ports", List.of(),
                "created_at", "2026-05-24T10:00:00Z",
                "updated_at", "2026-05-24T10:00:00Z",
                "last_active_at", "2026-05-24T10:00:00Z"
            ));
        });

        try {
            MicroVMClient client = clientFor(server);
            client.create(new CreateOptions().setImage("ubuntu:22.04"));
            assertNull(requestBody.get().get("allow_public_traffic"));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void createRoundTripsServerlessLifecycleFlag() throws Exception {
        AtomicReference<Map<String, Object>> requestBody = new AtomicReference<>();
        HttpServer server = startServer(exchange -> {
            requestBody.set(castMap(JsonSupport.read(exchange.getRequestBody().readAllBytes(), Map.class)));
            writeJson(exchange, 200, mapOf(
                "id", "sb-serverless",
                "image", "ubuntu:22.04",
                "status", "started",
                "public_url", "https://sb-serverless.example.com",
                "cpu", 1,
                "memory_mb", 1024,
                "disk_gb", 10,
                "os_user", "root",
                "network_block_all", false,
                "toolbox_enabled", true,
                "exposed_ports", List.of(),
                "created_at", "2026-05-24T10:00:00Z",
                "updated_at", "2026-05-24T10:00:00Z",
                "last_active_at", "2026-05-24T10:00:00Z",
                "lifecycle", mapOf(
                    "stop_if_idle_for", 300_000_000_000L,
                    "serverless", true
                )
            ));
        });

        try {
            MicroVMClient client = clientFor(server);
            Sandbox sandbox = client.create(
                new CreateOptions()
                    .setImage("ubuntu:22.04")
                    .setLifecycle(new Lifecycle()
                        .setStopIfIdleFor(300_000_000_000L)
                        .setServerless(Boolean.TRUE))
            );

            Map<String, Object> payload = requestBody.get();
            Map<String, Object> lifecycle = castMap(payload.get("lifecycle"));
            assertEquals(Boolean.TRUE, lifecycle.get("serverless"));
            assertEquals(300_000_000_000L, ((Number) lifecycle.get("stop_if_idle_for")).longValue());
            assertEquals(Boolean.TRUE, sandbox.lifecycle.serverless);
        } finally {
            server.stop(0);
        }
    }

    @Test
    void createSnapshotMapsRequestAndResponseShapes() throws Exception {
        List<Map<String, Object>> requestBodies = new ArrayList<>();
        HttpServer server = startServer(exchange -> {
            assertEquals("POST", exchange.getRequestMethod());
            assertEquals("/v1/sandboxes/sb-1/snapshot", exchange.getRequestURI().getPath());
            Map<String, Object> request = castMap(JsonSupport.read(exchange.getRequestBody().readAllBytes(), Map.class));
            requestBodies.add(request);
            String name = String.valueOf(request.get("name"));
            writeJson(exchange, 200, mapOf(
                "name", name,
                "image", name,
                "image_id", "sha256:snap-1",
                "source_sandbox_id", "sb-1",
                "created_at", "2026-05-14T10:00:00Z"
            ));
        });

        try {
            MicroVMClient client = clientFor(server);
            SandboxSnapshot snapshot = client.createSnapshot("sb-1", "snapshots/demo:v1");
            Sandbox sandbox = new Sandbox(client, new SandboxData());
            sandbox.id = "sb-1";
            SandboxSnapshot sandboxSnapshot = sandbox.createSnapshot("snapshots/from-sandbox:v1");

            assertEquals(2, requestBodies.size());
            assertEquals("snapshots/demo:v1", requestBodies.get(0).get("name"));
            assertEquals("snapshots/from-sandbox:v1", requestBodies.get(1).get("name"));
            assertEquals("snapshots/demo:v1", snapshot.name);
            assertEquals("sha256:snap-1", snapshot.imageId);
            assertEquals("sb-1", snapshot.sourceSandboxId);
            assertEquals("snapshots/from-sandbox:v1", sandboxSnapshot.name);
        } finally {
            server.stop(0);
        }
    }

    @Test
    void registerSnapshotMapsRequestAndResponseShapes() throws Exception {
        AtomicReference<Map<String, Object>> requestBody = new AtomicReference<>();
        HttpServer server = startServer(exchange -> {
            assertEquals("POST", exchange.getRequestMethod());
            assertEquals("/v1/snapshots", exchange.getRequestURI().getPath());
            requestBody.set(castMap(JsonSupport.read(exchange.getRequestBody().readAllBytes(), Map.class)));
            writeJson(exchange, 201, mapOf(
                "name", "py-base",
                "image", "python:3.12-slim",
                "image_id", "sha256:snap-2",
                "source_sandbox_id", "",
                "created_at", "2026-05-15T10:00:00Z",
                "region_id", "us",
                "cpu", 2.0,
                "gpu", 1.0,
                "memory_mb", 4096,
                "disk_gb", 10
            ));
        });

        try {
            MicroVMClient client = clientFor(server);
            SandboxSnapshot snapshot = client.registerSnapshot(
                new RegisterSnapshotOptions()
                    .setName("py-base")
                    .setImage("python:3.12-slim")
                    .setRegionId("us")
                    .setCpu(2.0)
                    .setGpu(1.0)
                    .setMemoryMb(4096)
                    .setDiskGb(10)
            );

            Map<String, Object> payload = requestBody.get();
            assertEquals("py-base", payload.get("name"));
            assertEquals("python:3.12-slim", payload.get("image"));
            assertEquals("us", payload.get("region_id"));
            assertEquals(2.0, ((Number) payload.get("cpu")).doubleValue());
            assertEquals(1.0, ((Number) payload.get("gpu")).doubleValue());
            assertEquals(4096, ((Number) payload.get("memory_mb")).intValue());
            assertEquals(10, ((Number) payload.get("disk_gb")).intValue());
            assertEquals("sha256:snap-2", snapshot.imageId);
            assertEquals("us", snapshot.regionId);
            assertEquals(2.0, snapshot.cpu);
            assertEquals(1.0, snapshot.gpu);
            assertEquals(4096, snapshot.memoryMb);
            assertEquals(10, snapshot.diskGb);
        } finally {
            server.stop(0);
        }
    }

    @Test
    void registerSnapshotFromImageSendsDockerfilePath() throws Exception {
        AtomicReference<Map<String, Object>> requestBody = new AtomicReference<>();
        HttpServer server = startServer(exchange -> {
            assertEquals("POST", exchange.getRequestMethod());
            assertEquals("/v1/snapshots", exchange.getRequestURI().getPath());
            requestBody.set(castMap(JsonSupport.read(exchange.getRequestBody().readAllBytes(), Map.class)));
            writeJson(exchange, 201, mapOf(
                "name", "built",
                "image", "snapshots/built:resolved",
                "image_id", "sha256:snap-3",
                "source_sandbox_id", "",
                "created_at", "2026-05-15T10:00:00Z",
                "entrypoint", List.of("/bin/sh", "-c", "echo hi")
            ));
        });

        try {
            MicroVMClient client = clientFor(server);
            SandboxSnapshot snapshot = client.registerSnapshotFromImage(
                "built",
                Image.base("debian:bookworm-slim").runCommands("apt-get update"),
                new RegisterSnapshotOptions().setEntrypoint(List.of("/bin/sh", "-c", "echo hi"))
            );

            Map<String, Object> payload = requestBody.get();
            assertEquals("built", payload.get("name"));
            assertTrue(payload.containsKey("dockerfile_content"));
            assertTrue(String.valueOf(payload.get("dockerfile_content")).contains("FROM debian:bookworm-slim"));
            assertTrue(String.valueOf(payload.get("dockerfile_content")).contains("RUN apt-get update"));
            assertEquals(false, payload.containsKey("image"));
            assertEquals(List.of("/bin/sh", "-c", "echo hi"), payload.get("entrypoint"));
            assertEquals("snapshots/built:resolved", snapshot.image);
            assertEquals(List.of("/bin/sh", "-c", "echo hi"), snapshot.entrypoint);
        } finally {
            server.stop(0);
        }
    }

    @Test
    void registerSnapshotValidatesInputBeforeSending() throws Exception {
        HttpServer server = startServer(exchange -> {
            throw new AssertionError("validation should fail before the request fires; got " + exchange.getRequestMethod() + " " + exchange.getRequestURI());
        });

        try {
            MicroVMClient client = clientFor(server);

            MicroVMException missingName = assertThrows(MicroVMException.class, () -> client.registerSnapshot(
                new RegisterSnapshotOptions().setImage("alpine")
            ));
            assertTrue(missingName.getMessage().contains("name is required"));

            MicroVMException missingPayload = assertThrows(MicroVMException.class, () -> client.registerSnapshot(
                new RegisterSnapshotOptions().setName("x")
            ));
            assertTrue(missingPayload.getMessage().contains("image or dockerfile_content is required"));

            MicroVMException bothSet = assertThrows(MicroVMException.class, () -> client.registerSnapshot(
                new RegisterSnapshotOptions().setName("x").setImage("alpine").setDockerfileContent("FROM busybox")
            ));
            assertTrue(bothSet.getMessage().contains("mutually exclusive"));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void sandboxSessionMethodsAndMountsMapApiShapes() throws Exception {
        HttpServer server = startServer(exchange -> {
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod();
            if ("GET".equals(method) && "/v1/sandboxes/sb-1/mounts".equals(path)) {
                writeJson(exchange, 200, mapOf(
                    "mounts", List.of(mapOf(
                        "type", "s3",
                        "target", "/workspace",
                        "source", "s3://bucket/prefix",
                        "options", mapOf("region", "us-east-1"),
                        "read_only", true,
                        "has_credentials", true
                    ))
                ));
                return;
            }
            if ("POST".equals(method) && "/v1/sandboxes/sb-1/sessions".equals(path)) {
                Map<String, Object> request = castMap(JsonSupport.read(exchange.getRequestBody().readAllBytes(), Map.class));
                writeJson(exchange, 200, mapOf(
                    "id", "ses-1",
                    "name", request.get("name"),
                    "argv", List.of("sh", "-c", request.get("command")),
                    "workdir", request.get("workdir"),
                    "pty", true,
                    "status", "running",
                    "exit_code", 0,
                    "created_at", "2026-05-07T10:05:00Z",
                    "started_at", "2026-05-07T10:05:01Z",
                    "recording", true,
                    "bytes", 0,
                    "attached", 1
                ));
                return;
            }
            if ("GET".equals(method) && "/v1/sandboxes/sb-1/sessions".equals(path)) {
                writeJson(exchange, 200, mapOf(
                    "sessions", List.of(mapOf(
                        "id", "ses-1",
                        "name", "default",
                        "argv", List.of("bash"),
                        "pty", true,
                        "status", "running",
                        "exit_code", 0,
                        "created_at", "2026-05-07T10:05:00Z",
                        "started_at", "2026-05-07T10:05:01Z",
                        "recording", true,
                        "bytes", 12,
                        "attached", 1
                    ))
                ));
                return;
            }
            if ("GET".equals(method) && "/v1/sandboxes/sb-1/sessions/ses-1".equals(path)) {
                writeJson(exchange, 200, mapOf(
                    "id", "ses-1",
                    "name", "default",
                    "argv", List.of("bash"),
                    "workdir", "/workspace",
                    "pty", true,
                    "status", "running",
                    "exit_code", 0,
                    "created_at", "2026-05-07T10:05:00Z",
                    "started_at", "2026-05-07T10:05:01Z",
                    "recording", true,
                    "bytes", 99,
                    "attached", 2
                ));
                return;
            }
            if ("POST".equals(method) && path.endsWith("/signal")) {
                writeResponse(exchange, 204, "application/json", new byte[0]);
                return;
            }
            if ("POST".equals(method) && path.endsWith("/resize")) {
                writeResponse(exchange, 204, "application/json", new byte[0]);
                return;
            }
            if ("DELETE".equals(method) && path.endsWith("/sessions/ses-1")) {
                writeResponse(exchange, 204, "application/json", new byte[0]);
                return;
            }
            if ("GET".equals(method) && path.endsWith("/log")) {
                writeResponse(exchange, 200, "application/octet-stream", "session log".getBytes(StandardCharsets.UTF_8));
                return;
            }
            if ("GET".equals(method) && path.endsWith("/recording")) {
                writeResponse(exchange, 200, "application/octet-stream", "{\"version\":2}".getBytes(StandardCharsets.UTF_8));
                return;
            }
            throw new AssertionError("unexpected request: " + method + " " + path);
        });

        try {
            MicroVMClient client = clientFor(server);
            Sandbox sandbox = new Sandbox(client, new SandboxData());
            sandbox.id = "sb-1";

            List<MountSpecRedacted> mounts = client.mounts("sb-1");
            Session created = sandbox.createSession(
                new CreateSessionOptions()
                    .setName("default")
                    .setCommand("bash")
                    .setWorkDir("/workspace")
                    .setPty(true)
                    .setCols(120)
                    .setRows(40)
            );
            List<Session> sessions = sandbox.listSessions();
            Session session = sandbox.getSession("ses-1");
            sandbox.signalSession("ses-1", "INT");
            sandbox.resizeSession("ses-1", 120, 40);
            sandbox.deleteSession("ses-1");
            byte[] log = sandbox.sessionLog("ses-1");
            byte[] recording = sandbox.sessionRecording("ses-1");

            assertEquals(1, mounts.size());
            assertEquals("s3", mounts.get(0).type);
            assertTrue(mounts.get(0).hasCredentials);
            assertEquals("ses-1", created.id);
            assertEquals("/workspace", created.workDir);
            assertEquals(1, sessions.size());
            assertEquals("ses-1", session.id);
            assertEquals(99, session.bytes);
            assertArrayEquals("session log".getBytes(StandardCharsets.UTF_8), log);
            assertArrayEquals("{\"version\":2}".getBytes(StandardCharsets.UTF_8), recording);
        } finally {
            server.stop(0);
        }
    }

    @Test
    void networkUsageAndLimitsMapApiShapes() throws Exception {
        AtomicReference<Map<String, Object>> patchBody = new AtomicReference<>();
        AtomicReference<String> patchMethod = new AtomicReference<>();
        HttpServer server = startServer(exchange -> {
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod();
            if ("GET".equals(method) && "/v1/sandboxes/sb-1/network/usage".equals(path)) {
                writeJson(exchange, 200, mapOf(
                    "sandbox_id", "sb-1",
                    "bytes_in", 1024,
                    "bytes_out", 2048,
                    "bytes_in_limit", 1048576,
                    "bytes_out_limit", 0,
                    "quota_exceeded", false,
                    "last_sampled_at", "2026-05-15T10:00:00Z"
                ));
                return;
            }
            if ("PATCH".equals(method) && "/v1/sandboxes/sb-1/network/limits".equals(path)) {
                patchMethod.set(method);
                patchBody.set(castMap(JsonSupport.read(exchange.getRequestBody().readAllBytes(), Map.class)));
                writeJson(exchange, 200, mapOf(
                    "sandbox_id", "sb-1",
                    "bytes_in", 0,
                    "bytes_out", 0,
                    "bytes_in_limit", 4096,
                    "bytes_out_limit", 0,
                    "quota_exceeded", false,
                    "last_sampled_at", "2026-05-15T10:00:00Z"
                ));
                return;
            }
            throw new AssertionError("unexpected request: " + method + " " + path);
        });

        try {
            MicroVMClient client = clientFor(server);
            NetworkUsage usage = client.getNetworkUsage("sb-1");
            assertEquals("sb-1", usage.sandboxId);
            assertEquals(1024, usage.bytesIn);
            assertEquals(0, usage.bytesOutLimit);

            NetworkUsage updated = client.setNetworkLimits(
                "sb-1",
                new SetNetworkLimitsOptions().setNetworkBytesInLimit(4096L)
            );
            assertEquals(4096, updated.bytesInLimit);
            assertEquals("PATCH", patchMethod.get());
            assertEquals(4096, ((Number) patchBody.get().get("network_bytes_in_limit")).longValue());
            assertEquals(1, patchBody.get().size(), "unset fields should not be serialized");
        } finally {
            server.stop(0);
        }
    }

    @Test
    void execHealthAndUploadMapApiShapes() throws Exception {
        AtomicReference<String> multipartBody = new AtomicReference<>();
        AtomicReference<String> multipartContentType = new AtomicReference<>();
        HttpServer server = startServer(exchange -> {
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod();
            if ("POST".equals(method) && "/v1/sandboxes/sb-1/toolbox/process/execute".equals(path)) {
                Map<String, Object> request = castMap(JsonSupport.read(exchange.getRequestBody().readAllBytes(), Map.class));
                assertEquals("echo ok", request.get("command"));
                assertEquals("/workspace", request.get("workdir"));
                assertEquals(2, ((Number) request.get("timeout_seconds")).intValue());
                writeJson(exchange, 200, mapOf(
                    "stdout", "ok",
                    "stderr", "",
                    "exit_code", 0,
                    "duration_ms", 5
                ));
                return;
            }
            if ("GET".equals(method) && "/health".equals(path)) {
                writeJson(exchange, 200, mapOf(
                    "status", "ok",
                    "sandboxes", 1,
                    "docker", "ok",
                    "caddy", "ok",
                    "ssh_gateway", "disabled",
                    "version", "dev"
                ));
                return;
            }
            if ("POST".equals(method) && "/v1/sandboxes/sb-1/toolbox/files/upload".equals(path)) {
                multipartContentType.set(exchange.getRequestHeaders().getFirst("Content-Type"));
                multipartBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
                writeResponse(exchange, 201, "application/json", new byte[0]);
                return;
            }
            throw new AssertionError("unexpected request: " + method + " " + path);
        });

        try {
            MicroVMClient client = clientFor(server);

            ExecResult result = client.exec(
                "sb-1",
                new ExecRequest()
                    .setCommand("echo ok")
                    .setWorkDir("/workspace")
                    .setTimeoutSeconds(2)
            );
            client.uploadFile("sb-1", "/workspace/file.txt", "hello".getBytes(StandardCharsets.UTF_8));

            assertEquals(0, result.exitCode);
            assertEquals(5, result.durationMs);
            assertEquals("disabled", client.health().sshGateway);
            assertNotNull(multipartContentType.get());
            assertTrue(multipartContentType.get().startsWith("multipart/form-data; boundary="));
            assertTrue(multipartBody.get().contains("name=\"path\""));
            assertTrue(multipartBody.get().contains("/workspace/file.txt"));
            assertTrue(multipartBody.get().contains("hello"));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void execStreamUsesWebSocketProtocolAndCallbacks() {
        FakeWebSocketConnector connector = new FakeWebSocketConnector();
        MicroVMClient client = new MicroVMClient(
            new MicroVMConfig().setApiUrl("https://api.example.com").setPatToken("pat-token"),
            HttpClient.newHttpClient(),
            connector,
            name -> null
        );

        List<byte[]> stdout = new ArrayList<>();
        List<byte[]> stderr = new ArrayList<>();
        List<String> errors = new ArrayList<>();

        ExecStreamHandle handle = client.execStream(
            "sb-stream",
            new ExecStreamOptions()
                .setCommand("bash")
                .setTty(true)
                .setCols(120)
                .setRows(40)
                .setOnStdout(stdout::add)
                .setOnStderr(stderr::add)
                .setOnError(errors::add)
        );

        assertEquals(URI.create("wss://api.example.com/v1/sandboxes/sb-stream/toolbox/process/exec/stream"), connector.uri);
        assertEquals("Bearer pat-token", connector.authorizationHeader);
        assertEquals(1, connector.socket.sentTexts.size());

        handle.write("pwd\n");
        handle.resize(120, 40);
        handle.signal("INT");

        connector.emitBinary(new byte[] {1, 'h', 'i'});
        connector.emitBinary(new byte[] {2, 'o', 'k'});
        connector.emitText("{\"type\":\"exit\",\"code\":0}");

        ExecExitInfo exit = handle.waitForExit();
        assertEquals(0, exit.code);
        assertEquals("hi", new String(stdout.get(0), StandardCharsets.UTF_8));
        assertEquals("ok", new String(stderr.get(0), StandardCharsets.UTF_8));
        assertTrue(errors.isEmpty());
        assertEquals("pwd\n", new String(connector.socket.sentBinary.get(0), StandardCharsets.UTF_8));
        assertTrue(connector.socket.sentTexts.get(1).contains("\"type\":\"resize\""));
        assertTrue(connector.socket.sentTexts.get(2).contains("\"type\":\"signal\""));
    }

    @Test
    void attachSessionUsesInitialResizeAndExitCallback() {
        FakeWebSocketConnector connector = new FakeWebSocketConnector();
        MicroVMClient client = new MicroVMClient(
            new MicroVMConfig().setApiUrl("https://api.example.com").setPatToken("pat-token"),
            HttpClient.newHttpClient(),
            connector,
            name -> null
        );

        List<byte[]> stdout = new ArrayList<>();
        AtomicReference<ExecExitInfo> exitSeen = new AtomicReference<>();

        SessionAttachHandle handle = client.attachSession(
            "sb-1",
            "ses-1",
            new SessionAttachOptions()
                .setCols(120)
                .setRows(40)
                .setOnStdout(stdout::add)
                .setOnExit(exitSeen::set)
        );

        assertEquals(URI.create("wss://api.example.com/v1/sandboxes/sb-1/sessions/ses-1/attach"), connector.uri);
        assertEquals(1, connector.socket.sentTexts.size());
        assertTrue(connector.socket.sentTexts.get(0).contains("\"type\":\"resize\""));

        handle.write("echo attached\n");
        handle.signal("TERM");
        connector.emitBinary(new byte[] {1, 'o', 'k'});
        connector.emitText("{\"type\":\"exit\",\"code\":0,\"signal\":\"TERM\"}");

        ExecExitInfo exit = handle.waitForExit();
        assertEquals(0, exit.code);
        assertEquals("TERM", exit.signal);
        assertEquals("ok", new String(stdout.get(0), StandardCharsets.UTF_8));
        assertNotNull(exitSeen.get());
        assertEquals("TERM", exitSeen.get().signal);
    }

    @Test
    void requiresPatTokenWhenConfigAndEnvironmentAreEmpty() {
        MicroVMException error = assertThrows(
            MicroVMException.class,
            () -> new MicroVMClient(new MicroVMConfig(), HttpClient.newHttpClient(), new FakeWebSocketConnector(), name -> null)
        );
        assertTrue(error.getMessage().contains("PAT token is required"));
    }

    // Mirrors pkg/api/v1/list_filter_test.go: tag-filter list calls must
    // emit every pair under the `tag.` prefix the server's parseTagFilter
    // keys on. If this drifts (e.g. someone switches to `tags[user_id]`),
    // the server silently returns the full list and breaks multi-tenant
    // scoping.
    @Test
    void listWithTagsRendersTagDotPrefix() throws Exception {
        AtomicReference<String> seenPath = new AtomicReference<>();
        AtomicReference<String> seenQuery = new AtomicReference<>();
        HttpServer server = startServer(exchange -> {
            seenPath.set(exchange.getRequestURI().getPath());
            seenQuery.set(exchange.getRequestURI().getRawQuery());
            writeJson(exchange, 200, List.of());
        });

        try {
            MicroVMClient client = clientFor(server);
            Map<String, String> tags = new java.util.LinkedHashMap<>();
            tags.put("user_id", "alice");
            tags.put("project_id", "p1");
            client.list(tags);
            assertEquals("/v1/sandboxes", seenPath.get());
            String q = seenQuery.get();
            assertNotNull(q, "expected a query string");
            assertTrue(q.contains("tag.user_id=alice"), "missing tag.user_id=alice: " + q);
            assertTrue(q.contains("tag.project_id=p1"), "missing tag.project_id=p1: " + q);
        } finally {
            server.stop(0);
        }
    }

    // Backward-compat: list() and list(emptyMap) must produce the pre-filter
    // URL byte-for-byte. A stray trailing "?" would break HTTP fixtures and
    // request matchers in downstream code.
    @Test
    void listWithoutTagsOmitsQueryString() throws Exception {
        AtomicReference<String> seenQuery = new AtomicReference<>();
        AtomicInteger calls = new AtomicInteger();
        HttpServer server = startServer(exchange -> {
            seenQuery.set(exchange.getRequestURI().getRawQuery());
            calls.incrementAndGet();
            writeJson(exchange, 200, List.of());
        });

        try {
            MicroVMClient client = clientFor(server);
            client.list();
            assertEquals(null, seenQuery.get());
            client.list(java.util.Collections.emptyMap());
            assertEquals(null, seenQuery.get());
            client.list(null);
            assertEquals(null, seenQuery.get());
            assertEquals(3, calls.get());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void customDomainsAddListAndRemoveMapApiShapes() throws Exception {
        AtomicReference<Map<String, Object>> addBody = new AtomicReference<>();
        AtomicReference<String> deletePath = new AtomicReference<>();
        AtomicInteger deleteCalls = new AtomicInteger();
        HttpServer server = startServer(exchange -> {
            String path = exchange.getRequestURI().getRawPath();
            String method = exchange.getRequestMethod();
            if ("POST".equals(method) && "/v1/sandboxes/sb-1/custom-domains".equals(path)) {
                addBody.set(castMap(JsonSupport.read(exchange.getRequestBody().readAllBytes(), Map.class)));
                writeJson(exchange, 201, mapOf(
                    "custom_domains", List.of(mapOf(
                        "hostname", "api.acme.com",
                        "status", "pending_dns",
                        "created_at", "2026-05-24T10:00:00Z",
                        "updated_at", "2026-05-24T10:00:00Z"
                    ))
                ));
                return;
            }
            if ("GET".equals(method) && "/v1/sandboxes/sb-1/custom-domains".equals(path)) {
                writeJson(exchange, 200, mapOf(
                    "custom_domains", List.of(
                        mapOf(
                            "hostname", "api.acme.com",
                            "status", "ready",
                            "created_at", "2026-05-24T10:00:00Z",
                            "updated_at", "2026-05-24T10:05:00Z"
                        ),
                        mapOf(
                            "hostname", "app.acme.com",
                            "status", "failed",
                            "last_error", "no DNS",
                            "created_at", "2026-05-24T10:00:00Z",
                            "updated_at", "2026-05-24T10:05:00Z"
                        )
                    )
                ));
                return;
            }
            if ("DELETE".equals(method) && path.startsWith("/v1/sandboxes/sb-1/custom-domains/")) {
                deletePath.set(path);
                deleteCalls.incrementAndGet();
                writeResponse(exchange, 204, "application/json", new byte[0]);
                return;
            }
            throw new AssertionError("unexpected request: " + method + " " + path);
        });

        try {
            MicroVMClient client = clientFor(server);
            Sandbox sandbox = new Sandbox(client, new SandboxData());
            sandbox.id = "sb-1";

            List<CustomDomain> added = sandbox.addCustomDomain("api.acme.com");
            assertEquals(1, added.size());
            assertEquals("api.acme.com", added.get(0).hostname);
            assertEquals(CustomDomainStatus.PENDING_DNS, added.get(0).status);
            assertEquals("api.acme.com", addBody.get().get("hostname"));

            List<CustomDomain> listed = sandbox.listCustomDomains();
            assertEquals(2, listed.size());
            assertEquals(CustomDomainStatus.READY, listed.get(0).status);
            assertEquals(CustomDomainStatus.FAILED, listed.get(1).status);
            assertEquals("no DNS", listed.get(1).lastError);

            // Hostname with a space-y / colon-y character to prove URL-encoding.
            sandbox.removeCustomDomain("API.acme.com");
            assertEquals("/v1/sandboxes/sb-1/custom-domains/API.acme.com", deletePath.get());

            sandbox.removeCustomDomain("a b.example.com");
            assertEquals("/v1/sandboxes/sb-1/custom-domains/a%20b.example.com", deletePath.get());

            assertEquals(2, deleteCalls.get());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void addCustomDomainSurfacesServerError() throws Exception {
        HttpServer server = startServer(exchange -> {
            writeJson(exchange, 409, mapOf("error", "hostname already attached to sandbox sb-other"));
        });

        try {
            MicroVMClient client = clientFor(server);
            MicroVMException error = assertThrows(MicroVMException.class, () -> client.addCustomDomain("sb-1", "api.acme.com"));
            assertTrue(error.getMessage().contains("already attached"));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void createIncludesCustomDomainsWhenSet() throws Exception {
        AtomicReference<Map<String, Object>> requestBody = new AtomicReference<>();
        HttpServer server = startServer(exchange -> {
            requestBody.set(castMap(JsonSupport.read(exchange.getRequestBody().readAllBytes(), Map.class)));
            writeJson(exchange, 200, mapOf(
                "id", "sb-cd",
                "image", "ubuntu:22.04",
                "status", "started",
                "public_url", "https://sb-cd.example.com",
                "cpu", 1,
                "memory_mb", 512,
                "disk_gb", 10,
                "os_user", "root",
                "network_block_all", false,
                "toolbox_enabled", true,
                "exposed_ports", List.of(),
                "created_at", "2026-05-24T10:00:00Z",
                "updated_at", "2026-05-24T10:00:00Z",
                "last_active_at", "2026-05-24T10:00:00Z"
            ));
        });

        try {
            MicroVMClient client = clientFor(server);
            client.create(new CreateOptions()
                .setImage("ubuntu:22.04")
                .setCustomDomains(List.of("api.acme.com", "app.acme.com")));
            assertEquals(List.of("api.acme.com", "app.acme.com"), requestBody.get().get("custom_domains"));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void dnsTargetReturnsHostnameOrIpsFromIngress() throws Exception {
        AtomicReference<String> seenPath = new AtomicReference<>();
        AtomicInteger calls = new AtomicInteger();
        HttpServer server = startServer(exchange -> {
            seenPath.set(exchange.getRequestURI().getRawPath());
            int n = calls.incrementAndGet();
            if (n == 1) {
                writeJson(exchange, 200, mapOf(
                    "hostname", "ingress.acme.com",
                    "source", "hostname"
                ));
                return;
            }
            writeJson(exchange, 200, mapOf(
                "ips", List.of("203.0.113.10", "203.0.113.11"),
                "source", "ips"
            ));
        });

        try {
            MicroVMClient client = clientFor(server);
            IngressTarget hostnameTarget = client.dnsTarget();
            assertEquals("/v1/ingress/dns", seenPath.get());
            assertEquals("ingress.acme.com", hostnameTarget.hostname);
            assertEquals(null, hostnameTarget.ips);
            assertEquals("hostname", hostnameTarget.source);

            IngressTarget ipsTarget = client.dnsTarget();
            assertEquals(null, ipsTarget.hostname);
            assertEquals(List.of("203.0.113.10", "203.0.113.11"), ipsTarget.ips);
            assertEquals("ips", ipsTarget.source);
        } finally {
            server.stop(0);
        }
    }

    @Test
    void customDomainDnsReturnsRecordsAndTarget() throws Exception {
        AtomicReference<String> seenPath = new AtomicReference<>();
        AtomicReference<String> seenMethod = new AtomicReference<>();
        HttpServer server = startServer(exchange -> {
            seenMethod.set(exchange.getRequestMethod());
            seenPath.set(exchange.getRequestURI().getRawPath());
            writeJson(exchange, 200, mapOf(
                "records", List.of(
                    mapOf(
                        "hostname", "api.acme.com",
                        "type", "CNAME",
                        "name", "api.acme.com",
                        "value", "ingress.acme.com",
                        "notes", "primary"
                    ),
                    mapOf(
                        "hostname", "app.acme.com",
                        "type", "A",
                        "name", "app.acme.com",
                        "value", "203.0.113.10"
                    )
                ),
                "target", mapOf(
                    "hostname", "ingress.acme.com",
                    "source", "hostname"
                )
            ));
        });

        try {
            MicroVMClient client = clientFor(server);
            Sandbox sandbox = new Sandbox(client, new SandboxData());
            sandbox.id = "sb-1";

            CustomDomainDnsRecords result = sandbox.customDomainDns();
            assertEquals("GET", seenMethod.get());
            assertEquals("/v1/sandboxes/sb-1/custom-domains/dns", seenPath.get());
            assertNotNull(result);
            assertNotNull(result.records);
            assertEquals(2, result.records.size());

            DnsRecord first = result.records.get(0);
            assertEquals("api.acme.com", first.hostname);
            assertEquals("CNAME", first.type);
            assertEquals("api.acme.com", first.name);
            assertEquals("ingress.acme.com", first.value);
            assertEquals("primary", first.notes);

            DnsRecord second = result.records.get(1);
            assertEquals("A", second.type);
            assertEquals("203.0.113.10", second.value);
            assertEquals(null, second.notes);

            assertNotNull(result.target);
            assertEquals("ingress.acme.com", result.target.hostname);
            assertEquals("hostname", result.target.source);
        } finally {
            server.stop(0);
        }
    }

    @Test
    void customDomainDnsDefaultsRecordsToEmptyList() throws Exception {
        HttpServer server = startServer(exchange -> {
            writeJson(exchange, 200, mapOf(
                "target", mapOf("hostname", "ingress.acme.com", "source", "hostname")
            ));
        });

        try {
            MicroVMClient client = clientFor(server);
            CustomDomainDnsRecords result = client.customDomainDns("sb-1");
            assertNotNull(result.records);
            assertTrue(result.records.isEmpty());
            assertNotNull(result.target);
            assertEquals("ingress.acme.com", result.target.hostname);
        } finally {
            server.stop(0);
        }
    }

    @Test
    void createTemplatePostsAndMapsResponse() throws Exception {
        AtomicReference<Map<String, Object>> body = new AtomicReference<>();
        HttpServer server = startServer(exchange -> {
            assertEquals("POST", exchange.getRequestMethod());
            assertEquals("/v1/templates", exchange.getRequestURI().getPath());
            body.set(castMap(JsonSupport.read(exchange.getRequestBody().readAllBytes(), Map.class)));
            writeJson(exchange, 202, mapOf(
                "id", "tpl-java",
                "image", "docker://python:3.11",
                "status", "pending",
                "min_size_mib", 512,
                "created_at", "2026-05-27T10:00:00Z",
                "updated_at", "2026-05-27T10:00:00Z",
                "has_snapshot", false,
                "has_overlay", false
            ));
        });
        try {
            MicroVMClient client = clientFor(server);
            Template tpl = client.createTemplate(new CreateTemplateOptions()
                .setId("tpl-java")
                .setImage("docker://python:3.11")
                .setMinSizeMib(512));
            assertEquals("tpl-java", tpl.id);
            assertEquals(TemplateStatus.PENDING, tpl.status);
            assertEquals(Integer.valueOf(512), tpl.minSizeMib);
            assertEquals("tpl-java", body.get().get("id"));
            assertEquals("docker://python:3.11", body.get().get("image"));
            assertEquals(512, ((Number) body.get().get("min_size_mib")).intValue());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void createTemplateRejectsEmptyImage() {
        MicroVMClient client = new MicroVMClient(
            new MicroVMConfig().setApiUrl("http://127.0.0.1:1").setPatToken("pat-token"),
            HttpClient.newHttpClient(),
            new FakeWebSocketConnector(),
            name -> null
        );
        assertThrows(MicroVMException.class, () -> client.createTemplate(new CreateTemplateOptions()));
    }

    @Test
    void listTemplatesMapsRows() throws Exception {
        HttpServer server = startServer(exchange -> {
            assertEquals("GET", exchange.getRequestMethod());
            assertEquals("/v1/templates", exchange.getRequestURI().getPath());
            writeJson(exchange, 200, List.of(
                mapOf(
                    "id", "tpl-1",
                    "image", "docker://alpine:3.19",
                    "status", "ready",
                    "created_at", "2026-05-27T10:00:00Z",
                    "updated_at", "2026-05-27T10:05:00Z",
                    "ready_at", "2026-05-27T10:04:00Z",
                    "has_snapshot", true,
                    "has_overlay", false,
                    "push_state", "active"
                )
            ));
        });
        try {
            MicroVMClient client = clientFor(server);
            List<Template> rows = client.listTemplates();
            assertEquals(1, rows.size());
            assertEquals("tpl-1", rows.get(0).id);
            assertEquals(TemplateStatus.READY, rows.get(0).status);
            assertTrue(rows.get(0).hasSnapshot);
        } finally {
            server.stop(0);
        }
    }

    @Test
    void rebuildTemplatePostsToRebuildPathAndReturnsUnhealthyRow() throws Exception {
        AtomicReference<String> seenPath = new AtomicReference<>();
        HttpServer server = startServer(exchange -> {
            seenPath.set(exchange.getRequestURI().getPath());
            assertEquals("POST", exchange.getRequestMethod());
            writeJson(exchange, 202, mapOf(
                "id", "tpl-r",
                "image", "docker://alpine:3.19",
                "status", "unhealthy",
                "created_at", "2026-05-27T10:00:00Z",
                "updated_at", "2026-05-27T10:10:00Z",
                "has_snapshot", true,
                "has_overlay", false
            ));
        });
        try {
            MicroVMClient client = clientFor(server);
            Template tpl = client.rebuildTemplate("tpl-r");
            assertEquals("/v1/templates/tpl-r/rebuild", seenPath.get());
            assertEquals(TemplateStatus.UNHEALTHY, tpl.status);
        } finally {
            server.stop(0);
        }
    }

    @Test
    void rebuildTemplate412SurfacesAsException() throws Exception {
        HttpServer server = startServer(exchange -> {
            writeJson(exchange, 412, mapOf("error", "template not eligible for rebuild: current status=pending"));
        });
        try {
            MicroVMClient client = clientFor(server);
            MicroVMException ex = assertThrows(MicroVMException.class, () -> client.rebuildTemplate("tpl-pending"));
            assertTrue(ex.getMessage().contains("not eligible for rebuild"),
                "exception message = " + ex.getMessage());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void deleteTemplateSendsDelete() throws Exception {
        AtomicReference<String> seenPath = new AtomicReference<>();
        AtomicReference<String> seenMethod = new AtomicReference<>();
        HttpServer server = startServer(exchange -> {
            seenMethod.set(exchange.getRequestMethod());
            seenPath.set(exchange.getRequestURI().getPath());
            exchange.sendResponseHeaders(204, -1);
        });
        try {
            MicroVMClient client = clientFor(server);
            client.deleteTemplate("tpl-x");
            assertEquals("DELETE", seenMethod.get());
            assertEquals("/v1/templates/tpl-x", seenPath.get());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void createWasmModulePostsAndMapsResponse() throws Exception {
        AtomicReference<Map<String, Object>> body = new AtomicReference<>();
        HttpServer server = startServer(exchange -> {
            assertEquals("POST", exchange.getRequestMethod());
            assertEquals("/v1/wasm-modules", exchange.getRequestURI().getPath());
            body.set(castMap(JsonSupport.read(exchange.getRequestBody().readAllBytes(), Map.class)));
            writeJson(exchange, 201, mapOf(
                "id", "mod-java",
                "module_ref", "file:///agent.wasm",
                "status", "ready",
                "module_size_bytes", 4096,
                "has_warm", true,
                "created_at", "2026-05-27T10:00:00Z",
                "updated_at", "2026-05-27T10:00:00Z",
                "ready_at", "2026-05-27T10:00:00Z"
            ));
        });
        try {
            MicroVMClient client = clientFor(server);
            WasmModule module = client.createWasmModule(new CreateWasmModuleOptions()
                .setModuleRef("file:///agent.wasm")
                .setEntrypoint("_start"));
            assertEquals("mod-java", module.id);
            assertEquals(WasmModuleStatus.READY, module.status);
            assertEquals("file:///agent.wasm", module.moduleRef);
            assertTrue(module.hasWarm);
            assertEquals("file:///agent.wasm", body.get().get("module_ref"));
            assertEquals("_start", body.get().get("entrypoint"));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void createWasmModuleRejectsEmptyModuleRef() {
        MicroVMClient client = new MicroVMClient(
            new MicroVMConfig().setApiUrl("http://127.0.0.1:1").setPatToken("pat-token"),
            HttpClient.newHttpClient(),
            new FakeWebSocketConnector(),
            name -> null
        );
        assertThrows(MicroVMException.class, () -> client.createWasmModule(new CreateWasmModuleOptions()));
    }

    @Test
    void deleteWasmModuleSendsDelete() throws Exception {
        AtomicReference<String> seenPath = new AtomicReference<>();
        AtomicReference<String> seenMethod = new AtomicReference<>();
        HttpServer server = startServer(exchange -> {
            seenMethod.set(exchange.getRequestMethod());
            seenPath.set(exchange.getRequestURI().getPath());
            exchange.sendResponseHeaders(204, -1);
        });
        try {
            MicroVMClient client = clientFor(server);
            client.deleteWasmModule("mod-x");
            assertEquals("DELETE", seenMethod.get());
            assertEquals("/v1/wasm-modules/mod-x", seenPath.get());
        } finally {
            server.stop(0);
        }
    }

    private static MicroVMClient clientFor(HttpServer server) {
        return new MicroVMClient(
            new MicroVMConfig().setApiUrl(serverUrl(server)).setPatToken("pat-token"),
            HttpClient.newHttpClient(),
            new FakeWebSocketConnector(),
            name -> null
        );
    }

    private static HttpServer startServer(ThrowingHandler handler) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            try (ExchangeResource exchangeResource = new ExchangeResource(exchange)) {
                exchangeResource.touch();
                handler.handle(exchange);
            }
        });
        server.start();
        return server;
    }

    private static String serverUrl(HttpServer server) {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    private static void writeJson(HttpExchange exchange, int status, Object value) throws IOException {
        writeResponse(exchange, status, "application/json", JsonSupport.writeBytes(value));
    }

    private static void writeResponse(HttpExchange exchange, int status, String contentType, byte[] body) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.sendResponseHeaders(status, body.length);
        exchange.getResponseBody().write(body);
    }

    private static Map<String, Object> mapOf(Object... entries) {
        Map<String, Object> map = new HashMap<>();
        for (int i = 0; i < entries.length; i += 2) {
            map.put((String) entries[i], entries[i + 1]);
        }
        return map;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> castMap(Object value) {
        return (Map<String, Object>) value;
    }

    @FunctionalInterface
    private interface ThrowingHandler {
        void handle(HttpExchange exchange) throws IOException;
    }

    private static final class ExchangeResource implements AutoCloseable {
        private final HttpExchange exchange;

        private ExchangeResource(HttpExchange exchange) {
            this.exchange = exchange;
        }

        private void touch() {
        }

        @Override
        public void close() {
            exchange.close();
        }
    }

    private static final class FakeWebSocketConnector implements WebSocketConnector {
        private URI uri;
        private String authorizationHeader;
        private FakeStreamingWebSocket socket;
        private StreamingWebSocketListener listener;

        @Override
        public StreamingWebSocket connect(URI uri, String authorizationHeader, StreamingWebSocketListener listener) {
            this.uri = uri;
            this.authorizationHeader = authorizationHeader;
            this.listener = listener;
            this.socket = new FakeStreamingWebSocket();
            return socket;
        }

        private void emitText(String text) {
            listener.onText(text);
        }

        private void emitBinary(byte[] data) {
            listener.onBinary(data);
        }
    }

    private static final class FakeStreamingWebSocket implements StreamingWebSocket {
        private final List<String> sentTexts = new ArrayList<>();
        private final List<byte[]> sentBinary = new ArrayList<>();
        private final AtomicInteger closes = new AtomicInteger();

        @Override
        public void sendText(String text) {
            sentTexts.add(text);
        }

        @Override
        public void sendBinary(ByteBuffer data) {
            byte[] bytes = new byte[data.remaining()];
            data.get(bytes);
            sentBinary.add(bytes);
        }

        @Override
        public void sendClose(int statusCode, String reason) {
            closes.incrementAndGet();
        }
    }
}
