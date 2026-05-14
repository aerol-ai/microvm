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
import ai.aerol.microvm.model.ExecExitInfo;
import ai.aerol.microvm.model.ExecRequest;
import ai.aerol.microvm.model.ExecResult;
import ai.aerol.microvm.model.ExecStreamOptions;
import ai.aerol.microvm.model.Lifecycle;
import ai.aerol.microvm.model.MountSpec;
import ai.aerol.microvm.model.MountSpecRedacted;
import ai.aerol.microvm.model.NetworkUsage;
import ai.aerol.microvm.model.SandboxData;
import ai.aerol.microvm.model.SandboxSnapshot;
import ai.aerol.microvm.model.Session;
import ai.aerol.microvm.model.SessionAttachOptions;
import ai.aerol.microvm.model.SetNetworkLimitsOptions;

class MicroVMClientTest {
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
                )
            ));
        });

        try {
            MicroVMClient client = clientFor(server);
            Sandbox sandbox = client.create(
                new CreateOptions()
                    .setImage("ubuntu:22.04")
                    .setMemoryMb(2048)
                    .setNetworkBlockAll(true)
                    .setMounts(List.of(
                        new MountSpec()
                            .setType("s3")
                            .setTarget("/workspace")
                            .setSource("s3://bucket/prefix")
                    ))
                    .setLifecycle(new Lifecycle()
                        .setStopIfIdleFor(3_600_000_000_000L)
                        .setDestroyAtAge(86_400_000_000_000L))
            );

            assertEquals("sb-create", sandbox.id);
            assertEquals("PRIVATE", sandbox.sshPrivateKey);
            assertEquals("ssh-ed25519 AAAA sandbox", sandbox.sshPublicKey);
            assertEquals(2048, sandbox.memoryMb);
            assertEquals(3_600_000_000_000L, sandbox.lifecycle.stopIfIdleFor);
            assertEquals(86_400_000_000_000L, sandbox.lifecycle.destroyAtAge);

            Map<String, Object> payload = requestBody.get();
            assertEquals("ubuntu:22.04", payload.get("image"));
            assertEquals(2048, ((Number) payload.get("memory_mb")).intValue());
            assertEquals(Boolean.TRUE, payload.get("network_block_all"));
            Map<String, Object> lifecycle = castMap(payload.get("lifecycle"));
            assertEquals(3_600_000_000_000L, ((Number) lifecycle.get("stop_if_idle_for")).longValue());
            assertEquals(86_400_000_000_000L, ((Number) lifecycle.get("destroy_at_age")).longValue());
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