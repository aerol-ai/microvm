package ai.aerol.microvm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import ai.aerol.microvm.internal.JsonSupport;
import ai.aerol.microvm.internal.StreamingWebSocket;
import ai.aerol.microvm.internal.StreamingWebSocketListener;
import ai.aerol.microvm.internal.WebSocketConnector;
import ai.aerol.microvm.model.ExecRequest;
import ai.aerol.microvm.model.ExecResult;
import ai.aerol.microvm.model.ExecStreamOptions;

/**
 * Exec options an older sandbox agent would ignore, against a fake sandboxd
 * whose toolbox plays the agent: the SDK reads /version first and refuses to
 * send what the agent does not list (plan section 10, ER4).
 */
class ExecOptionsTest {
    private static final String VERSION_PATH = "/v1/sandboxes/sb-1/toolbox/version";
    private static final String EXEC_PATH = "/v1/sandboxes/sb-1/toolbox/process/execute";

    /** A running fake agent; {@code calls} holds "METHOD path" and {@code bodies} each exec body. */
    static final class FakeAgent implements AutoCloseable {
        final HttpServer server;
        final List<String> calls = Collections.synchronizedList(new ArrayList<>());
        final List<Map<String, Object>> bodies = Collections.synchronizedList(new ArrayList<>());

        FakeAgent(List<String> features, Map<String, Object> execResult) throws IOException {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", exchange -> {
                try {
                    String path = exchange.getRequestURI().getPath();
                    calls.add(exchange.getRequestMethod() + " " + path);
                    if (path.equals(VERSION_PATH)) {
                        Map<String, Object> info = new HashMap<>();
                        info.put("version", "0.6.11");
                        if (features != null) {
                            info.put("features", features);
                        }
                        write(exchange, info);
                    } else if (path.equals(EXEC_PATH)) {
                        bodies.add(castMap(JsonSupport.read(exchange.getRequestBody().readAllBytes(), Map.class)));
                        Map<String, Object> result = new HashMap<>(Map.of("stdout", "", "stderr", "", "exit_code", 0, "duration_ms", 1));
                        result.putAll(execResult);
                        write(exchange, result);
                    } else {
                        exchange.sendResponseHeaders(404, -1);
                    }
                } finally {
                    exchange.close();
                }
            });
            server.start();
        }

        MicroVMClient client() {
            return new MicroVMClient(new MicroVMConfig()
                .setApiUrl("http://127.0.0.1:" + server.getAddress().getPort())
                .setPatToken("pat-token"));
        }

        /** A client whose exec streams go to {@code streams}, which records each start message. */
        MicroVMClient client(RecordingConnector streams) {
            return new MicroVMClient(
                new MicroVMConfig().setApiUrl("http://127.0.0.1:" + server.getAddress().getPort()).setPatToken("pat-token"),
                java.net.http.HttpClient.newHttpClient(),
                streams,
                name -> null);
        }

        @Override
        public void close() {
            server.stop(0);
        }

        private static void write(HttpExchange exchange, Object value) throws IOException {
            byte[] body = JsonSupport.writeBytes(value);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
        }

        @SuppressWarnings("unchecked")
        private static Map<String, Object> castMap(Object value) {
            return (Map<String, Object>) value;
        }
    }

    @Test
    void outputCapsAreSentWhenTheAgentListsThem() throws Exception {
        try (FakeAgent agent = new FakeAgent(List.of("exec.max_output_bytes"), Map.of("stdout", "aaaa", "stdout_truncated", true))) {
            ExecResult result = agent.client().exec("sb-1", new ExecRequest()
                .setCommand("yes a")
                .setMaxStdoutBytes(4L)
                .setMaxStderrBytes(100L));
            assertEquals(List.of("GET " + VERSION_PATH, "POST " + EXEC_PATH), agent.calls);
            assertEquals(4, ((Number) agent.bodies.get(0).get("max_stdout_bytes")).intValue());
            assertEquals(100, ((Number) agent.bodies.get(0).get("max_stderr_bytes")).intValue());
            assertEquals("aaaa", result.stdout);
            assertTrue(result.stdoutTruncated);
            assertFalse(result.stderrTruncated);
        }
    }

    // ER4 mixed-version: an agent that does not list the caps never gets the exec.
    @Test
    void outputCapsFailClosedOnAnOlderAgent() throws Exception {
        for (List<String> features : java.util.Arrays.asList(null, List.<String>of(), List.of("files.copy"))) {
            try (FakeAgent agent = new FakeAgent(features, Map.of())) {
                MicroVMUnsupportedFeatureException err = assertThrows(MicroVMUnsupportedFeatureException.class,
                    () -> agent.client().exec("sb-1", new ExecRequest().setCommand("yes").setMaxStdoutBytes(1024L)));
                assertEquals(List.of("exec.max_output_bytes"), err.getFeatures());
                assertTrue(err.getMessage().contains("restart the sandbox"));
                assertEquals(List.of("GET " + VERSION_PATH), agent.calls);
                assertTrue(agent.bodies.isEmpty());
            }
        }
    }

    @Test
    void execWithoutCapsMakesNoVersionCall() throws Exception {
        try (FakeAgent agent = new FakeAgent(null, Map.of())) {
            ExecResult result = agent.client().exec("sb-1", new ExecRequest().setCommand("ls").setMaxStdoutBytes(0L));
            assertEquals(List.of("POST " + EXEC_PATH), agent.calls);
            assertFalse(result.stdoutTruncated);
            assertFalse(result.stderrTruncated);
        }
    }

    /** Records the start message of each exec stream and answers exit 0. */
    static final class RecordingConnector implements WebSocketConnector {
        final List<String> sent = Collections.synchronizedList(new ArrayList<>());

        @Override
        public StreamingWebSocket connect(java.net.URI uri, Map<String, String> headers, StreamingWebSocketListener listener) {
            return new StreamingWebSocket() {
                @Override
                public void sendText(String text) {
                    sent.add(text);
                    listener.onText("{\"type\":\"exit\",\"code\":0}");
                }

                @Override
                public void sendBinary(java.nio.ByteBuffer data) {
                }

                @Override
                public void sendClose(int statusCode, String reason) {
                }
            };
        }
    }

    // E2 + ER4: argv goes out only after the agent listed exec.argv, on exec
    // and on the exec stream; an older agent gets neither (mixed-version).
    @Test
    void argvIsSentWhenTheAgentListsIt() throws Exception {
        List<String> argv = List.of("printf", "%s|", "a b", "$HOME", "; echo pwned");
        try (FakeAgent agent = new FakeAgent(List.of("exec.argv"), Map.of())) {
            RecordingConnector streams = new RecordingConnector();
            MicroVMClient client = agent.client(streams);
            client.exec("sb-1", new ExecRequest().setArgv(argv));
            assertEquals(argv, agent.bodies.get(0).get("argv"));
            assertFalse(agent.bodies.get(0).containsKey("command"));

            assertEquals(0, client.execStream("sb-1", new ExecStreamOptions().setArgv(argv)).waitForExit().code);
            Map<?, ?> start = JsonSupport.read(streams.sent.get(0).getBytes(java.nio.charset.StandardCharsets.UTF_8), Map.class);
            assertEquals(argv, start.get("argv"));
            assertEquals(List.of("GET " + VERSION_PATH, "POST " + EXEC_PATH), agent.calls);
        }
    }

    @Test
    void argvFailsClosedOnAnOlderAgent() throws Exception {
        for (List<String> features : java.util.Arrays.asList(null, List.of("exec.max_output_bytes"))) {
            try (FakeAgent agent = new FakeAgent(features, Map.of())) {
                RecordingConnector streams = new RecordingConnector();
                MicroVMClient client = agent.client(streams);
                MicroVMUnsupportedFeatureException execErr = assertThrows(MicroVMUnsupportedFeatureException.class,
                    () -> client.exec("sb-1", new ExecRequest().setArgv(List.of("ls"))));
                assertEquals(List.of("exec.argv"), execErr.getFeatures());
                assertThrows(MicroVMUnsupportedFeatureException.class,
                    () -> client.execStream("sb-1", new ExecStreamOptions().setArgv(List.of("ls"))));
                assertEquals(List.of("GET " + VERSION_PATH, "GET " + VERSION_PATH), agent.calls);
                assertTrue(streams.sent.isEmpty());
            }
        }
    }

    @Test
    void execStreamNeedsCommandOrArgv() throws Exception {
        try (FakeAgent agent = new FakeAgent(List.of("exec.argv"), Map.of())) {
            RecordingConnector streams = new RecordingConnector();
            MicroVMClient client = agent.client(streams);
            MicroVMException both = assertThrows(MicroVMException.class,
                () -> client.execStream("sb-1", new ExecStreamOptions().setCommand("ls").setArgv(List.of("ls"))));
            assertEquals("set command or argv, not both", both.getMessage());
            MicroVMException neither = assertThrows(MicroVMException.class,
                () -> client.execStream("sb-1", new ExecStreamOptions().setArgv(List.of())));
            assertEquals("command is required", neither.getMessage());
            assertTrue(agent.calls.isEmpty());
            assertTrue(streams.sent.isEmpty());
        }
    }
}
