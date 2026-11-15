package ai.aerol.microvm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import ai.aerol.microvm.internal.JsonSupport;
import ai.aerol.microvm.internal.StreamingWebSocket;
import ai.aerol.microvm.internal.StreamingWebSocketListener;
import ai.aerol.microvm.internal.WebSocketConnector;
import ai.aerol.microvm.internal.WebSocketHandshakeFailure;
import ai.aerol.microvm.model.CodeContext;
import ai.aerol.microvm.model.CodeContextOptions;
import ai.aerol.microvm.model.CodeResult;
import ai.aerol.microvm.model.Execution;
import ai.aerol.microvm.model.ExecutionError;
import ai.aerol.microvm.model.RetryConfig;
import ai.aerol.microvm.model.RunCodeOptions;
import ai.aerol.microvm.model.SandboxData;

/**
 * The code interpreter against a fake sandboxd: REST contexts through its
 * HTTP server, runs through a scripted WebSocket connector. The toolbox plays
 * an agent that lists {@code features} on /version.
 */
class CodeInterpreterTest {
    private static final String TOOLBOX = "/v1/sandboxes/sb-1/toolbox";
    private static final String VERSION_PATH = TOOLBOX + "/version";
    private static final String CONTEXT_PATH = TOOLBOX + "/process/interpreter/context";
    private static final List<String> FEATURES = List.of("code.interpreter", "exec.argv");

    /** A fake sandboxd; {@code calls} holds "METHOD rawPath" and {@code bodies} each POST body. */
    static final class FakeAgent implements AutoCloseable {
        final HttpServer server;
        final List<String> calls = Collections.synchronizedList(new ArrayList<>());
        final List<String> bodies = Collections.synchronizedList(new ArrayList<>());
        final AtomicInteger createFailures = new AtomicInteger();
        volatile boolean nullContexts;

        FakeAgent(List<String> features) throws IOException {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", exchange -> {
                try {
                    String method = exchange.getRequestMethod();
                    String path = exchange.getRequestURI().getRawPath();
                    calls.add(method + " " + path);
                    if (method.equals("POST")) {
                        bodies.add(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
                    }
                    if (path.equals(VERSION_PATH)) {
                        Map<String, Object> info = new HashMap<>();
                        info.put("version", "0.7.6");
                        if (features != null) {
                            info.put("features", features);
                        }
                        write(exchange, 200, info);
                    } else if (path.equals(CONTEXT_PATH) && method.equals("POST")) {
                        if (createFailures.getAndDecrement() > 0) {
                            write(exchange, 502, Map.of("error", "bad gateway"));
                            return;
                        }
                        write(exchange, 200, context("ctx-1", "javascript", "/work", true));
                    } else if (path.equals(CONTEXT_PATH) && method.equals("GET")) {
                        Map<String, Object> list = new HashMap<>();
                        list.put("contexts", nullContexts ? null : List.of(context("ctx-1", "python", "/work", true), context("ctx-2", "r", "/tmp", false)));
                        write(exchange, 200, list);
                    } else if (path.equals(CONTEXT_PATH + "/ctx-1") && method.equals("GET")) {
                        write(exchange, 200, context("ctx-1", "python", "/work", true));
                    } else if (path.equals(CONTEXT_PATH + "/ctx%2F2") && method.equals("GET")) {
                        write(exchange, 200, context("ctx/2", "python", "/work", true));
                    } else if (path.equals(CONTEXT_PATH + "/ctx-1") && method.equals("DELETE")) {
                        write(exchange, 200, Map.of("message", "Context deleted successfully"));
                    } else if (path.equals(CONTEXT_PATH + "/ctx-1/restart") && method.equals("POST")) {
                        write(exchange, 200, context("ctx-1", "python", "/work", true));
                    } else if (path.equals(CONTEXT_PATH + "/full/restart") && method.equals("POST")) {
                        write(exchange, 429, Map.of("error", "too many code contexts", "message", "limit is 32"));
                    } else {
                        write(exchange, 404, Map.of("error", "context not found", "message", "context not found"));
                    }
                } finally {
                    exchange.close();
                }
            });
            server.start();
        }

        MicroVMClient client(WebSocketConnector streams) {
            return new MicroVMClient(
                new MicroVMConfig()
                    .setApiUrl("http://127.0.0.1:" + server.getAddress().getPort())
                    .setPatToken("pat-token")
                    .setRetry(new RetryConfig().setBaseDelayMs(1).setMaxDelayMs(1).setMaxRetryAfterMs(0)),
                java.net.http.HttpClient.newHttpClient(),
                streams,
                name -> null);
        }

        /** Every call but the /version check. */
        List<String> interpreterCalls() {
            List<String> out = new ArrayList<>();
            synchronized (calls) {
                for (String call : calls) {
                    if (!call.endsWith(VERSION_PATH)) {
                        out.add(call);
                    }
                }
            }
            return out;
        }

        @Override
        public void close() {
            server.stop(0);
        }

        private static Map<String, Object> context(String id, String language, String cwd, boolean active) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("id", id);
            out.put("language", language);
            out.put("cwd", cwd);
            out.put("createdAt", "2026-11-15T10:00:00Z");
            out.put("active", active);
            return out;
        }

        private static void write(HttpExchange exchange, int status, Object value) throws IOException {
            byte[] body = JsonSupport.writeBytes(value);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, body.length);
            exchange.getResponseBody().write(body);
        }
    }

    /**
     * A WebSocket stand-in. When the client sends its start frame it replays
     * {@code script} (text frames, then the close in {@code closeCode}), all
     * on the calling thread, so the run has ended when startCode returns.
     */
    static final class ScriptedConnector implements WebSocketConnector {
        final List<String> script = new ArrayList<>();
        Integer closeCode;
        String closeReason = "";
        RuntimeException failWith;
        URI uri;
        Map<String, String> headers;
        StreamingWebSocketListener listener;
        final List<String> sent = Collections.synchronizedList(new ArrayList<>());
        final AtomicInteger closes = new AtomicInteger();
        int connects;

        ScriptedConnector frames(String... frames) {
            Collections.addAll(script, frames);
            return this;
        }

        ScriptedConnector thenClose(int code, String reason) {
            closeCode = code;
            closeReason = reason;
            return this;
        }

        @Override
        public StreamingWebSocket connect(URI uri, Map<String, String> headers, StreamingWebSocketListener listener) {
            connects++;
            if (failWith != null) {
                throw failWith;
            }
            this.uri = uri;
            this.headers = headers;
            this.listener = listener;
            return new StreamingWebSocket() {
                @Override
                public void sendText(String text) {
                    sent.add(text);
                    if (sent.size() == 1) {
                        for (String frame : script) {
                            listener.onText(frame);
                        }
                        if (closeCode != null) {
                            listener.onClose(closeCode, closeReason);
                        }
                    }
                }

                @Override
                public void sendBinary(ByteBuffer data) {
                }

                @Override
                public void sendClose(int statusCode, String reason) {
                    closes.incrementAndGet();
                }
            };
        }

        Map<?, ?> start() {
            return JsonSupport.read(sent.get(0).getBytes(StandardCharsets.UTF_8), Map.class);
        }
    }

    // Daytona frames always carry all five fields; result and
    // execution_count frames add theirs (richOutput).
    private static String frame(String type, String text) {
        return "{\"type\":\"" + type + "\",\"text\":" + JsonSupport.write(text) + ",\"name\":\"\",\"value\":\"\",\"traceback\":\"\"}";
    }

    private static final String COMPLETED = frame("control", "completed");
    private static final String INTERRUPTED = frame("control", "interrupted");

    @Test
    void runCodeStreamsOutputAndReturnsTheExecution() throws Exception {
        try (FakeAgent agent = new FakeAgent(FEATURES)) {
            ScriptedConnector streams = new ScriptedConnector().frames(
                "{\"type\":\"execution_count\",\"count\":3,\"text\":\"\",\"name\":\"\",\"value\":\"\",\"traceback\":\"\"}",
                frame("stdout", "hi\n"),
                frame("stderr", "warn\n"),
                "{\"type\":\"result\",\"text\":\"\",\"name\":\"\",\"value\":\"\",\"traceback\":\"\",\"png\":\"iVBORw0KGgo=\",\"is_main_result\":false}",
                "{\"type\":\"result\",\"text\":\"   a\\n0  1\",\"name\":\"\",\"value\":\"\",\"traceback\":\"\",\"html\":\"<table></table>\","
                    + "\"data\":{\"a\":[1]},\"json\":{\"k\":true},\"extra\":{\"application/vnd.custom\":\"x\",\"application/a\":1},\"is_main_result\":true}",
                frame("stdout", "bye\n"),
                COMPLETED
            ).thenClose(1000, "");
            List<String> stdout = new ArrayList<>();
            List<String> stderr = new ArrayList<>();
            List<CodeResult> results = new ArrayList<>();

            Execution execution = agent.client(streams).runCode("sb-1", "print('hi')", new RunCodeOptions()
                .setContextId("ctx-1")
                .setEnvs(Map.of("A", "1"))
                .setTimeoutSeconds(30)
                .setOnStdout(stdout::add)
                .setOnStderr(stderr::add)
                .setOnResult(results::add));

            assertEquals(URI.create("ws://127.0.0.1:" + agent.server.getAddress().getPort() + TOOLBOX + "/process/interpreter/execute"), streams.uri);
            assertEquals("Bearer pat-token", streams.headers.get("Authorization"));
            assertEquals("{\"code\":\"print('hi')\",\"contextId\":\"ctx-1\",\"envs\":{\"A\":\"1\"},\"timeout\":30,\"richOutput\":true}", streams.sent.get(0));
            assertEquals(1, streams.sent.size(), "the client sends only the start frame");
            assertEquals(List.of("GET " + VERSION_PATH), agent.calls);

            assertEquals(List.of("hi\n", "bye\n"), stdout);
            assertEquals(List.of("hi\n", "bye\n"), execution.logs.stdout);
            assertEquals(List.of("warn\n"), stderr);
            assertEquals(List.of("warn\n"), execution.logs.stderr);
            assertEquals(Integer.valueOf(3), execution.executionCount);
            assertFalse(execution.interrupted);
            assertNull(execution.error);
            assertEquals(2, execution.results.size());
            assertEquals(execution.results, results);

            CodeResult chart = execution.results.get(0);
            assertNull(chart.text, "an empty text field means the result has no text form");
            assertEquals(List.of("png"), chart.formats());
            assertFalse(chart.isMainResult);

            CodeResult table = execution.results.get(1);
            assertTrue(table.isMainResult);
            assertEquals("<table></table>", table.html);
            assertEquals(List.of(1), table.data.get("a"));
            assertEquals(true, table.json.get("k"));
            assertEquals(List.of("text", "html", "json", "data", "application/a", "application/vnd.custom"), table.formats());
            assertEquals("   a\n0  1", execution.getText());
        }
    }

    @Test
    void theStartFrameCarriesOnlyWhatWasSet() throws Exception {
        try (FakeAgent agent = new FakeAgent(FEATURES)) {
            ScriptedConnector streams = new ScriptedConnector().thenClose(1000, "");
            MicroVMClient client = agent.client(streams);

            client.runCode("sb-1", "x = 5");
            assertEquals("{\"code\":\"x = 5\",\"richOutput\":true}", streams.sent.get(0));

            streams.sent.clear();
            client.runCode("sb-1", "1", new RunCodeOptions().setLanguage("javascript").setEnvs(Map.of()).setTimeoutSeconds(0));
            assertEquals("{\"code\":\"1\",\"language\":\"javascript\",\"timeout\":0,\"richOutput\":true}", streams.sent.get(0));

            streams.sent.clear();
            CodeContext context = new CodeContext();
            context.id = "ctx-9";
            client.runCode("sb-1", "1", new RunCodeOptions().setContext(context).setLanguage("  "));
            assertEquals("ctx-9", streams.start().get("contextId"));
            assertFalse(streams.start().containsKey("language"));
            assertFalse(streams.start().containsKey("timeout"), "unset timeout keeps the server default");

            // One /version call for the sandbox: the feature list is cached.
            assertEquals(List.of("GET " + VERSION_PATH), agent.calls);
        }
    }

    @Test
    void anExceptionInTheCodeIsPartOfTheExecution() throws Exception {
        try (FakeAgent agent = new FakeAgent(FEATURES)) {
            ScriptedConnector streams = new ScriptedConnector().frames(
                frame("stdout", "before\n"),
                "{\"type\":\"error\",\"text\":\"\",\"name\":\"ZeroDivisionError\",\"value\":\"division by zero\",\"traceback\":\"Traceback...\"}",
                COMPLETED
            ).thenClose(1000, "");
            List<ExecutionError> errors = new ArrayList<>();

            Execution execution = agent.client(streams).runCode("sb-1", "1/0", new RunCodeOptions().setOnError(errors::add));

            assertEquals("ZeroDivisionError", execution.error.name);
            assertEquals("division by zero", execution.error.value);
            assertEquals("Traceback...", execution.error.traceback);
            assertEquals(List.of(execution.error), errors);
            assertEquals(List.of("before\n"), execution.logs.stdout);
            assertNull(execution.getText());
        }
    }

    @Test
    void anInterruptedControlFrameMarksTheExecution() throws Exception {
        try (FakeAgent agent = new FakeAgent(FEATURES)) {
            ScriptedConnector streams = new ScriptedConnector().frames(frame("stdout", "1\n"), INTERRUPTED).thenClose(1000, "");
            Execution execution = agent.client(streams).runCode("sb-1", "while True: pass");
            assertTrue(execution.interrupted);
            assertEquals(List.of("1\n"), execution.logs.stdout);
        }
    }

    @Test
    void closeCode4008IsATimeoutCarryingThePartialExecution() throws Exception {
        try (FakeAgent agent = new FakeAgent(FEATURES)) {
            ScriptedConnector streams = new ScriptedConnector().frames(frame("stdout", "working\n"), INTERRUPTED)
                .thenClose(4008, "execution timed out");
            MicroVMCodeTimeoutException err = assertThrows(MicroVMCodeTimeoutException.class,
                () -> agent.client(streams).runCode("sb-1", "import time; time.sleep(99)", new RunCodeOptions().setTimeoutSeconds(1)));
            assertInstanceOf(MicroVMCodeRunException.class, err);
            assertEquals(4008, err.getCloseCode());
            assertEquals("execution timed out", err.getReason());
            assertEquals("code run timed out: execution timed out", err.getMessage());
            assertEquals(List.of("working\n"), err.getExecution().logs.stdout);
            assertTrue(err.getExecution().interrupted);

            ScriptedConnector bare = new ScriptedConnector().thenClose(4008, "");
            assertEquals("code run timed out",
                assertThrows(MicroVMCodeTimeoutException.class, () -> agent.client(bare).runCode("sb-1", "x")).getMessage());
        }
    }

    @Test
    void otherCloseCodesAreRunErrorsWithTheReason() throws Exception {
        Map<Integer, String> cases = new LinkedHashMap<>();
        cases.put(1001, "worker process ended");
        cases.put(1002, "");
        cases.put(1008, "context not found: abc");
        cases.put(1011, "default context failed");
        try (FakeAgent agent = new FakeAgent(FEATURES)) {
            for (Map.Entry<Integer, String> c : cases.entrySet()) {
                ScriptedConnector streams = new ScriptedConnector().frames(frame("stderr", "partial")).thenClose(c.getKey(), c.getValue());
                MicroVMCodeRunException err = assertThrows(MicroVMCodeRunException.class,
                    () -> agent.client(streams).runCode("sb-1", "x", new RunCodeOptions().setContextId("abc")));
                assertFalse(err instanceof MicroVMCodeTimeoutException, "close " + c.getKey() + " is not a timeout");
                assertEquals(c.getKey().intValue(), err.getCloseCode());
                assertEquals(c.getValue(), err.getReason());
                String want = "code run failed (close " + c.getKey() + ")" + (c.getValue().isEmpty() ? "" : ": " + c.getValue());
                assertEquals(want, err.getMessage());
                assertEquals(List.of("partial"), err.getExecution().logs.stderr);
            }

            // A close frame with no status counts as the server finishing.
            ScriptedConnector noStatus = new ScriptedConnector().frames(frame("stdout", "ok")).thenClose(1005, "");
            assertEquals(List.of("ok"), agent.client(noStatus).runCode("sb-1", "x").logs.stdout);
        }
    }

    @Test
    void aDroppedConnectionIsARunErrorWithCode1006() throws Exception {
        try (FakeAgent agent = new FakeAgent(FEATURES)) {
            ScriptedConnector streams = new ScriptedConnector();
            CodeRunHandle handle = agent.client(streams).startCode("sb-1", "x", null);
            streams.listener.onText(frame("stdout", "a"));
            streams.listener.onError(new IOException("connection reset"));
            MicroVMCodeRunException err = assertThrows(MicroVMCodeRunException.class, handle::waitForResult);
            assertEquals(1006, err.getCloseCode());
            assertEquals("connection reset", err.getReason());
            assertEquals(List.of("a"), err.getExecution().logs.stdout);
            // Frames after the end are ignored.
            streams.listener.onText(frame("stdout", "late"));
            assertEquals(List.of("a"), err.getExecution().logs.stdout);
        }
    }

    @Test
    void interruptSendsTheInterruptFrameAndTheRunEndsNormally() throws Exception {
        try (FakeAgent agent = new FakeAgent(FEATURES)) {
            ScriptedConnector streams = new ScriptedConnector();
            Sandbox sandbox = new Sandbox(agent.client(streams), sandboxData());
            CodeRunHandle handle = sandbox.startCode("while True: pass", new RunCodeOptions());
            assertFalse(handle.completion().isDone());

            handle.interrupt();
            assertEquals(2, streams.sent.size());
            assertEquals("{\"type\":\"interrupt\"}", streams.sent.get(1));

            streams.listener.onText(INTERRUPTED);
            streams.listener.onClose(1000, "");
            Execution execution = handle.waitForResult();
            assertTrue(execution.interrupted);
            assertEquals(execution, handle.completion().get());

            handle.interrupt();
            assertEquals(2, streams.sent.size(), "no interrupt once the run has ended");
        }
    }

    @Test
    void closingTheHandleFailsTheWaitAndClosesTheSocket() throws Exception {
        try (FakeAgent agent = new FakeAgent(FEATURES)) {
            ScriptedConnector streams = new ScriptedConnector();
            CodeRunHandle handle = agent.client(streams).startCode("sb-1", "x", null);
            streams.listener.onText(frame("stdout", "a"));
            handle.close();
            handle.close();
            MicroVMCodeRunException err = assertThrows(MicroVMCodeRunException.class, handle::waitForResult);
            assertEquals("closed by the client", err.getReason());
            assertEquals(List.of("a"), err.getExecution().logs.stdout);
            assertTrue(streams.closes.get() >= 1);
            // The server's answering close does not turn it into a success.
            streams.listener.onClose(1000, "");
            assertThrows(MicroVMCodeRunException.class, handle::waitForResult);
        }
    }

    @Test
    void unknownAndMalformedFramesAreIgnored() throws Exception {
        try (FakeAgent agent = new FakeAgent(FEATURES)) {
            ScriptedConnector streams = new ScriptedConnector().frames(
                "not json",
                "{\"no_type\":1}",
                frame("keepalive", ""),
                "{\"type\":\"result\",\"text\":\"[1, 2]\",\"json\":[1,2],\"data\":\"oops\",\"is_main_result\":true}",
                COMPLETED
            ).thenClose(1000, "");
            ScriptedConnector withBinary = streams;
            CodeRunHandle handle = agent.client(withBinary).startCode("sb-1", "x", null);
            withBinary.listener.onBinary(new byte[] {1, 2});
            Execution execution = handle.waitForResult();
            assertEquals(1, execution.results.size());
            assertNull(execution.results.get(0).json, "a json value that is not an object is dropped, not the frame");
            assertNull(execution.results.get(0).data);
            assertEquals("[1, 2]", execution.getText());
        }
    }

    @Test
    void aFailingCallbackEndsTheWait() throws Exception {
        try (FakeAgent agent = new FakeAgent(FEATURES)) {
            ScriptedConnector streams = new ScriptedConnector().frames(frame("stdout", "a"), frame("stdout", "b"), COMPLETED).thenClose(1000, "");
            List<String> seen = new ArrayList<>();
            MicroVMException err = assertThrows(MicroVMException.class, () -> agent.client(streams).runCode("sb-1", "x",
                new RunCodeOptions().setOnStdout(text -> {
                    seen.add(text);
                    throw new IllegalStateException("boom");
                })));
            assertTrue(err.getMessage().contains("code run callback failed: boom"), err.getMessage());
            assertEquals(List.of("a"), seen);
            assertEquals(1, streams.closes.get());
        }
    }

    @Test
    void contextAndLanguageTogetherAreRefusedBeforeAnythingIsSent() throws Exception {
        try (FakeAgent agent = new FakeAgent(FEATURES)) {
            ScriptedConnector streams = new ScriptedConnector();
            MicroVMException err = assertThrows(MicroVMException.class, () -> agent.client(streams).runCode("sb-1", "x",
                new RunCodeOptions().setContextId("ctx-1").setLanguage("python")));
            assertEquals("set context or language, not both", err.getMessage());
            assertEquals(0, streams.connects);
            assertTrue(agent.calls.isEmpty());
        }
    }

    // An older agent (or a runtime without the interpreter) never gets an
    // interpreter request: every call checks /version first.
    @Test
    void everyCallFailsClosedOnAnAgentWithoutTheInterpreter() throws Exception {
        for (List<String> features : java.util.Arrays.asList(null, List.<String>of(), List.of("exec.argv"))) {
            try (FakeAgent agent = new FakeAgent(features)) {
                ScriptedConnector streams = new ScriptedConnector();
                MicroVMClient client = agent.client(streams);
                List<Runnable> calls = List.of(
                    () -> client.runCode("sb-1", "x"),
                    () -> client.startCode("sb-1", "x", null),
                    () -> client.createCodeContext("sb-1"),
                    () -> client.listCodeContexts("sb-1"),
                    () -> client.getCodeContext("sb-1", "ctx-1"),
                    () -> client.deleteCodeContext("sb-1", "ctx-1"),
                    () -> client.restartCodeContext("sb-1", "ctx-1"));
                for (Runnable call : calls) {
                    MicroVMUnsupportedFeatureException err = assertThrows(MicroVMUnsupportedFeatureException.class, call::run);
                    assertEquals(List.of("code.interpreter"), err.getFeatures());
                    assertTrue(err.getMessage().contains("restart the sandbox"), err.getMessage());
                }
                assertEquals(0, streams.connects);
                assertTrue(agent.interpreterCalls().isEmpty(), agent.calls.toString());
            }
        }
    }

    @Test
    void contextCallsUseTheInterpreterRoutes() throws Exception {
        try (FakeAgent agent = new FakeAgent(FEATURES)) {
            MicroVMClient client = agent.client(new ScriptedConnector());
            Sandbox sandbox = new Sandbox(client, sandboxData());

            CodeContext created = sandbox.createCodeContext(new CodeContextOptions().setLanguage("javascript").setCwd("/work"));
            assertEquals("ctx-1", created.id);
            assertEquals("javascript", created.language);
            assertEquals("/work", created.cwd);
            assertEquals("2026-11-15T10:00:00Z", created.createdAt);
            assertTrue(created.active);
            assertEquals("{\"language\":\"javascript\",\"cwd\":\"/work\"}", agent.bodies.get(0));

            sandbox.createCodeContext();
            assertEquals("{}", agent.bodies.get(1), "no options still sends a JSON object");

            List<CodeContext> listed = sandbox.listCodeContexts();
            assertEquals(2, listed.size());
            assertEquals("r", listed.get(1).language);
            assertFalse(listed.get(1).active);

            assertEquals("ctx-1", sandbox.getCodeContext("ctx-1").id);
            assertEquals("ctx/2", sandbox.getCodeContext("ctx/2").id);
            sandbox.deleteCodeContext("ctx-1");
            sandbox.deleteCodeContext(created);
            assertEquals("ctx-1", sandbox.restartCodeContext("ctx-1").id);
            assertEquals("ctx-1", sandbox.restartCodeContext(created).id);

            assertEquals(List.of(
                "POST " + CONTEXT_PATH,
                "POST " + CONTEXT_PATH,
                "GET " + CONTEXT_PATH,
                "GET " + CONTEXT_PATH + "/ctx-1",
                "GET " + CONTEXT_PATH + "/ctx%2F2",
                "DELETE " + CONTEXT_PATH + "/ctx-1",
                "DELETE " + CONTEXT_PATH + "/ctx-1",
                "POST " + CONTEXT_PATH + "/ctx-1/restart",
                "POST " + CONTEXT_PATH + "/ctx-1/restart"), agent.interpreterCalls());
            assertEquals(1, agent.calls.stream().filter(call -> call.endsWith(VERSION_PATH)).count());

            agent.nullContexts = true;
            assertTrue(client.listCodeContexts("sb-1").isEmpty());
        }
    }

    @Test
    void contextErrorsComeBackAsApiExceptions() throws Exception {
        try (FakeAgent agent = new FakeAgent(FEATURES)) {
            MicroVMClient client = agent.client(new ScriptedConnector());
            assertThrows(MicroVMNotFoundException.class, () -> client.getCodeContext("sb-1", "missing"));
            assertThrows(MicroVMNotFoundException.class, () -> client.deleteCodeContext("sb-1", "missing"));
            assertThrows(MicroVMNotFoundException.class, () -> client.restartCodeContext("sb-1", "missing"));
            MicroVMApiException limit = assertThrows(MicroVMApiException.class, () -> client.restartCodeContext("sb-1", "full"));
            assertEquals(429, limit.getStatusCode());
            assertEquals("context id is required", assertThrows(MicroVMException.class, () -> client.getCodeContext("sb-1", " ")).getMessage());
            assertThrows(MicroVMException.class, () -> client.deleteCodeContext("sb-1", (CodeContext) null));
        }
    }

    // Each create makes a new context, so one that may have reached the
    // server is never sent again: a 502 surfaces after one attempt.
    @Test
    void createIsNotRetriedOnceItMayHaveReachedTheServer() throws Exception {
        try (FakeAgent agent = new FakeAgent(FEATURES)) {
            agent.createFailures.set(1);
            MicroVMApiException err = assertThrows(MicroVMApiException.class, () -> agent.client(new ScriptedConnector()).createCodeContext("sb-1", null));
            assertEquals(502, err.getStatusCode());
            assertEquals(List.of("POST " + CONTEXT_PATH), agent.interpreterCalls());
        }
    }

    @Test
    void aRefusedHandshakeIsAnApiException() throws Exception {
        try (FakeAgent agent = new FakeAgent(FEATURES)) {
            ScriptedConnector streams = new ScriptedConnector();
            streams.failWith = new WebSocketHandshakeFailure("websocket connect failed: status=404", null, 404, Map.of(),
                "{\"error\":\"sandbox not found\"}");
            MicroVMNotFoundException err = assertThrows(MicroVMNotFoundException.class, () -> agent.client(streams).runCode("sb-1", "x"));
            assertEquals("sandbox not found", err.getMessage());
        }
    }

    @Test
    void resultFormatsListOnlyPresentFields() {
        CodeResult result = new CodeResult();
        assertTrue(result.formats().isEmpty());
        result.text = "";
        result.svg = "<svg/>";
        result.markdown = "# hi";
        result.latex = "x";
        result.pdf = "JVBER";
        result.jpeg = "/9j/";
        result.javascript = "1";
        result.extra = Map.of();
        assertEquals(List.of("markdown", "svg", "jpeg", "pdf", "latex", "javascript"), result.formats());
        assertTrue(result.toString().contains("markdown"));
        assertEquals("E: v", new ExecutionError("E", "v", "tb").toString());
    }

    private static SandboxData sandboxData() {
        SandboxData data = new SandboxData();
        data.id = "sb-1";
        return data;
    }
}
