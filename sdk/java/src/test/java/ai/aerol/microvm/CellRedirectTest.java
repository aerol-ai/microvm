package ai.aerol.microvm;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
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
import ai.aerol.microvm.model.RetryConfig;

/**
 * Cells of a federation (plans/kubernetes-v2-architecture.md §12.4, C16): a
 * call for a sandbox in another cell is answered 421 with that cell's base
 * URL in X-Aerolvm-Cell-Endpoint. The client sends it there once, remembers
 * the cell for that sandbox, and never follows a second hop.
 */
class CellRedirectTest {
    private final List<HttpServer> servers = new ArrayList<>();
    private final ExecutorService pool = Executors.newCachedThreadPool();

    @AfterEach
    void stop() {
        servers.forEach(server -> server.stop(0));
        pool.shutdownNow();
    }

    /** One request as a fake cell saw it. */
    static final class Seen {
        final String method;
        final String uri;
        final String authorization;
        final String team;
        final String contentType;
        final byte[] body;

        Seen(HttpExchange exchange, byte[] body) {
            this.method = exchange.getRequestMethod();
            this.uri = exchange.getRequestURI().toString();
            this.authorization = exchange.getRequestHeaders().getFirst("Authorization");
            this.team = exchange.getRequestHeaders().getFirst(MicroVMClient.TEAM_HEADER);
            this.contentType = exchange.getRequestHeaders().getFirst("Content-Type");
            this.body = body;
        }
    }

    @FunctionalInterface
    interface Answer {
        /** {@code sandbox} is the path segment after /v1/sandboxes/, or null. */
        void answer(HttpExchange exchange, String sandbox) throws IOException;
    }

    /** A fake cell at {@code url} (with an optional path prefix) that records every request. */
    final class Cell {
        final List<Seen> seen = Collections.synchronizedList(new ArrayList<>());
        final String url;

        Cell(String prefix, Answer answer) throws IOException {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.setExecutor(pool);
            server.createContext("/", exchange -> {
                try {
                    // Read the whole body first, as a real server would before
                    // it answers, so the client never sees a reset.
                    seen.add(new Seen(exchange, exchange.getRequestBody().readAllBytes()));
                    answer.answer(exchange, sandboxOf(exchange.getRequestURI().getPath()));
                } finally {
                    exchange.close();
                }
            });
            server.start();
            servers.add(server);
            url = "http://127.0.0.1:" + server.getAddress().getPort() + prefix;
        }

        int hits() {
            return seen.size();
        }
    }

    @Test
    void followsACellRedirectOnceWithTheSameAuthAndBody() throws Exception {
        Cell cell2 = new Cell("", (exchange, sandbox) -> json(exchange, 200, execResult("from cell 2")));
        Cell cell1 = new Cell("", (exchange, sandbox) -> redirect(exchange, cell2.url));

        // exec never re-sends on a plain 421; the cell hop is its first real
        // send, so it goes anyway.
        ExecResult result = client(cell1.url).exec("sb-x", new ExecRequest().setCommand("echo hi"));

        assertEquals("from cell 2", result.stdout);
        assertEquals(1, cell1.hits());
        assertEquals(1, cell2.hits());
        Seen first = cell1.seen.get(0);
        Seen second = cell2.seen.get(0);
        assertEquals("POST", second.method);
        assertEquals("/v1/sandboxes/sb-x/toolbox/process/execute", second.uri);
        assertEquals(first.uri, second.uri);
        assertEquals("Bearer pat-token", second.authorization);
        assertEquals("team-a", second.team);
        assertEquals("application/json", second.contentType);
        assertArrayEquals(first.body, second.body);
        assertTrue(new String(second.body, StandardCharsets.UTF_8).contains("echo hi"));
    }

    @Test
    void aStreamedDownloadFollowsTheRedirectWithItsQuery() throws Exception {
        Cell cell2 = new Cell("", (exchange, sandbox) -> raw(exchange, 200, "file body".getBytes(StandardCharsets.UTF_8)));
        Cell cell1 = new Cell("", (exchange, sandbox) -> redirect(exchange, cell2.url));

        byte[] data = client(cell1.url).downloadFile("sb-x", "/tmp/a b.txt");

        assertEquals("file body", new String(data, StandardCharsets.UTF_8));
        assertEquals(cell1.seen.get(0).uri, cell2.seen.get(0).uri);
        assertTrue(cell2.seen.get(0).uri.startsWith("/v1/sandboxes/sb-x/toolbox/files/download?path="), cell2.seen.get(0).uri);
    }

    @Test
    void remembersTheCellForThatSandboxOnly() throws Exception {
        Cell cell2 = new Cell("", (exchange, sandbox) -> json(exchange, 200, sandbox(sandbox)));
        Cell cell1 = new Cell("", (exchange, sandbox) -> {
            if ("sb-x".equals(sandbox)) {
                redirect(exchange, cell2.url);
            } else {
                json(exchange, 200, sandbox(sandbox));
            }
        });
        MicroVMClient client = client(cell1.url);

        assertEquals("sb-x", client.get("sb-x").id);
        // Any route under the sandbox goes straight to its cell.
        client.stop("sb-x");
        client.get("sb-x");
        assertEquals(1, cell1.hits());
        assertEquals(3, cell2.hits());
        assertEquals("/v1/sandboxes/sb-x/stop", cell2.seen.get(1).uri);

        // Another sandbox, even one whose ID starts the same, still goes to
        // the configured cell.
        assertEquals("sb-xy", client.get("sb-xy").id);
        assertEquals("sb-y", client.get("sb-y").id);
        assertEquals(3, cell1.hits());
        assertEquals(3, cell2.hits());
    }

    @Test
    void misdirectedWithoutACellEndpointRetriesTheSameCell() throws Exception {
        // null: no header at all; "": an empty one, which names no cell.
        for (String header : java.util.Arrays.asList(null, "")) {
            AtomicInteger hits = new AtomicInteger();
            Cell cell1 = new Cell("", (exchange, sandbox) -> {
                if (hits.incrementAndGet() == 1) {
                    if (header != null) {
                        exchange.getResponseHeaders().set(MicroVMClient.CELL_ENDPOINT_HEADER, header);
                    }
                    json(exchange, 421, Map.of("error", "misdirected request; reconnect"));
                    return;
                }
                json(exchange, 200, sandbox(sandbox));
            });
            MicroVMClient client = client(cell1.url);

            assertEquals("sb-x", client.get("sb-x").id);
            assertEquals(2, cell1.hits(), "header " + header);
            client.get("sb-x");
            assertEquals(3, cell1.hits(), "header " + header);
        }
    }

    @Test
    void aSecondCellRedirectSurfacesWithoutALoop() throws Exception {
        AtomicReference<String> cell1Url = new AtomicReference<>();
        Cell cell2 = new Cell("", (exchange, sandbox) -> redirect(exchange, cell1Url.get()));
        Cell cell1 = new Cell("", (exchange, sandbox) -> redirect(exchange, cell2.url));
        cell1Url.set(cell1.url);

        MicroVMApiException error = assertThrows(MicroVMApiException.class, () -> client(cell1.url).get("sb-x"));

        assertEquals(421, error.getStatusCode());
        assertEquals(1, cell1.hits());
        assertEquals(1, cell2.hits());
    }

    @Test
    void anHttpsClientDoesNotFollowAnHttpCell() throws Exception {
        AtomicReference<String> endpoint = new AtomicReference<>();
        Cell cell2 = new Cell("", (exchange, sandbox) -> json(exchange, 200, sandbox(sandbox)));
        Cell cell1 = new Cell("", (exchange, sandbox) -> redirect(exchange, endpoint.get()));
        PlainTextTls transport = new PlainTextTls();
        MicroVMClient client = client(https(cell1.url), transport, null);

        endpoint.set(cell2.url);
        MicroVMApiException error = assertThrows(MicroVMApiException.class, () -> client.get("sb-x"));
        assertEquals(421, error.getStatusCode());
        assertEquals(1, cell1.hits());
        assertEquals(0, cell2.hits());

        // The same answer over https is followed, so the scheme alone was
        // the refusal, and the refused cell was not remembered.
        endpoint.set(https(cell2.url));
        assertEquals("sb-x", client.get("sb-x").id);
        assertEquals(2, cell1.hits());
        assertEquals(1, cell2.hits());
        assertEquals(https(cell2.url) + "/v1/sandboxes/sb-x", transport.uris.get(transport.uris.size() - 1));
    }

    @Test
    void anUnusableCellEndpointSurfacesAtOnce() throws Exception {
        List<String> endpoints = List.of(
            "ftp://cell2.example",
            "cell2.example",
            "http://",
            "https://cell2.example/?x=1",
            "https://cell2.example/#top",
            "not a url"
        );
        for (String endpoint : endpoints) {
            Cell cell1 = new Cell("", (exchange, sandbox) -> redirect(exchange, endpoint));

            MicroVMApiException error = assertThrows(MicroVMApiException.class, () -> client(cell1.url).get("sb-x"), endpoint);

            // The sandbox is in another cell, so asking this one again is no use.
            assertEquals(421, error.getStatusCode(), endpoint);
            assertEquals(1, cell1.hits(), endpoint);
        }
    }

    @Test
    void aNotFoundFromTheRememberedCellForgetsIt() throws Exception {
        AtomicInteger cell2Status = new AtomicInteger(200);
        Cell cell2 = new Cell("", (exchange, sandbox) -> {
            if (cell2Status.get() == 404) {
                json(exchange, 404, Map.of("error", "sandbox not found"));
            } else {
                json(exchange, 200, sandbox(sandbox));
            }
        });
        Cell cell1 = new Cell("", (exchange, sandbox) -> redirect(exchange, cell2.url));
        MicroVMClient client = client(cell1.url);
        client.get("sb-x");

        cell2Status.set(404);
        assertThrows(MicroVMNotFoundException.class, () -> client.get("sb-x"));
        assertEquals(1, cell1.hits());
        assertEquals(2, cell2.hits());

        // Forgotten: the next call asks the configured cell first.
        cell2Status.set(200);
        client.get("sb-x");
        assertEquals(2, cell1.hits());
        assertEquals(3, cell2.hits());
    }

    @Test
    void aMissingFileDoesNotForgetTheCell() throws Exception {
        Cell cell2 = new Cell("", (exchange, sandbox) -> {
            if (exchange.getRequestURI().getPath().endsWith("/toolbox/files/info")) {
                json(exchange, 404, Map.of("error", "stat /nope: no such file or directory", "code", "file_not_found"));
            } else {
                json(exchange, 200, sandbox(sandbox));
            }
        });
        Cell cell1 = new Cell("", (exchange, sandbox) -> redirect(exchange, cell2.url));
        MicroVMClient client = client(cell1.url);
        client.get("sb-x");

        assertFalse(client.fileExists("sb-x", "/nope"));
        client.get("sb-x");

        assertEquals(1, cell1.hits());
        assertEquals(3, cell2.hits());
    }

    @Test
    void aStreamedBodyIsNotResentButTheCellIsRemembered() throws Exception {
        Cell cell2 = new Cell("", (exchange, sandbox) -> json(exchange, 200, Map.of()));
        Cell cell1 = new Cell("", (exchange, sandbox) -> redirect(exchange, cell2.url));
        MicroVMClient client = client(cell1.url);

        MicroVMApiException error = assertThrows(MicroVMApiException.class, () ->
            client.uploadFileStream("sb-x", "/a.txt", new ByteArrayInputStream("first".getBytes(StandardCharsets.UTF_8)), null));
        assertEquals(421, error.getStatusCode());
        assertEquals(0, cell2.hits());

        // The caller's own retry, with fresh data, goes straight to the cell.
        client.uploadFileStream("sb-x", "/a.txt", new ByteArrayInputStream("second".getBytes(StandardCharsets.UTF_8)), null);
        assertEquals(1, cell1.hits());
        assertEquals(1, cell2.hits());
        assertTrue(new String(cell2.seen.get(0).body, StandardCharsets.UTF_8).contains("second"));
    }

    @Test
    void theCellUrlKeepsItsOwnPathPrefix() throws Exception {
        Cell cell2 = new Cell("/cell-two", (exchange, sandbox) -> json(exchange, 200, sandbox(sandbox)));
        // A trailing slash on the endpoint must not double the slash.
        Cell cell1 = new Cell("/cell-one", (exchange, sandbox) -> redirect(exchange, cell2.url + "/"));

        assertEquals("sb-x", client(cell1.url).get("sb-x").id);

        assertEquals("/cell-one/v1/sandboxes/sb-x", cell1.seen.get(0).uri);
        assertEquals("/cell-two/v1/sandboxes/sb-x", cell2.seen.get(0).uri);
    }

    @Test
    void aStreamToARememberedSandboxGoesToItsCell() throws Exception {
        Cell cell2 = new Cell("", (exchange, sandbox) -> json(exchange, 200, sandbox(sandbox)));
        Cell cell1 = new Cell("", (exchange, sandbox) -> redirect(exchange, cell2.url));
        RecordingConnector sockets = new RecordingConnector();
        MicroVMClient client = client(cell1.url, HttpClient.newHttpClient(), sockets);

        client.execStream("sb-x", new ExecStreamOptions().setCommand("ls"));
        client.get("sb-x");
        client.execStream("sb-x", new ExecStreamOptions().setCommand("ls"));

        assertEquals(List.of(
            ws(cell1.url) + "/v1/sandboxes/sb-x/toolbox/process/exec/stream",
            ws(cell2.url) + "/v1/sandboxes/sb-x/toolbox/process/exec/stream"
        ), sockets.uris);
    }

    @Test
    void concurrentCallsLearnEachSandboxOnce() throws Exception {
        Cell cell2 = new Cell("", (exchange, sandbox) -> json(exchange, 200, sandbox(sandbox)));
        Cell cell1 = new Cell("", (exchange, sandbox) -> redirect(exchange, cell2.url));
        MicroVMClient client = client(cell1.url);
        int sandboxes = 16;

        for (int round = 0; round < 2; round++) {
            List<Future<String>> calls = new ArrayList<>();
            for (int i = 0; i < sandboxes; i++) {
                String id = "sb-" + i;
                calls.add(pool.submit(() -> client.get(id).id));
            }
            for (int i = 0; i < sandboxes; i++) {
                assertEquals("sb-" + i, calls.get(i).get());
            }
        }

        assertEquals(sandboxes, cell1.hits());
        assertEquals(2 * sandboxes, cell2.hits());
    }

    @Test
    void cellRoutesDropTheOldestPastTheCap() {
        assertEquals(10_000, MicroVMClient.CellRoutes.MAX_ENTRIES);
        MicroVMClient.CellRoutes routes = new MicroVMClient.CellRoutes(2);
        routes.put("sb-a", "https://cell1.example");
        routes.put("sb-b", "https://cell2.example");
        routes.put("sb-c", "https://cell3.example");

        assertEquals(2, routes.size());
        assertNull(routes.get("sb-a"));
        assertEquals("https://cell2.example", routes.get("sb-b"));
        assertEquals("https://cell3.example", routes.get("sb-c"));

        // A 404 from a cell other than the remembered one keeps the route.
        routes.remove("sb-b", "https://cell1.example");
        assertEquals("https://cell2.example", routes.get("sb-b"));
        routes.remove("sb-b", "https://cell2.example");
        assertNull(routes.get("sb-b"));
    }

    private MicroVMClient client(String apiUrl) {
        return client(apiUrl, HttpClient.newHttpClient(), null);
    }

    private MicroVMClient client(String apiUrl, HttpClient httpClient, WebSocketConnector sockets) {
        return new MicroVMClient(
            new MicroVMConfig()
                .setApiUrl(apiUrl)
                .setPatToken("pat-token")
                .setTeam("team-a")
                // Backoff timing is not under test.
                .setRetry(new RetryConfig().setMaxRetries(3).setBaseDelayMs(1).setMaxDelayMs(1)),
            httpClient,
            sockets,
            name -> null
        );
    }

    private static String sandboxOf(String path) {
        int at = path.indexOf("/v1/sandboxes/");
        if (at < 0) {
            return null;
        }
        String rest = path.substring(at + "/v1/sandboxes/".length());
        int slash = rest.indexOf('/');
        return slash < 0 ? rest : rest.substring(0, slash);
    }

    private static void redirect(HttpExchange exchange, String endpoint) throws IOException {
        exchange.getResponseHeaders().set(MicroVMClient.CELL_ENDPOINT_HEADER, endpoint);
        json(exchange, 421, Map.of("error", "this sandbox is in another cell: send the request to the address in " + MicroVMClient.CELL_ENDPOINT_HEADER));
    }

    private static void json(HttpExchange exchange, int status, Object value) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        raw(exchange, status, JsonSupport.writeBytes(value));
    }

    private static void raw(HttpExchange exchange, int status, byte[] body) throws IOException {
        exchange.sendResponseHeaders(status, body.length);
        exchange.getResponseBody().write(body);
    }

    private static Map<String, Object> sandbox(String id) {
        Map<String, Object> sandbox = new LinkedHashMap<>();
        sandbox.put("id", id);
        sandbox.put("image", "ubuntu:22.04");
        sandbox.put("status", "started");
        return sandbox;
    }

    private static Map<String, Object> execResult(String stdout) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("stdout", stdout);
        result.put("stderr", "");
        result.put("exit_code", 0);
        result.put("duration_ms", 1);
        return result;
    }

    private static String https(String url) {
        return "https" + url.substring("http".length());
    }

    private static String ws(String url) {
        return "ws" + url.substring("http".length());
    }

    /**
     * Stands in for TLS: sends an https URL to the loopback server as plain
     * http and records the URL the client asked for, so a test can give the
     * client an https base without a certificate.
     */
    private static final class PlainTextTls extends HttpClient {
        private final HttpClient delegate = HttpClient.newHttpClient();
        final List<String> uris = Collections.synchronizedList(new ArrayList<>());

        @Override
        public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> handler) throws IOException, InterruptedException {
            String url = request.uri().toString();
            uris.add(url);
            if (!url.startsWith("https://")) {
                throw new IOException("the client sent plain http: " + url);
            }
            HttpRequest.Builder plain = HttpRequest.newBuilder(URI.create("http" + url.substring("https".length())))
                .method(request.method(), request.bodyPublisher().orElse(HttpRequest.BodyPublishers.noBody()));
            request.headers().map().forEach((name, values) -> values.forEach(value -> plain.header(name, value)));
            return delegate.send(plain.build(), handler);
        }

        @Override
        public <T> java.util.concurrent.CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request, HttpResponse.BodyHandler<T> handler) {
            throw new UnsupportedOperationException();
        }

        @Override
        public <T> java.util.concurrent.CompletableFuture<HttpResponse<T>> sendAsync(
            HttpRequest request,
            HttpResponse.BodyHandler<T> handler,
            HttpResponse.PushPromiseHandler<T> pushPromiseHandler
        ) {
            throw new UnsupportedOperationException();
        }

        @Override
        public java.util.Optional<java.net.CookieHandler> cookieHandler() {
            return delegate.cookieHandler();
        }

        @Override
        public java.util.Optional<java.time.Duration> connectTimeout() {
            return delegate.connectTimeout();
        }

        @Override
        public Redirect followRedirects() {
            return delegate.followRedirects();
        }

        @Override
        public java.util.Optional<java.net.ProxySelector> proxy() {
            return delegate.proxy();
        }

        @Override
        public javax.net.ssl.SSLContext sslContext() {
            return delegate.sslContext();
        }

        @Override
        public javax.net.ssl.SSLParameters sslParameters() {
            return delegate.sslParameters();
        }

        @Override
        public java.util.Optional<java.net.Authenticator> authenticator() {
            return delegate.authenticator();
        }

        @Override
        public Version version() {
            return delegate.version();
        }

        @Override
        public java.util.Optional<java.util.concurrent.Executor> executor() {
            return delegate.executor();
        }
    }

    /** Records where each stream was opened; the socket itself does nothing. */
    private static final class RecordingConnector implements WebSocketConnector {
        final List<String> uris = Collections.synchronizedList(new ArrayList<>());

        @Override
        public StreamingWebSocket connect(URI uri, Map<String, String> headers, StreamingWebSocketListener listener) {
            uris.add(uri.toString());
            return new StreamingWebSocket() {
                @Override
                public void sendText(String text) {
                }

                @Override
                public void sendBinary(ByteBuffer data) {
                }

                @Override
                public void sendClose(int statusCode, String reason) {
                }
            };
        }
    }
}
