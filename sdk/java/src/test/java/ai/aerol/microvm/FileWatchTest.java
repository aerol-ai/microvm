package ai.aerol.microvm;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpServer;

import ai.aerol.microvm.internal.StreamingWebSocket;
import ai.aerol.microvm.internal.StreamingWebSocketListener;
import ai.aerol.microvm.internal.WebSocketConnector;
import ai.aerol.microvm.internal.WebSocketHandshakeFailure;
import ai.aerol.microvm.model.FileEvent;
import ai.aerol.microvm.model.WatchOptions;

class FileWatchTest {
    private static final String START = "{\"type\":\"start\",\"path\":\"/work\",\"recursive\":true}";

    private static MicroVMClient client(WebSocketConnector connector) {
        return new MicroVMClient(
            new MicroVMConfig().setApiUrl("https://api.example.com").setPatToken("pat-token"),
            HttpClient.newHttpClient(),
            connector,
            name -> null
        );
    }

    @Test
    void watchFilesBuildsTheRequestAndDeliversEventsInOrder() {
        WatchConnector connector = new WatchConnector();
        connector.onConnect.add(START);
        List<FileEvent> seen = new CopyOnWriteArrayList<>();

        FileWatchHandle handle = client(connector).watchFiles("sb-1", "/work dir/a&b", new WatchOptions().setRecursive(true), seen::add);

        assertEquals(URI.create("wss://api.example.com/v1/sandboxes/sb-1/toolbox/files/watch?path=%2Fwork+dir%2Fa%26b&recursive=true"), connector.uri);
        assertEquals("Bearer pat-token", connector.headers.get("Authorization"));
        assertTrue(connector.socket.sentTexts.isEmpty(), "the client sends nothing");

        connector.emit("{\"type\":\"events\",\"events\":["
            + "{\"type\":\"create\",\"path\":\"/work/a\"},"
            + "{\"type\":\"create\",\"path\":\"/work/sub\",\"is_dir\":true},"
            + "{\"type\":\"write\",\"path\":\"/work/a\"},"
            + "{\"type\":\"overflow\",\"reason\":\"kernel_queue\"},"
            + "{\"type\":\"something_new\",\"path\":\"/work/x\"}]}");
        connector.emit("{\"type\":\"unknown_frame\"}");
        connector.emit("{\"type\":\"events\",\"events\":[{\"type\":\"remove\",\"path\":\"/work/a\"}]}");

        assertEquals(6, seen.size());
        assertEquals("create", seen.get(0).type);
        assertEquals("/work/a", seen.get(0).path);
        assertFalse(seen.get(0).isDir);
        assertNull(seen.get(0).reason);
        assertTrue(seen.get(1).isDir);
        assertEquals(FileEvent.WRITE, seen.get(2).type);
        assertEquals(FileEvent.OVERFLOW, seen.get(3).type);
        assertEquals("kernel_queue", seen.get(3).reason);
        assertEquals("something_new", seen.get(4).type, "unknown event types are passed through");
        assertEquals(FileEvent.REMOVE, seen.get(5).type);
        handle.stop();
    }

    @Test
    void recursiveIsSentOnlyWhenAsked() {
        WatchConnector connector = new WatchConnector();
        connector.onConnect.add(START);
        client(connector).watchFiles("sb-1", "/work", null, e -> { }).stop();
        assertEquals(URI.create("wss://api.example.com/v1/sandboxes/sb-1/toolbox/files/watch?path=%2Fwork"), connector.uri);
        client(connector).watchFiles("sb-1", "/work", new WatchOptions(), e -> { }).stop();
        assertFalse(connector.uri.toString().contains("recursive"));
    }

    @Test
    void watchFilesReturnsOnlyAfterTheStartFrame() {
        WatchConnector connector = new WatchConnector();
        AtomicBoolean startSent = new AtomicBoolean();
        connector.afterConnect = listener -> new Thread(() -> {
            try {
                Thread.sleep(200);
            } catch (InterruptedException ignored) {
            }
            startSent.set(true);
            listener.onText(START);
        }).start();

        long began = System.nanoTime();
        FileWatchHandle handle = client(connector).watchFiles("sb-1", "/work", null, e -> { });
        assertTrue(startSent.get(), "returned before the start frame");
        assertTrue(System.nanoTime() - began >= 150_000_000L);
        handle.stop();
    }

    @Test
    void aCloseBeforeStartFailsTheCall() {
        WatchConnector connector = new WatchConnector();
        connector.afterConnect = listener -> listener.onClose(1006, "gone");
        MicroVMException error = assertThrows(MicroVMException.class,
            () -> client(connector).watchFiles("sb-1", "/work", null, e -> { }));
        assertTrue(error.getMessage().contains("file watch closed"), error.getMessage());
    }

    @Test
    void anEndFrameFailsWaitWithTheReason() {
        WatchConnector connector = new WatchConnector();
        connector.onConnect.add(START);
        List<FileEvent> seen = new ArrayList<>();
        FileWatchHandle handle = client(connector).watchFiles("sb-1", "/work", null, seen::add);

        connector.emit("{\"type\":\"events\",\"events\":[{\"type\":\"remove\",\"path\":\"/work\",\"is_dir\":true}]}");
        connector.emit("{\"type\":\"end\",\"reason\":\"the watched folder was removed\"}");
        connector.listener.onClose(1000, "");

        MicroVMException error = assertThrows(MicroVMException.class, handle::waitForEnd);
        assertEquals("the watched folder was removed", error.getMessage());
        assertEquals(1, seen.size());
        assertTrue(connector.socket.closes.get() >= 1);
    }

    @Test
    void stopEndsTheWatchNormallyAndIsIdempotent() {
        WatchConnector connector = new WatchConnector();
        connector.onConnect.add(START);
        List<FileEvent> seen = new ArrayList<>();
        FileWatchHandle handle = client(connector).watchFiles("sb-1", "/work", null, seen::add);

        handle.stop();
        handle.stop();
        handle.close();
        connector.listener.onClose(1000, "stop");
        handle.waitForEnd();
        assertTrue(handle.completion().isDone());
        assertEquals(1, connector.socket.closes.get());
        // Nothing reaches the callback once stopped.
        connector.emit("{\"type\":\"events\",\"events\":[{\"type\":\"create\",\"path\":\"/work/late\"}]}");
        assertTrue(seen.isEmpty());
    }

    @Test
    void aDroppedConnectionFailsWait() {
        WatchConnector connector = new WatchConnector();
        connector.onConnect.add(START);
        FileWatchHandle handle = client(connector).watchFiles("sb-1", "/work", null, e -> { });
        connector.listener.onError(new RuntimeException("connection reset"));
        MicroVMException error = assertThrows(MicroVMException.class, handle::waitForEnd);
        assertEquals("connection reset", error.getMessage());
    }

    @Test
    void aThrowingCallbackEndsTheWatch() {
        WatchConnector connector = new WatchConnector();
        connector.onConnect.add(START);
        FileWatchHandle handle = client(connector).watchFiles("sb-1", "/work", null, e -> {
            throw new IllegalStateException("boom");
        });
        connector.emit("{\"type\":\"events\",\"events\":[{\"type\":\"create\",\"path\":\"/work/a\"}]}");
        MicroVMException error = assertThrows(MicroVMException.class, handle::waitForEnd);
        assertTrue(error.getMessage().contains("boom"), error.getMessage());
        assertEquals(1, connector.socket.closes.get());
    }

    @Test
    void anAgentWithoutTheRouteIsUnsupportedFeature() {
        for (WebSocketHandshakeFailure failure : List.of(
            handshake(404, Map.of("X-Toolbox-Route", List.of("none")), "{\"error\":\"not found\"}"),
            handshake(404, Map.of("x-toolbox-route", List.of("none")), ""),
            handshake(404, Map.of(), "{\"error\":\"not found\"}")
        )) {
            WatchConnector connector = new WatchConnector();
            connector.failWith = failure;
            MicroVMUnsupportedFeatureException error = assertThrows(MicroVMUnsupportedFeatureException.class,
                () -> client(connector).watchFiles("sb-old", "/work", null, e -> { }));
            assertEquals(List.of("files.watch"), error.getFeatures());
            assertEquals("sb-old", error.getSandboxId());
            assertTrue(error.getMessage().contains("restart the sandbox"), error.getMessage());
        }
    }

    @Test
    void otherHandshakeErrorsAreApiErrors() {
        Object[][] cases = {
            {501, "{\"error\":\"file watching needs a gVisor or Firecracker sandbox\"}", "file watching needs a gVisor or Firecracker sandbox"},
            {404, "{\"error\":\"path not found: /x\"}", "path not found: /x"},
            {404, "{\"error\":\"sandbox not found\"}", "sandbox not found"},
            {409, "{\"error\":\"not a folder: /x\"}", "not a folder: /x"},
            {429, "{\"error\":\"too many file watches open in this sandbox; stop one first\"}", "too many file watches open in this sandbox; stop one first"},
            {502, "<html>bad gateway</html>", "request failed with status 502"},
        };
        for (Object[] c : cases) {
            WatchConnector connector = new WatchConnector();
            connector.failWith = handshake((Integer) c[0], Map.of(), (String) c[1]);
            MicroVMApiException error = assertThrows(MicroVMApiException.class,
                () -> client(connector).watchFiles("sb-1", "/work", null, e -> { }));
            assertEquals((int) (Integer) c[0], error.getStatusCode());
            assertEquals(c[2], error.getMessage());
        }
    }

    @Test
    void argumentsAreChecked() {
        MicroVMClient client = client(new WatchConnector());
        assertThrows(MicroVMException.class, () -> client.watchFiles(" ", "/work", null, e -> { }));
        assertThrows(MicroVMException.class, () -> client.watchFiles("sb-1", "", null, e -> { }));
        assertThrows(MicroVMException.class, () -> client.watchFiles("sb-1", "/work", null, null));
    }

    @Test
    void sandboxWatchFilesUsesItsId() {
        WatchConnector connector = new WatchConnector();
        connector.onConnect.add(START);
        MicroVMClient client = client(connector);
        ai.aerol.microvm.model.SandboxData data = new ai.aerol.microvm.model.SandboxData();
        data.id = "sb-obj";
        Sandbox sandbox = new Sandbox(client, data);
        sandbox.watchFiles("/work", new WatchOptions().setRecursive(true), e -> { }).stop();
        assertTrue(connector.uri.getPath().endsWith("/v1/sandboxes/sb-obj/toolbox/files/watch"), connector.uri.toString());
    }

    // The real JDK WebSocket client against a server that refuses the
    // upgrade: the status, header and body must survive the handshake path.
    @Test
    void realHandshakeRefusalsMapToTheRightErrors() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        AtomicReference<String> auth = new AtomicReference<>();
        server.createContext("/", exchange -> {
            auth.set(exchange.getRequestHeaders().getFirst("Authorization"));
            String path = exchange.getRequestURI().getPath();
            byte[] body;
            int status;
            if (path.contains("/sb-old/")) {
                exchange.getResponseHeaders().add("X-Toolbox-Route", "none");
                status = 404;
                body = "{\"error\":\"not found\"}".getBytes(StandardCharsets.UTF_8);
            } else {
                status = 501;
                body = "{\"error\":\"file watching needs a gVisor or Firecracker sandbox\"}".getBytes(StandardCharsets.UTF_8);
            }
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        try {
            MicroVMClient client = new MicroVMClient(
                new MicroVMConfig().setApiUrl("http://127.0.0.1:" + server.getAddress().getPort()).setPatToken("pat-token"),
                HttpClient.newHttpClient(),
                null,
                name -> null
            );
            MicroVMUnsupportedFeatureException old = assertThrows(MicroVMUnsupportedFeatureException.class,
                () -> client.watchFiles("sb-old", "/work", null, e -> { }));
            assertEquals(List.of("files.watch"), old.getFeatures());
            assertEquals("Bearer pat-token", auth.get());

            MicroVMApiException refused = assertThrows(MicroVMApiException.class,
                () -> client.watchFiles("sb-docker", "/work", null, e -> { }));
            assertEquals(501, refused.getStatusCode());
            assertEquals("file watching needs a gVisor or Firecracker sandbox", refused.getMessage());
        } finally {
            server.stop(0);
        }
    }

    private static WebSocketHandshakeFailure handshake(int status, Map<String, List<String>> headers, String body) {
        return new WebSocketHandshakeFailure("websocket connect failed: status=" + status, null, status, headers, body);
    }

    private static final class WatchConnector implements WebSocketConnector {
        URI uri;
        Map<String, String> headers;
        StreamingWebSocketListener listener;
        final RecordingSocket socket = new RecordingSocket();
        final List<String> onConnect = new ArrayList<>();
        java.util.function.Consumer<StreamingWebSocketListener> afterConnect;
        RuntimeException failWith;

        @Override
        public StreamingWebSocket connect(URI uri, Map<String, String> headers, StreamingWebSocketListener listener) {
            this.uri = uri;
            this.headers = headers;
            this.listener = listener;
            if (failWith != null) {
                throw failWith;
            }
            for (String frame : onConnect) {
                listener.onText(frame);
            }
            if (afterConnect != null) {
                afterConnect.accept(listener);
            }
            return socket;
        }

        void emit(String text) {
            listener.onText(text);
        }
    }

    private static final class RecordingSocket implements StreamingWebSocket {
        final List<String> sentTexts = new ArrayList<>();
        final AtomicInteger closes = new AtomicInteger();

        @Override
        public void sendText(String text) {
            sentTexts.add(text);
        }

        @Override
        public void sendBinary(ByteBuffer data) {
        }

        @Override
        public void sendClose(int statusCode, String reason) {
            closes.incrementAndGet();
        }
    }
}
