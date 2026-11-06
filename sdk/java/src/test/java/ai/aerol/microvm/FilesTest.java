package ai.aerol.microvm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import ai.aerol.microvm.internal.JsonSupport;
import ai.aerol.microvm.model.CopyFileOptions;
import ai.aerol.microvm.model.DeleteFileOptions;
import ai.aerol.microvm.model.FileInfo;
import ai.aerol.microvm.model.FileList;
import ai.aerol.microvm.model.ListFilesOptions;
import ai.aerol.microvm.model.MakeDirOptions;
import ai.aerol.microvm.model.MoveFileOptions;
import ai.aerol.microvm.model.RetryConfig;
import ai.aerol.microvm.model.SandboxData;

/**
 * File verbs beyond upload and download (plans/agent-sandbox-feature-
 * parity.md, F1): the toolbox routes they call, the /version check before an
 * option an older agent would ignore, and each verb's retry rule.
 */
class FilesTest {
    static final class Call {
        private final String method;
        private final String route;
        private final Map<String, String> query;

        Call(String method, String route, Map<String, String> query) {
            this.method = method;
            this.route = route;
            this.query = query;
        }

        String method() {
            return method;
        }

        String route() {
            return route;
        }

        Map<String, String> query() {
            return query;
        }
    }

    static final class Reply {
        private final int status;
        private final Object body;
        private final Map<String, String> headers;

        Reply(int status, Object body, Map<String, String> headers) {
            this.status = status;
            this.body = body;
            this.headers = headers;
        }

        static Reply of(int status, Object body) {
            return new Reply(status, body, Map.of());
        }

        int status() {
            return status;
        }

        Object body() {
            return body;
        }

        Map<String, String> headers() {
            return headers;
        }
    }

    interface Responder {
        Reply reply(Call call, int n);
    }

    private HttpServer server;
    private final List<Call> calls = Collections.synchronizedList(new ArrayList<>());

    @AfterEach
    void stop() {
        if (server != null) {
            server.stop(0);
        }
    }

    /** A local stand-in for sandboxd's toolbox pass-through. */
    private MicroVMClient serve(List<String> features, Responder responder) throws IOException {
        Map<String, Integer> counts = new HashMap<>();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            try {
                String path = exchange.getRequestURI().getPath();
                if (path.endsWith("/toolbox/version")) {
                    write(exchange, Reply.of(200, Map.of("version", "test", "features", features)));
                    return;
                }
                Map<String, String> query = new LinkedHashMap<>();
                String raw = exchange.getRequestURI().getRawQuery();
                if (raw != null) {
                    for (String pair : raw.split("&")) {
                        String[] kv = pair.split("=", 2);
                        query.put(URLDecoder.decode(kv[0], StandardCharsets.UTF_8), kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "");
                    }
                }
                Call call = new Call(exchange.getRequestMethod(), path.substring(path.indexOf("/toolbox") + "/toolbox".length()), query);
                int n;
                synchronized (counts) {
                    // Keyed by the full path, so each sandbox counts its own calls.
                    String key = call.method() + " " + path;
                    n = counts.getOrDefault(key, 0);
                    counts.put(key, n + 1);
                }
                calls.add(call);
                write(exchange, responder.reply(call, n));
            } finally {
                exchange.close();
            }
        });
        server.start();
        return new MicroVMClient(
            new MicroVMConfig()
                .setApiUrl("http://127.0.0.1:" + server.getAddress().getPort())
                .setPatToken("pat")
                .setRetry(new RetryConfig().setMaxRetries(3).setBaseDelayMs(1).setMaxDelayMs(1)),
            HttpClient.newHttpClient(),
            null,
            name -> null);
    }

    private static void write(HttpExchange exchange, Reply reply) throws IOException {
        reply.headers().forEach((k, v) -> exchange.getResponseHeaders().set(k, v));
        if (reply.body() == null) {
            exchange.sendResponseHeaders(reply.status(), -1);
            return;
        }
        byte[] body = JsonSupport.writeBytes(reply.body());
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(reply.status(), body.length);
        exchange.getResponseBody().write(body);
    }

    private static Map<String, Object> err(String message, String code) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", message);
        if (code != null) {
            body.put("code", code);
        }
        return body;
    }

    private static Map<String, Object> entry(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            m.put((String) kv[i], kv[i + 1]);
        }
        return m;
    }

    @Test
    void listFilesSendsADepthAndCapAndReadsExtendedInfo() throws Exception {
        MicroVMClient client = serve(List.of("files.verbs"), (call, n) -> new Reply(200, List.of(
            entry("name", "a", "isDir", true, "size", 64, "size_bytes", 64, "path", "/w/a", "modTime", "2026-01-01T00:00:00Z"),
            entry("name", "big", "size", 2147483647L, "size_bytes", 5L << 30, "path", "/w/big"),
            entry("name", "link", "size", 4, "size_bytes", 4, "path", "/w/link", "symlink_target", "a"),
            entry("name", "old", "size", 7)), Map.of("X-Toolbox-Truncated", "true")));
        FileList list = client.listFiles("sb-1", "/w/");
        assertEquals(Map.of("path", "/w/", "depth", "1", "limit", "10000", "extended", "true"), calls.get(0).query());
        assertTrue(list.truncated);
        assertEquals(List.of("/w/a", "/w/big", "/w/link", "/w/old"), list.entries.stream().map(e -> e.path).collect(Collectors.toList()));
        assertEquals(5L << 30, list.entries.get(1).size);
        assertEquals("a", list.entries.get(2).symlinkTarget);
        assertEquals(7, list.entries.get(3).size);
        assertTrue(list.entries.get(0).isDir);
        assertEquals("2026-01-01T00:00:00Z", list.entries.get(0).modTime);
        assertNull(list.entries.get(0).symlinkTarget);

        client.listFiles("sb-1", "/w", new ListFilesOptions().setDepth(3).setLimit(5));
        assertEquals("3", calls.get(1).query().get("depth"));
        assertEquals("5", calls.get(1).query().get("limit"));
        assertThrows(MicroVMException.class, () -> client.listFiles("sb-1", "/w", new ListFilesOptions().setDepth(0)));
    }

    @Test
    void anOlderAgentFailsClosedBeforeAnyFileCall() throws Exception {
        MicroVMClient client = serve(List.of(), (call, n) -> Reply.of(204, null));
        List<Runnable> refused = List.of(
            () -> client.listFiles("sb-1", "/"),
            () -> client.moveFile("sb-1", "/a", "/b"),
            () -> client.copyFile("sb-1", "/a", "/b"),
            () -> client.makeDir("sb-1", "/d"));
        for (Runnable call : refused) {
            MicroVMUnsupportedFeatureException e = assertThrows(MicroVMUnsupportedFeatureException.class, call::run);
            assertEquals(List.of("files.verbs"), e.getFeatures());
        }
        assertTrue(calls.isEmpty());
        // An older agent does what these ask anyway, so no check is needed.
        client.moveFile("sb-1", "/a", "/b", new MoveFileOptions().setOverwrite(true));
        client.makeDir("sb-1", "/d", new MakeDirOptions().setParents(true));
        assertEquals("true", calls.get(0).query().get("overwrite"));
        assertEquals("true", calls.get(1).query().get("parents"));
    }

    @Test
    void getFileInfoFallsBackAndFileExistsTellsAMissingFileFromAMissingSandbox() throws Exception {
        Map<String, Reply> answers = Map.of(
            "/new", Reply.of(200, entry("name", "new", "size", 2147483647L, "size_bytes", 3L << 30, "path", "/new")),
            "/old", Reply.of(200, entry("name", "old", "size", 12)),
            "/gone", Reply.of(404, err("stat /gone: no such file or directory", "file_not_found")),
            "/gone-old", Reply.of(404, err("stat /gone-old: no such file or directory", null)),
            "/no-sandbox", Reply.of(404, err("sandbox not found", null)),
            "/broken", Reply.of(403, err("permission denied", null)));
        MicroVMClient client = serve(List.of(), (call, n) -> answers.get(call.query().get("path")));
        FileInfo info = client.getFileInfo("sb-1", "/new");
        assertEquals(3L << 30, info.size);
        assertEquals("true", calls.get(0).query().get("extended"));
        FileInfo old = client.getFileInfo("sb-1", "/old");
        assertEquals(12, old.size);
        assertEquals("/old", old.path);
        assertTrue(client.fileExists("sb-1", "/new"));
        assertFalse(client.fileExists("sb-1", "/gone"));
        assertFalse(client.fileExists("sb-1", "/gone-old"));
        assertThrows(MicroVMApiException.class, () -> client.fileExists("sb-1", "/no-sandbox"));
        assertThrows(MicroVMApiException.class, () -> client.fileExists("sb-1", "/broken"));
    }

    @Test
    void aRetriedDeleteOrMkdirCountsWorkAlreadyDone() throws Exception {
        // n counts per route and every delete is one route (the path is in
        // the query), so the cases that fail only their first try count
        // their own tries.
        Map<String, Integer> tries = new java.util.concurrent.ConcurrentHashMap<>();
        MicroVMClient client = serve(List.of("files.verbs"), (call, n) -> {
            String path = call.query().getOrDefault("path", "");
            int tried = tries.merge(path, 1, Integer::sum);
            if (path.startsWith("/lost")) {
                if (n == 0) {
                    return Reply.of(502, null);
                }
                return "DELETE".equals(call.method())
                    ? Reply.of(404, err("lstat: no such file or directory", "file_not_found"))
                    : Reply.of(409, err(path + " already exists", "folder_exists"));
            }
            switch (path) {
                case "/route-missing":
                    return tried == 1 ? new Reply(503, null, Map.of("Retry-After", "0")) : Reply.of(404, err("not found", null));
                case "/refused":
                    // A 429 is answered before any work: the path was never there.
                    return tried == 1
                        ? new Reply(429, null, Map.of("Retry-After", "0"))
                        : Reply.of(404, err("lstat: no such file or directory", "file_not_found"));
                case "/missing":
                    return Reply.of(404, err("lstat /missing: no such file or directory", "file_not_found"));
                case "/a-file":
                    return Reply.of(409, err("mkdir /a-file: file exists", null));
                case "/new-dir":
                    return Reply.of(201, null);
                default:
                    return Reply.of(204, null);
            }
        });
        client.deleteFile("sb-1", "/lost-del", new DeleteFileOptions().setRecursive(true));
        assertEquals("true", calls.get(0).query().get("recursive"));
        client.makeDir("sb-1", "/lost-dir", new MakeDirOptions().setMode(01750));
        assertEquals(Map.of("path", "/lost-dir", "parents", "false", "mode", "1750"), calls.get(2).query());
        client.makeDir("sb-1", "/new-dir");
        MicroVMApiException missing = assertThrows(MicroVMApiException.class, () -> client.deleteFile("sb-1", "/missing"));
        assertEquals(404, missing.getStatusCode());
        assertEquals("file_not_found", missing.getCode());
        assertEquals(409, assertThrows(MicroVMApiException.class, () -> client.makeDir("sb-1", "/a-file")).getStatusCode());
        // An uncoded 404 on a retry may be an agent without the route.
        assertEquals(404, assertThrows(MicroVMApiException.class, () -> client.deleteFile("sb-1", "/route-missing")).getStatusCode());
        // After a 429 the server did nothing, so a coded 404 on the retry
        // means the path never existed, not that this call deleted it.
        MicroVMApiException refused = assertThrows(MicroVMApiException.class, () -> client.deleteFile("sb-1", "/refused"));
        assertEquals(404, refused.getStatusCode());
        assertEquals("file_not_found", refused.getCode());
        assertEquals(2, tries.get("/refused"));
    }

    @Test
    void moveAndCopyRetryOnlyA429Or503() throws Exception {
        MicroVMClient client = serve(List.of("files.verbs"), (call, n) -> {
            String source = call.query().getOrDefault("source", "");
            if (source.equals("/refused-once") && n == 0) {
                return Reply.of(503, null);
            }
            if (source.equals("/bad-gateway")) {
                return Reply.of(502, null);
            }
            if (source.equals("/taken")) {
                return Reply.of(409, err("rename /taken /b: file exists", null));
            }
            return Reply.of(204, null);
        });
        client.moveFile("sb-1", "/refused-once", "/b");
        assertEquals(2, calls.size());
        assertEquals(502, assertThrows(MicroVMApiException.class, () -> client.moveFile("sb-1", "/bad-gateway", "/b")).getStatusCode());
        assertEquals(3, calls.size(), "a 502 on a move was re-sent");
        assertEquals(409, assertThrows(MicroVMApiException.class, () -> client.moveFile("sb-1", "/taken", "/b")).getStatusCode());
        assertThrows(MicroVMApiException.class, () -> client.copyFile("sb-1", "/bad-gateway", "/c", new CopyFileOptions().setRecursive(true)));
        Call last = calls.get(calls.size() - 1);
        assertEquals("/files/copy", last.route());
        assertEquals(Map.of("source", "/bad-gateway", "destination", "/c", "overwrite", "false", "recursive", "true"), last.query());
    }

    @Test
    void searchAndFind() throws Exception {
        MicroVMClient client = serve(List.of(), (call, n) -> {
            boolean search = call.route().endsWith("/search");
            if ("none".equals(call.query().get("pattern"))) {
                Map<String, Object> noFiles = new HashMap<>();
                noFiles.put("files", null);
                return Reply.of(200, search ? noFiles : List.of());
            }
            return Reply.of(200, search
                ? Map.of("files", List.of("/w/A.java"))
                : List.of(entry("file", "/w/A.java", "line", 2, "content", "class A {}")));
        });
        assertEquals(List.of("/w/A.java"), client.searchFiles("sb-1", "/w", "*.java"));
        assertEquals(2, client.findInFiles("sb-1", "/w", "class").get(0).line);
        assertEquals("class A {}", client.findInFiles("sb-1", "/w", "class").get(0).content);
        assertTrue(client.searchFiles("sb-1", "/w", "none").isEmpty());
        assertTrue(client.findInFiles("sb-1", "/w", "none").isEmpty());
    }

    @Test
    void sandboxFileMethodsDelegate() throws Exception {
        MicroVMClient client = serve(List.of("files.verbs"), (call, n) -> {
            if (call.route().equals("/files/info")) {
                return Reply.of(200, entry("name", "x"));
            }
            if (call.method().equals("GET")) {
                return Reply.of(200, call.route().equals("/files/search") ? Map.of("files", List.of()) : List.of());
            }
            return Reply.of(204, null);
        });
        SandboxData data = new SandboxData();
        data.id = "sb-1";
        Sandbox sandbox = new Sandbox(client, data);
        sandbox.listFiles("/");
        sandbox.listFiles("/", new ListFilesOptions());
        sandbox.getFileInfo("/x");
        assertTrue(sandbox.fileExists("/x"));
        sandbox.deleteFile("/x");
        sandbox.deleteFile("/x", new DeleteFileOptions());
        sandbox.makeDir("/d", new MakeDirOptions().setParents(true));
        sandbox.moveFile("/a", "/b", new MoveFileOptions().setOverwrite(true));
        sandbox.copyFile("/a", "/b");
        sandbox.copyFile("/a", "/b", new CopyFileOptions());
        sandbox.searchFiles("/", "*");
        sandbox.findInFiles("/", "x");
        assertEquals(
            List.of("/files", "/files", "/files/info", "/files/info", "/files", "/files", "/files/folder", "/files/move",
                "/files/copy", "/files/copy", "/files/search", "/files/find"),
            calls.stream().map(Call::route).collect(Collectors.toList()));
    }

    @Test
    void uploadOptionsAreSentAfterTheVersionCheckOnTheRightRetryTier() throws Exception {
        MicroVMClient client = serve(List.of("files.write_options"), (call, n) -> n == 0 ? Reply.of(502, null) : Reply.of(201, Map.of()));
        // A plain upload is re-sent after a 502.
        client.uploadFile("sb-1", "/a", new byte[] {1});
        assertEquals(2, calls.size());
        assertTrue(calls.get(0).query().isEmpty());
        // create_only is not: the first send may have made the file.
        MicroVMApiException err = assertThrows(MicroVMApiException.class, () -> client.uploadFile("sb-2", "/a", new byte[] {1},
            new ai.aerol.microvm.model.UploadFileOptions().setCreateOnly(true).setAtomic(true).setMode(0600)));
        assertEquals(502, err.getStatusCode());
        assertEquals(3, calls.size());
        assertEquals(Map.of("create_only", "true", "atomic", "true", "mode", "600"), calls.get(2).query());
    }

    @Test
    void uploadOptionsFailClosedOnAnOlderAgent() throws Exception {
        MicroVMClient client = serve(List.of(), (call, n) -> Reply.of(201, Map.of()));
        List<ai.aerol.microvm.model.UploadFileOptions> options = List.of(
            new ai.aerol.microvm.model.UploadFileOptions().setAppend(true),
            new ai.aerol.microvm.model.UploadFileOptions().setCreateOnly(true),
            new ai.aerol.microvm.model.UploadFileOptions().setAtomic(true),
            new ai.aerol.microvm.model.UploadFileOptions().setMode(0644));
        for (ai.aerol.microvm.model.UploadFileOptions option : options) {
            assertThrows(MicroVMUnsupportedFeatureException.class, () -> client.uploadFile("sb-1", "/a", new byte[] {1}, option));
        }
        assertTrue(calls.isEmpty());
        SandboxData data = new SandboxData();
        data.id = "sb-1";
        Sandbox sandbox = new Sandbox(client, data);
        sandbox.uploadFile("/a", new byte[] {1});
        assertThrows(MicroVMUnsupportedFeatureException.class,
            () -> sandbox.uploadFile("/a", new byte[] {1}, new ai.aerol.microvm.model.UploadFileOptions().setAppend(true)));
        assertEquals(1, calls.size());
    }

    @Test
    void uploadDirSendsTheFolderOnceWithExtract(@org.junit.jupiter.api.io.TempDir java.nio.file.Path root) throws Exception {
        java.nio.file.Files.write(root.resolve("a.txt"), "alpha".getBytes(StandardCharsets.UTF_8));
        List<byte[]> bodies = Collections.synchronizedList(new ArrayList<>());
        MicroVMClient client = serve(List.of("files.extract"), (call, n) -> Reply.of(503, null));
        server.removeContext("/");
        server.createContext("/", exchange -> {
            try {
                String path = exchange.getRequestURI().getPath();
                if (path.endsWith("/toolbox/version")) {
                    write(exchange, Reply.of(200, Map.of("version", "t", "features", List.of("files.extract"))));
                    return;
                }
                calls.add(new Call(exchange.getRequestMethod(), path, Map.of("query", String.valueOf(exchange.getRequestURI().getRawQuery()))));
                bodies.add(exchange.getRequestBody().readAllBytes());
                write(exchange, Reply.of(503, null));
            } finally {
                exchange.close();
            }
        });
        MicroVMApiException err = assertThrows(MicroVMApiException.class, () -> client.uploadDir("sb-1", root, "/work/app"));
        assertEquals(503, err.getStatusCode());
        assertEquals(1, calls.size(), "a folder upload was re-sent");
        assertEquals("extract=true", calls.get(0).query().get("query"));
        String body = new String(bodies.get(0), StandardCharsets.ISO_8859_1);
        assertTrue(body.contains("/work/app"));
        int start = body.indexOf("\r\n\r\n", body.indexOf("name=\"file\"")) + 4;
        byte[] archive = java.util.Arrays.copyOfRange(bodies.get(0), start, bodies.get(0).length);
        assertTrue(new String(ai.aerol.microvm.internal.TarWriterTestAccess.gunzip(archive), StandardCharsets.ISO_8859_1).contains("alpha"));
    }

    @Test
    void uploadDirRefusals(@org.junit.jupiter.api.io.TempDir java.nio.file.Path root) throws Exception {
        MicroVMClient client = serve(List.of(), (call, n) -> Reply.of(201, Map.of()));
        assertThrows(MicroVMUnsupportedFeatureException.class, () -> client.uploadDir("sb-1", root, "/w"));
        assertThrows(MicroVMException.class, () -> client.uploadDir("sb-1", root.resolve("missing"), "/w"));
        assertTrue(calls.isEmpty());
        MicroVMClient ok = serve(List.of("files.extract"), (call, n) -> Reply.of(201, Map.of()));
        SandboxData data = new SandboxData();
        data.id = "sb-1";
        new Sandbox(ok, data).uploadDir(root, "/w");
        assertEquals(1, calls.size());
    }

    /** A raw server for the download and stream tests: path -> handler. */
    private MicroVMClient rawServer(com.sun.net.httpserver.HttpHandler handler) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            try {
                if (exchange.getRequestURI().getPath().endsWith("/toolbox/version")) {
                    write(exchange, Reply.of(200, Map.of("version", "t", "features", List.of("files.write_options"))));
                    return;
                }
                handler.handle(exchange);
            } finally {
                exchange.close();
            }
        });
        server.start();
        return new MicroVMClient(
            new MicroVMConfig().setApiUrl("http://127.0.0.1:" + server.getAddress().getPort()).setPatToken("pat")
                .setRetry(new RetryConfig().setMaxRetries(3).setBaseDelayMs(1).setMaxDelayMs(1)),
            HttpClient.newHttpClient(), null, name -> null);
    }

    @Test
    void downloadsHonourMaxBytesAndRetryUntilTheFileStarts() throws Exception {
        java.util.concurrent.atomic.AtomicInteger hits = new java.util.concurrent.atomic.AtomicInteger();
        MicroVMClient client = rawServer(exchange -> {
            int n = hits.incrementAndGet();
            String query = exchange.getRequestURI().getQuery();
            byte[] body = "0123456789".getBytes(StandardCharsets.UTF_8);
            if (query.contains("/flaky") && n == 1) {
                exchange.sendResponseHeaders(503, -1);
                return;
            }
            // 0 is chunked: no Content-Length, the size shows only as it arrives.
            exchange.sendResponseHeaders(200, query.contains("/streamed") ? 0 : body.length);
            exchange.getResponseBody().write(body);
        });
        assertEquals("0123456789", new String(client.downloadFile("sb-1", "/flaky"), StandardCharsets.UTF_8));
        assertEquals(2, hits.get());
        ai.aerol.microvm.model.DownloadFileOptions five = new ai.aerol.microvm.model.DownloadFileOptions().setMaxBytes(5L);
        MicroVMFileTooLargeException sized = assertThrows(MicroVMFileTooLargeException.class, () -> client.downloadFile("sb-1", "/sized", five));
        assertEquals(5, sized.getMaxBytes());
        assertEquals("/sized", sized.getPath());
        assertEquals(10, client.downloadFile("sb-1", "/sized", new ai.aerol.microvm.model.DownloadFileOptions().setMaxBytes(10L)).length);
        assertThrows(MicroVMFileTooLargeException.class, () -> client.downloadFile("sb-1", "/streamed", five));
        try (java.io.InputStream in = client.downloadFileStream("sb-1", "/streamed", five)) {
            byte[] got = new byte[5];
            int total = 0;
            while (total < 5) {
                total += in.read(got, total, 5 - total);
            }
            assertEquals("01234", new String(got, StandardCharsets.UTF_8));
            IOException err = assertThrows(IOException.class, () -> in.read());
            assertTrue(err.getCause() instanceof MicroVMFileTooLargeException);
        }
        // A read with room for more than the limit still hands over the
        // bytes under it; the read after that fails.
        try (java.io.InputStream in = client.downloadFileStream("sb-1", "/streamed", five)) {
            byte[] got = new byte[64];
            int total = 0;
            IOException err = null;
            try {
                for (int n; (n = in.read(got, total, got.length - total)) >= 0; ) {
                    total += n;
                }
            } catch (IOException e) {
                err = e;
            }
            assertEquals("01234", new String(got, 0, total, StandardCharsets.UTF_8));
            assertTrue(err != null && err.getCause() instanceof MicroVMFileTooLargeException);
        }
        assertEquals(10, client.downloadFile("sb-1", "/streamed", new ai.aerol.microvm.model.DownloadFileOptions().setMaxBytes(10L)).length);
        SandboxData data = new SandboxData();
        data.id = "sb-1";
        Sandbox sandbox = new Sandbox(client, data);
        assertEquals(10, sandbox.downloadFile("/sized", null).length);
        try (java.io.InputStream in = sandbox.downloadFileStream("/sized", null)) {
            assertEquals(10, in.readAllBytes().length);
        }
    }

    @Test
    void downloadErrorsAreApiErrors() throws Exception {
        MicroVMClient client = rawServer(exchange -> {
            byte[] body = "{\"error\":\"open /x: no such file or directory\",\"code\":\"file_not_found\"}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(404, body.length);
            exchange.getResponseBody().write(body);
        });
        MicroVMApiException err = assertThrows(MicroVMApiException.class, () -> client.downloadFile("sb-1", "/x"));
        assertEquals(404, err.getStatusCode());
        assertEquals("file_not_found", err.getCode());
    }

    @Test
    void uploadFileStreamSendsTheBodyOnce() throws Exception {
        List<String> bodies = Collections.synchronizedList(new ArrayList<>());
        List<String> queries = Collections.synchronizedList(new ArrayList<>());
        MicroVMClient client = rawServer(exchange -> {
            bodies.add(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            queries.add(String.valueOf(exchange.getRequestURI().getQuery()));
            exchange.sendResponseHeaders(bodies.size() == 1 ? 503 : 201, -1);
        });
        byte[] data = "a".repeat(5000).getBytes(StandardCharsets.UTF_8);
        MicroVMApiException err = assertThrows(MicroVMApiException.class,
            () -> client.uploadFileStream("sb-1", "/w/big.bin", new java.io.ByteArrayInputStream(data), null));
        assertEquals(503, err.getStatusCode());
        assertEquals(1, bodies.size(), "a streamed upload was re-sent");
        assertTrue(bodies.get(0).contains("name=\"path\"\r\n\r\n/w/big.bin\r\n"));
        assertTrue(bodies.get(0).contains("a".repeat(5000)));
        SandboxData sandboxData = new SandboxData();
        sandboxData.id = "sb-1";
        new Sandbox(client, sandboxData).uploadFileStream("/w/x", new java.io.ByteArrayInputStream(new byte[] {1}),
            new ai.aerol.microvm.model.UploadFileOptions().setCreateOnly(true));
        assertEquals("create_only=true", queries.get(1));
    }
}
