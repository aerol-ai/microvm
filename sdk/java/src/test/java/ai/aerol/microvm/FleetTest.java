package ai.aerol.microvm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import ai.aerol.microvm.internal.JsonSupport;
import ai.aerol.microvm.model.CreateOptions;
import ai.aerol.microvm.model.RetryConfig;

/**
 * Calls that act on sandboxes by name or tag (plan section 5.3, S4 and S5),
 * against a fake sandboxd that keeps sandboxes by name the way the real one
 * does: names unique per owner, a second create of a name is a 409.
 */
class FleetTest {
    private final List<HttpServer> servers = new ArrayList<>();
    private final ExecutorService pool = Executors.newCachedThreadPool();

    @AfterEach
    void stop() {
        servers.forEach(server -> server.stop(0));
        pool.shutdownNow();
    }

    /** A fake sandboxd. lookupBarrier holds the first N name lookups until all N arrive. */
    final class FakeSandboxd {
        final Map<String, Map<String, Object>> sandboxes = Collections.synchronizedMap(new TreeMap<>());
        final List<String> requests = Collections.synchronizedList(new ArrayList<>());
        final Map<String, Integer> deleteStatus = Collections.synchronizedMap(new HashMap<>());
        volatile boolean conflictWithoutName;
        private int nextId;
        private int barrierLeft;
        private final CountDownLatch barrier;
        final MicroVMClient client;

        FakeSandboxd(int lookupBarrier) throws IOException {
            barrierLeft = lookupBarrier;
            barrier = new CountDownLatch(lookupBarrier);
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.setExecutor(pool);
            server.createContext("/", exchange -> {
                try {
                    handle(exchange);
                } finally {
                    exchange.close();
                }
            });
            server.start();
            servers.add(server);
            client = new MicroVMClient(
                new MicroVMConfig()
                    .setApiUrl("http://127.0.0.1:" + server.getAddress().getPort())
                    .setPatToken("pat")
                    .setRetry(new RetryConfig().setMaxRetries(0)),
                HttpClient.newHttpClient(),
                null,
                name -> null);
        }

        synchronized String add(String name, Map<String, String> tags, String image) {
            nextId++;
            String id = String.format("sb-%03d", nextId);
            Map<String, Object> sandbox = new LinkedHashMap<>();
            sandbox.put("id", id);
            sandbox.put("name", name);
            sandbox.put("image", image);
            sandbox.put("status", "started");
            sandbox.put("tags", tags == null ? Map.of() : tags);
            sandboxes.put(id, sandbox);
            return id;
        }

        long count(String method) {
            synchronized (requests) {
                return requests.stream().filter(r -> r.startsWith(method + " ")).count();
            }
        }

        private void handle(HttpExchange exchange) throws IOException {
            String method = exchange.getRequestMethod();
            String path = exchange.getRequestURI().getPath();
            Map<String, String> query = new LinkedHashMap<>();
            String raw = exchange.getRequestURI().getRawQuery();
            if (raw != null) {
                for (String part : raw.split("&")) {
                    String[] kv = part.split("=", 2);
                    query.put(URLDecoder.decode(kv[0], StandardCharsets.UTF_8), kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "");
                }
            }
            requests.add(method + " " + exchange.getRequestURI());
            if (method.equals("GET") && path.equals("/v1/sandboxes") && query.containsKey("name")) {
                boolean wait;
                synchronized (this) {
                    wait = barrierLeft > 0;
                    if (wait) {
                        barrierLeft--;
                    }
                }
                if (wait) {
                    barrier.countDown();
                    try {
                        barrier.await(10, TimeUnit.SECONDS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
                List<Object> hits = new ArrayList<>();
                synchronized (sandboxes) {
                    sandboxes.values().stream().filter(s -> query.get("name").equals(s.get("name"))).forEach(hits::add);
                }
                json(exchange, 200, hits);
            } else if (method.equals("GET") && path.equals("/v1/sandboxes")) {
                List<Map<String, Object>> matched = new ArrayList<>();
                synchronized (sandboxes) {
                    for (Map<String, Object> s : sandboxes.values()) {
                        @SuppressWarnings("unchecked")
                        Map<String, String> tags = (Map<String, String>) s.get("tags");
                        boolean ok = query.entrySet().stream()
                            .filter(e -> e.getKey().startsWith("tag."))
                            .allMatch(e -> e.getValue().equals(tags.get(e.getKey().substring(4))));
                        if (ok) {
                            matched.add(s);
                        }
                    }
                }
                int start = Integer.parseInt(query.getOrDefault("page_token", "0"));
                int end = Math.min(start + 2, matched.size());
                if (end < matched.size()) {
                    exchange.getResponseHeaders().set("X-Cluster-List-Next-Page-Token", String.valueOf(end));
                }
                json(exchange, 200, new ArrayList<>(matched.subList(Math.min(start, end), end)));
            } else if (method.equals("POST") && path.equals("/v1/sandboxes")) {
                @SuppressWarnings("unchecked")
                Map<String, Object> body = JsonSupport.read(exchange.getRequestBody().readAllBytes(), Map.class);
                synchronized (this) {
                    String name = (String) body.getOrDefault("name", "");
                    if (conflictWithoutName) {
                        json(exchange, 409, Map.of("error", "sandbox id already reserved"));
                        return;
                    }
                    boolean taken;
                    synchronized (sandboxes) {
                        taken = !name.isEmpty() && sandboxes.values().stream().anyMatch(s -> name.equals(s.get("name")));
                    }
                    if (taken) {
                        json(exchange, 409, Map.of("error", "sandbox name already in use"));
                        return;
                    }
                    @SuppressWarnings("unchecked")
                    Map<String, String> tags = (Map<String, String>) body.get("tags");
                    String id = add(name, tags, (String) body.get("image"));
                    json(exchange, 201, sandboxes.get(id));
                }
            } else if (method.equals("DELETE") && path.startsWith("/v1/sandboxes/")) {
                String id = path.substring("/v1/sandboxes/".length());
                Integer forced = deleteStatus.get(id);
                int status = forced != null ? forced : (sandboxes.remove(id) != null ? 204 : 404);
                if (status == 204) {
                    exchange.sendResponseHeaders(204, -1);
                } else {
                    json(exchange, status, Map.of("error", "delete failed with " + status));
                }
            } else {
                json(exchange, 404, Map.of("error", "not found"));
            }
        }

        private void json(HttpExchange exchange, int status, Object value) throws IOException {
            byte[] body = JsonSupport.writeBytes(value);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, body.length);
            exchange.getResponseBody().write(body);
        }
    }

    @Test
    void getOrCreateCreatesWhenTheNameIsFree() throws Exception {
        FakeSandboxd fake = new FakeSandboxd(0);
        CreateOptions options = new CreateOptions().setImage("alpine");
        options.tags = Map.of("team", "x");
        GetOrCreateResult result = fake.client.getOrCreate(" agent-1 ", options);
        assertTrue(result.isCreated());
        assertEquals("agent-1", result.getSandbox().name);
        assertEquals(Map.of("team", "x"), result.getSandbox().tags);
        assertEquals(null, options.name, "the caller's options are not changed");
        assertEquals(1, fake.count("GET"));
        assertEquals(1, fake.count("POST"));
    }

    @Test
    void getOrCreateReturnsTheExistingSandbox() throws Exception {
        FakeSandboxd fake = new FakeSandboxd(0);
        String id = fake.add("agent-1", Map.of(), "ubuntu");
        CreateOptions options = new CreateOptions().setImage("alpine");
        options.name = "agent-1";
        GetOrCreateResult result = fake.client.getOrCreate("agent-1", options);
        assertFalse(result.isCreated());
        assertEquals(id, result.getSandbox().id);
        assertEquals("ubuntu", result.getSandbox().image);
        assertEquals(0, fake.count("POST"));
    }

    @Test
    void getOrCreateGivesConcurrentCallersOneSandbox() throws Exception {
        int callers = 8;
        FakeSandboxd fake = new FakeSandboxd(callers);
        List<Future<GetOrCreateResult>> futures = new ArrayList<>();
        for (int i = 0; i < callers; i++) {
            futures.add(pool.submit(() -> fake.client.getOrCreate("shared", new CreateOptions().setImage("alpine"))));
        }
        Set<String> ids = new HashSet<>();
        int created = 0;
        for (Future<GetOrCreateResult> future : futures) {
            GetOrCreateResult result = future.get(15, TimeUnit.SECONDS);
            ids.add(result.getSandbox().id);
            created += result.isCreated() ? 1 : 0;
        }
        assertEquals(1, ids.size());
        assertEquals(1, created);
        assertEquals(1, fake.sandboxes.size());
        assertEquals(callers, fake.count("POST"));
    }

    @Test
    void getOrCreateThrowsAConflictOnSomethingElse() throws Exception {
        FakeSandboxd fake = new FakeSandboxd(0);
        fake.conflictWithoutName = true;
        MicroVMConflictException err = assertThrows(MicroVMConflictException.class,
            () -> fake.client.getOrCreate("agent-1", new CreateOptions().setImage("alpine")));
        assertEquals("sandbox id already reserved", err.getMessage());
    }

    @Test
    void getOrCreateRefusesBadNamesBeforeSending() throws Exception {
        FakeSandboxd fake = new FakeSandboxd(0);
        CreateOptions other = new CreateOptions().setImage("alpine");
        other.name = "b";
        assertThrows(IllegalArgumentException.class, () -> fake.client.getOrCreate(" ", new CreateOptions()));
        assertThrows(IllegalArgumentException.class, () -> fake.client.getOrCreate(null, new CreateOptions()));
        assertThrows(IllegalArgumentException.class, () -> fake.client.getOrCreate("a", other));
        assertEquals(0, fake.requests.size());
    }
}
