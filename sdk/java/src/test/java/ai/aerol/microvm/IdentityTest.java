package ai.aerol.microvm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ai.aerol.microvm.internal.JsonSupport;
import ai.aerol.microvm.model.CreateOptions;
import ai.aerol.microvm.model.IdentityOptions;
import ai.aerol.microvm.model.IdentityRole;
import ai.aerol.microvm.model.IdentityRoleList;
import ai.aerol.microvm.model.IdentityRoleOptions;
import ai.aerol.microvm.model.ListIdentityRolesOptions;
import ai.aerol.microvm.model.SandboxData;
import ai.aerol.microvm.model.SandboxIdentity;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Cloud identity per sandbox: the create option, the identity view and the admin role-tag calls. */
class IdentityTest {
    private interface Handler {
        void handle(HttpExchange exchange) throws IOException;
    }

    private static HttpServer start(Handler handler) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            try {
                handler.handle(exchange);
            } finally {
                exchange.close();
            }
        });
        server.start();
        return server;
    }

    private static MicroVMClient clientFor(HttpServer server) {
        String url = "http://127.0.0.1:" + server.getAddress().getPort();
        return new MicroVMClient(new MicroVMConfig().setApiUrl(url).setPatToken("pat-token"));
    }

    private static void writeJson(HttpExchange exchange, Object value) throws IOException {
        byte[] body = JsonSupport.writeBytes(value);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, body.length);
        exchange.getResponseBody().write(body);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> readBody(HttpExchange exchange) throws IOException {
        return (Map<String, Object>) JsonSupport.read(exchange.getRequestBody().readAllBytes(), Map.class);
    }

    @Test
    void createSendsIdentityAndReadsItBack() throws Exception {
        List<Map<String, Object>> bodies = new ArrayList<>();
        HttpServer server = start(exchange -> {
            bodies.add(readBody(exchange));
            Map<String, Object> identity = new LinkedHashMap<>();
            identity.put("role_tag", "deploy");
            identity.put("audience", "sts.amazonaws.com");
            identity.put("subject", "team:payments:role:deploy");
            identity.put("aws_role_arn", "arn:aws:iam::123456789012:role/deploy");
            identity.put("token_file", "/run/aerolvm/identity/token");
            Map<String, Object> sandbox = new LinkedHashMap<>();
            sandbox.put("id", "sb-1");
            sandbox.put("image", "alpine");
            sandbox.put("status", "started");
            sandbox.put("identity", identity);
            writeJson(exchange, sandbox);
        });
        try {
            Sandbox sandbox = clientFor(server).create(new CreateOptions().setImage("alpine")
                .setIdentity(new IdentityOptions().setRoleTag("deploy").setAwsRoleArn("arn:aws:iam::123456789012:role/deploy")));
            @SuppressWarnings("unchecked")
            Map<String, Object> sent = (Map<String, Object>) bodies.get(0).get("identity");
            assertEquals("deploy", sent.get("role_tag"));
            assertEquals("arn:aws:iam::123456789012:role/deploy", sent.get("aws_role_arn"));
            assertFalse(sent.containsKey("audience"), "unset fields stay off the wire");
            SandboxData data = sandbox.toData();
            SandboxIdentity identity = data.identity;
            assertEquals("team:payments:role:deploy", identity.subject);
            assertEquals("/run/aerolvm/identity/token", identity.tokenFile);
            assertNull(identity.tokenExpiresAt);
            // A copy owns its own identity.
            SandboxData copy = data.copy();
            copy.identity.subject = "changed";
            assertEquals("team:payments:role:deploy", sandbox.toData().identity.subject);
        } finally {
            server.stop(0);
        }
    }

    @Test
    void roleCallsMapWireShape() throws Exception {
        List<String> requests = new ArrayList<>();
        List<Map<String, Object>> bodies = new ArrayList<>();
        HttpServer server = start(exchange -> {
            String method = exchange.getRequestMethod();
            String uri = exchange.getRequestURI().toString();
            requests.add(method + " " + uri);
            if ("DELETE".equals(method)) {
                exchange.sendResponseHeaders(204, -1);
                return;
            }
            if ("PUT".equals(method)) {
                bodies.add(readBody(exchange));
                Map<String, Object> role = new LinkedHashMap<>();
                role.put("tag", "deploy");
                role.put("min_role", "runner");
                role.put("team", "payments");
                writeJson(exchange, role);
                return;
            }
            Map<String, Object> page = new LinkedHashMap<>();
            page.put("roles", null);
            page.put("next_cursor", "z");
            writeJson(exchange, page);
        });
        try {
            MicroVMClient client = clientFor(server);
            IdentityRole role = client.putIdentityRole("deploy", new IdentityRoleOptions().setMinRole("runner").setTeam("payments"));
            assertEquals("runner", role.minRole);
            assertEquals("payments", role.team);
            assertEquals(Map.of("min_role", "runner"), bodies.get(0), "the team rides the query, not the body");
            IdentityRoleList page = client.listIdentityRoles(new ListIdentityRolesOptions().setTeam("payments").setCursor("a").setLimit(5));
            assertTrue(page.roles.isEmpty());
            assertEquals("z", page.nextCursor);
            client.listIdentityRoles();
            client.deleteIdentityRole("deploy", "payments");
            client.deleteIdentityRole("ops");
            client.putIdentityRole("ops", new IdentityRoleOptions().setMinRole("admin"));
            assertEquals(List.of(
                "PUT /v1/identity/roles/deploy?team=payments",
                "GET /v1/identity/roles?team=payments&cursor=a&limit=5",
                "GET /v1/identity/roles",
                "DELETE /v1/identity/roles/deploy?team=payments",
                "DELETE /v1/identity/roles/ops",
                "PUT /v1/identity/roles/ops"), requests);
        } finally {
            server.stop(0);
        }
    }
}
