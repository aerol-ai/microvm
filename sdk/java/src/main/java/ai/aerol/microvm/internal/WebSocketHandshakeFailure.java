package ai.aerol.microvm.internal;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import ai.aerol.microvm.MicroVMException;

/**
 * A WebSocket handshake the server answered with an HTTP status instead of
 * 101. It keeps the status, headers and body, so a caller can tell a route
 * an older agent lacks (404 with {@code X-Toolbox-Route: none}) from an
 * error the route itself returned. Its message is the one the connector
 * always gave, so callers that only print it see no change.
 */
public class WebSocketHandshakeFailure extends MicroVMException {
    private static final long serialVersionUID = 1L;

    private final int statusCode;
    private final Map<String, List<String>> headers;
    private final String body;

    public WebSocketHandshakeFailure(String message, Throwable cause, int statusCode, Map<String, List<String>> headers, String body) {
        super(message, cause);
        this.statusCode = statusCode;
        Map<String, List<String>> copy = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        if (headers != null) {
            copy.putAll(headers);
        }
        this.headers = Collections.unmodifiableMap(copy);
        this.body = body == null ? "" : body;
    }

    /** The HTTP status the server answered the handshake with. */
    public int getStatusCode() {
        return statusCode;
    }

    /** The first value of a response header (case-insensitive), or null. */
    public String header(String name) {
        List<String> values = headers.get(name);
        return values == null || values.isEmpty() ? null : values.get(0);
    }

    /** The response body, empty when there was none. */
    public String getBody() {
        return body;
    }
}
