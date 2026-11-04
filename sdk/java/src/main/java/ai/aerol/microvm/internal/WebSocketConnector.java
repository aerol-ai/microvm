package ai.aerol.microvm.internal;

import java.net.URI;
import java.util.Map;

public interface WebSocketConnector {
    /**
     * Opens a WebSocket to {@code uri}. {@code headers} holds the handshake
     * headers: {@code Authorization}, plus {@code X-AerolVM-Team} when the
     * client has a team.
     */
    StreamingWebSocket connect(URI uri, Map<String, String> headers, StreamingWebSocketListener listener);
}