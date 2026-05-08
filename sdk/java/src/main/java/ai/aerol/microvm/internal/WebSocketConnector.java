package ai.aerol.microvm.internal;

import java.net.URI;

public interface WebSocketConnector {
    StreamingWebSocket connect(URI uri, String authorizationHeader, StreamingWebSocketListener listener);
}