package ai.aerol.microvm.internal;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;

import ai.aerol.microvm.MicroVMException;

@SuppressWarnings({"ThrowableResultOfMethodCallIgnored", "ResultOfMethodCallIgnored"})
public final class JavaNetWebSocketConnector implements WebSocketConnector {
    private final HttpClient httpClient;

    public JavaNetWebSocketConnector(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public StreamingWebSocket connect(URI uri, String authorizationHeader, StreamingWebSocketListener listener) {
        WebSocket.Builder builder = httpClient.newWebSocketBuilder();
        if (authorizationHeader != null && !authorizationHeader.isEmpty()) {
            builder.header("Authorization", authorizationHeader);
        }

        try {
            WebSocket webSocket = builder.buildAsync(uri, new AdapterListener(listener)).join();
            return new AdapterSocket(webSocket);
        } catch (CompletionException ex) {
            throw new MicroVMException("failed to connect websocket", resolveCause(ex));
        }
    }

    private static final class AdapterSocket implements StreamingWebSocket {
        private final WebSocket webSocket;

        private AdapterSocket(WebSocket webSocket) {
            this.webSocket = webSocket;
        }

        @Override
        public void sendText(String text) {
            join(webSocket.sendText(text, true), "failed to send websocket text frame");
        }

        @Override
        public void sendBinary(ByteBuffer data) {
            join(webSocket.sendBinary(data, true), "failed to send websocket binary frame");
        }

        @Override
        public void sendClose(int statusCode, String reason) {
            join(webSocket.sendClose(statusCode, reason), "failed to close websocket");
        }

        private static void join(CompletableFuture<?> future, String message) {
            try {
                future.join();
            } catch (CompletionException ex) {
                throw new MicroVMException(message, resolveCause(ex));
            }
        }
    }

    private static Throwable resolveCause(CompletionException ex) {
        Throwable cause = ex.getCause();
        return cause == null ? ex : cause;
    }

    private static final class AdapterListener implements WebSocket.Listener {
        private final StreamingWebSocketListener listener;
        private final StringBuilder textBuffer = new StringBuilder();
        private final ByteArrayOutputStream binaryBuffer = new ByteArrayOutputStream();

        private AdapterListener(StreamingWebSocketListener listener) {
            this.listener = listener;
        }

        @Override
        public void onOpen(WebSocket webSocket) {
            webSocket.request(1);
        }

        @Override
        public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
            textBuffer.append(data);
            if (last) {
                listener.onText(textBuffer.toString());
                textBuffer.setLength(0);
            }
            webSocket.request(1);
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public CompletionStage<?> onBinary(WebSocket webSocket, ByteBuffer data, boolean last) {
            byte[] chunk = new byte[data.remaining()];
            data.get(chunk);
            binaryBuffer.write(chunk, 0, chunk.length);
            if (last) {
                listener.onBinary(binaryBuffer.toByteArray());
                binaryBuffer.reset();
            }
            webSocket.request(1);
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
            listener.onClose(statusCode, reason);
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public void onError(WebSocket webSocket, Throwable error) {
            listener.onError(error);
        }
    }
}