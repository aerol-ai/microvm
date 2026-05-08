package ai.aerol.microvm.internal;

import java.nio.ByteBuffer;

public interface StreamingWebSocket {
    void sendText(String text);

    void sendBinary(ByteBuffer data);

    void sendClose(int statusCode, String reason);
}