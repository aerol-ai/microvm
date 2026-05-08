package ai.aerol.microvm.internal;

public interface StreamingWebSocketListener {
    void onText(String text);

    void onBinary(byte[] data);

    void onClose(int statusCode, String reason);

    void onError(Throwable error);
}