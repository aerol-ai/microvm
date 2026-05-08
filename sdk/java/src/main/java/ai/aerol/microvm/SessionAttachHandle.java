package ai.aerol.microvm;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import ai.aerol.microvm.internal.JsonSupport;
import ai.aerol.microvm.internal.StreamControlMessage;
import ai.aerol.microvm.internal.StreamingWebSocket;
import ai.aerol.microvm.model.ExecExitInfo;

public class SessionAttachHandle {
    private final StreamingWebSocket socket;
    private final CompletableFuture<ExecExitInfo> completion;

    SessionAttachHandle(StreamingWebSocket socket, CompletableFuture<ExecExitInfo> completion) {
        this.socket = socket;
        this.completion = completion;
    }

    public CompletableFuture<ExecExitInfo> completion() {
        return completion;
    }

    public ExecExitInfo waitForExit() {
        try {
            return completion.join();
        } catch (CompletionException ex) {
            Throwable cause = ex.getCause();
            if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            }
            throw new MicroVMException("failed waiting for session attach", cause);
        }
    }

    public void write(byte[] data) {
        socket.sendBinary(ByteBuffer.wrap(data));
    }

    public void write(String data) {
        write(data.getBytes(StandardCharsets.UTF_8));
    }

    public void resize(int cols, int rows) {
        socket.sendText(JsonSupport.write(StreamControlMessage.resize(cols, rows)));
    }

    public void signal(String name) {
        socket.sendText(JsonSupport.write(StreamControlMessage.signal(name)));
    }

    public void close() {
        socket.sendText(JsonSupport.write(StreamControlMessage.close()));
        socket.sendClose(1000, "detach");
    }
}