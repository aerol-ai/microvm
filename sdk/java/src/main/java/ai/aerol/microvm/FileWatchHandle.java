package ai.aerol.microvm;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import ai.aerol.microvm.internal.JsonSupport;
import ai.aerol.microvm.internal.StreamingWebSocket;
import ai.aerol.microvm.internal.StreamingWebSocketListener;
import ai.aerol.microvm.model.FileEvent;

/**
 * A running file watch. Events reach the callback on the socket's reader
 * thread, in order. {@link #stop()} ends the watch; {@link #waitForEnd()}
 * then returns normally. When the server ends the watch on its own (the
 * folder was removed or moved), or the connection drops, {@link #waitForEnd()}
 * throws a {@link MicroVMException} saying why. The handshake is sent once
 * and never retried.
 */
public class FileWatchHandle implements AutoCloseable {
    private final Consumer<FileEvent> onEvent;
    private final CompletableFuture<Void> started = new CompletableFuture<>();
    private final CompletableFuture<Void> completion = new CompletableFuture<>();
    private final AtomicReference<StreamingWebSocket> socket = new AtomicReference<>();
    private final AtomicBoolean stopped = new AtomicBoolean();

    FileWatchHandle(Consumer<FileEvent> onEvent) {
        this.onEvent = onEvent;
    }

    /** Completes when the watch ends: normally after stop(), exceptionally otherwise. */
    public CompletableFuture<Void> completion() {
        return completion;
    }

    /**
     * Blocks until the watch ends. Returns normally after {@link #stop()};
     * throws when the server ended the watch or the connection dropped.
     */
    public void waitForEnd() {
        try {
            completion.join();
        } catch (CompletionException ex) {
            Throwable cause = ex.getCause();
            if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            }
            throw new MicroVMException("failed waiting for file watch", cause);
        }
    }

    /** Stops the watch. Safe to call more than once. */
    public void stop() {
        if (stopped.compareAndSet(false, true)) {
            completion.complete(null);
            closeSocket("stop");
        }
    }

    /** Same as {@link #stop()}, for try-with-resources. */
    @Override
    public void close() {
        stop();
    }

    StreamingWebSocketListener listener() {
        return new StreamingWebSocketListener() {
            @Override
            public void onText(String text) {
                if (completion.isDone()) {
                    return;
                }
                WatchFrame frame = JsonSupport.tryRead(text.getBytes(StandardCharsets.UTF_8), WatchFrame.class);
                if (frame == null || frame.type == null) {
                    return;
                }
                switch (frame.type) {
                    case "start":
                        started.complete(null);
                        break;
                    case "events":
                        deliver(frame.events);
                        break;
                    case "end":
                        String reason = frame.reason == null || frame.reason.isEmpty() ? "the file watch ended" : frame.reason;
                        fail(new MicroVMException(reason));
                        closeSocket("end");
                        break;
                    default:
                        // A frame type this SDK does not know: newer server.
                        break;
                }
            }

            @Override
            public void onBinary(byte[] data) {
            }

            @Override
            public void onClose(int statusCode, String reason) {
                if (stopped.get()) {
                    completion.complete(null);
                    return;
                }
                fail(new MicroVMException("file watch closed: code=" + statusCode
                    + (reason == null || reason.isEmpty() ? "" : " reason=" + reason)));
            }

            @Override
            public void onError(Throwable error) {
                if (stopped.get()) {
                    completion.complete(null);
                    return;
                }
                String message = error == null || error.getMessage() == null ? "file watch connection failed" : error.getMessage();
                fail(new MicroVMException(message, error));
            }
        };
    }

    private void deliver(List<FileEvent> events) {
        if (events == null) {
            return;
        }
        for (FileEvent event : events) {
            if (completion.isDone()) {
                return;
            }
            try {
                onEvent.accept(event);
            } catch (RuntimeException ex) {
                // The callback's failure ends the watch rather than being
                // lost on the reader thread.
                fail(new MicroVMException("file watch callback failed: " + ex.getMessage(), ex));
                closeSocket("callback failed");
                return;
            }
        }
    }

    void attach(StreamingWebSocket webSocket) {
        socket.set(webSocket);
        if (completion.isDone()) {
            closeSocket("done");
        }
    }

    /**
     * Waits for the server's start frame, so a file changed right after
     * watchFiles returns is seen. On failure the socket is closed and the
     * cause thrown.
     */
    void awaitStart(Duration timeout) {
        try {
            started.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (ExecutionException ex) {
            abort();
            Throwable cause = ex.getCause();
            if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            }
            throw new MicroVMException("file watch failed to start", cause);
        } catch (TimeoutException ex) {
            abort();
            throw new MicroVMException("file watch did not start within " + timeout.getSeconds() + "s");
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            abort();
            throw new MicroVMException("interrupted waiting for the file watch to start", ex);
        }
    }

    private void abort() {
        stopped.set(true);
        completion.complete(null);
        closeSocket("abort");
    }

    private void fail(MicroVMException error) {
        started.completeExceptionally(error);
        completion.completeExceptionally(error);
    }

    private void closeSocket(String reason) {
        StreamingWebSocket webSocket = socket.get();
        if (webSocket == null) {
            return;
        }
        try {
            webSocket.sendClose(1000, reason);
        } catch (RuntimeException ignored) {
            // Already closed by the other side.
        }
    }

    @SuppressWarnings("unused")
    private static final class WatchFrame {
        public String type;
        public String path;
        public Boolean recursive;
        public List<FileEvent> events;
        public String reason;
    }
}
