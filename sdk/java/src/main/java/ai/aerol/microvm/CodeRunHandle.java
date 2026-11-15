package ai.aerol.microvm;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import ai.aerol.microvm.internal.JsonSupport;
import ai.aerol.microvm.internal.StreamControlMessage;
import ai.aerol.microvm.internal.StreamingWebSocket;
import ai.aerol.microvm.internal.StreamingWebSocketListener;
import ai.aerol.microvm.model.CodeResult;
import ai.aerol.microvm.model.Execution;
import ai.aerol.microvm.model.ExecutionError;
import ai.aerol.microvm.model.RunCodeOptions;

/**
 * A code run in flight, from {@link MicroVMClient#startCode}. Output reaches
 * the callbacks on the socket's reader thread, in order.
 * {@link #waitForResult()} returns the {@link Execution} once the server ends
 * the run. {@link #interrupt()} asks the server to stop the code; a stopped
 * run still returns normally, with {@link Execution#interrupted} set.
 * {@link #close()} only drops the connection: the code keeps running in the
 * sandbox, so interrupt first when you want it stopped.
 */
public class CodeRunHandle implements AutoCloseable {
    // The close code a server that finished the run sends, and the code
    // java.net.http reports for a close frame that carried none.
    private static final int CLOSE_NORMAL = 1000;
    private static final int CLOSE_NO_STATUS = 1005;
    // What java.net.http reports as onError rather than a close frame: the
    // connection dropped without one.
    private static final int CLOSE_ABNORMAL = 1006;

    private final RunCodeOptions options;
    private final Execution execution = new Execution();
    private final CompletableFuture<Execution> completion = new CompletableFuture<>();
    private final AtomicReference<StreamingWebSocket> socket = new AtomicReference<>();

    CodeRunHandle(RunCodeOptions options) {
        this.options = options;
    }

    /**
     * Completes with the {@link Execution} when the server ends the run, or
     * exceptionally with a {@link MicroVMCodeRunException}
     * ({@link MicroVMCodeTimeoutException} when the run timed out).
     */
    public CompletableFuture<Execution> completion() {
        return completion;
    }

    /**
     * Blocks until the run ends and returns what it produced. Throws
     * {@link MicroVMCodeTimeoutException} when the run's timeout fired and
     * {@link MicroVMCodeRunException} when the stream ended any other way
     * than the server finishing the run.
     */
    public Execution waitForResult() {
        try {
            return completion.join();
        } catch (CompletionException ex) {
            Throwable cause = ex.getCause();
            if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            }
            throw new MicroVMException("failed waiting for code run", cause);
        }
    }

    /**
     * Asks the server to stop the code, as Ctrl-C would. The run then ends
     * normally with {@link Execution#interrupted} set. Does nothing once the
     * run has ended.
     */
    public void interrupt() {
        StreamingWebSocket webSocket = socket.get();
        if (webSocket == null || completion.isDone()) {
            return;
        }
        webSocket.sendText(JsonSupport.write(StreamControlMessage.interrupt()));
    }

    /**
     * Drops the connection without stopping the code, which keeps running in
     * the sandbox. If the run had not ended, {@link #waitForResult()} then
     * throws a {@link MicroVMCodeRunException}. Safe to call more than once.
     */
    @Override
    public void close() {
        completion.completeExceptionally(new MicroVMCodeRunException(CLOSE_NORMAL, "closed by the client", execution));
        closeSocket("closed by the client");
    }

    void attach(StreamingWebSocket webSocket) {
        socket.set(webSocket);
        if (completion.isDone()) {
            closeSocket("done");
        }
    }

    boolean isDone() {
        return completion.isDone();
    }

    StreamingWebSocketListener listener() {
        return new StreamingWebSocketListener() {
            @Override
            public void onText(String text) {
                if (completion.isDone()) {
                    return;
                }
                Frame frame = JsonSupport.tryRead(text.getBytes(StandardCharsets.UTF_8), Frame.class);
                if (frame == null || frame.type == null) {
                    return;
                }
                try {
                    handle(frame);
                } catch (RuntimeException ex) {
                    // The callback's failure ends the wait rather than being
                    // lost on the reader thread. The code keeps running.
                    completion.completeExceptionally(new MicroVMException("code run callback failed: " + ex.getMessage(), ex));
                    closeSocket("callback failed");
                }
            }

            @Override
            public void onBinary(byte[] data) {
                // The interpreter sends text frames only.
            }

            @Override
            public void onClose(int statusCode, String reason) {
                // The close frame, not the control frame, decides how the run
                // ended: a timed-out run may say "interrupted" and then close
                // with 4008.
                if (statusCode == CLOSE_NORMAL || statusCode == CLOSE_NO_STATUS) {
                    completion.complete(execution);
                } else if (statusCode == MicroVMCodeTimeoutException.CLOSE_CODE) {
                    completion.completeExceptionally(new MicroVMCodeTimeoutException(reason, execution));
                } else {
                    completion.completeExceptionally(new MicroVMCodeRunException(statusCode, reason, execution));
                }
            }

            @Override
            public void onError(Throwable error) {
                String message = error == null || error.getMessage() == null ? "connection lost" : error.getMessage();
                completion.completeExceptionally(new MicroVMCodeRunException(CLOSE_ABNORMAL, message, execution));
            }
        };
    }

    private void handle(Frame frame) {
        switch (frame.type) {
            case "stdout":
                execution.logs.stdout.add(nullToEmpty(frame.text));
                emit(options.onStdout, nullToEmpty(frame.text));
                break;
            case "stderr":
                execution.logs.stderr.add(nullToEmpty(frame.text));
                emit(options.onStderr, nullToEmpty(frame.text));
                break;
            case "result":
                CodeResult result = frame.toResult();
                execution.results.add(result);
                emit(options.onResult, result);
                break;
            case "execution_count":
                execution.executionCount = frame.count;
                break;
            case "error":
                ExecutionError error = new ExecutionError(nullToEmpty(frame.name), nullToEmpty(frame.value), nullToEmpty(frame.traceback));
                execution.error = error;
                emit(options.onError, error);
                break;
            case "control":
                if ("interrupted".equals(frame.text)) {
                    execution.interrupted = true;
                }
                break;
            default:
                // A frame type this SDK does not know: newer server.
                break;
        }
    }

    private static <T> void emit(Consumer<T> callback, T value) {
        if (callback != null) {
            callback.accept(value);
        }
    }

    private void closeSocket(String reason) {
        StreamingWebSocket webSocket = socket.get();
        if (webSocket == null) {
            return;
        }
        try {
            webSocket.sendClose(CLOSE_NORMAL, reason);
        } catch (RuntimeException ignored) {
            // Already closed by the other side.
        }
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    private static String emptyToNull(String value) {
        return value == null || value.isEmpty() ? null : value;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> mapOrNull(Object value) {
        return value instanceof Map ? (Map<String, Object>) value : null;
    }

    /**
     * Every field any server frame carries. json, data and extra are read as
     * any JSON value, so one of an unexpected shape drops that field, not
     * the whole frame.
     */
    @SuppressWarnings("unused")
    private static final class Frame {
        public String type;
        public String text;
        public String name;
        public String value;
        public String traceback;
        public Integer count;
        public String html;
        public String markdown;
        public String svg;
        public String png;
        public String jpeg;
        public String pdf;
        public String latex;
        public Object json;
        public String javascript;
        public Object data;
        public Object extra;
        public boolean isMainResult;

        CodeResult toResult() {
            CodeResult result = new CodeResult();
            // Every frame carries "text"; on a result an empty one means the
            // result has no plain-text form.
            result.text = emptyToNull(text);
            result.html = emptyToNull(html);
            result.markdown = emptyToNull(markdown);
            result.svg = emptyToNull(svg);
            result.png = emptyToNull(png);
            result.jpeg = emptyToNull(jpeg);
            result.pdf = emptyToNull(pdf);
            result.latex = emptyToNull(latex);
            result.json = mapOrNull(json);
            result.javascript = emptyToNull(javascript);
            result.data = mapOrNull(data);
            result.extra = mapOrNull(extra);
            result.isMainResult = isMainResult;
            return result;
        }
    }
}
