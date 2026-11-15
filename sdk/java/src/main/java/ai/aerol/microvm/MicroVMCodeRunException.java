package ai.aerol.microvm;

import ai.aerol.microvm.model.Execution;

/**
 * A code run ended without the server finishing it: the server closed the
 * stream with an error (an unknown context, a dead interpreter), the
 * connection dropped, or the caller closed the run's handle.
 * {@link #getExecution()} holds what arrived before that. An exception the
 * user's code raised is not this: it is {@link Execution#error}.
 */
public class MicroVMCodeRunException extends MicroVMException {
    private static final long serialVersionUID = 1L;

    private final int closeCode;
    private final String reason;
    private final transient Execution execution;

    public MicroVMCodeRunException(int closeCode, String reason, Execution execution) {
        this("code run failed (close " + closeCode + ")" + suffix(reason), closeCode, reason, execution);
    }

    protected MicroVMCodeRunException(String message, int closeCode, String reason, Execution execution) {
        super(message);
        this.closeCode = closeCode;
        this.reason = reason == null ? "" : reason;
        this.execution = execution;
    }

    /** The WebSocket close code, such as 1008 or 1011; 1006 when the connection dropped. */
    public int getCloseCode() {
        return closeCode;
    }

    /** The server's close reason, such as {@code context not found: <id>}; empty when none. */
    public String getReason() {
        return reason;
    }

    /** The output, results and error that arrived before the run failed. */
    public Execution getExecution() {
        return execution;
    }

    static String suffix(String reason) {
        return reason == null || reason.isEmpty() ? "" : ": " + reason;
    }
}
