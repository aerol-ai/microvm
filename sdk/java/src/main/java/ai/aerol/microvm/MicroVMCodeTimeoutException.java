package ai.aerol.microvm;

import ai.aerol.microvm.model.Execution;

/**
 * The run's timeout ({@code RunCodeOptions.timeoutSeconds}, 600 seconds by
 * default) fired: the server interrupted the code, then stopped it, and
 * closed the stream with code 4008. The context starts a fresh interpreter
 * on its next run, so its variables are gone. {@link #getExecution()} holds
 * the output that arrived in time.
 */
public class MicroVMCodeTimeoutException extends MicroVMCodeRunException {
    private static final long serialVersionUID = 1L;

    /** The close code the server uses for a run that timed out. */
    public static final int CLOSE_CODE = 4008;

    public MicroVMCodeTimeoutException(String reason, Execution execution) {
        super("code run timed out" + suffix(reason), CLOSE_CODE, reason, execution);
    }
}
