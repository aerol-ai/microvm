package ai.aerol.microvm;

import java.time.Duration;

/**
 * HTTP 409: the call clashes with what is there now, such as a sandbox name
 * you already use. It extends {@link MicroVMApiException}, so a {@code catch
 * (MicroVMApiException e)} still catches it.
 */
public class MicroVMConflictException extends MicroVMApiException {
    private static final long serialVersionUID = 1L;

    public MicroVMConflictException(int statusCode, String code, String message, Duration retryAfter) {
        super(statusCode, code, message, retryAfter);
    }
}
