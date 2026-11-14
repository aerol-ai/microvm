package ai.aerol.microvm;

import java.time.Duration;

/**
 * HTTP 408 or 504: the server, or a proxy in front of it, gave up waiting.
 * It extends {@link MicroVMApiException}, so a {@code catch
 * (MicroVMApiException e)} still catches it.
 */
public class MicroVMTimeoutException extends MicroVMApiException {
    private static final long serialVersionUID = 1L;

    public MicroVMTimeoutException(int statusCode, String code, String message, Duration retryAfter) {
        super(statusCode, code, message, retryAfter);
    }
}
