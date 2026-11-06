package ai.aerol.microvm;

import java.time.Duration;

/**
 * HTTP 401 (the token is missing, wrong or expired) or 403 (the token may
 * not do this). It extends {@link MicroVMApiException}, so a {@code catch
 * (MicroVMApiException e)} still catches it.
 */
public class MicroVMAuthException extends MicroVMApiException {
    private static final long serialVersionUID = 1L;

    public MicroVMAuthException(int statusCode, String code, String message, Duration retryAfter) {
        super(statusCode, code, message, retryAfter);
    }
}
