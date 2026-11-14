package ai.aerol.microvm;

import java.time.Duration;

/**
 * HTTP 404: the sandbox, file, snapshot or other thing the call named does
 * not exist (or is not yours). It extends {@link MicroVMApiException}, so a
 * {@code catch (MicroVMApiException e)} still catches it.
 */
public class MicroVMNotFoundException extends MicroVMApiException {
    private static final long serialVersionUID = 1L;

    public MicroVMNotFoundException(int statusCode, String code, String message, Duration retryAfter) {
        super(statusCode, code, message, retryAfter);
    }
}
