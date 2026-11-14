package ai.aerol.microvm;

import java.time.Duration;

/**
 * HTTP 503: the server has no room for the call right now or is shedding
 * load. The client has already retried it; try again later. It extends
 * {@link MicroVMApiException}, so a {@code catch (MicroVMApiException e)}
 * still catches it.
 */
public class MicroVMCapacityException extends MicroVMApiException {
    private static final long serialVersionUID = 1L;

    public MicroVMCapacityException(int statusCode, String code, String message, Duration retryAfter) {
        super(statusCode, code, message, retryAfter);
    }
}
