package ai.aerol.microvm;

import java.time.Duration;

/**
 * An HTTP error response from the AerolVM server. {@link #getMessage()} is
 * the server's message, or {@code request failed with status N} when the
 * body carries none (a proxy's error page, say): the same text the SDK threw
 * before this class existed. It extends {@link MicroVMException}, so a
 * {@code catch (MicroVMException e)} still catches it.
 *
 * <p>Branch on {@link #getCode()}, not on the message: the code is a stable
 * identifier, the message is wording for a person.
 */
public class MicroVMApiException extends MicroVMException {
    private static final long serialVersionUID = 1L;

    private final int statusCode;
    private final String code;
    private final Duration retryAfter;

    public MicroVMApiException(int statusCode, String code, String message, Duration retryAfter) {
        super(message);
        this.statusCode = statusCode;
        this.code = code;
        this.retryAfter = retryAfter;
    }

    /**
     * The most specific subclass for a status: {@link MicroVMNotFoundException}
     * (404), {@link MicroVMConflictException} (409),
     * {@link MicroVMCapacityException} (503), {@link MicroVMTimeoutException}
     * (408, 504), {@link MicroVMAuthException} (401, 403), or this class for
     * any other status. The subclasses let a caller catch the one case it
     * handles instead of comparing numbers; catching this class still
     * catches them all.
     */
    public static MicroVMApiException forStatus(int statusCode, String code, String message, Duration retryAfter) {
        switch (statusCode) {
            case 401:
            case 403:
                return new MicroVMAuthException(statusCode, code, message, retryAfter);
            case 404:
                return new MicroVMNotFoundException(statusCode, code, message, retryAfter);
            case 408:
            case 504:
                return new MicroVMTimeoutException(statusCode, code, message, retryAfter);
            case 409:
                return new MicroVMConflictException(statusCode, code, message, retryAfter);
            case 503:
                return new MicroVMCapacityException(statusCode, code, message, retryAfter);
            default:
                return new MicroVMApiException(statusCode, code, message, retryAfter);
        }
    }

    /** The HTTP status of the final attempt, such as 422 or 503. */
    public int getStatusCode() {
        return statusCode;
    }

    /**
     * The server's stable error code, such as {@code "idempotency_key_reused"}
     * or {@code "overloaded"}. Null when the response has none: many errors
     * are only ever shown to a person, and a proxy's error page has no code.
     */
    public String getCode() {
        return code;
    }

    /**
     * How long the response's {@code Retry-After} header asked the caller to
     * wait, or null without a usable header.
     */
    public Duration getRetryAfter() {
        return retryAfter;
    }
}
