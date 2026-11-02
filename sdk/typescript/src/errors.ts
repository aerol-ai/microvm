/**
 * An HTTP error response from the AerolVM server. `message` is the server's
 * message, or `request failed with status N` when the body carries none (a
 * proxy's HTML error page, say): the same text the SDK threw before this
 * class existed, so code that printed or matched it sees no change.
 *
 * Branch on `code`, not on `message`: the code is a stable identifier, the
 * message is wording for a person.
 */
export class MicroVMApiError extends Error {
  /** The HTTP status of the final attempt, such as 422 or 503. */
  readonly status: number;
  /**
   * The server's stable error code, such as `"idempotency_key_reused"` or
   * `"overloaded"`. Undefined when the response has none: many errors are
   * only ever shown to a person, and a proxy's error page has no code.
   */
  readonly code: string | undefined;
  /**
   * How long the response's `Retry-After` header asked the caller to wait,
   * in milliseconds. Undefined without a usable header.
   */
  readonly retryAfterMs: number | undefined;

  constructor(status: number, message: string, options: { code?: string; retryAfterMs?: number } = {}) {
    super(message);
    this.name = "MicroVMApiError";
    this.status = status;
    this.code = options.code;
    this.retryAfterMs = options.retryAfterMs;
  }
}
