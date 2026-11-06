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

/**
 * The sandbox's agent (toolboxd) is older than an option this call needs. An
 * older agent would silently ignore the option (an overwrite guard, an output
 * cap), so the SDK refuses instead of sending it. Restart the sandbox, or
 * re-create its Firecracker template, to get the current agent.
 */
export class MicroVMUnsupportedFeatureError extends Error {
  /** The sandbox whose agent is too old. */
  readonly sandboxID: string;
  /** The features the agent did not list. */
  readonly features: string[];
  /** The agent's version when it reported one. */
  readonly agentVersion: string;

  constructor(sandboxID: string, features: string[], agentVersion = "") {
    const agent = agentVersion ? `toolboxd ${agentVersion}` : "an older toolboxd";
    super(
      `sandbox ${sandboxID} runs ${agent}, which does not support ${features.join(", ")}; ` +
        "restart the sandbox, or re-create its Firecracker template, to get the current agent",
    );
    this.name = "MicroVMUnsupportedFeatureError";
    this.sandboxID = sandboxID;
    this.features = features;
    this.agentVersion = agentVersion;
  }
}

/**
 * A download was larger than its `maxBytes`. Thrown before reading when the
 * server states the size, otherwise as soon as more arrives.
 */
export class MicroVMFileTooLargeError extends Error {
  readonly path: string;
  readonly maxBytes: number;

  constructor(path: string, maxBytes: number) {
    super(`${path} is larger than maxBytes (${maxBytes} bytes)`);
    this.name = "MicroVMFileTooLargeError";
    this.path = path;
    this.maxBytes = maxBytes;
  }
}
