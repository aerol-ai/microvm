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

// The typed errors below extend MicroVMApiError, so code that catches
// MicroVMApiError and reads `status` keeps working unchanged; new code can
// test `instanceof` for the one case it handles instead of comparing numbers.
// They keep `name` "MicroVMApiError": code that checks the name (often done
// where two copies of the SDK make instanceof unreliable) keeps working too.

/** HTTP 404: the sandbox, file, snapshot or other thing the call named does not exist (or is not yours). */
export class MicroVMNotFoundError extends MicroVMApiError {}

/** HTTP 409: the call clashes with what is there now, such as a sandbox name you already use. */
export class MicroVMConflictError extends MicroVMApiError {}

/**
 * HTTP 503: the server has no room for the call right now or is shedding
 * load. The SDK has already retried it; try again later.
 */
export class MicroVMCapacityError extends MicroVMApiError {}

/** HTTP 408 or 504: the server, or a proxy in front of it, gave up waiting. */
export class MicroVMTimeoutError extends MicroVMApiError {}

/** HTTP 401 or 403: the token is missing, wrong or expired (401), or it may not do this (403). */
export class MicroVMAuthError extends MicroVMApiError {}

const API_ERROR_CLASSES: Record<number, typeof MicroVMApiError> = {
  401: MicroVMAuthError,
  403: MicroVMAuthError,
  404: MicroVMNotFoundError,
  408: MicroVMTimeoutError,
  409: MicroVMConflictError,
  503: MicroVMCapacityError,
  504: MicroVMTimeoutError,
};

/** The most specific {@link MicroVMApiError} subclass for a status. */
export function apiErrorFor(
  status: number,
  message: string,
  options: { code?: string; retryAfterMs?: number } = {},
): MicroVMApiError {
  const ErrorClass = API_ERROR_CLASSES[status] ?? MicroVMApiError;
  return new ErrorClass(status, message, options);
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
  /**
   * Set (for example "wasm") when the sandbox's runtime cannot offer the
   * features at all; a restart does not help there.
   */
  readonly runtime: string;

  constructor(sandboxID: string, features: string[], agentVersion = "", runtime = "") {
    const agent = agentVersion ? `toolboxd ${agentVersion}` : "an older toolboxd";
    super(
      runtime
        ? `sandbox ${sandboxID} is a ${runtimeDisplayName(runtime)} sandbox, which does not support ${features.join(", ")}`
        : `sandbox ${sandboxID} runs ${agent}, which does not support ${features.join(", ")}; ` +
            "restart the sandbox, or re-create its Firecracker template, to get the current agent",
    );
    this.name = "MicroVMUnsupportedFeatureError";
    this.sandboxID = sandboxID;
    this.features = features;
    this.agentVersion = agentVersion;
    this.runtime = runtime;
  }
}

function runtimeDisplayName(runtime: string): string {
  if (runtime === "wasm") return "WebAssembly";
  if (runtime === "isolate") return "V8 isolate";
  return runtime;
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
