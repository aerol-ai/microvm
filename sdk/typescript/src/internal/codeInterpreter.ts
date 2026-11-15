import { MicroVMCodeRunError, MicroVMCodeTimeoutError } from "../errors.js";
import type { CodeContext, CodeResult, Execution, ExecutionError, ExecutionLogs, RunCodeOptions } from "../types.js";

/** The toolboxd feature (on /version) that serves the code interpreter routes. */
export const FEATURE_CODE_INTERPRETER = "code.interpreter";

/**
 * How long an aborted run waits for the sandbox to confirm the interrupt
 * before the socket is dropped. Longer than the server's own 2 second wait
 * between its interrupt and its kill, so a run that ignores the interrupt
 * still reports how it ended.
 */
export const INTERRUPT_GRACE_MS = 5_000;

/** The server's close code for a run its timeout stopped. */
const CLOSE_TIMEOUT = 4008;

/** Close codes that mean the run finished: 1005 is a close frame without a code. */
const CLOSE_DONE = new Set([1000, 1005]);

/** CodeResult's named formats, in the order formats() lists them. */
const RESULT_FORMATS = ["text", "html", "markdown", "svg", "png", "jpeg", "pdf", "latex", "json", "javascript", "data"] as const;

/** The string formats; json, data and extra are objects. */
const STRING_FORMATS = ["text", "html", "markdown", "svg", "png", "jpeg", "pdf", "latex", "javascript"] as const;

type ApiCodeContext = {
  id?: unknown;
  language?: unknown;
  cwd?: unknown;
  createdAt?: unknown;
  active?: unknown;
};

export function fromApiCodeContext(raw: ApiCodeContext): CodeContext {
  return {
    id: String(raw?.id ?? ""),
    language: String(raw?.language ?? ""),
    cwd: String(raw?.cwd ?? ""),
    createdAt: String(raw?.createdAt ?? ""),
    active: Boolean(raw?.active),
  };
}

class CodeResultValue implements CodeResult {
  text?: string;
  html?: string;
  markdown?: string;
  svg?: string;
  png?: string;
  jpeg?: string;
  pdf?: string;
  latex?: string;
  json?: unknown;
  javascript?: string;
  data?: Record<string, unknown>;
  extra?: Record<string, unknown>;
  isMainResult: boolean;

  constructor(frame: Record<string, unknown>) {
    // Every frame carries "text", empty when the result has no plain text,
    // so an empty string counts as absent.
    for (const name of STRING_FORMATS) {
      const value = frame[name];
      if (typeof value === "string" && value !== "") this[name] = value;
    }
    if (frame.json !== undefined && frame.json !== null) this.json = frame.json;
    if (isObject(frame.data)) this.data = frame.data;
    if (isObject(frame.extra) && Object.keys(frame.extra).length > 0) this.extra = frame.extra;
    this.isMainResult = frame.is_main_result === true;
  }

  formats(): string[] {
    const named: string[] = RESULT_FORMATS.filter((name) => this[name] !== undefined);
    return named.concat(Object.keys(this.extra ?? {}).sort());
  }
}

export class ExecutionValue implements Execution {
  results: CodeResult[] = [];
  logs: ExecutionLogs = { stdout: [], stderr: [] };
  error?: ExecutionError;
  executionCount?: number;
  interrupted = false;

  get text(): string | undefined {
    return this.results.find((result) => result.isMainResult)?.text;
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The run's first frame. Throws before anything is sent when it cannot be built. */
export function runCodeStartFrame(code: string, options: RunCodeOptions): Record<string, unknown> {
  const contextID = typeof options.context === "string" ? options.context : options.context?.id;
  if (contextID && options.language) {
    throw new Error("set context or language, not both");
  }
  const frame: Record<string, unknown> = { code };
  if (contextID) frame.contextId = contextID;
  else if (options.language) frame.language = options.language;
  if (options.envs && Object.keys(options.envs).length > 0) frame.envs = options.envs;
  // 0 is sent: it asks for no timeout, where an absent one means the
  // server's default.
  if (options.timeoutSeconds !== undefined) frame.timeout = options.timeoutSeconds;
  // Turns on the result and execution_count frames; a Daytona client never
  // sends it and sees Daytona's protocol unchanged.
  frame.richOutput = true;
  return frame;
}

/**
 * Records one server text frame in `execution` and returns the caller's
 * callback for it, still to be called, or undefined when there is none.
 * Frames that are not JSON objects, and frame types a newer server may add,
 * are skipped so this client keeps working.
 */
export function applyCodeFrame(execution: ExecutionValue, data: string, options: RunCodeOptions): (() => void) | undefined {
  let frame: unknown;
  try {
    frame = JSON.parse(data);
  } catch {
    return undefined;
  }
  if (!isObject(frame)) return undefined;
  const text = typeof frame.text === "string" ? frame.text : "";
  switch (frame.type) {
    case "stdout":
      execution.logs.stdout.push(text);
      return options.onStdout && (() => options.onStdout!(text));
    case "stderr":
      execution.logs.stderr.push(text);
      return options.onStderr && (() => options.onStderr!(text));
    case "result": {
      const result = new CodeResultValue(frame);
      execution.results.push(result);
      return options.onResult && (() => options.onResult!(result));
    }
    case "execution_count":
      if (typeof frame.count === "number") execution.executionCount = frame.count;
      return undefined;
    case "error": {
      const error: ExecutionError = {
        name: String(frame.name ?? ""),
        value: String(frame.value ?? ""),
        traceback: String(frame.traceback ?? ""),
      };
      execution.error = error;
      return options.onError && (() => options.onError!(error));
    }
    case "control":
      if (text === "interrupted") execution.interrupted = true;
      return undefined;
    default:
      return undefined;
  }
}

/**
 * What a close frame means for the run: undefined when it finished, else the
 * error to reject with. `errorDetail` is what the socket's error event said;
 * a lost connection (1006) carries no reason of its own.
 */
export function codeRunCloseError(
  execution: Execution,
  closeCode: number,
  reason: string,
  errorDetail: string,
): MicroVMCodeRunError | undefined {
  if (CLOSE_DONE.has(closeCode)) return undefined;
  if (closeCode === CLOSE_TIMEOUT) {
    return new MicroVMCodeTimeoutError(`code run timed out${reason ? `: ${reason}` : ""}`, closeCode, reason, execution);
  }
  const detail = reason || errorDetail;
  return new MicroVMCodeRunError(`code run failed (close ${closeCode})${detail ? `: ${detail}` : ""}`, closeCode, reason, execution);
}
