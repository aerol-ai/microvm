package ai.aerol.microvm.model;

import java.util.Map;
import java.util.function.Consumer;

/**
 * Options for {@code runCode} and {@code startCode}. With no context and no
 * language the code runs in the sandbox's default Python context.
 */
public class RunCodeOptions {
    /** The context to run in. Set this or {@link #language}, not both. */
    public String contextId;
    /**
     * Run in this language's default context. Set this or
     * {@link #contextId}, not both.
     */
    public String language;
    /** Environment variables for this run only. */
    public Map<String, String> envs;
    /**
     * Stop the run after this many seconds. Null keeps the server's default
     * (600); 0 means no limit.
     */
    public Integer timeoutSeconds;
    /** Called with each chunk the code prints to stdout, on the socket's reader thread. */
    public Consumer<String> onStdout;
    /** Called with each chunk the code prints to stderr, on the socket's reader thread. */
    public Consumer<String> onStderr;
    /** Called with each rich result, on the socket's reader thread. */
    public Consumer<CodeResult> onResult;
    /** Called when the code raises an exception, on the socket's reader thread. */
    public Consumer<ExecutionError> onError;

    public RunCodeOptions setContextId(String contextId) {
        this.contextId = contextId;
        return this;
    }

    /** Runs in {@code context}; the same as {@link #setContextId(String)} with its id. */
    public RunCodeOptions setContext(CodeContext context) {
        this.contextId = context == null ? null : context.id;
        return this;
    }

    public RunCodeOptions setLanguage(String language) {
        this.language = language;
        return this;
    }

    public RunCodeOptions setEnvs(Map<String, String> envs) {
        this.envs = envs;
        return this;
    }

    public RunCodeOptions setTimeoutSeconds(Integer timeoutSeconds) {
        this.timeoutSeconds = timeoutSeconds;
        return this;
    }

    public RunCodeOptions setOnStdout(Consumer<String> onStdout) {
        this.onStdout = onStdout;
        return this;
    }

    public RunCodeOptions setOnStderr(Consumer<String> onStderr) {
        this.onStderr = onStderr;
        return this;
    }

    public RunCodeOptions setOnResult(Consumer<CodeResult> onResult) {
        this.onResult = onResult;
        return this;
    }

    public RunCodeOptions setOnError(Consumer<ExecutionError> onError) {
        this.onError = onError;
        return this;
    }
}
