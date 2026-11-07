package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class ExecResult {
    public String stdout;
    public String stderr;
    @JsonProperty("exit_code")
    public int exitCode;
    @JsonProperty("duration_ms")
    public long durationMs;
    /** True when the command ran past its timeout and the sandbox killed its whole process group. Older sandbox agents never set it. */
    @JsonProperty("timed_out")
    public boolean timedOut;
    /** True when stdout was longer than its cap (maxStdoutBytes, or the server's own limit) and was cut. */
    @JsonProperty("stdout_truncated")
    public boolean stdoutTruncated;
    /** True when stderr was longer than its cap and was cut. */
    @JsonProperty("stderr_truncated")
    public boolean stderrTruncated;
    /**
     * The signal that ended the command, such as "SIGKILL"; null when it exited on its own.
     * exitCode is -1 then; a shell would say 128 + the signal's number (137 for SIGKILL).
     */
    public String signal;
}