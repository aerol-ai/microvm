package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class ExecResult {
    public String stdout;
    public String stderr;
    @JsonProperty("exit_code")
    public int exitCode;
    @JsonProperty("duration_ms")
    public long durationMs;
}