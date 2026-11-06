package ai.aerol.microvm.model;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class ExecRequest {
    public String command;
    /**
     * Runs a program with these arguments instead of {@link #command}, with no shell parsing: spaces,
     * quotes, $ and ; reach it as written. Set command or argv, not both. A sandbox whose agent
     * predates argv throws MicroVMUnsupportedFeatureException before anything runs.
     */
    public List<String> argv;
    @JsonProperty("workdir")
    public String workDir;
    public Map<String, String> env;
    @JsonProperty("timeout_seconds")
    public Integer timeoutSeconds;
    /**
     * Keep only the first N bytes of stdout; the rest is dropped and the command is not slowed
     * down. A sandbox whose agent predates the caps throws MicroVMUnsupportedFeatureException
     * instead of returning all output.
     */
    @JsonProperty("max_stdout_bytes")
    public Long maxStdoutBytes;
    /** Keep only the first N bytes of stderr. Same rules as {@link #maxStdoutBytes}. */
    @JsonProperty("max_stderr_bytes")
    public Long maxStderrBytes;

    public ExecRequest setCommand(String command) {
        this.command = command;
        return this;
    }

    public ExecRequest setArgv(List<String> argv) {
        this.argv = argv;
        return this;
    }

    public ExecRequest setWorkDir(String workDir) {
        this.workDir = workDir;
        return this;
    }

    public ExecRequest setEnv(Map<String, String> env) {
        this.env = env;
        return this;
    }

    public ExecRequest setTimeoutSeconds(Integer timeoutSeconds) {
        this.timeoutSeconds = timeoutSeconds;
        return this;
    }

    public ExecRequest setMaxStdoutBytes(Long maxStdoutBytes) {
        this.maxStdoutBytes = maxStdoutBytes;
        return this;
    }

    public ExecRequest setMaxStderrBytes(Long maxStderrBytes) {
        this.maxStderrBytes = maxStderrBytes;
        return this;
    }
}