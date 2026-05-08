package ai.aerol.microvm.model;

import java.util.Map;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class ExecRequest {
    public String command;
    @JsonProperty("workdir")
    public String workDir;
    public Map<String, String> env;
    @JsonProperty("timeout_seconds")
    public Integer timeoutSeconds;

    public ExecRequest setCommand(String command) {
        this.command = command;
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
}