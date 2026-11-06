package ai.aerol.microvm.model;

import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class ExecStreamOptions {
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
    public Boolean tty;
    public Integer cols;
    public Integer rows;
    @JsonIgnore
    public Consumer<byte[]> onStdout;
    @JsonIgnore
    public Consumer<byte[]> onStderr;
    @JsonIgnore
    public Consumer<String> onError;

    public ExecStreamOptions setCommand(String command) {
        this.command = command;
        return this;
    }

    public ExecStreamOptions setArgv(List<String> argv) {
        this.argv = argv;
        return this;
    }

    public ExecStreamOptions setWorkDir(String workDir) {
        this.workDir = workDir;
        return this;
    }

    public ExecStreamOptions setEnv(Map<String, String> env) {
        this.env = env;
        return this;
    }

    public ExecStreamOptions setTty(Boolean tty) {
        this.tty = tty;
        return this;
    }

    public ExecStreamOptions setCols(Integer cols) {
        this.cols = cols;
        return this;
    }

    public ExecStreamOptions setRows(Integer rows) {
        this.rows = rows;
        return this;
    }

    public ExecStreamOptions setOnStdout(Consumer<byte[]> onStdout) {
        this.onStdout = onStdout;
        return this;
    }

    public ExecStreamOptions setOnStderr(Consumer<byte[]> onStderr) {
        this.onStderr = onStderr;
        return this;
    }

    public ExecStreamOptions setOnError(Consumer<String> onError) {
        this.onError = onError;
        return this;
    }
}