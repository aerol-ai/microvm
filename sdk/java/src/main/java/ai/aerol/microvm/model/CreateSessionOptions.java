package ai.aerol.microvm.model;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class CreateSessionOptions {
    public String name;
    public List<String> argv;
    public String command;
    @JsonProperty("workdir")
    public String workDir;
    public Map<String, String> env;
    public Boolean pty;
    public Integer cols;
    public Integer rows;

    public CreateSessionOptions setName(String name) {
        this.name = name;
        return this;
    }

    public CreateSessionOptions setArgv(List<String> argv) {
        this.argv = argv;
        return this;
    }

    public CreateSessionOptions setCommand(String command) {
        this.command = command;
        return this;
    }

    public CreateSessionOptions setWorkDir(String workDir) {
        this.workDir = workDir;
        return this;
    }

    public CreateSessionOptions setEnv(Map<String, String> env) {
        this.env = env;
        return this;
    }

    public CreateSessionOptions setPty(Boolean pty) {
        this.pty = pty;
        return this;
    }

    public CreateSessionOptions setCols(Integer cols) {
        this.cols = cols;
        return this;
    }

    public CreateSessionOptions setRows(Integer rows) {
        this.rows = rows;
        return this;
    }
}