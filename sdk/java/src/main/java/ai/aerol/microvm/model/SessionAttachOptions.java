package ai.aerol.microvm.model;

import java.util.function.Consumer;

import com.fasterxml.jackson.annotation.JsonIgnore;

public class SessionAttachOptions {
    public Integer cols;
    public Integer rows;
    @JsonIgnore
    public Consumer<byte[]> onStdout;
    @JsonIgnore
    public Consumer<byte[]> onStderr;
    @JsonIgnore
    public Consumer<String> onError;
    @JsonIgnore
    public Consumer<ExecExitInfo> onExit;

    public SessionAttachOptions setCols(Integer cols) {
        this.cols = cols;
        return this;
    }

    public SessionAttachOptions setRows(Integer rows) {
        this.rows = rows;
        return this;
    }

    public SessionAttachOptions setOnStdout(Consumer<byte[]> onStdout) {
        this.onStdout = onStdout;
        return this;
    }

    public SessionAttachOptions setOnStderr(Consumer<byte[]> onStderr) {
        this.onStderr = onStderr;
        return this;
    }

    public SessionAttachOptions setOnError(Consumer<String> onError) {
        this.onError = onError;
        return this;
    }

    public SessionAttachOptions setOnExit(Consumer<ExecExitInfo> onExit) {
        this.onExit = onExit;
        return this;
    }
}