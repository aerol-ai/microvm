package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class ExecExitInfo {
    public int code;
    public String signal;

    public ExecExitInfo setCode(int code) {
        this.code = code;
        return this;
    }

    public ExecExitInfo setSignal(String signal) {
        this.signal = signal;
        return this;
    }
}