package ai.aerol.microvm.model;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;

/** Everything one {@code runCode} call produced. */
public class Execution {
    /** Rich results (the last expression's value, charts, tables), in order. */
    public List<CodeResult> results = new ArrayList<>();
    public ExecutionLogs logs = new ExecutionLogs();
    /** The exception the code raised, or null. */
    public ExecutionError error;
    /** The interpreter's run counter, or null when the server sent none. */
    public Integer executionCount;
    /** True when the run was interrupted before it finished. */
    public boolean interrupted;

    /** The text of the main result (the last expression's value), or null. */
    @JsonIgnore
    public String getText() {
        for (CodeResult result : results) {
            if (result.isMainResult) {
                return result.text;
            }
        }
        return null;
    }
}
