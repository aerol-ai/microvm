package ai.aerol.microvm.model;

import java.util.ArrayList;
import java.util.List;

/** What a run printed, in the chunks the server sent them. */
public class ExecutionLogs {
    public List<String> stdout = new ArrayList<>();
    public List<String> stderr = new ArrayList<>();
}
