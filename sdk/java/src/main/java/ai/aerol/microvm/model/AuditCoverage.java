package ai.aerol.microvm.model;

import java.util.ArrayList;
import java.util.List;

/** Which nodes answered an audit read. */
public class AuditCoverage {
    public List<String> answered = new ArrayList<>();
    public List<String> missing = new ArrayList<>();
    public boolean partial;
}
