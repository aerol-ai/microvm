package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.ArrayList;
import java.util.List;

/** One page of a sandbox's audit log. */
public class AuditPage {
    public List<AuditEvent> events = new ArrayList<>();
    public AuditCoverage coverage = new AuditCoverage();
    /** Pass back as {@link AuditOptions#setCursor} for the next page; null on the last page. */
    @JsonProperty("next_cursor")
    public String nextCursor;
}
