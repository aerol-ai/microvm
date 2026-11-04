package ai.aerol.microvm.model;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

/** One name-ordered page of snapshots from {@code listSnapshots}. */
public class SnapshotList {
    public List<SandboxSnapshot> snapshots = new ArrayList<>();

    /** True when more snapshots remain after this page. */
    @JsonProperty("has_more")
    public boolean hasMore;
}
