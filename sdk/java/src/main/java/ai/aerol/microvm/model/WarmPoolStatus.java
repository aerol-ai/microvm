package ai.aerol.microvm.model;

import java.util.ArrayList;
import java.util.List;

/** Ready and target slots in total, and on each server that runs a warm pool. */
public class WarmPoolStatus {
    public int ready;
    public int target;
    public List<WarmPoolServerStatus> servers = new ArrayList<>();
}
