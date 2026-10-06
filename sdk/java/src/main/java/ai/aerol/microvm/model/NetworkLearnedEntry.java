package ai.aerol.microvm.model;

import java.util.ArrayList;
import java.util.List;

/** One destination a learn-mode sandbox reached. */
public class NetworkLearnedEntry {
    public String host;
    /** Connection ports; empty when the name was only resolved. */
    public List<Integer> ports = new ArrayList<>();
    public String firstSeen;
    public String lastSeen;
    public long hits;
}
