package ai.aerol.microvm.model;

import java.util.ArrayList;
import java.util.List;

/** One page of egress profiles; pass {@code nextCursor} back for the next. */
public class EgressProfileList {
    public List<EgressProfile> profiles = new ArrayList<>();
    public String nextCursor;
}
