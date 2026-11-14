package ai.aerol.microvm.model;

import java.util.ArrayList;
import java.util.List;

/** The wire shape of {@code GET /v1/warm-pools}; {@code listWarmPools} returns the entries. */
public class WarmPoolList {
    public List<WarmPool> pools = new ArrayList<>();
}
