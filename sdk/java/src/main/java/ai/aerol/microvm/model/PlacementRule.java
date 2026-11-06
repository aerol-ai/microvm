package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Where a sandbox may run in a cluster. Every field you set must match the
 * node's labels exactly. If no node matches, create fails with 409
 * {@code placement_unsatisfiable}; it never falls back to another node.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PlacementRule {
    /** Run only on nodes in this zone (the node's {@code SB_NODE_ZONE}). */
    public String zone;
    /** Run only on nodes that have all of these labels ({@code SB_NODE_LABELS}). */
    public Map<String, String> labels;

    public PlacementRule setZone(String zone) {
        this.zone = zone;
        return this;
    }

    public PlacementRule setLabels(Map<String, String> labels) {
        this.labels = labels;
        return this;
    }

    public PlacementRule copy() {
        return new PlacementRule().setZone(zone).setLabels(labels == null ? null : new LinkedHashMap<>(labels));
    }
}
