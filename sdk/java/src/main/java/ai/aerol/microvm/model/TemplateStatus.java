package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Lifecycle states for a Firecracker rootfs template. The state machine is
 * defined daemon-side in plans/snapshot-clone-fast-boot.md.
 *
 * <ul>
 *   <li>{@link #PENDING} / {@link #BUILDING_ROOTFS} / {@link #SNAPSHOTTING}:
 *       the build pipeline is in flight; sandbox creations against this
 *       template will not see fast-boot until the row reaches {@link #READY}.
 *   <li>{@link #READY}: cold boot + fast snapshot clone both available.
 *   <li>{@link #READY_NO_SNAPSHOT}: cold boot works; the snapshot phase
 *       failed and {@code snapshotError} carries the cause.
 *   <li>{@link #UNHEALTHY}: snapshot was detected as corrupt; an async
 *       rebuild is in flight or will be re-kicked on the next daemon
 *       restart.
 *   <li>{@link #FAILED}: terminal state from a failed initial build; the
 *       row must be deleted and recreated.
 * </ul>
 */
public enum TemplateStatus {
    @JsonProperty("pending") PENDING,
    @JsonProperty("building_rootfs") BUILDING_ROOTFS,
    @JsonProperty("snapshotting") SNAPSHOTTING,
    @JsonProperty("ready") READY,
    @JsonProperty("ready_no_snapshot") READY_NO_SNAPSHOT,
    @JsonProperty("failed") FAILED,
    @JsonProperty("unhealthy") UNHEALTHY,
}
