package ai.aerol.microvm.model;

/**
 * Why a sandbox is in its current status ({@link SandboxData#statusReason}).
 * The first seven are reasons a sandbox is stopped; {@link #PROGRAM_EXITED},
 * {@link #FAILOVER} and {@link #RESTARTED} can also describe a started one.
 * Strings rather than an enum, so a newer server's reason still reads.
 */
public final class StatusReason {
    /** A stop call: the API, an SDK, the CLI, a facade, or the operator. */
    public static final String USER_STOP = "user_stop";
    /** stopIfIdleFor, or the server's default idle stop. */
    public static final String IDLE = "idle";
    /** stopAtAge. */
    public static final String MAX_AGE = "max_age";
    /** The sandbox's init was killed for using too much memory. */
    public static final String OUT_OF_MEMORY = "out_of_memory";
    /** It wrote more than its disk size. */
    public static final String DISK_LIMIT = "disk_limit";
    /** It went down on its own with a non-zero exit code. */
    public static final String CRASHED = "crashed";
    /** The server found it stopped without seeing why. */
    public static final String RECONCILE = "reconcile";
    /** Its main program ended; exitCode says how. */
    public static final String PROGRAM_EXITED = "program_exited";
    /** It was recreated on another node after its node failed. */
    public static final String FAILOVER = "failover";
    /** restartOnFailure started it again after a crash. */
    public static final String RESTARTED = "restarted";

    private StatusReason() {
    }
}
