package ai.aerol.microvm.model;

/**
 * The exception the user's code raised during a run. It is part of the
 * {@link Execution}, not an SDK error: the run still ended normally.
 */
public class ExecutionError {
    /** The exception's type, such as {@code ZeroDivisionError}. */
    public String name;
    /** The exception's message. */
    public String value;
    /** The formatted traceback. */
    public String traceback;

    public ExecutionError() {
    }

    public ExecutionError(String name, String value, String traceback) {
        this.name = name;
        this.value = value;
        this.traceback = traceback;
    }

    @Override
    public String toString() {
        return name + ": " + value;
    }
}
