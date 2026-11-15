package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * A code interpreter context: one interpreter process in the sandbox that
 * keeps its variables, imports and working folder between runs. Made by
 * {@code createCodeContext}; pass it (or its {@link #id}) to
 * {@link RunCodeOptions#setContext(CodeContext)}.
 */
public class CodeContext {
    public String id;
    /** The language the context runs: python, javascript, typescript, bash, r or java. */
    public String language;
    /** The folder runs start in. */
    public String cwd;
    /** When the context was made, as the server wrote it (RFC 3339). */
    // The interpreter routes speak Daytona's camelCase, unlike the rest of
    // the API, which the client's snake_case mapper would otherwise expect.
    @JsonProperty("createdAt")
    public String createdAt;
    /**
     * False after a run timed out or the interpreter died; the context keeps
     * its id and starts a fresh interpreter (state lost) on its next run.
     */
    public boolean active;

    @Override
    public String toString() {
        return "CodeContext{id=" + id + ", language=" + language + ", cwd=" + cwd
            + ", createdAt=" + createdAt + ", active=" + active + "}";
    }
}
