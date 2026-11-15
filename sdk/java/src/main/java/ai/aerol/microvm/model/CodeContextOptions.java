package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonInclude;

/** Options for {@code createCodeContext}. Unset fields take the server's defaults. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CodeContextOptions {
    /**
     * python (the default), javascript, typescript, bash, r or java. The
     * sandbox's image must have the interpreter.
     */
    public String language;
    /** The folder runs start in; the sandbox's working folder when unset. */
    public String cwd;

    public CodeContextOptions setLanguage(String language) {
        this.language = language;
        return this;
    }

    public CodeContextOptions setCwd(String cwd) {
        this.cwd = cwd;
        return this;
    }
}
