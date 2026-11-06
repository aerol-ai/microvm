package ai.aerol.microvm.model;

/** Filters and paging for {@code Sandbox.audit}. Unset fields are not sent. */
public class AuditOptions {
    private String kind;
    private Integer limit;
    private String cursor;
    private String incarnationId;
    private String caller;

    public String getKind() {
        return kind;
    }

    public AuditOptions setKind(String kind) {
        this.kind = kind;
        return this;
    }

    public Integer getLimit() {
        return limit;
    }

    public AuditOptions setLimit(Integer limit) {
        this.limit = limit;
        return this;
    }

    public String getCursor() {
        return cursor;
    }

    public AuditOptions setCursor(String cursor) {
        this.cursor = cursor;
        return this;
    }

    public String getIncarnationId() {
        return incarnationId;
    }

    public AuditOptions setIncarnationId(String incarnationId) {
        this.incarnationId = incarnationId;
        return this;
    }

    public String getCaller() {
        return caller;
    }

    /**
     * Only records by this caller: an id such as {@code "system:lifecycle"},
     * or {@code "system:*"} for everything the server did on its own.
     */
    public AuditOptions setCaller(String caller) {
        this.caller = caller;
        return this;
    }
}
