package ai.aerol.microvm.model;

/** Paging for {@code listEgressProfiles}. */
public class ListEgressProfilesOptions {
    private String cursor;
    private Integer limit;

    public String getCursor() {
        return cursor;
    }

    public ListEgressProfilesOptions setCursor(String cursor) {
        this.cursor = cursor;
        return this;
    }

    public Integer getLimit() {
        return limit;
    }

    public ListEgressProfilesOptions setLimit(Integer limit) {
        this.limit = limit;
        return this;
    }
}
