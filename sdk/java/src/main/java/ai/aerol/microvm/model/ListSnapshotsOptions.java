package ai.aerol.microvm.model;

/** Paging for {@code listSnapshots}: one name-ordered page. */
public class ListSnapshotsOptions {
    private Integer limit;
    private String startingAfter;

    public Integer getLimit() {
        return limit;
    }

    public ListSnapshotsOptions setLimit(Integer limit) {
        this.limit = limit;
        return this;
    }

    public String getStartingAfter() {
        return startingAfter;
    }

    public ListSnapshotsOptions setStartingAfter(String startingAfter) {
        this.startingAfter = startingAfter;
        return this;
    }
}
