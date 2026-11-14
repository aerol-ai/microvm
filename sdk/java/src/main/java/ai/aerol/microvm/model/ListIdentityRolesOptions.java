package ai.aerol.microvm.model;

/** Paging for {@code listIdentityRoles}. */
public class ListIdentityRolesOptions {
    private String team;
    private String cursor;
    private Integer limit;

    public String getTeam() {
        return team;
    }

    public ListIdentityRolesOptions setTeam(String team) {
        this.team = team;
        return this;
    }

    public String getCursor() {
        return cursor;
    }

    public ListIdentityRolesOptions setCursor(String cursor) {
        this.cursor = cursor;
        return this;
    }

    public Integer getLimit() {
        return limit;
    }

    public ListIdentityRolesOptions setLimit(Integer limit) {
        this.limit = limit;
        return this;
    }
}
