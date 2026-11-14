package ai.aerol.microvm.model;

import java.util.ArrayList;
import java.util.List;

/** One page of a team's identity allow list; pass {@code nextCursor} back for the next. */
public class IdentityRoleList {
    public List<IdentityRole> roles = new ArrayList<>();
    public String nextCursor;
}
