package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.ArrayList;
import java.util.List;

/** The body of {@code putEgressProfile}: a full replace. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class EgressProfileOptions {
    private List<String> allowOut = new ArrayList<>();
    private String description;

    public List<String> getAllowOut() {
        return allowOut;
    }

    public EgressProfileOptions setAllowOut(List<String> allowOut) {
        this.allowOut = allowOut == null ? new ArrayList<>() : allowOut;
        return this;
    }

    public String getDescription() {
        return description;
    }

    public EgressProfileOptions setDescription(String description) {
        this.description = description;
        return this;
    }
}
