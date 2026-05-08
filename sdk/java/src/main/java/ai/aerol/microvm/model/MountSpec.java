package ai.aerol.microvm.model;

import java.util.Map;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class MountSpec {
    public String type;
    public String target;
    public String source;
    public Map<String, String> options;
    public Map<String, String> credentials;
    @JsonProperty("read_only")
    public Boolean readOnly;

    public MountSpec setType(String type) {
        this.type = type;
        return this;
    }

    public MountSpec setTarget(String target) {
        this.target = target;
        return this;
    }

    public MountSpec setSource(String source) {
        this.source = source;
        return this;
    }

    public MountSpec setOptions(Map<String, String> options) {
        this.options = options;
        return this;
    }

    public MountSpec setCredentials(Map<String, String> credentials) {
        this.credentials = credentials;
        return this;
    }

    public MountSpec setReadOnly(Boolean readOnly) {
        this.readOnly = readOnly;
        return this;
    }
}