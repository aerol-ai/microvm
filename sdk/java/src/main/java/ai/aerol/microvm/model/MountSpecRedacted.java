package ai.aerol.microvm.model;

import java.util.Map;

import com.fasterxml.jackson.annotation.JsonProperty;

public class MountSpecRedacted {
    public String type;
    public String target;
    public String source;
    public Map<String, String> options;
    @JsonProperty("read_only")
    public boolean readOnly;
    @JsonProperty("has_credentials")
    public boolean hasCredentials;
}