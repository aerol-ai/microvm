package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

// Long (boxed) so unset fields serialize as missing — server reads "leave
// alone" for nulls and "unlimited" for an explicit 0.
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SetNetworkLimitsOptions {
    @JsonProperty("network_bytes_in_limit")
    public Long networkBytesInLimit;
    @JsonProperty("network_bytes_out_limit")
    public Long networkBytesOutLimit;

    public SetNetworkLimitsOptions setNetworkBytesInLimit(Long limit) {
        this.networkBytesInLimit = limit;
        return this;
    }

    public SetNetworkLimitsOptions setNetworkBytesOutLimit(Long limit) {
        this.networkBytesOutLimit = limit;
        return this;
    }
}
