package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Request body for {@link ai.aerol.microvm.MicroVMClient#createTemplate}.
 *
 * <p>Supplying an explicit {@link #id} makes retries idempotent: a duplicate
 * id is rejected by the server with HTTP 409 so a re-run CI step does not
 * register two rows for the same logical template.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CreateTemplateOptions {
    public String id;
    public String image;
    @JsonProperty("min_size_mib")
    public Integer minSizeMib;

    public CreateTemplateOptions setId(String id) {
        this.id = id;
        return this;
    }

    public CreateTemplateOptions setImage(String image) {
        this.image = image;
        return this;
    }

    public CreateTemplateOptions setMinSizeMib(Integer minSizeMib) {
        this.minSizeMib = minSizeMib;
        return this;
    }
}
