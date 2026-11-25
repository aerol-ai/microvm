package ai.aerol.microvm.model;

import java.util.ArrayList;
import java.util.List;

/** The body of {@code GET /v1/runtimes}; {@code client.runtimes().list()} returns its {@code runtimes}. */
public class RuntimeList {
    public List<RuntimeInfo> runtimes = new ArrayList<>();
}
