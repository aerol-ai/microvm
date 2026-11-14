package ai.aerol.microvm.model;

import java.util.ArrayList;
import java.util.List;

/** The result of {@code listFiles}. */
public class FileList {
    public List<FileInfo> entries = new ArrayList<>();
    /** True when the listing reached its limit and stopped; more entries exist. */
    public boolean truncated;
}
