package ai.aerol.microvm.internal;

import java.io.IOException;

/** Lets tests in other packages read back a gzipped archive. */
public final class TarWriterTestAccess {
    private TarWriterTestAccess() {
    }

    public static byte[] gunzip(byte[] data) throws IOException {
        return TarWriterTest.gunzip(data);
    }
}
