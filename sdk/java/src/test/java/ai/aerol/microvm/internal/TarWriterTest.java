package ai.aerol.microvm.internal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TarWriterTest {
    static final class Entry {
        final String name;
        final char type;
        final int mode;
        final byte[] data;
        final String link;

        Entry(String name, char type, int mode, byte[] data, String link) {
            this.name = name;
            this.type = type;
            this.mode = mode;
            this.data = data;
            this.link = link;
        }
    }

    private static String field(byte[] block, int offset, int length) {
        int end = offset;
        while (end < offset + length && block[end] != 0) {
            end++;
        }
        return new String(block, offset, end - offset, StandardCharsets.UTF_8);
    }

    /** Reads a tar back the way a tar reader does, checking each checksum. */
    static List<Entry> parse(byte[] archive) {
        List<Entry> out = new ArrayList<>();
        Map<String, String> pax = new HashMap<>();
        int offset = 0;
        while (offset + 512 <= archive.length) {
            byte[] block = java.util.Arrays.copyOfRange(archive, offset, offset + 512);
            boolean zero = true;
            int sum = 0;
            for (int i = 0; i < 512; i++) {
                zero &= block[i] == 0;
                sum += i >= 148 && i < 156 ? 32 : block[i] & 0xff;
            }
            if (zero) {
                break;
            }
            assertEquals(sum, Integer.parseInt(field(block, 148, 7).trim(), 8), "checksum");
            assertEquals("ustar", field(block, 257, 6));
            int size = Integer.parseInt(field(block, 124, 12), 8);
            byte[] data = java.util.Arrays.copyOfRange(archive, offset + 512, offset + 512 + size);
            char type = (char) block[156];
            offset += 512 + (size + 511) / 512 * 512;
            if (type == 'x') {
                String rest = new String(data, StandardCharsets.UTF_8);
                while (!rest.isEmpty()) {
                    int length = Integer.parseInt(rest.substring(0, rest.indexOf(' ')));
                    String record = rest.substring(0, length);
                    assertTrue(record.endsWith("\n"), "a PAX record's length must count the whole record");
                    String kv = record.substring(record.indexOf(' ') + 1, record.length() - 1);
                    pax.put(kv.substring(0, kv.indexOf('=')), kv.substring(kv.indexOf('=') + 1));
                    rest = rest.substring(length);
                }
                continue;
            }
            String name = pax.containsKey("path") ? pax.remove("path") : field(block, 0, 100);
            String link = pax.containsKey("linkpath") ? pax.remove("linkpath") : field(block, 157, 100);
            out.add(new Entry(name, type, Integer.parseInt(field(block, 100, 8), 8), data, link));
        }
        return out;
    }

    static byte[] gunzip(byte[] data) throws IOException {
        try (GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(data))) {
            return in.readAllBytes();
        }
    }

    @Test
    void writesFilesFoldersSymlinksAndLongNames(@TempDir Path root) throws IOException {
        Files.createDirectories(root.resolve("pkg"));
        Files.write(root.resolve("a.txt"), "alpha".getBytes(StandardCharsets.UTF_8));
        Files.write(root.resolve("pkg/B.java"), "beta".getBytes(StandardCharsets.UTF_8));
        Files.setPosixFilePermissions(root.resolve("pkg/B.java"), PosixFilePermissions.fromString("rwxr-x---"));
        String longName = "x".repeat(120);
        Files.write(root.resolve("pkg").resolve(longName), "long".getBytes(StandardCharsets.UTF_8));
        Files.createSymbolicLink(root.resolve("link"), Path.of("a.txt"));
        Files.createLink(root.resolve("hard.txt"), root.resolve("a.txt"));

        List<Entry> entries = parse(gunzip(TarWriter.gzippedFolder(root)));
        List<String> names = new ArrayList<>();
        for (Entry e : entries) {
            names.add(e.name + ":" + e.type);
        }
        assertEquals(List.of("a.txt:0", "hard.txt:0", "link:2", "pkg/:5", "pkg/B.java:0", "pkg/" + longName + ":0"), names);
        assertArrayEquals("alpha".getBytes(StandardCharsets.UTF_8), entries.get(1).data, "a hard-linked file is sent as its own file");
        assertEquals("a.txt", entries.get(2).link);
        assertEquals(0750, entries.get(4).mode);
        assertArrayEquals("long".getBytes(StandardCharsets.UTF_8), entries.get(5).data);
    }

    @Test
    void longLinkTargetsUsePax() throws IOException {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        String target = "t".repeat(130);
        TarWriter.entry(out, "far", '2', 0777, 0, new byte[0], target);
        assertEquals(target, parse(out.toByteArray()).get(0).link);
    }

    @Test
    void aPaxRecordLengthCountsItsOwnDigits() {
        for (int n = 80; n < 1010; n++) {
            byte[] record = TarWriter.paxRecord("path", "v".repeat(n));
            String text = new String(record, StandardCharsets.UTF_8);
            assertEquals(record.length, Integer.parseInt(text.substring(0, text.indexOf(' '))), "value length " + n);
        }
    }
}
