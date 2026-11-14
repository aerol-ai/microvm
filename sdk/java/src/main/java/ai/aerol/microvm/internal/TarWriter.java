package ai.aerol.microvm.internal;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import java.util.zip.GZIPOutputStream;

/**
 * A minimal tar writer for {@code uploadDir} (plans/agent-sandbox-feature-
 * parity.md, F3). The JDK has no tar, and the SDK takes no extra dependency.
 * It writes ustar headers, with a PAX record for a name or link target past
 * ustar's 100 bytes, which Go's archive/tar (toolboxd) reads.
 */
public final class TarWriter {
    private static final int BLOCK = 512;

    private TarWriter() {
    }

    /**
     * The contents of {@code root} as a gzipped tar, names relative to it.
     * Symlinks are stored as links, hard-linked files as separate files;
     * devices, pipes and sockets are skipped.
     */
    public static byte[] gzippedFolder(Path root) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(buffer)) {
            walk(root, "", gzip);
            gzip.write(new byte[BLOCK * 2]);
        }
        return buffer.toByteArray();
    }

    private static void walk(Path root, String prefix, OutputStream out) throws IOException {
        Path dir = prefix.isEmpty() ? root : root.resolve(prefix);
        List<String> names = new ArrayList<>();
        try (Stream<Path> children = Files.list(dir)) {
            children.forEach(child -> names.add(child.getFileName().toString()));
        }
        Collections.sort(names);
        for (String name : names) {
            String rel = prefix.isEmpty() ? name : prefix + "/" + name;
            Path full = root.resolve(rel);
            BasicFileAttributes attrs = Files.readAttributes(full, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            long mtime = attrs.lastModifiedTime().toMillis() / 1000;
            int mode = mode(full, attrs.isDirectory());
            if (attrs.isSymbolicLink()) {
                entry(out, rel, '2', mode, mtime, new byte[0], Files.readSymbolicLink(full).toString());
            } else if (attrs.isDirectory()) {
                entry(out, rel + "/", '5', mode, mtime, new byte[0], "");
                walk(root, rel, out);
            } else if (attrs.isRegularFile()) {
                entry(out, rel, '0', mode, mtime, Files.readAllBytes(full), "");
            }
            // Devices, pipes and sockets are skipped: the sandbox refuses them.
        }
    }

    private static int mode(Path path, boolean dir) {
        try {
            Set<PosixFilePermission> perms = Files.readAttributes(path, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS).permissions();
            int mode = 0;
            for (PosixFilePermission perm : perms) {
                mode |= 1 << (8 - perm.ordinal());
            }
            return mode;
        } catch (UnsupportedOperationException | IOException ex) {
            return dir ? 0755 : 0644;
        }
    }

    static void entry(OutputStream out, String name, char typeflag, int mode, long mtime, byte[] data, String link) throws IOException {
        byte[] nameBytes = name.getBytes(StandardCharsets.UTF_8);
        byte[] linkBytes = link.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream records = new ByteArrayOutputStream();
        if (nameBytes.length > 100) {
            records.write(paxRecord("path", name));
        }
        if (linkBytes.length > 100) {
            records.write(paxRecord("linkpath", link));
        }
        if (records.size() > 0) {
            out.write(header("PaxHeader".getBytes(StandardCharsets.UTF_8), 'x', 0644, records.size(), mtime, new byte[0]));
            padded(out, records.toByteArray());
        }
        out.write(header(nameBytes, typeflag, mode, data.length, mtime, linkBytes));
        padded(out, data);
    }

    private static void padded(OutputStream out, byte[] data) throws IOException {
        out.write(data);
        int rest = data.length % BLOCK;
        if (rest != 0) {
            out.write(new byte[BLOCK - rest]);
        }
    }

    private static byte[] header(byte[] name, char typeflag, int mode, long size, long mtime, byte[] link) {
        byte[] block = new byte[BLOCK];
        put(block, 0, 100, name);
        octal(block, 100, 8, mode & 07777);
        octal(block, 108, 8, 0);
        octal(block, 116, 8, 0);
        octal(block, 124, 12, size);
        octal(block, 136, 12, mtime);
        java.util.Arrays.fill(block, 148, 156, (byte) ' ');
        block[156] = (byte) typeflag;
        put(block, 157, 100, link);
        put(block, 257, 6, "ustar\0".getBytes(StandardCharsets.US_ASCII));
        put(block, 263, 2, "00".getBytes(StandardCharsets.US_ASCII));
        int sum = 0;
        for (byte b : block) {
            sum += b & 0xff;
        }
        put(block, 148, 8, String.format("%06o\0 ", sum).getBytes(StandardCharsets.US_ASCII));
        return block;
    }

    private static void put(byte[] block, int offset, int length, byte[] value) {
        System.arraycopy(value, 0, block, offset, Math.min(length, value.length));
    }

    private static void octal(byte[] block, int offset, int length, long value) {
        String digits = Long.toOctalString(value);
        StringBuilder padded = new StringBuilder();
        for (int i = digits.length(); i < length - 1; i++) {
            padded.append('0');
        }
        put(block, offset, length - 1, padded.append(digits).toString().getBytes(StandardCharsets.US_ASCII));
    }

    /** A PAX record: "&lt;length&gt; &lt;key&gt;=&lt;value&gt;\n", the length counting itself. */
    static byte[] paxRecord(String key, String value) {
        int body = (" " + key + "=" + value + "\n").getBytes(StandardCharsets.UTF_8).length;
        int length = body + Integer.toString(body).length();
        if (Integer.toString(length).length() != Integer.toString(body).length()) {
            // Adding the digits made the number one digit longer (98 -> 100).
            length = body + Integer.toString(length).length();
        }
        return (length + " " + key + "=" + value + "\n").getBytes(StandardCharsets.UTF_8);
    }
}
