// AerolVM code interpreter driver for Java (JShell).
//
// One process is one context: a JShell whose snippets run in this JVM (the
// "local" execution engine). It speaks the frame protocol in
// internal/codeinterp/doc.go, "fd" mode only (toolboxd). Run as a
// single-file source program: java java_driver.java. Needs JDK 11 or newer
// with the jdk.jshell module; standard library only.
//
// The local engine is used because user output then goes straight to this
// process's stdout and stderr, so a flush before the markers orders it
// against results. The default engine runs snippets in a second JVM and
// relays its output over a socket, where no flush can order it.
//
// Written for AerolVM (MIT). No code is taken from Daytona or E2B.

import java.io.ByteArrayOutputStream;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

import jdk.jshell.DeclarationSnippet;
import jdk.jshell.Diag;
import jdk.jshell.EvalException;
import jdk.jshell.JShell;
import jdk.jshell.JShellException;
import jdk.jshell.Snippet;
import jdk.jshell.SnippetEvent;
import jdk.jshell.SourceCodeAnalysis;
import jdk.jshell.UnresolvedReferenceException;

public class AerolJavaDriver {
    static final String PROTOCOL_VERSION = "1";
    static final char US = 0x1f;
    // The host refuses frames over 32 MiB (codeinterp.MaxFramePayload).
    static final int MAX_RESULT = 16 << 20;
    static final int MAX_ERROR = 1 << 20;

    // The jshell tool's default imports: code written for jshell expects
    // List, Files or Stream without importing them.
    static final String[] DEFAULT_IMPORTS = {
        "import java.io.*;",
        "import java.math.*;",
        "import java.net.*;",
        "import java.nio.file.*;",
        "import java.util.*;",
        "import java.util.concurrent.*;",
        "import java.util.function.*;",
        "import java.util.prefs.*;",
        "import java.util.regex.*;",
        "import java.util.stream.*;",
    };

    static InputStream req;
    static OutputStream ev;
    // Unbuffered writers on fd 1 and 2 for the markers; user code may
    // replace System.out, never these.
    static final OutputStream rawOut = new FileOutputStream(FileDescriptor.out);
    static final OutputStream rawErr = new FileOutputStream(FileDescriptor.err);
    static final PrintStream origOut = System.out;
    static final PrintStream origErr = System.err;
    static String nonce = "";
    static long seq = 0;
    static int count = 0;
    static JShell shell;

    // running: a cell is between COUNT and DONE. interrupted: SIGINT came
    // during it. inEval: JShell is evaluating a snippet now.
    static final Object lock = new Object();
    static boolean running = false;
    static volatile boolean interrupted = false;
    static volatile boolean inEval = false;

    // ------------------------------------------------------------ frames

    static synchronized void emit(String kind, String payload) throws IOException {
        byte[] body = payload.getBytes(StandardCharsets.UTF_8);
        byte[] head = (kind + " " + body.length + "\n").getBytes(StandardCharsets.US_ASCII);
        byte[] frame = new byte[head.length + body.length];
        System.arraycopy(head, 0, frame, 0, head.length);
        System.arraycopy(body, 0, frame, head.length, body.length);
        ev.write(frame);
        ev.flush();
    }

    static void flushUser() {
        for (PrintStream s : new PrintStream[] {System.out, System.err, origOut, origErr}) {
            try {
                s.flush();
            } catch (RuntimeException e) {
                // A user stream that fails to flush must not stop the run.
            }
        }
    }

    // sync orders the user's output before the next frame (doc.go).
    static void sync() throws IOException {
        flushUser();
        seq++;
        byte[] mark = ("\u001e" + nonce + ":" + seq + "\u001e").getBytes(StandardCharsets.UTF_8);
        for (OutputStream o : new OutputStream[] {rawOut, rawErr}) {
            try {
                o.write(mark);
            } catch (IOException e) {
                // The user closed it; the host then sees the pipe end instead.
            }
        }
        emit("SYNC", Long.toString(seq));
    }

    static final class Frame {
        final String kind;
        final byte[] payload;

        Frame(String kind, byte[] payload) {
            this.kind = kind;
            this.payload = payload;
        }
    }

    // readFrame returns the next request, or null at the end of the stream.
    static Frame readFrame() throws IOException {
        ByteArrayOutputStream header = new ByteArrayOutputStream();
        for (;;) {
            int b = req.read();
            if (b < 0) return null;
            if (b == '\n') break;
            header.write(b);
        }
        String h = header.toString(StandardCharsets.US_ASCII.name());
        int sp = h.indexOf(' ');
        if (sp <= 0) return null;
        int n;
        try {
            n = Integer.parseInt(h.substring(sp + 1));
        } catch (NumberFormatException e) {
            return null;
        }
        if (n < 0) return null;
        byte[] payload = new byte[n];
        int off = 0;
        while (off < n) {
            int r = req.read(payload, off, n - off);
            if (r < 0) return null;
            off += r;
        }
        return new Frame(h.substring(0, sp), payload);
    }

    // ------------------------------------------------------- environment

    // The JVM's environment map, made writable by reflection (it needs the
    // --add-opens the launcher passes). Null when this JDK keeps it away:
    // a run's variables then reach System properties only.
    static Map<String, String> writableEnv() {
        try {
            Map<String, String> env = System.getenv();
            Field f = env.getClass().getDeclaredField("m");
            f.setAccessible(true);
            @SuppressWarnings("unchecked")
            Map<String, String> m = (Map<String, String>) f.get(env);
            return m;
        } catch (ReflectiveOperationException | RuntimeException e) {
            return null;
        }
    }

    static final Map<String, String> ENV = writableEnv();

    static final class Saved {
        final String prop;
        final String env;

        Saved(String prop, String env) {
            this.prop = prop;
            this.env = env;
        }
    }

    static void setOrClear(String name, String prop, String env) {
        if (prop == null) System.clearProperty(name);
        else System.setProperty(name, prop);
        if (ENV != null) {
            try {
                if (env == null) ENV.remove(name);
                else ENV.put(name, env);
            } catch (RuntimeException e) {
                // A name the platform environment refuses.
            }
        }
    }

    // A run's variables go to System.getenv and, as a notebook's Java
    // kernel does it, to System properties. A child process gets them only
    // through ProcessBuilder.environment(): without it, Java hands the
    // child the JVM's native environment, which pure Java cannot change.
    static Map<String, Saved> applyEnv(List<String> pairs) {
        Map<String, Saved> saved = new LinkedHashMap<>();
        for (String pair : pairs) {
            int eq = pair.indexOf('=');
            if (eq <= 0) continue;
            String name = pair.substring(0, eq);
            if (!saved.containsKey(name)) {
                saved.put(name, new Saved(System.getProperty(name), System.getenv(name)));
            }
            String value = pair.substring(eq + 1);
            setOrClear(name, value, value);
        }
        return saved;
    }

    static void restoreEnv(Map<String, Saved> saved) {
        for (Map.Entry<String, Saved> e : saved.entrySet()) {
            setOrClear(e.getKey(), e.getValue().prop, e.getValue().env);
        }
    }

    // ------------------------------------------------------------- errors

    static String simpleName(String className) {
        int dot = className.lastIndexOf('.');
        return dot < 0 ? className : className.substring(dot + 1);
    }

    static String clip(String s, boolean tail) {
        if (s.length() <= MAX_ERROR) return s;
        return tail ? s.substring(s.length() - MAX_ERROR) : s.substring(0, MAX_ERROR);
    }

    static String errorPayload(String name, String value, String traceback) {
        return name + US + clip(value == null ? "" : value, false) + US + clip(traceback, true);
    }

    // stackText renders an exception like Throwable.printStackTrace, with
    // the snippet frames JShell already rewrote to "#id:line".
    static String stackText(JShellException e, String className) {
        StringBuilder sb = new StringBuilder(className);
        if (e.getMessage() != null) sb.append(": ").append(e.getMessage());
        for (StackTraceElement st : e.getStackTrace()) {
            String cls = st.getClassName();
            // Below the snippet is this driver and JShell's machinery.
            if (cls.startsWith("jdk.jshell.") || cls.startsWith("jdk.internal.reflect.")
                    || cls.startsWith("java.lang.reflect.") || cls.equals(AerolJavaDriver.class.getName())) {
                break;
            }
            sb.append("\n\tat ").append(st);
        }
        Throwable cause = e.getCause();
        if (cause instanceof EvalException) {
            EvalException c = (EvalException) cause;
            sb.append("\nCaused by: ").append(stackText(c, c.getExceptionClassName()));
        }
        return sb.toString();
    }

    static String exceptionPayload(JShellException e) {
        if (e instanceof EvalException) {
            String cls = ((EvalException) e).getExceptionClassName();
            return errorPayload(simpleName(cls), e.getMessage(), stackText(e, cls));
        }
        if (e instanceof UnresolvedReferenceException) {
            DeclarationSnippet s = ((UnresolvedReferenceException) e).getSnippet();
            String missing = shell.unresolvedDependencies(s).collect(Collectors.joining(", "));
            String msg = "attempted to use " + s.source().trim() + " which cannot be used until "
                    + missing + " is declared";
            return errorPayload("UnresolvedReferenceException", msg, msg);
        }
        return errorPayload(simpleName(e.getClass().getName()), e.getMessage(), stackText(e, e.getClass().getName()));
    }

    // compilePayload is the jshell tool's view of a rejected snippet: each
    // diagnostic with the line it points at and a caret under the span.
    static String compilePayload(Snippet s) {
        List<String> messages = new ArrayList<>();
        StringBuilder tb = new StringBuilder();
        String src = s.source();
        for (Diag d : shell.diagnostics(s).collect(Collectors.toList())) {
            String msg = d.getMessage(Locale.ROOT);
            messages.add(msg);
            if (tb.length() > 0) tb.append('\n');
            tb.append(d.isError() ? "Error: " : "Warning: ").append(msg);
            long start = d.getStartPosition();
            if (start >= 0 && start <= src.length()) {
                int lineStart = src.lastIndexOf('\n', (int) Math.max(0, start - 1)) + 1;
                if (start == 0) lineStart = 0;
                int lineEnd = src.indexOf('\n', (int) start);
                if (lineEnd < 0) lineEnd = src.length();
                long end = Math.max(start + 1, Math.min(d.getEndPosition(), lineEnd));
                tb.append('\n').append(src, lineStart, lineEnd).append('\n');
                for (long i = lineStart; i < start; i++) tb.append(src.charAt((int) i) == '\t' ? '\t' : ' ');
                for (long i = start; i < end; i++) tb.append('^');
            }
        }
        if (messages.isEmpty()) messages.add("the snippet does not compile");
        return errorPayload("CompilationError", String.join("\n", messages), tb.toString());
    }

    // -------------------------------------------------------------- runs

    static boolean shows(Snippet s) {
        switch (s.kind()) {
            case EXPRESSION:
                return true;
            case VAR:
                return s.subKind() == Snippet.SubKind.TEMP_VAR_EXPRESSION_SUBKIND;
            default:
                return false;
        }
    }

    // runCell evaluates the cell snippet by snippet and returns the status.
    static String runCell(String code) throws IOException {
        SourceCodeAnalysis sca = shell.sourceCodeAnalysis();
        String remaining = code;
        String value = null;
        while (!remaining.trim().isEmpty()) {
            if (interrupted) return "interrupted";
            SourceCodeAnalysis.CompletionInfo ci = sca.analyzeCompletion(remaining);
            String src;
            switch (ci.completeness()) {
                case EMPTY:
                    return finishCell(value);
                case COMPLETE:
                case COMPLETE_WITH_SEMI:
                case UNKNOWN:
                    src = ci.source() != null ? ci.source() : remaining;
                    remaining = ci.remaining() != null ? ci.remaining() : "";
                    break;
                default:
                    // Incomplete: evaluating it gives the compiler's error.
                    src = remaining;
                    remaining = "";
            }
            value = null;
            List<SnippetEvent> events;
            inEval = true;
            try {
                events = shell.eval(src);
            } finally {
                inEval = false;
            }
            if (interrupted) return "interrupted";
            for (SnippetEvent e : events) {
                if (e.causeSnippet() != null) continue;
                Snippet s = e.snippet();
                if (e.status() == Snippet.Status.REJECTED) {
                    String payload = compilePayload(s);
                    sync();
                    emit("ERROR", payload);
                    return "error";
                }
                if (e.exception() != null) {
                    String payload = exceptionPayload(e.exception());
                    sync();
                    emit("ERROR", payload);
                    return "error";
                }
                if (shows(s) && e.value() != null && !"void".equals(typeName(s))) {
                    value = e.value();
                }
            }
        }
        return finishCell(value);
    }

    static String typeName(Snippet s) {
        if (s instanceof jdk.jshell.ExpressionSnippet) return ((jdk.jshell.ExpressionSnippet) s).typeName();
        if (s instanceof jdk.jshell.VarSnippet) return ((jdk.jshell.VarSnippet) s).typeName();
        return "";
    }

    // finishCell sends the last snippet's value as the main result.
    static String finishCell(String value) throws IOException {
        if (value != null) {
            if (value.length() > MAX_RESULT / 4) value = value.substring(0, MAX_RESULT / 8) + "\n... [truncated]";
            sync();
            emit("TEXT", value);
        }
        return "ok";
    }

    static void execute(String code, List<String> pairs) throws IOException {
        Map<String, Saved> saved;
        synchronized (lock) {
            count++;
            interrupted = false;
            running = true;
            saved = applyEnv(pairs);
        }
        emit("COUNT", Integer.toString(count));
        String status;
        try {
            status = runCell(code);
        } catch (RuntimeException e) {
            // JShell itself failed (an internal error): the run's error, and
            // the context lives on.
            status = "error";
            String payload = errorPayload(e.getClass().getSimpleName(), String.valueOf(e.getMessage()), e.toString());
            sync();
            emit("ERROR", payload);
        } finally {
            synchronized (lock) {
                running = false;
                restoreEnv(saved);
            }
        }
        if (interrupted) status = "interrupted";
        sync();
        emit("DONE", status);
    }

    // onInterrupt runs on the JVM's signal thread. stop() only reaches
    // user code that is executing, so a SIGINT that lands while JShell
    // still compiles the snippet is retried until the snippet ends.
    static void onInterrupt() {
        synchronized (lock) {
            // Between runs a stray SIGINT must not end the context (the
            // JVM's default) and is otherwise ignored.
            if (!running || interrupted) return;
            interrupted = true;
        }
        Thread t = new Thread(() -> {
            while (interrupted && running) {
                if (inEval) shell.stop();
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    return;
                }
            }
        }, "aerol-interrupt");
        t.setDaemon(true);
        t.start();
    }

    // installSigint uses sun.misc.Signal (module jdk.unsupported) through
    // reflection, so a JDK without it still starts, only without interrupts.
    static void installSigint() {
        try {
            Class<?> signal = Class.forName("sun.misc.Signal");
            Class<?> handlerType = Class.forName("sun.misc.SignalHandler");
            Object handler = Proxy.newProxyInstance(handlerType.getClassLoader(), new Class<?>[] {handlerType},
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "handle":
                            onInterrupt();
                            return null;
                        case "hashCode":
                            return System.identityHashCode(proxy);
                        case "equals":
                            return proxy == args[0];
                        default:
                            return "aerol-sigint";
                    }
                });
            Object sigint = signal.getConstructor(String.class).newInstance("INT");
            signal.getMethod("handle", signal, handlerType).invoke(null, sigint, handler);
        } catch (ReflectiveOperationException | RuntimeException | LinkageError e) {
            System.err.println("aerolvm interpreter driver: interrupts unavailable: " + e);
        }
    }

    static void serve() throws IOException {
        List<String> env = new ArrayList<>();
        for (;;) {
            Frame f = readFrame();
            if (f == null || f.kind.equals("QUIT")) return;
            String payload = new String(f.payload, StandardCharsets.UTF_8);
            if (f.kind.equals("ENV")) {
                env.add(payload);
            } else if (f.kind.equals("EXEC")) {
                List<String> pairs = env;
                env = new ArrayList<>();
                execute(payload, pairs);
            }
        }
    }

    static void fatal(String message) {
        if (ev != null) {
            try {
                emit("FATAL", message);
            } catch (IOException e) {
                // Nobody to tell but stderr.
            }
        }
        origErr.println("aerolvm interpreter driver: " + message);
        origErr.flush();
        Runtime.getRuntime().halt(1);
    }

    public static void main(String[] args) {
        if (!"fd".equals(System.getenv("AEROL_INTERP_MODE"))) {
            System.err.println("aerolvm interpreter driver: java runs only in fd mode");
            System.exit(1);
        }
        nonce = System.getenv("AEROL_INTERP_NONCE");
        if (nonce == null) nonce = "";
        try {
            // Without the host's pipes, the JVM's own files (its module
            // image) may sit on 3 and 4.
            java.nio.file.Path fd3 = java.nio.file.Paths.get("/dev/fd/3");
            if (!java.nio.file.Files.exists(fd3) || java.nio.file.Files.isRegularFile(fd3)
                    || java.nio.file.Files.isDirectory(fd3)) {
                throw new IOException("fd 3 is not a pipe");
            }
            ev = new FileOutputStream("/dev/fd/4");
            req = new java.io.BufferedInputStream(new FileInputStream("/dev/fd/3"), 1 << 16);
        } catch (IOException e) {
            System.err.println("aerolvm interpreter driver: protocol descriptors 3 and 4 are not open: " + e);
            System.exit(1);
        }
        if (ENV != null) {
            ENV.remove("AEROL_INTERP_MODE");
            ENV.remove("AEROL_INTERP_NONCE");
        }
        try {
            shell = JShell.builder().executionEngine("local").build();
            // Warm the compiler up before READY: the first snippet costs
            // seconds, which belong to the launch, not the first run.
            for (String imp : DEFAULT_IMPORTS) {
                for (SnippetEvent e : shell.eval(imp)) {
                    if (e.status() == Snippet.Status.REJECTED) {
                        fatal("jshell rejected " + imp);
                    }
                }
            }
        } catch (RuntimeException | LinkageError e) {
            fatal("jshell failed to start: " + e);
        }
        installSigint();
        try {
            emit("READY", PROTOCOL_VERSION);
            serve();
        } catch (IOException e) {
            fatal(e.toString());
        }
        flushUser();
        Runtime.getRuntime().halt(0);
    }
}
