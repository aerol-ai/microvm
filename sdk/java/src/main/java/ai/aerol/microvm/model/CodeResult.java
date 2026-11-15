package ai.aerol.microvm.model;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * One rich result of a run, in every format the interpreter offered: a
 * chart comes as {@link #png}, a pandas table as {@link #html} and
 * {@link #data}. Unset formats are null; {@link #formats()} lists the set ones.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CodeResult {
    public String text;
    public String html;
    public String markdown;
    public String svg;
    /** Base64-encoded PNG. */
    public String png;
    /** Base64-encoded JPEG. */
    public String jpeg;
    public String pdf;
    public String latex;
    public Map<String, Object> json;
    public String javascript;
    public Map<String, Object> data;
    /** Formats with no field of their own, keyed by MIME type. */
    public Map<String, Object> extra;
    /** True for the value of the run's last expression, as a notebook shows it. */
    public boolean isMainResult;

    /**
     * The formats this result has, in a fixed order (text, html, markdown,
     * svg, png, jpeg, pdf, latex, json, javascript, data), then the keys of
     * {@link #extra}, sorted.
     */
    public List<String> formats() {
        List<String> out = new ArrayList<>();
        addIf(out, "text", text);
        addIf(out, "html", html);
        addIf(out, "markdown", markdown);
        addIf(out, "svg", svg);
        addIf(out, "png", png);
        addIf(out, "jpeg", jpeg);
        addIf(out, "pdf", pdf);
        addIf(out, "latex", latex);
        if (json != null) {
            out.add("json");
        }
        addIf(out, "javascript", javascript);
        if (data != null) {
            out.add("data");
        }
        if (extra != null) {
            out.addAll(new TreeSet<>(extra.keySet()));
        }
        return out;
    }

    private static void addIf(List<String> out, String name, String value) {
        if (value != null && !value.isEmpty()) {
            out.add(name);
        }
    }

    @Override
    public String toString() {
        return "CodeResult{formats=" + formats() + ", isMainResult=" + isMainResult + "}";
    }
}
