package ai.aerol.microvm;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import ai.aerol.microvm.internal.JsonSupport;

/** Fluent Dockerfile builder for image builds. */
public final class Image {
    private static final Pattern DOCKER_BARE_VALUE = Pattern.compile("^[A-Za-z0-9_\\-./:@]+$");

    private final StringBuilder dockerfile;

    private Image(String dockerfile) {
        this.dockerfile = new StringBuilder(dockerfile);
    }

    public static Image base(String image) {
        String trimmed = trimToNull(image);
        if (trimmed == null) {
            throw new IllegalArgumentException("Image.base requires a non-empty image string");
        }
        return new Image("FROM " + trimmed + "\n");
    }

    public static Image fromDockerfile(String dockerfile) {
        if (trimToNull(dockerfile) == null) {
            throw new IllegalArgumentException("Image.fromDockerfile requires a non-empty Dockerfile string");
        }
        return new Image(dockerfile.endsWith("\n") ? dockerfile : dockerfile + "\n");
    }

    public String getDockerfile() {
        return dockerfile.toString();
    }

    /** Each argument becomes its own RUN line. */
    public Image runCommands(String... commands) {
        for (String command : commands) {
            String trimmed = trimToNull(command);
            if (trimmed != null) {
                dockerfile.append("RUN ").append(trimmed).append('\n');
            }
        }
        return this;
    }

    /** A list argument is joined with && so the commands share one layer. */
    public Image runCommands(List<String> commands) {
        String joined = commands.stream()
            .map(Image::trimToNull)
            .filter(Objects::nonNull)
            .collect(Collectors.joining(" && "));
        if (!joined.isEmpty()) {
            dockerfile.append("RUN ").append(joined).append('\n');
        }
        return this;
    }

    public Image env(Map<String, String> envVars) {
        if (envVars == null || envVars.isEmpty()) {
            return this;
        }
        String joined = envVars.entrySet().stream()
            .sorted(Map.Entry.comparingByKey())
            .map(entry -> entry.getKey() + "=" + dockerQuote(entry.getValue()))
            .collect(Collectors.joining(" "));
        dockerfile.append("ENV ").append(joined).append('\n');
        return this;
    }

    public Image workdir(String dirPath) {
        if (trimToNull(dirPath) == null) {
            throw new IllegalArgumentException("Image.workdir requires a non-empty path");
        }
        dockerfile.append("WORKDIR ").append(dirPath).append('\n');
        return this;
    }

    public Image entrypoint(List<String> commands) {
        dockerfile.append("ENTRYPOINT ").append(JsonSupport.write(commands)).append('\n');
        return this;
    }

    public Image entrypoint(String... commands) {
        return entrypoint(Arrays.asList(commands));
    }

    public Image cmd(List<String> commands) {
        dockerfile.append("CMD ").append(JsonSupport.write(commands)).append('\n');
        return this;
    }

    public Image cmd(String... commands) {
        return cmd(Arrays.asList(commands));
    }

    public Image user(String username) {
        if (trimToNull(username) == null) {
            throw new IllegalArgumentException("Image.user requires a non-empty username");
        }
        dockerfile.append("USER ").append(username).append('\n');
        return this;
    }

    public Image expose(int port) {
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("Image.expose: port " + port + " is out of range");
        }
        dockerfile.append("EXPOSE ").append(port).append('\n');
        return this;
    }

    private static String dockerQuote(String value) {
        if (value != null && DOCKER_BARE_VALUE.matcher(value).matches()) {
            return value;
        }
        String safe = value == null ? "" : value.replace("\\", "\\\\").replace("\"", "\\\"");
        return '"' + safe + '"';
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}