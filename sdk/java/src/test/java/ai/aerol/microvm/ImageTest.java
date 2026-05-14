package ai.aerol.microvm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class ImageTest {
    @Test
    void baseEmitsFromLine() {
        assertEquals("FROM ubuntu:22.04\n", Image.base("ubuntu:22.04").getDockerfile());
    }

    @Test
    void runCommandsAndDirectivesEmitExpectedLines() {
        Image image = Image.base("alpine")
            .runCommands("apk add curl")
            .runCommands(List.of("apk add bash", "echo ready"))
            .env(Map.of("FOO", "bar", "PATH", "/opt/bin:/usr/bin"))
            .workdir("/app")
            .user("nobody")
            .expose(8080)
            .entrypoint("/bin/sh", "-c")
            .cmd("echo", "hi");

        assertEquals(
            "FROM alpine\n"
                + "RUN apk add curl\n"
                + "RUN apk add bash && echo ready\n"
                + "ENV FOO=bar PATH=/opt/bin:/usr/bin\n"
                + "WORKDIR /app\n"
                + "USER nobody\n"
                + "EXPOSE 8080\n"
                + "ENTRYPOINT [\"/bin/sh\",\"-c\"]\n"
                + "CMD [\"echo\",\"hi\"]\n",
            image.getDockerfile()
        );
    }

    @Test
    void fromDockerfileNormalizesTrailingNewline() {
        assertEquals(
            "FROM alpine\nRUN echo hi\n",
            Image.fromDockerfile("FROM alpine\nRUN echo hi").getDockerfile()
        );
    }

    @Test
    void invalidInputsRaise() {
        assertTrue(assertThrows(IllegalArgumentException.class, () -> Image.base("   ")).getMessage().contains("non-empty"));
        assertTrue(assertThrows(IllegalArgumentException.class, () -> Image.fromDockerfile("   ")).getMessage().contains("non-empty"));
        assertTrue(assertThrows(IllegalArgumentException.class, () -> Image.base("alpine").workdir(" ")).getMessage().contains("non-empty"));
        assertTrue(assertThrows(IllegalArgumentException.class, () -> Image.base("alpine").user(" ")).getMessage().contains("non-empty"));
        assertTrue(assertThrows(IllegalArgumentException.class, () -> Image.base("alpine").expose(0)).getMessage().contains("out of range"));
        assertTrue(assertThrows(IllegalArgumentException.class, () -> Image.base("alpine").expose(70000)).getMessage().contains("out of range"));
    }
}