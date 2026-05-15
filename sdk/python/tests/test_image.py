import unittest

from microvm import Image


class ImageTests(unittest.TestCase):
    def test_base_emits_from_line(self):
        self.assertEqual(Image.base("ubuntu:22.04").dockerfile, "FROM ubuntu:22.04\n")

    def test_base_rejects_empty_image(self):
        with self.assertRaisesRegex(TypeError, "non-empty"):
            Image.base("")
        with self.assertRaisesRegex(TypeError, "non-empty"):
            Image.base("   ")

    def test_run_commands_and_directives_emit_expected_lines(self):
        image = (
            Image.base("alpine")
            .run_commands("apk add curl", ["apk add bash", "echo ready"])
            .env({"FOO": "bar", "PATH": "/opt/bin:/usr/bin"})
            .workdir("/app")
            .user("nobody")
            .expose(8080)
            .entrypoint(["/bin/sh", "-c"])
            .cmd(["echo", "hi"])
        )
        self.assertEqual(
            image.dockerfile,
            "FROM alpine\n"
            "RUN apk add curl\n"
            "RUN apk add bash && echo ready\n"
            "ENV FOO=bar PATH=/opt/bin:/usr/bin\n"
            "WORKDIR /app\n"
            "USER nobody\n"
            "EXPOSE 8080\n"
            'ENTRYPOINT ["/bin/sh","-c"]\n'
            'CMD ["echo","hi"]\n',
        )

    def test_from_dockerfile_normalizes_trailing_newline(self):
        image = Image.from_dockerfile("FROM alpine\nRUN echo hi")
        self.assertEqual(image.dockerfile, "FROM alpine\nRUN echo hi\n")

    def test_expose_rejects_out_of_range_ports(self):
        with self.assertRaisesRegex(ValueError, "out of range"):
            Image.base("alpine").expose(0)
        with self.assertRaisesRegex(ValueError, "out of range"):
            Image.base("alpine").expose(70000)


if __name__ == "__main__":
    unittest.main()