import assert from "node:assert/strict";
import test from "node:test";

import { Image } from "./Image.js";

test("Image.base emits a FROM line", () => {
  assert.equal(Image.base("ubuntu:22.04").dockerfile, "FROM ubuntu:22.04\n");
});

test("Image.base rejects empty image", () => {
  assert.throws(() => Image.base(""), /non-empty/);
  assert.throws(() => Image.base("   "), /non-empty/);
});

test("runCommands appends one RUN per string argument", () => {
  const image = Image.base("ubuntu").runCommands("apt-get update", "apt-get install -y curl");
  assert.equal(
    image.dockerfile,
    "FROM ubuntu\nRUN apt-get update\nRUN apt-get install -y curl\n",
  );
});

test("runCommands joins array argument with && in a single RUN", () => {
  const image = Image.base("alpine").runCommands(["apk add curl", "apk add bash"]);
  assert.equal(image.dockerfile, "FROM alpine\nRUN apk add curl && apk add bash\n");
});

test("env emits a single ENV with all pairs", () => {
  const image = Image.base("alpine").env({ FOO: "bar", PATH: "/opt/bin:/usr/bin" });
  assert.equal(
    image.dockerfile,
    'FROM alpine\nENV FOO=bar PATH=/opt/bin:/usr/bin\n',
  );
});

test("env quotes values that contain whitespace", () => {
  const image = Image.base("alpine").env({ MSG: "hello world" });
  assert.equal(image.dockerfile, 'FROM alpine\nENV MSG="hello world"\n');
});

test("workdir, entrypoint, cmd, user, expose all emit correct lines", () => {
  const image = Image.base("alpine")
    .workdir("/app")
    .user("nobody")
    .expose(8080)
    .entrypoint(["/bin/sh", "-c"])
    .cmd(["echo", "hi"]);
  assert.equal(
    image.dockerfile,
    [
      "FROM alpine",
      "WORKDIR /app",
      "USER nobody",
      "EXPOSE 8080",
      'ENTRYPOINT ["/bin/sh","-c"]',
      'CMD ["echo","hi"]',
      "",
    ].join("\n"),
  );
});

test("fromDockerfile accepts raw Dockerfile and normalizes trailing newline", () => {
  const image = Image.fromDockerfile("FROM alpine\nRUN echo hi");
  assert.equal(image.dockerfile, "FROM alpine\nRUN echo hi\n");
});

test("expose rejects out-of-range ports", () => {
  assert.throws(() => Image.base("alpine").expose(0), RangeError);
  assert.throws(() => Image.base("alpine").expose(70000), RangeError);
});
