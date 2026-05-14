/**
 * Image is a fluent Dockerfile builder. The shape mirrors the Daytona SDK's
 * Image API so examples port across by changing the import. The output is a
 * Dockerfile string accessible via `.dockerfile` — the SDK ships it to
 * `POST /v2/images/build` when an Image is passed to `MicroVM.create`.
 *
 * Caller-side context (COPY/ADD from local files) needs the
 * SB_IMAGE_BUILD_CONTEXT_ENABLED operator flag on the daemon. Without that,
 * use only `runCommands`, `env`, `workdir`, `entrypoint`, `cmd`, `user`, and
 * `expose` — every step they emit is RUN/ENV/WORKDIR/etc. against the base
 * image, no local files involved.
 */
export class Image {
  private _dockerfile = "";

  private constructor(dockerfile: string) {
    this._dockerfile = dockerfile;
  }

  get dockerfile(): string {
    return this._dockerfile;
  }

  /** Start a new image from `FROM <image>`. */
  static base(image: string): Image {
    if (typeof image !== "string" || image.trim() === "") {
      throw new TypeError("Image.base requires a non-empty image string");
    }
    return new Image(`FROM ${image.trim()}\n`);
  }

  /**
   * Build from a raw Dockerfile string. Use when you need full control
   * (multi-stage builds, ARG, ONBUILD, HEALTHCHECK, etc.) that the fluent
   * API doesn't expose. Caller is responsible for the Dockerfile validity.
   */
  static fromDockerfile(dockerfile: string): Image {
    if (typeof dockerfile !== "string" || dockerfile.trim() === "") {
      throw new TypeError("Image.fromDockerfile requires a non-empty Dockerfile string");
    }
    return new Image(dockerfile.endsWith("\n") ? dockerfile : dockerfile + "\n");
  }

  /**
   * Append one or more RUN steps. Each argument becomes its own RUN line;
   * an array argument is joined with `&&` so the commands share one layer.
   */
  runCommands(...commands: (string | string[])[]): Image {
    for (const entry of commands) {
      if (Array.isArray(entry)) {
        const joined = entry.map((c) => c.trim()).filter(Boolean).join(" && ");
        if (joined !== "") {
          this._dockerfile += `RUN ${joined}\n`;
        }
        continue;
      }
      const cmd = entry.trim();
      if (cmd !== "") {
        this._dockerfile += `RUN ${cmd}\n`;
      }
    }
    return this;
  }

  /** Append ENV K=V pairs (one ENV line per call, all vars on it). */
  env(envVars: Record<string, string>): Image {
    const parts = Object.entries(envVars).map(([k, v]) => `${k}=${dockerQuote(v)}`);
    if (parts.length > 0) {
      this._dockerfile += `ENV ${parts.join(" ")}\n`;
    }
    return this;
  }

  workdir(dirPath: string): Image {
    if (dirPath.trim() === "") {
      throw new TypeError("Image.workdir requires a non-empty path");
    }
    this._dockerfile += `WORKDIR ${dirPath}\n`;
    return this;
  }

  entrypoint(entrypointCommands: string[]): Image {
    this._dockerfile += `ENTRYPOINT ${jsonExecForm(entrypointCommands)}\n`;
    return this;
  }

  cmd(cmd: string[]): Image {
    this._dockerfile += `CMD ${jsonExecForm(cmd)}\n`;
    return this;
  }

  user(username: string): Image {
    if (username.trim() === "") {
      throw new TypeError("Image.user requires a non-empty username");
    }
    this._dockerfile += `USER ${username}\n`;
    return this;
  }

  expose(port: number): Image {
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new RangeError(`Image.expose: port ${port} is out of range`);
    }
    this._dockerfile += `EXPOSE ${port}\n`;
    return this;
  }
}

function dockerQuote(value: string): string {
  // Quote when the value contains whitespace or a special char; otherwise
  // leave bare to match canonical Dockerfile style.
  if (/^[A-Za-z0-9_\-./:@]+$/.test(value)) {
    return value;
  }
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function jsonExecForm(parts: string[]): string {
  return JSON.stringify(parts);
}
