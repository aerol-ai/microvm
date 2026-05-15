from __future__ import annotations

import json
import re
from typing import Mapping, Sequence, Union


_DOCKER_BARE_VALUE = re.compile(r"^[A-Za-z0-9_\-./:@]+$")


class Image:
    """Fluent Dockerfile builder for MicroVM image builds."""

    def __init__(self, dockerfile: str) -> None:
        self._dockerfile = dockerfile

    @property
    def dockerfile(self) -> str:
        return self._dockerfile

    @staticmethod
    def base(image: str) -> "Image":
        if not isinstance(image, str) or image.strip() == "":
            raise TypeError("Image.base requires a non-empty image string")
        return Image(f"FROM {image.strip()}\n")

    @staticmethod
    def from_dockerfile(dockerfile: str) -> "Image":
        if not isinstance(dockerfile, str) or dockerfile.strip() == "":
            raise TypeError("Image.from_dockerfile requires a non-empty Dockerfile string")
        return Image(dockerfile if dockerfile.endswith("\n") else dockerfile + "\n")

    def run_commands(self, *commands: Union[str, Sequence[str]]) -> "Image":
        for entry in commands:
            if isinstance(entry, str):
                command = entry.strip()
                if command != "":
                    self._dockerfile += f"RUN {command}\n"
                continue

            if isinstance(entry, (list, tuple)):
                joined = " && ".join(item.strip() for item in entry if isinstance(item, str) and item.strip() != "")
                if joined != "":
                    self._dockerfile += f"RUN {joined}\n"
                continue

            raise TypeError(f"Image.run_commands accepts str or sequence[str], got {type(entry)!r}")

        return self

    def env(self, env_vars: Mapping[str, str]) -> "Image":
        parts = [f"{key}={_docker_quote(value)}" for key, value in env_vars.items()]
        if parts:
            self._dockerfile += f"ENV {' '.join(parts)}\n"
        return self

    def workdir(self, dir_path: str) -> "Image":
        if not isinstance(dir_path, str) or dir_path.strip() == "":
            raise TypeError("Image.workdir requires a non-empty path")
        self._dockerfile += f"WORKDIR {dir_path}\n"
        return self

    def entrypoint(self, entrypoint_commands: Sequence[str]) -> "Image":
        self._dockerfile += f"ENTRYPOINT {_json_exec_form(entrypoint_commands)}\n"
        return self

    def cmd(self, command: Sequence[str]) -> "Image":
        self._dockerfile += f"CMD {_json_exec_form(command)}\n"
        return self

    def user(self, username: str) -> "Image":
        if not isinstance(username, str) or username.strip() == "":
            raise TypeError("Image.user requires a non-empty username")
        self._dockerfile += f"USER {username}\n"
        return self

    def expose(self, port: int) -> "Image":
        if not isinstance(port, int) or port < 1 or port > 65535:
            raise ValueError(f"Image.expose: port {port} is out of range")
        self._dockerfile += f"EXPOSE {port}\n"
        return self


def _docker_quote(value: str) -> str:
    if _DOCKER_BARE_VALUE.match(value):
        return value
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _json_exec_form(parts: Sequence[str]) -> str:
    return json.dumps(list(parts), separators=(",", ":"))