# @aerol-ai/aerolvm

`aerolvm` drives [AerolVM](https://github.com/aerol-ai/microvm) sandboxes from a
terminal, a script or an AI agent. The same binary is a CLI and an MCP server.

```sh
npx -y @aerol-ai/aerolvm login https://sandbox.example.com   # asks for your token once
npx -y @aerol-ai/aerolvm shell build-box     # an interactive shell in a sandbox
npx -y @aerol-ai/aerolvm exec build-box -- python -V
```

Run it as an MCP server over stdio:

```sh
npx -y @aerol-ai/aerolvm mcp
```

`aerolvm mcp config <claude-code|claude-desktop|cursor|vscode>` prints the
setup snippet for each client. `aerolvm --help` lists every command.

This package is a small Node launcher. npm installs the prebuilt binary for
your platform from one of the `@aerol-ai/aerolvm-<platform>-<arch>` packages
(linux, darwin and win32 on x64 and arm64). To skip Node entirely, install the
binary with `install.sh --cli-only` or download it from the
[releases page](https://github.com/aerol-ai/microvm/releases).
