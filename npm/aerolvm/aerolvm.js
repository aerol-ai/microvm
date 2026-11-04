#!/usr/bin/env node
// Launcher for the aerolvm binary. npm installs exactly one of the
// @aerol-ai/aerolvm-<platform>-<arch> optional dependencies (each declares
// its os and cpu), and this script runs the binary inside it with the
// caller's stdio, arguments and exit status.
//
// It must never write to stdout: under `aerolvm mcp` stdout is the MCP
// protocol stream, and one stray byte breaks the client. It must not read
// stdin either; the binary inherits it.
'use strict';

const { spawn } = require('node:child_process');
const { constants } = require('node:os');

function binaryPath() {
  const pkg = `@aerol-ai/aerolvm-${process.platform}-${process.arch}`;
  const exe = process.platform === 'win32' ? 'aerolvm.exe' : 'aerolvm';
  try {
    return require.resolve(`${pkg}/bin/${exe}`);
  } catch {
    process.stderr.write(
      `aerolvm: no prebuilt binary for ${process.platform}-${process.arch}: ${pkg} is not installed.\n` +
        'Binaries ship for linux, darwin and win32 on x64 and arm64. If npm ran with\n' +
        '--omit=optional, reinstall without it, or download the binary from\n' +
        'https://github.com/aerol-ai/microvm/releases\n',
    );
    process.exit(1);
  }
}

const child = spawn(binaryPath(), process.argv.slice(2), { stdio: 'inherit', windowsHide: true });

// A terminal's Ctrl-C already reaches the binary (same process group).
// Forwarding covers a signal sent to this launcher's pid alone, such as an
// MCP host's SIGTERM at shutdown, which would otherwise kill the launcher and
// leave the binary running. A duplicate SIGINT is harmless to aerolvm.
for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
  process.on(sig, () => child.kill(sig));
}

child.on('error', (err) => {
  process.stderr.write(`aerolvm: ${err.message}\n`);
  process.exit(1);
});

child.on('exit', (code, signal) => {
  process.exit(code ?? 128 + (constants.signals[signal] ?? 0));
});
