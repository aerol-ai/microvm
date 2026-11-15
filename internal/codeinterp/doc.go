// Package codeinterp is the stateful code interpreter shared by toolboxd
// (container and VM sandboxes) and the WASM driver (plans/code-interpreter.md).
//
// A context is one long-lived interpreter process (a Kernel) started by a
// small driver script. Code sent to a context runs in the same process, so
// variables survive between runs. Two wire adapters sit on top of a Manager:
// Daytona's WebSocket protocol (also used by the AerolVM SDKs, with opt-in
// extensions) and E2B's NDJSON protocol.
//
// # Driver protocol
//
// The driver protocol is deliberately language neutral so the Bash, R and
// Java drivers need no JSON parser. Every message is a frame:
//
//	KIND SP LEN LF <LEN bytes>
//
// where KIND is an upper-case word and LEN the payload length in bytes, in
// decimal. Requests go from the host to the driver, events come back.
//
// Requests:
//
//	ENV  "NAME=VALUE"   set for the next EXEC only (zero or more)
//	EXEC <code>         run code; the driver answers with events ending in DONE
//	QUIT ""             exit
//
// Events:
//
//	READY  <protocol version>       once, when the driver is ready
//	FATAL  <message>                startup failed (for example a bad cwd)
//	COUNT  <decimal>                execution count of the run that starts
//	OUT    <text> / ERR <text>      output, stdio mode only (see below)
//	RESULT <json {"data":{mime:value},"main":bool}>
//	TEXT   <text>                   shorthand for a main text/plain result
//	ERROR  name US value US traceback   (US is the 0x1f unit separator)
//	SYNC   <decimal seq>            see markers below
//	DONE   ok | error | interrupted
//
// There are two transport modes, picked by the AEROL_INTERP_MODE variable:
//
//   - "fd" (toolboxd): requests on file descriptor 3, events on 4. The
//     user's output goes to the process's real stdout and stderr (fd 1 and
//     2), which the host reads from pipes, so output from child processes is
//     captured too. To keep output ordered with results and errors, the
//     driver flushes, writes the marker RS NONCE ":" SEQ RS (RS is 0x1e,
//     NONCE comes from AEROL_INTERP_NONCE) to both fd 1 and fd 2, and then
//     sends SYNC SEQ. The host forwards every output byte before the two
//     markers before it handles the frames after SYNC. Drivers send SYNC
//     before every RESULT, TEXT, ERROR and DONE.
//   - "stdio" (WASM, which has no child processes and no extra
//     descriptors): requests on stdin, events on stdout, and the driver
//     wraps the user's output into OUT and ERR frames itself. No markers.
//     WASI has no working directory to inherit, so the launcher passes the
//     context's cwd in AEROL_INTERP_CWD and the driver enters it before
//     READY (FATAL when it cannot).
package codeinterp
