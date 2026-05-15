# Daytona Toolbox Matrix

These tables describe the current toolbox compatibility surface exposed through `/daytona/toolbox/{sandboxId}`.

## General and process routes

| Daytona toolbox route or capability | Status | AerolVM mapping | Notes |
|---|---|---|---|
| `GET /daytona/toolbox/{id}` | Supported | Proxies toolbox root | Basic toolbox identity/version entry point. |
| `GET /daytona/toolbox/{id}/health` | Supported | Proxies toolbox health | Native toolbox health check. |
| `GET /daytona/toolbox/{id}/version` | Supported | Proxies toolbox version | Native toolbox version response. |
| `GET /daytona/toolbox/{id}/user-home-dir` | Supported | Implemented via shell lookup | Compatibility helper on top of toolbox exec. |
| `GET /daytona/toolbox/{id}/workdir` | Supported | Implemented via shell lookup | Compatibility helper on top of toolbox exec. |
| `POST /daytona/toolbox/{id}/process/execute` | Supported | Maps onto native toolbox exec | One-shot command execution. |
| `POST /daytona/toolbox/{id}/process/session` | Supported | Maps onto native toolbox session manager | Creates or reuses a named non-PTY session. |
| `GET /daytona/toolbox/{id}/process/session` | Supported | Facade over native toolbox session manager | Lists tracked Daytona-compatible sessions. |
| `GET /daytona/toolbox/{id}/process/session/{sessionId}` | Supported | Facade over native toolbox session manager | Returns Daytona-shaped session view. |
| `DELETE /daytona/toolbox/{id}/process/session/{sessionId}` | Supported | Maps onto native toolbox session delete | Deletes the backing session and Daytona compatibility state. |
| `POST /daytona/toolbox/{id}/process/session/{sessionId}/exec` | Partial | Runs commands inside a persistent shell session | Commands are serialized per session and do not fully reproduce Daytona's richer command lifecycle. |
| `GET /daytona/toolbox/{id}/process/session/{sessionId}/command/{commandId}` | Partial | Reads facade-maintained command state | Works only for commands executed through the compatibility layer. |
| `GET /daytona/toolbox/{id}/process/session/{sessionId}/command/{commandId}/logs` | Partial | Reads facade-maintained command logs | Works only for commands executed through the compatibility layer. |
| `POST /daytona/toolbox/{id}/process/session/{sessionId}/command/{commandId}/input` | Unsupported | No mapping | Interactive command input is not implemented. |
| `GET /daytona/toolbox/{id}/process/session/entrypoint` | Unsupported | No mapping | Entry-point session compatibility is not implemented. |
| `GET /daytona/toolbox/{id}/process/session/entrypoint/logs` | Unsupported | No mapping | Entry-point session log compatibility is not implemented. |
| PTY session routes | Unsupported | No Daytona PTY facade yet | Native toolbox has sessions, but Daytona PTY endpoints are not mapped. |
| Code-run or interpreter routes | Unsupported | No mapping | No Daytona code interpreter facade exists. |

## File-system routes

| Daytona toolbox route or capability | Status | AerolVM mapping | Notes |
|---|---|---|---|
| `GET /daytona/toolbox/{id}/files` | Supported | Native toolbox file listing | Lists directory contents. |
| `GET /daytona/toolbox/{id}/files/info` | Supported | Native toolbox file stat helper | Returns file metadata in Daytona shape. |
| `POST /daytona/toolbox/{id}/files/upload` | Supported | Native toolbox upload | Single-file upload. |
| `GET /daytona/toolbox/{id}/files/download` | Supported | Native toolbox download | Single-file download. |
| `POST /daytona/toolbox/{id}/files/move` | Supported | Native toolbox move helper | Move or rename using query parameters. |
| `GET /daytona/toolbox/{id}/files/search` | Supported | Native toolbox filename search helper | Pattern-based recursive filename search. |
| `GET /daytona/toolbox/{id}/files/find` | Supported | Native toolbox text search helper | Recursive text search across files. |
| `POST /daytona/toolbox/{id}/files/bulk-upload` | Supported | Facade helper over native single-file upload | Multipart compatibility helper. |
| `POST /daytona/toolbox/{id}/files/bulk-download` | Supported | Facade helper over native single-file download | Multipart compatibility helper. |
| `POST /daytona/toolbox/{id}/files/replace` | Unsupported | No mapping | No Daytona replace-in-files facade exists. |
| `POST /daytona/toolbox/{id}/files/folder` | Unsupported | No mapping | Folder-create alias is not implemented. |
| `DELETE /daytona/toolbox/{id}/files` | Unsupported | No mapping | Daytona delete-file route is not implemented. |
| `POST /daytona/toolbox/{id}/files/permissions` | Unsupported | No mapping | Permission and ownership updates are not implemented. |

## Git routes

| Daytona toolbox route or capability | Status | AerolVM mapping | Notes |
|---|---|---|---|
| `POST /daytona/toolbox/{id}/git/add` | Supported | Native toolbox git CLI wrapper | Stages specific files. |
| `POST /daytona/toolbox/{id}/git/checkout` | Supported | Native toolbox git CLI wrapper | Branch or commit checkout. |
| `POST /daytona/toolbox/{id}/git/clone` | Supported | Native toolbox git CLI wrapper | Clone plus optional branch and commit checkout. |
| `POST /daytona/toolbox/{id}/git/commit` | Supported | Native toolbox git CLI wrapper | Commit with supplied author, email, and message. |
| `GET /daytona/toolbox/{id}/git/branches` | Supported | Native toolbox git CLI wrapper | Lists branches. |
| `POST /daytona/toolbox/{id}/git/branches` | Supported | Native toolbox git CLI wrapper | Creates a branch. |
| `DELETE /daytona/toolbox/{id}/git/branches` | Supported | Native toolbox git CLI wrapper | Deletes a branch. |
| `GET /daytona/toolbox/{id}/git/history` | Supported | Native toolbox git CLI wrapper | Returns commit history in Daytona-shaped JSON. |
| `GET /daytona/toolbox/{id}/git/status` | Supported | Native toolbox git CLI wrapper | Returns Daytona-shaped git status. |
| `POST /daytona/toolbox/{id}/git/pull` | Unsupported | No mapping | Remote sync is not implemented. |
| `POST /daytona/toolbox/{id}/git/push` | Unsupported | No mapping | Remote sync is not implemented. |

## Larger toolbox gaps

| Daytona area | Status | Gap |
|---|---|---|
| LSP routes | Unsupported | No language-server backend exists in toolboxd for Daytona LSP APIs. |
| Computer-use routes | Unsupported | No browser or desktop automation compatibility layer exists. |
| Interpreter routes | Unsupported | No Daytona interpreter/code-run compatibility layer exists. |
| Full command interactivity | Partial | Persistent sessions exist, but command input and the richer Daytona command model are not fully implemented. |