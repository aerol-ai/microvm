# Daytona vs AerolVM SDK Summary

This is the short side-by-side view. The detailed route tables live under `../daytona/`, and the native AerolVM SDK inventory lives under `../aerolvm/`.

| Category | AerolVM native SDKs | Daytona SDKs against AerolVM | Notes |
|---|---|---|---|
| Primary API target | Supported | Partial | AerolVM SDKs target `/v1`. Daytona SDKs target the `/daytona` facade, which is only a subset. |
| First-party language SDKs | Supported | N/A | AerolVM ships Go, Java, Python, Rust, and TypeScript SDKs from this repo. |
| Official Daytona high-level SDKs | N/A | Partial | Go, Java, Python, Ruby, and TypeScript can only use the implemented `/daytona` subset. |
| Sandbox lifecycle | Supported | Supported | Create, list, get, start, stop, destroy, resize all exist in the current facade. |
| Persistent Daytona names and labels | N/A | Supported | Stored as compatibility metadata so lookup survives restarts. |
| Daytona auto-stop and auto-delete | N/A | Supported | Mapped to native AerolVM lifecycle timers. |
| Daytona auto-archive | N/A | Partial | Metadata is stored, but there is no real archive behavior. |
| Toolbox exec | Supported | Supported | One-shot command execution works on both sides. |
| Toolbox persistent sessions | Supported | Partial | Native toolbox sessions exist; Daytona-compatible session semantics are implemented only partially. |
| Toolbox file upload and download | Supported | Supported | Single-file plus bulk compatibility helpers exist. |
| Toolbox file listing, info, move, search, find | Partial native surface | Supported in Daytona facade | Added in toolboxd for Daytona compatibility. |
| Toolbox Git | Limited native surface | Supported subset | Add, checkout, clone, commit, branches, history, and status exist. Pull and push do not. |
| Toolbox LSP | Unsupported | Unsupported | No LSP backend exists in AerolVM toolboxd yet. |
| Toolbox computer-use | Unsupported | Unsupported | No desktop/browser automation compatibility layer exists. |
| Toolbox interpreter or code-run | Unsupported | Unsupported | No Daytona interpreter facade exists. |

## Bottom line

| Question | Answer |
|---|---|
| If you want full AerolVM support today, what should you use? | The native AerolVM SDKs in `sdk/`. |
| If you want to reuse an existing Daytona integration, what should you expect? | Partial compatibility only. Use only the supported `/daytona` routes listed in the detailed matrices. |
| Is the current Daytona status a language problem or an endpoint problem? | An endpoint problem. The same subset applies across Daytona SDK languages. |