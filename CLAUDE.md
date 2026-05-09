# AerolVM — Claude Code Instructions

## Documentation rules

- **Never use raw HTTP / curl examples in docs or in any md file.** All code examples must use one of the five SDK languages (TypeScript, Python, Go, Rust, Java) shown in `<Tabs syncKey="lang">` blocks. curl is only acceptable in `getting-started.md` for the initial server-install one-liners, not for sandbox API calls.
- When adding a new top-level feature to the docs (GPU sandboxes, a new runtime, a new resource type, etc.), create a **new `.mdx` file** rather than appending a subsection to an existing page. Register the new page in the sidebar config at `docs/src/content/config.ts`.
- Every new docs page must cover all five SDK languages with synced tab keys (`syncKey="lang"`).
