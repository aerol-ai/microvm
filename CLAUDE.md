# AerolVM — Claude Code Instructions

## Documentation rules

- **Never use raw HTTP / curl examples in docs or in any md file.** All code examples must use one of the five SDK languages (TypeScript, Python, Go, Rust, Java) shown in `<Tabs syncKey="lang">` blocks. curl is only acceptable in `getting-started.md` for the initial server-install one-liners, not for sandbox API calls.
- When adding a new top-level feature to the docs (GPU sandboxes, a new runtime, a new resource type, etc.), create a **new `.mdx` file** rather than appending a subsection to an existing page. Register the new page in the sidebar config at `docs/src/content/config.ts`.
- Every new docs page must cover all five SDK languages with synced tab keys (`syncKey="lang"`).

## API design & PR review

Before opening or reviewing any PR that touches `internal/service`, `internal/store`, `pkg/caddy`, `pkg/api`, or the SDKs, read [`pr-review.md`](./pr-review.md). It is the canonical source for:

- the idempotency requirement on all sandbox APIs,
- the rule that any work added to `CreateSandbox` / sandbox boot must be explicitly called out,
- the lazy-bootstrap pattern (atomic latch + single-flight mutex) for best-effort daemon-start work,
- failure-path state-consistency rules for caddy + store writes,
- the regression-test requirement on changes to the TCP host-port pool or the L4 bootstrap,
- the PR description template that must be filled in for every PR (silence is not acceptable on these axes).
