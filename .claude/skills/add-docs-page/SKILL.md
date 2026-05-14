---
name: add-docs-page
description: Add a new AerolVM docs page (.mdx) with synced five-language tabs and register it in the Starlight sidebar. Enforces the repo's hard rules — no raw curl, all five SDK languages, syncKey="lang" on every tab block. Use when the user asks to "add a docs page", "document this feature", "write the docs for X", or after shipping a user-facing capability that isn't documented yet. Proactively suggest after a new SDK method or top-level feature lands.
---

# Add a docs page

## Hard rules (from CLAUDE.md)

- **No raw curl / HTTP examples.** Only the install one-liner in `getting-started.md` may use curl. Every other code example uses one of the five SDK languages.
- **New top-level feature → new `.mdx` file**, not a subsection on an existing page.
- **Every code example covers all five SDK languages** in `<Tabs syncKey="lang">` blocks. Order: TypeScript, Python, Go, Rust, Java.

## Steps

1. **Create the file.** `docs/src/content/docs/<slug>.mdx`. Use `.mdx` (not `.md`) — feature pages need MDX for `<Tabs>`.
2. **Frontmatter:**
   ```yaml
   ---
   title: Human-Readable Title
   description: One-line summary used in metadata + sidebar.
   ---
   ```
3. **Tabbed examples:**
   ```mdx
   import { Tabs, TabItem } from '@astrojs/starlight/components'

   <Tabs syncKey="lang">
     <TabItem label="TypeScript">…</TabItem>
     <TabItem label="Python">…</TabItem>
     <TabItem label="Go">…</TabItem>
     <TabItem label="Rust">…</TabItem>
     <TabItem label="Java">…</TabItem>
   </Tabs>
   ```
   Same `syncKey="lang"` across every Tabs block on the page (and the site) so picking a language sticks.
4. **Register in the sidebar.** Edit `docs/src/content.config.ts` (note: file is `content.config.ts`, not `content/config.ts`):
   - Pick a `NavigationCategory` (`OVERVIEW`, `SANDBOX`, `TOOLBOX`, `ACCESS`, `SDKS`, `FEATURES`, `USE_CASES`).
   - Add an entry to the right group in `getDocsSidebarConfig()` (or `getUseCasesSidebarConfig()` for use-cases):
     ```ts
     { type: 'link', href: '/<slug>', label: 'Label', description: 'Sidebar hover text.' }
     ```
5. **Local preview:** `make docs-dev` → http://localhost:4321.
6. **Build smoke-test:** `make docs-build` before committing.

## Style

- Open with a one-paragraph description of *what the feature is and why a user wants it*, not implementation detail.
- Lead with the simplest working code example, then expand.
- Keep tab content roughly the same length per language — large length skew suggests an inconsistent example.
