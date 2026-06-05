# README Rewrite Plan

Reference: [Daytona README](https://github.com/daytonaio/daytona/blob/main/README.md)

---

## 10 Things the Current README Lacks

1. **No logo / hero section.** The file opens with a plain `# AerolVM` heading. GitHub renders a logo prominently when you use centered HTML `<picture>` - the first scroll matters for first impressions.

2. **No tagline.** There is no one-line pitch that tells a visitor what the product is and who it is for. Daytona leads with "Run AI Code. Secure and Elastic Infrastructure." The current README leads with a paragraph.

3. **No navigation links.** No links to docs, bug reports, feature requests, or community. Daytona puts these at the very top so visitors land on the right next action.

4. **No features / capabilities table.** The current README has a flat list of bullet points under "What AerolVM Does" - five items, none linked. Daytona has a rich table with 5 categories and 30+ linked rows. AerolVM has sessions, SSH, TCP ports, snapshots, external storage, GPU support, egress control, and more that are invisible in the current README.

5. **No architecture section.** Nothing explains how the system is composed: single Go binary, Caddy for TLS + L7 + L4 routing, SQLite store, cluster mode with Raft FSM + SWIM gossip. Visitors cannot evaluate operational fit from the current README.

6. **No comparison vs Daytona and e2b.** The comparison doc exists at `docs/src/content/docs/comparison.md` with a detailed table, cost analysis, and prose. The README links to none of it. This is AerolVM's strongest sales pitch and it is hidden.

7. **Multi-language quick start is missing.** The SDK example shows only TypeScript. AerolVM ships SDKs for TypeScript, Python, Go, Rust, and Java. No install commands appear (`npm install`, `pip install`, `go get`, etc.).

8. **Daytona / e2b SDK facade compatibility is not mentioned.** The `/daytona` and `/e2b` API facades are a zero-migration-cost selling point for teams already on those SDKs. The README does not mention them at all.

9. **No use-cases section.** There is a `use-cases/` docs section covering coding agents, CI, data processing, and customer-facing products. The README does not link to it.

10. **Developer build commands crowd the README.** The `make install-git-hooks`, `make build`, `make test`, `make docs-install`, `make docs-dev` block is aimed at contributors, not users. It makes the README feel like an internal devlog rather than a product landing page.

---

## 10 Things That Are Good About the Daytona README

1. **Centered HTML logo block with dark/light `srcset`.** Works correctly on GitHub in both color modes without JavaScript.

2. **Two-line H3 tagline.** "Run AI Code. / Secure and Elastic Infrastructure for Running Your AI-Generated Code." One line for attention, one line for clarity.

3. **Nav links block in centered HTML.** Documentation · Report Bug · Request Feature · Join our Slack · Connect on X - all visible before any prose.

4. **Opening paragraph names the product category, key primitives, and target audience** in three sentences. No fluff, no marketing jargon.

5. **Features table uses a 5-column category structure.** Each column is a job: Platform governance, Sandboxes, Agent tools, Human tools, System tools. Each row is a link. A visitor can scan the full capability surface in 10 seconds.

6. **Architecture section explains planes without diving into internals.** Interface / Control / Compute planes, then a directory table that maps each `apps/` folder to one sentence. Easy for evaluators to understand operational shape.

7. **Client libraries section has install commands + package lists per language.** `pip install daytona`, `npm install @daytona/sdk`, `go get …` - all language-native. No guessing.

8. **Quick Start shows working code for every SDK.** Python, TypeScript, Ruby, Go, Java, curl, CLI - all in one section. Any visitor can copy-paste and have a running sandbox.

9. **Deployments section explains the full hosting spectrum.** Managed SaaS → open-source stack → customer-managed compute. Visitors understand their options without digging through docs.

10. **Contributing section is minimal and forward-linked.** One NOTE callout with links to the DCO and contributing guide. Not a wall of instructions.

---

## 20 Points: How to Build a Better README

1. **Add an HTML-centered logo block** with `<picture>` + `srcset` for dark/light mode. Use `docs/public/aerol-logo.svg` via GitHub raw URL.

2. **Write a 2-line tagline** under the logo: first line is action ("Run Untrusted Code Safely."), second line expands ("Self-Hosted Sandbox Infrastructure for AI Agents and Ephemeral Workloads.").

3. **Add a centered nav-links paragraph** under the tagline: Documentation · Quick Start · Report Bug · Request Feature. Gives every visitor a clear next action.

4. **Write a 3-sentence intro paragraph** that names: what it is (self-hosted Docker sandbox platform), what makes it different (single-binary, sub-90ms cold start, gVisor isolation, Raft cluster mode), who it is for (AI agent pipelines and ephemeral CI).

5. **Add a Features table with 4–5 columns** mapping capability areas to linked docs pages. Categories: Sandboxes · Execution · Networking & Ports · Storage & Secrets · Platform & Cluster. Each cell is a link.

6. **Add an Architecture section** with a plain-English description of the three layers: daemon (Go binary), routing (Caddy TLS + L4), storage (SQLite, single-writer WAL). For cluster mode, one sentence on Raft FSM + SWIM gossip.

7. **Add a Comparison section** with the existing table from `comparison.md`. Keep the full feature-row table; omit the cost calculation detail (link to the full page instead).

8. **Add an SDKs section** with one `install` command per language (npm, pip, go get, cargo add, Maven/Gradle snippet) and a one-sentence description.

9. **Show a multi-language Quick Start** with TypeScript, Python, and Go examples - the three most common agent languages. Link to the full docs for Rust and Java.

10. **Call out `/daytona` and `/e2b` facade compatibility** as a dedicated callout block: "Already on the Daytona SDK? Point `SB_API_URL` at your AerolVM host - no code changes required."

11. **Add an Installation section** with the two primary paths: local (`--local`) and production (with `--domain` + Cloudflare DNS-01). Keep the snippets from the current README but label them clearly.

12. **Add a Use Cases section** with 4 one-line callouts (AI code execution, ephemeral CI, interactive dev environments, data processing pipelines) each linking to the docs use-cases section.

13. **Link to `docs.aerol.ai`** for every docs reference. Use the production URL, not relative paths to `.md` files in the repo - those are internal links for GitHub web browsing, not for users.

14. **Add a Runtime Options table** keeping the current Docker / gVisor / Firecracker / Kata rows. It is a genuine differentiator worth surfacing early.

15. **Collapse or remove developer build commands.** Keep only `make test` in a one-line Development section. Redirect contributors to CONTRIBUTING.md for the full dev setup.

16. **Add a Contributing section** following the Daytona pattern: one NOTE callout with links to the license and a CONTRIBUTING.md (create the file if absent, or point to the PR template).

17. **Add a License line** at the bottom: `MIT · © Aerol AI, Inc.` with a link to LICENSE.

18. **Add a "Start Here" navigation table** (already exists in the current README but is buried) in a more prominent position, covering: Quick Start, Server Setup, SDK Setup, Comparison, Cluster Setup.

19. **Add GitHub badges** for CI status, license, and release - they are already defined in the current README but can be expanded with a `license` badge and a `latest release` badge.

20. **Use an HTML `<br>` and `&nbsp;` spacer** between the logo/header block and the prose sections, matching the Daytona visual rhythm that makes the README feel polished on GitHub.

---

## New README Structure (execution order)

```
1. HTML header block (logo + tagline + nav links)
2. Badges (CI, coverage, release, publish-sdks, license)
3. Intro paragraph (3 sentences)
4. Features table (5 categories, linked rows)
5. Why AerolVM (comparison vs Daytona + e2b, summary table)
6. Architecture (daemon + caddy + sqlite + cluster)
7. Runtimes table
8. SDKs (install commands + quick example per language)
9. Drop-in SDK Compatibility (daytona / e2b facades)
10. Installation (local + production + cluster link)
11. Use Cases (4 callouts + links)
12. Start Here / Documentation table
13. Contributing
14. License
```
