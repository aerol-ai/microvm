# Enterprise docs rework

Status: done 2026-10-11. All seven pages are written. The four deep dives moved to Blogs as `engineering-isolation`, `engineering-sandbox-filesystem`, `engineering-network-defenses` and `engineering-secret-handling`, with a byline. The tab is about 1,700 words of prose, down from 7,400.

## Positioning (founder decisions, 2026-10-11)

The tab is called **Enterprise**. It does two jobs: it is the production guide for an open-source project, the way Kubernetes documents itself, and it is where a company finds and engages the maintainer.

- **AerolVM is a community project.** It is MIT-licensed and runs on your own servers. No page suggests that Aerol runs it for you. The top of the Overview says so in one line.
- **The offer is the maintainer.** The "Work with the maintainer" page lists four ways to engage: architecture review, rollout help, sponsored features and a maintenance partnership. None of them means operating the company's servers. No prices; the button says "Talk to the maintainer".
- **Self-promotion is open, not hidden.** The maintainer bio answers a buyer's due-diligence question ("who is behind this, and will it last?"). `GOVERNANCE.md` says single maintainer, so the page says so and turns it into the ask: companies that depend on AerolVM can sponsor its maintenance.
- **Credibility is personal and portable.** The bio names Suman, with personal LinkedIn and GitHub links. Every claim is backed by the resume.
- **Enterprise features are discussed in the open.** Anything not built is *Proposed* and links to the **Ideas** Discussions category. An accepted idea becomes a pull request to `ROADMAP.md`.
- **The managed build stays off these pages.** Tenant tokens, metering, fleet suspend, the audit witness and enterprise mode live behind `pkg/controlplane` and are not open-source features.

Outside the tab, the network grows through:
- engineering posts under the maintainer's name;
- an `ADOPTERS.md` list;
- the Ideas proposals;
- a monthly community call.

## Why the current pages fail

They were built as a copy of microsandbox's **Security** tab: one security essay plus five deep dives. An enterprise reader needs the other kind of section, the one microsandbox calls **Enterprise**. That kind is short, task-based, and built from tables: choose a deployment, roll it out, who owns what, talk to us.

What went wrong, in order of impact:

1. **No reader in mind.** Nothing answers the three questions a buyer arrives with: *what do I get*, *how do I run it*, *how do I prove it is safe*.
2. **Enterprise features are missing from the landing page.** Clusters, AWS KMS, audit export, enterprise mode, tenant isolation and signed releases are scattered across five pages, or appear only in the Book-a-call text.
3. **Everything verified went in.** Five research agents found about 4,500 words of facts, and almost all of it went onto the pages. The honesty rule turned into "list every limit". The pages read as weakness inventories: there are more than 130 negations across them.
4. **Prose instead of matrices.** 60 H2s and about 170 bullets, where a few tables would do.
5. **Repetition.** The root user is covered on 4 pages (19 mentions). The default network posture is covered on 4 pages. "The server is trusted" appears 16 times.
6. **Internals a buyer does not need.** Port 2280, vsock, `/run/aerol/ready.sock`, and the token being removed from toolboxd's environment.

## Ratings

Each criterion is scored 1–10:

- **Find:** can a reader find an answer in 30 seconds?
- **Value:** does the page answer enterprise questions?
- **Lean:** words per useful fact.
- **True:** accuracy.
- **Act:** can the reader do something next?

| Page | Words | Find | Value | Lean | True | Act | Overall | Main problem |
|---|---|---|---|---|---|---|---|---|
| Security model (landing) | 1,517 | 3 | 3 | 3 | 8 | 4 | **4** | Starts with philosophy. Lists no enterprise features. The founder section sits under 1,500 words of security essay. |
| Isolation boundary | 1,369 | 4 | 4 | 3 | 8 | 3 | **4** | 14 H2s. The runtime comparison appears three times: diagram, table, then per-runtime sections. It reads like a list of weaknesses. |
| Filesystem and images | 971 | 5 | 4 | 5 | 8 | 5 | **5** | An internal-paths table. Mount rules that duplicate the storage pages. |
| Network defenses | 1,252 | 4 | 6 | 4 | 8 | 5 | **5** | It has the most useful facts, but the operator fix comes last, after 12 other sections. |
| Secret handling | 1,225 | 5 | 6 | 4 | 8 | 5 | **5.5** | A good opening table. Then it duplicates the env and network-rules pages. Audit is buried. |
| Hardening | 1,078 | 5 | 6 | 5 | 8 | 7 | **6** | The best content, the posture table, is at the bottom. Ten H3s for a checklist. |
| **Overall** | **7,412** | **4** | **4** | **4** | **8** | **5** | **4 / 10** | Accurate, but organized as an essay, not an evaluation path. |

Keep: the verified facts, the posture table, the default-posture table, the env-vs-inject table, the "where values live" table, the DNS-tricks table, and the diagrams.

## Readers and the questions each page must answer

| Reader | Arrives asking | Must find in 30 seconds |
|---|---|---|
| CTO or platform lead | What does it do for my company? Can I run it in my cloud? Does it scale and survive failures? Is it a healthy project? | A feature matrix with status, deployment options, the measured numbers, community links |
| Security reviewer (CISO team) | What is the isolation? Where do secrets live? What is logged? What is out of scope? | One control matrix, the known limits, the threat model link |
| Compliance or procurement | What evidence can I collect? How are vulnerabilities handled? Where do I get help? | Audit export, release provenance, the security policy, community channels |
| Operator | How do I lock it down? | A numbered hardening checklist |

## Writing rules for the rework

1. **Answer first.** Each page opens with a table that answers its main question. Explanation comes after.
2. **One fact, one home.** Every limit lives once, in **Known limits**. Other pages link to it.
3. **Budget:** at most 600 words of prose per page, and the landing page at most 500. At most 6 H2s per page.
4. **No internals** unless a reviewer needs them to judge risk. Leave out ports, socket paths and helper internals.
5. **Mark every row** as one of: *Default*, *You turn it on*, or *Proposed* (not built yet, with a link to its discussion).
6. **How-to stays in Docs.** Enterprise pages link to `network-access`, `sandbox-env`, `cluster-setup` and the others. They do not repeat them.
7. **Never claim what we do not have.** No SOC 2, SSO, RBAC or SLA claim, and no promise to run it for you.
8. **Project voice, not vendor voice.** "AerolVM does" and "you can", not "we offer". "Talk to the maintainer", not "Talk to sales".

## New structure (For enterprise tab)

| # | Page | Replaces | Opens with | Words |
|---|---|---|---|---|
| 1 | **Overview** `/enterprise/` | Security model | A feature matrix with one status per row: *Default*, *You turn it on* or *Proposed*. Then security at a glance (8 rows, each linking to page 3), and where to get help. | ≤500 |
| 2 | **Run it in production** `/enterprise/deployment` | (new; reuses cluster-setup) | A table: single server, mixed cluster, mixed and hetero cluster. Purpose, scale, failover, next step. Self-hosted only. | ≤500 |
| 3 | **Security controls** `/enterprise/security-controls` | Isolation, Filesystem, Network, Secrets | One control matrix with these areas: isolation, network, secrets, storage, API access, cluster, audit. Columns: what it is, default, how to turn it on. Then 4 short sections with the diagrams. | ≤600 |
| 4 | **Evidence for your audit** `/enterprise/audit-evidence` | (Secret handling, audit part) | An evidence table: the audit log (kinds, retention, hash chain, export targets), release provenance (checksums, SLSA, SBOM), threat model, security assessment, security policy and response times. | ≤500 |
| 5 | **Hardening checklist** `/enterprise/hardening` | Hardening | The posture table: own code, user code, hostile code. Then a numbered checklist, per sandbox and per server, each item with its setting name. | ≤600 |
| 6 | **Shared responsibility and known limits** `/enterprise/responsibility` | All "Where this boundary ends" sections | A two-column table, *AerolVM provides* and *You manage*. Then every known limit, once, with its workaround, and a link to its proposal when one exists. | ≤500 |
| 7 | **Work with the maintainer** `/enterprise/maintainer` | Book-a-call box | The four offers, the maintainer bio, then community links: Q&A, Ideas, security reports, contributing, the monthly call, `ADOPTERS.md`. | ≤450 |

The deep-dive pages (isolation, filesystem, network, secrets) go away, or move to Blogs as "How AerolVM isolates sandboxes". Their unique facts move into page 3's matrix or page 6's limits.

### Overview page outline (the one most people read)

1. One sentence: AerolVM is an open-source (MIT) sandbox platform that you run on your own servers, for running untrusted code.
2. **Feature matrix.** Columns: feature, status, works on (single server or cluster), docs link. Rows:
   - *Available:* five runtimes, network policies, keys kept out with inject rules, sealed secrets, the hash-chained audit log with export, AWS KMS, clusters with mTLS and failover, signed releases.
   - *Proposed:* SSO, scoped API tokens and roles, per-team quotas, caller identity in audit records, image signature checks. Each links to its Ideas discussion.
3. **Security at a glance:** 8 rows (isolation, outbound default, inbound default, secrets at rest, keys kept out, storage keys, API auth, audit). Each row gives the default and links to page 3.
4. **Evidence:** links to the threat model, the security assessment, the security policy and release verification.
5. **Work with the maintainer:** a small card with one line of bio and the button.

## Decisions needed before writing

| # | Question | Why it matters |
|---|---|---|
| D1 | What exactly is in the managed or enterprise build? Tenant tokens, the external audit witness, enterprise mode, anything else? | The feature matrix columns depend on it. |
| D2 | Do you offer support, an SLA or response times beyond SECURITY.md? Is there pricing to link? | Page 7, and the matrix's support row. |
| D3 | SSO, RBAC, per-tenant quotas: do they exist, or are they planned? (Not found in code.) | Buyers ask first. We must say "not yet" honestly, or leave them out. |
| D4 | Compliance status: SOC 2, ISO? | Avoids an unsafe claim. If there is none, page 4 says "evidence you can use" instead. |
| D5 | Fix before publishing, or document? The defaults that worry reviewers: no metadata block, no process limit, the user field ignored. | Each one fixed shortens "Known limits". The plan recommends fixing the metadata default first. |
| D6 | The source for "20,000 concurrent sandboxes", and the 100M+ users line. | The landing page and founder claims must hold up. |
| D7 | The Calendly link (`docs/src/utils/links.ts`). | Every CTA. |
| D8 | Keep the deep dives as Blogs posts, or drop them? | Saves the verified detail without cluttering the evaluation path. |

## Decisions (answered 2026-10-11)

| # | Decision |
|---|---|
| D1 | One column, not tiers. Everything listed is open source. Managed-build features are left off. |
| D2 | Community channels plus the four maintainer offers, all listed. Security response follows SECURITY.md. No SLA, no prices. |
| D3 | SSO, scoped tokens and roles, and per-team quotas are *Proposed*. |
| D4 | No certification badge. Page 4 is "Evidence for your audit". |
| D5 | Open. Until the defaults are fixed, Known limits lists them with their workarounds. |
| D6 | The bio uses the resume line, "200M+ users". The 20,000-sandbox number stays off the Enterprise tab until a run is published. |
| D7 | "Talk to the maintainer" uses `BOOKING_URL` in `docs/src/utils/links.ts`, set to the Google Calendar booking page. |
| D8 | The four deep dives leave the tab and become Blogs posts under the maintainer's name. |
| Extra | Add `ADOPTERS.md`. Hold the community call on the first Saturday of every month at 8 pm Pacific Time. The join link goes in the announcement thread ([#652](https://github.com/aerol-ai/microvm/discussions/652)) before each call. |

### Starter proposals for the Ideas category

Each one comes from a known limit, so the Known limits page can link straight to it. Draft the text here, and the founder posts them.

| Proposal | The limit it answers |
|---|---|
| SSO for the API (OIDC first) | API access is one bearer token per server |
| Scoped API tokens and roles | Anyone with the token can run commands in any sandbox |
| Per-team quotas | Limits are per sandbox, not per team |
| Caller identity in audit records | Records name the server, not the API caller |
| Image signature checks (cosign) | AerolVM does not check image signatures |
| Closed network by default | Outbound traffic is open until a policy is set (moot if D5 ships) |

## Phases

1. **Decisions D1–D8** with the founder. One short session. Post the starter proposals to Ideas so the matrix can link to them.
2. **Draft pages 1, 3 and 6** (overview, controls, limits). These carry 80% of the value. Review them before continuing.
3. **Draft pages 2, 4, 5 and 7** from existing verified content and the cluster-setup page.
4. **Cut:**
   - Delete or move the old deep dives.
   - Add redirects for the old URLs.
   - Update the sidebar in `content.config.ts`.
5. **Verify:**
   - Every matrix row has a code citation from the research notes.
   - The docs lint passes and the snippet check finds no unknown calls.
   - The 30-second test (below) passes.

## Acceptance tests

- **The 30-second test.** A reader new to AerolVM, given only the Overview, answers these within 30 seconds each, without scrolling past the second table:
  - Does it support KMS?
  - Can I export audit logs?
  - What is open by default?
  - How do I run it on my own cluster?
  - Where do I ask a question, and how do I propose a feature?
- **Size.** Total prose under 3,500 words, down from about 7,400. No limit is stated on more than one page.
- **Every claim is marked:** default, you turn it on, or proposed.
- **No vendor voice.** No page says or implies that Aerol runs AerolVM for you.
- **The founder reviews** the matrix and limits pages before they merge.
