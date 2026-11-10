# Cluster docs, rewritten for people who never ran a cluster

Status: written and reviewed, 2026-11-10 (three review rounds). Branches: `kops/pr19-join-command-full-line` (kops 19, code) and `kops/pr20-cluster-docs` (kops 20, docs), stacked on kops 18.

## Why

The cluster guide exists (`/cluster-setup`) and passed live AWS tests, but nobody can find it:

- The "Run a Cluster" sidebar group is commented out (`docs/src/content.config.ts`).
- The sidebar's "Cluster Setup" goes to a "book a call" page that never links to the guide.
- The "Choose a setup" page says a cluster needs AWS, Terraform and three config files. That is no longer true: any Linux machines work, with one command each.
- The single-server page never says how to upgrade.

The owner now wants clusters to be self-serve. A reader who builds apps with AI tools ("a vibecoder") must be able to build, grow, upgrade and fix a cluster from the docs alone.

## Who reads this

A developer who:

- has used Docker a little, and has rented a cloud server once or twice,
- has never run Kubernetes, and does not know words like "quorum", "control plane" or "certificate authority",
- may read English as a second language,
- copies commands and wants to know what they should see after each one.

A second reader knows Kubernetes. They want to map what they know onto AerolVM in one table.

## The bar: as easy to follow as kubeadm, easier to read

Kubernetes splits its setup docs into small pages: concepts, "create a cluster with kubeadm", "add nodes", "upgrade", "safely drain a node", "operating etcd" (backups), and the kubectl cheat sheet. We copy that shape. We beat it on language: no page assumes the reader already knows another page's words.

## Round 1 review (five agents, 2026-11-10)

Scores: 7, 7, 6, 7, 7 out of 10. All five stopped at the same place: step 7 asked readers to copy three values from the printed join command into a longer command typed by hand. Kubernetes' best promise is "paste the printed line".

**Fixed in code (kops 19):** `aerolvm join-command` now prints a command that works as pasted. It carries the cluster's `--domain` and DNS options, takes `--role mixed`, and reads the Cloudflare token from `$CLOUDFLARE_API_TOKEN` on the new machine, so the secret is not in the printed command. `sandboxd init` prints the same command, with fixed wording ("the token is valid until", "your computer").

**Fixed in the pages:**

- "What you need" comes first, and is concrete: machine size, rough cost, how to get a private network, why Cloudflare (and that the domain can be bought anywhere), where to get the CLI.
- Every command block says where it runs: "On your computer", "On node 1", "On node 2".
- Long steps are split. Step 5 (start the cluster) and step 7 (add machines) were the longest.
- One name for each thing (see the language rules).
- The Kubernetes table moves to the end of the overview, and its rows are exact. `drain` does not move sandboxes the way `kubectl drain` moves pods. `upgrade apply` upgrades every node, where `kubeadm upgrade apply` does one.
- Failover says what is kept (ID, links, ports, settings) and what is lost (files on the sandbox's own disk, running programs).
- New pages: "Back up and recover" (Kubernetes has "Operating etcd") and a one-screen "Command cheat sheet".
- The six existing reference pages sit under a "Reference" heading inside the +. They stay out of the "Next" chain.
- Diagrams: the overview picture shows a request being passed to the node that runs the sandbox. "Build a cluster" draws what talks to what (the firewall). The join diagram shows the order: prove the cluster, then send the token. A failover picture sits next to the failover code.

## Round 2 and the final round

Round 2 (the plan and two sample pages): 8, 9, 9, 9 and 8 out of 10.

Final round (all 11 pages), by page: overview 9, how it works 8, build 9.5, nodes 8, AWS 6, upgrade 7, backup 8, cheat sheet 9, Kubernetes 8 to 9, visuals 8, language 8.5. Every finding below was checked against the code and fixed:

- **AWS:** the page's `main.tf` did not match `Terraform/examples/from-url/main.tf`. The example is now three mixed nodes, and the page shows its real `var.` lines. The page now says how to copy the folder, never to change `ref=` to upgrade, the `-i` key flag, and the `aerolvm login` prompt.
- **Upgrade:** after a failed node or a `stop`, you run `apply` again (`resume` is refused there). A normal `apply` finalizes by itself, and then `rollback` is refused: the page says so, and points to `--hold`. A `skipped` node holds back finalize.
- **How a cluster works:** at most 5 nodes vote by default (`SB_CLUSTER_MAX_AUTO_VOTERS`). Mixed nodes past that keep copies without voting.
- **Keep it safe:** old workers get the fingerprint by `reset` and a new join command. Re-running their old join command fails, because tokens are removed a day after they expire. Admin token rotation starts with pinning `SB_OPERATOR_VOLUME_SCOPE` when platform volumes are on.
- **Back up:** restore is for a one-server install, or for the chosen survivor before `recover-quorum`. In a working cluster, replace a server node instead.
- **Nodes:** `--delete-sandboxes` has a warning. Moving failover sandboxes means `delete node --force`.
- **Sidebar:** a guide page opened at an `#anchor` keeps its + list open.
- **Code (kops 19):** the refused-token fix line names the role; notes say "works for one machine" and "To cancel it"; a worker's join says it holds only a fingerprint of the admin token.

## Where it lives: one sidebar entry with a + button

Like `Enterprise → SSO`, the sidebar shows one entry, **Cluster Setup**, with a + button. Unlike SSO (whose children are sections of one page), these children are real pages, and "Next" walks through the guide in order.

```
Getting Started
  - Introduction
  - Local Setup
  - Single Node Cloud Setup
  - Cluster Setup                       [+]   /cluster/
      How a cluster works                     /cluster/how-it-works/
      Build a cluster                         /cluster/create/
      Build it on AWS                         /cluster/aws/
      Add and remove nodes                    /cluster/nodes/
      Upgrade                                 /cluster/upgrade/
      Back up and recover                     /cluster/backup/
      Keep it safe                            /cluster/security/
      Fix problems                            /cluster/troubleshooting/
      Command cheat sheet                     /cluster/cheat-sheet/
      Coming from Kubernetes                  /cluster/kubernetes/
      Reference
        Ingress nodes                         /cluster-ingress/
        Secrets providers                     /cluster-secrets/
        Dashboard                             /dashboard/
        Runbooks                              /operational-runbooks/
        Reconcile                             /reconcile/
        Glossary                              /cluster-glossary/
```

Old addresses keep working through redirects:

- `/getting-started/cluster-setup` → `/cluster/`
- `/cluster-setup` → `/cluster/create/`

Every link inside the docs and the README moves to the new page and anchor.

Code change (`docs/src/utils/navigation.ts`, `SidebarSublist.astro`): a child whose link has no `#` is a page. It joins pagination and the section label. A child marked `reference` is listed under a "Reference" heading and stays out of pagination. Anchors (SSO's providers) are unchanged.

## The pages

Each task page has the same shape:

1. A one-line description under the title.
2. **What you will do**: 2 to 4 bullets.
3. **Before you start**: what you need.
4. `### Step N` headings. Each step does one thing. Each command block has a title that says where it runs. After it: **what you should see** (real output), then one or two sentences on what just happened.
5. **Check that it worked.**
6. **If something goes wrong**: a small table (what you see, what it means, what to do).
7. **Next**: one or two links.

| Page | What it answers | Diagrams |
|---|---|---|
| **Clusters** (`/cluster/`) | What is a cluster? Do I need one? What do I need (size, cost, private network, Cloudflare DNS, CLI)? How the build goes. What I get. My code does not change (five-language tabs). Which path to pick. Kubernetes words, at the end. | A request passed to the node that runs the sandbox; failover kept vs. lost |
| **How a cluster works** | Words to know. The three jobs a node can do (server, worker, ingress; mixed is all three). What happens when you create a sandbox. Why three servers. What happens when a machine dies, with what is kept and lost. Small vs. split clusters. | The three jobs; a create, step by step (5 arrows at most); 1 of 3 servers down vs. 2 of 3 down |
| **Build a cluster** | Three Linux machines from any cloud become three mixed nodes. `init` on the first, connect your computer, `join-command --role mixed`, paste the command, point the domain, check. | What talks to what (the firewall); how a machine joins |
| **Build it on AWS** | The Terraform way: one folder, three files, `terraform apply`. Optional gVisor, Firecracker, V8 isolates, GPUs in one table. A load balancer. | What Terraform makes (7 boxes at most) |
| **Add and remove nodes** | See nodes and what each status means. Add a worker. Pause one (cordon). Empty one (drain). Remove one (delete). Reuse a machine (reset). Remove a server safely. | A node's life, with `uncordon` back to ready and a plain meaning under each state |
| **Upgrade** | `aerolvm upgrade plan`, then `apply`. The order nodes go in. What running sandboxes see. Watch, pause, stop, roll back, finalize. No internet on the nodes. The first upgrade from v0.6. One server. | The upgrade order, with "stop and roll back" on failure |
| **Back up and recover** | What to back up. `sandboxd backup` and `sandboxd restore`. A server died: replace it. Most servers died: `sandboxd recover-quorum`. | 3 servers → 1 left → recover → 3 again |
| **Keep it safe** | The three secrets you hold (admin token, join tokens, Cloudflare token) and what each opens. Join token rules. Which nodes hold the admin token, and when. Rotate the admin token. Ports to keep private. Certificates renew themselves. | Private network vs. the internet (the same picture as "Build a cluster") |
| **Fix problems** | The first three commands to run. A table: what you see → what it means → what to do. Links to runbooks. | none |
| **Command cheat sheet** | Every cluster command on one screen, grouped by task, with where it runs. | none |
| **Coming from Kubernetes** | Ideas map. Commands map. What you do not need (no YAML, no network plugin, no etcd to run beside it). What is different (sandboxes are not pods; drain; upgrade does the whole cluster; finalize). | none (the tables do it) |

Existing reference pages (ingress, secrets, dashboard, runbooks, reconcile, glossary) keep their content, with three fixes: links to the new pages, the "Start a split cluster by hand" steps use the new join command, and any sentence over 25 words is split.

Other pages:

- **Choose a setup** (`/getting-started/`): the cluster column says "Three or more Linux machines, any cloud" and "One command per machine".
- **Install on a server**: a new "Upgrade" section (`aerolvm upgrade`, or run the installer again).
- **aerolvm CLI**: `join-command --role mixed`, the `CLOUDFLARE_API_TOKEN` step, and links to the new pages.
- **README**: cluster links move to `/cluster/`.

## Language rules

1. Sentences of 15 words or fewer on average. None over 25.
2. One idea per sentence. No semicolons. No em dashes.
3. "You" and the present tense.
4. One name for each thing, on every page:
   - **machine**: a computer before it joins. **node**: a machine in the cluster.
   - **server node**, **worker node**, **ingress node**, **mixed node**: the jobs. Never "server" alone for a node. "One server" means the one-server setup only.
   - **your computer**: where you run `aerolvm`. Never "laptop" or "workstation".
   - **node 1**: where you ran `init`.
   - **admin token**: the cluster's password for apps and admins. Say once that `--pat-token` and `SB_PAT_TOKEN` hold it.
   - **join token**: the short secret that lets one machine in. **join command**: the command that uses it. Never "join line" or "the line".
   - **Cloudflare token**: the Cloudflare API token.
   - **cluster ID**: the `sha256:...` value. `--ca-cert-hash` passes it.
   - **node certificate**: a node's signed ID card. **HTTPS certificate**: what makes `https://` work. Never "certificate" alone.
   - **cluster address**: `cluster.example.com`. **your domain**: `example.com`.
   - **admin login file**: `admin-context.json`. Say once that `aerolvm` calls a saved login a **context**.
   - **sandboxd**: "the AerolVM program on each node", said once per page.
5. A new word is **bold** and explained the first time it appears on each page. Readers arrive from search.
6. Never in running text: Raft, SWIM, gossip, mTLS, FSM, CA, SNI, quorum, etcd. When output shows one, explain it in one line right under the output block. The glossary keeps the precise terms.
7. No vague words: soon, some, a few, may, light, room, safe order. Give a number, a time, or a command that shows it.
8. No idioms: lands on, point at, top half, half way, spin up. Say what happens.
9. When a page describes a failure (a dead node, failover, reset, delete), say what is kept and what is lost.
10. Write "never" or "always" only when the code proves it.
11. Example output is real output from the code (golden test files, the `init` and `join` messages). Example values differ where real ones differ: two tokens get two IDs. When a real message breaks these rules, fix the message in the code, not on the page.
12. Diagrams: at most about 7 boxes, labels of 4 words or fewer.
13. No internal IDs (UC numbers, PR numbers, plan sections).

`readcheck.py` checks rules 1, 2, 6, 7, 8 and 13 on every changed page before each push.

## Checks before it ships

- Readability review by the same agents: round 2 on the revised plan and the two sample pages, then a final round on all pages.
- Every command and flag checked against the code: `cmd/aerolvm`, `cmd/sandboxd`, `internal/nodejoin`, `scripts/install.sh`, `Terraform/`.
- `astro build` passes. Every internal link resolves. Redirects work. Each diagram renders in light and dark mode. The + opens, the "Reference" heading shows, and "Next" walks the guide in order.
- The CLAUDE.md docs rules hold. The one page with SDK code (`/cluster/`) has all five languages in `syncKey="lang"` tabs. The task pages are shell-only, like `cli.mdx`. The only `curl` lines are the installer and the join command it prints.

## Not in this change

- A cluster on Docker alone, or on a Mac. The installer refuses `init` and `join` there. The docs say so plainly and point to cheap Linux cloud machines.
- Kubernetes or Helm install (a separate plan).
- npm and Homebrew publishing for the CLI (a one-time setup by the owner).
