# Ideas proposals: drafts for GitHub Discussions

**Posted 2026-10-11:** [SSO #647](https://github.com/aerol-ai/microvm/discussions/647), [scoped tokens #646](https://github.com/aerol-ai/microvm/discussions/646), [quotas #648](https://github.com/aerol-ai/microvm/discussions/648), [caller identity #649](https://github.com/aerol-ai/microvm/discussions/649), [image signatures #650](https://github.com/aerol-ai/microvm/discussions/650), [closed network #651](https://github.com/aerol-ai/microvm/discussions/651). The posted versions point to the booking link and the monthly call ([#652](https://github.com/aerol-ai/microvm/discussions/652), first Saturday of every month, 8 pm Pacific) instead of the docs, because the new docs were not deployed yet.

Six posts for the **Ideas** category of `aerol-ai/microvm` Discussions. Each one comes from a row on the docs' Known limits page (`/enterprise/responsibility/`). Post each one as written, then send the six links back so the docs' *Proposed* links can point at them.

Every claim below was checked against the code on 2026-10-11. The posts leave out anything still under private advisory.

The sponsor link points at `https://microvm.aerol.ai/enterprise/maintainer/`, which works once the docs are deployed.

---

## 1. SSO for the API

**Title:** Proposal: single sign-on (SSO) for the AerolVM API and dashboard

**Body:**

### The problem

Today, every AerolVM server has one API token, the operator token (`SB_PAT_TOKEN`). The SDKs and the `aerolvm` CLI send it, and so do MCP clients. The dashboard asks you to paste it into the browser. So everyone who uses the server shares one secret, and removing one person means changing the token for everyone.

### What you can do today

Keep the token in a secret manager, and hand it only to services, not people. Put the dashboard and API behind your own login proxy, and keep port `21212` private.

### A starting shape

- Sign in with OpenID Connect (OIDC) first, since Okta, Entra ID, Google and Keycloak all speak it. SAML could come later if people need it.
- `aerolvm login` opens the browser and saves a short-lived token instead of the operator token.
- The dashboard signs you in with your company account, so no one pastes the operator token.
- The operator token stays, for automation and for recovery.

This depends on [scoped tokens and roles](#), because a signed-in person needs a role.

### Questions for you

1. Which identity provider do you use?
2. Is the dashboard, the CLI or the SDK the place you most need SSO?
3. Do you need SAML, or is OIDC enough?
4. Do you need groups from your identity provider mapped to roles?

### How to weigh in

React with 👍 if you need this, and comment with your answers. If your company needs it soon, you can [sponsor the work](https://microvm.aerol.ai/enterprise/maintainer/). It is built in the open and ships to everyone.

---

## 2. Scoped API tokens and roles

**Title:** Proposal: scoped API tokens and roles

**Body:**

### The problem

The operator token can do everything on a server. It can create and delete any sandbox, read any sandbox's environment variables and run commands in any sandbox. You cannot give a CI job a token that only creates sandboxes, or give a teammate one that can only read.

### What you can do today

Put your own service in front of AerolVM and decide there who can do what. Keep the operator token inside that service.

### A starting shape

The API's auth layer already tells two kinds of callers apart: the operator, who sees everything, and an owner-scoped caller, who sees only their own sandboxes. The open-source build only accepts the operator token today. The proposal fills in the second kind:

- **Tokens the operator creates**, each tied to an owner, with an optional expiry date. A token can be revoked on its own.
- **Three roles to start:** *viewer* (read status and logs), *runner* (create, run commands, delete its own sandboxes), and *admin* (everything, like the operator token).
- **Owner scoping:** a runner sees only the sandboxes its owner created.
- **Audit:** every record names the token that made the call. See the [caller identity proposal](#).

### Questions for you

1. Are the three roles enough? What would you add?
2. Should a token be scoped by owner, by sandbox tags or by both?
3. Do you need tokens that can only reach some runtimes, such as Firecracker only?
4. How do you want to manage tokens: the CLI, the dashboard or an API?

### How to weigh in

React with 👍 if you need this, and comment with your answers. If your company needs it soon, you can [sponsor the work](https://microvm.aerol.ai/enterprise/maintainer/). It is built in the open and ships to everyone.

---

## 3. Quotas per team

**Title:** Proposal: quotas per team

**Body:**

### The problem

AerolVM limits each sandbox: 1 CPU, 1 GB of memory and 10 GB of disk unless you ask for more. Each server also refuses new sandboxes when it runs out of room. Nothing limits a team, though. One team's job can start hundreds of sandboxes and leave no room for anyone else.

### What you can do today

Count sandboxes in the service that calls AerolVM, and refuse creates there. Use `lifecycle` timers so forgotten sandboxes stop or get deleted.

### A starting shape

- A quota belongs to an owner (see [scoped tokens](#)). It caps running sandboxes, total CPU, total memory and outbound bytes.
- A create that would go over is refused with a clear error that names the quota. The sandbox is never half-created.
- In a cluster, the quota counts sandboxes on every server, not just one.
- The operator sets quotas in a file, like the network policy file.

### Questions for you

1. What would you cap first: the number of sandboxes, CPU and memory, or network bytes?
2. Should a team be able to burst over its quota for a short time?
3. Do you need quotas per runtime, such as a lower cap for Firecracker?
4. What should happen to running sandboxes when a quota is lowered?

### How to weigh in

React with 👍 if you need this, and comment with your answers. If your company needs it soon, you can [sponsor the work](https://microvm.aerol.ai/enterprise/maintainer/). It is built in the open and ships to everyone.

---

## 4. Caller identity in audit records

**Title:** Proposal: name the API caller in audit records

**Body:**

### The problem

AerolVM writes an audit record each time a sandbox's secrets are opened, and each time the network filter refuses a connection. The records sit in a hash chain, so a changed or deleted record shows. Each one names the sandbox and the server that did the work, but not who called the API. An auditor asking "who read this sandbox's variables?" gets a server name, not a person or service.

### What you can do today

Have your own gateway add an `X-Correlation-ID` or `X-Request-ID` header to each API call. When a call reads a sandbox's variables, the audit record keeps that value, so you can match it against the gateway's logs. Records written when a sandbox starts or is rebuilt have no caller, because no API call caused them.

### A starting shape

- Each record gets a `caller` field: the token's name or ID, or `operator` for the operator token.
- The field is covered by the hash chain, like every other field.
- With [scoped tokens](#) and [SSO](#), the caller is a real person or service.
- Exports to a file, a webhook and S3 carry the new field. Older records stay valid.

### Questions for you

1. Which question does your auditor ask most: who read a secret, who ran a command or who deleted a sandbox?
2. Should command runs and file reads be recorded too, not just secret reads?
3. Where do your audit records end up: a SIEM, S3 or something else?

### How to weigh in

React with 👍 if you need this, and comment with your answers. If your company needs it soon, you can [sponsor the work](https://microvm.aerol.ai/enterprise/maintainer/). It is built in the open and ships to everyone.

---

## 5. Image signature checks

**Title:** Proposal: check image signatures before a sandbox starts

**Body:**

### The problem

AerolVM runs whatever image a create names. It does not check signatures or attestations, so a tampered image or one from the wrong registry starts like any other.

### What you can do today

Check signatures in your build pipeline, for example with `cosign verify`. Then pin the checked image by digest (`image@sha256:...`), so the sandbox runs exactly what you checked.

### A starting shape

- The operator lists trusted signers in a policy file: public keys, or keyless identities through Sigstore (a public service for signing and checking software).
- Before a pull, the server checks the image's signature. With no valid signature, the create is refused and the reason is written to the audit log.
- The policy can apply to every image, or only to some registries.
- It covers each way an image reaches a sandbox: Docker, containerd, the Firecracker image builder, and WebAssembly modules pulled from a registry.

### Questions for you

1. Do you sign with keys, or keyless through Sigstore?
2. Do you need checks on attestations too, such as SLSA provenance or an SBOM?
3. Should a failed check refuse the create, or only warn at first?
4. Which registries do you pull from?

### How to weigh in

React with 👍 if you need this, and comment with your answers. If your company needs it soon, you can [sponsor the work](https://microvm.aerol.ai/enterprise/maintainer/). It is built in the open and ships to everyone.

---

## 6. Closed network by default

**Title:** Proposal: start sandboxes with a closed network by default

**Body:**

### The problem

A sandbox with no network policy can reach the internet, plus anything its server can reach. That includes private addresses, the cloud metadata service (`169.254.169.254`) and other sandboxes. V8 isolates are the one exception. The server-wide guards only apply once the operator writes a network policy file: a default policy, address ranges that are always blocked, and a guard for AerolVM's own ports. A fresh install has no such file.

### What you can do today

Set `networkBlockAll` or `networkAllowOut` on every create. Or write a policy file (`SB_EGRESS_OPERATOR_FILE`) with `default_policy: block_all`, add `169.254.169.254/32` to `deny_cidrs`, and keep the control-port guard on. The [Hardening](https://microvm.aerol.ai/enterprise/hardening/) page has the file.

### A starting shape

Two steps, so nobody's setup breaks without warning:

1. **Always on, even with no policy file:** block the cloud metadata service and AerolVM's own ports for every sandbox. Very little real code needs either, and both are common targets.
2. **New installs start closed:** `install.sh` writes a policy file with `default_policy: block_all`. Existing servers keep their behavior until the operator opts in, and a release note says how.

A sandbox that needs the internet still asks for it with `networkAllowOut`.

### Questions for you

1. Would step 1 break anything you run? Some setups read the metadata service on purpose.
2. Should new installs start with `block_all`, or with an allow list of common package sites?
3. How much warning do you need before a default changes on existing servers?

### How to weigh in

React with 👍 if you need this, and comment with your answers. If your company needs it soon, you can [sponsor the work](https://microvm.aerol.ai/enterprise/maintainer/). It is built in the open and ships to everyone.
