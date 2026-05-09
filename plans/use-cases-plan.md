# AerolVM Use Cases Plan

## Objective

Create a use-cases section that shows how AerolVM can support high-impact modern workloads across infrastructure, coding agents, browser-driven workflows, QA, data, machine learning, and secure product backends.

This plan uses two lenses at once:

1. What AerolVM can support with the SDK and docs that exist today.
2. What adjacent platforms such as E2B and Daytona highlight as market-relevant workload patterns.

The goal is not to copy those products feature-for-feature. The goal is to map the highest-value workload space onto AerolVM accurately, then separate `Native` coverage from `Composed` and `Extended` patterns.

## Sources Reviewed

### AerolVM repository sources

- Docs pages reviewed: sandbox lifecycle, SDK setup, process execution, sessions, file system, preview, external storage, network isolation, SSH access.
- SDK surfaces reviewed: TypeScript, Python, Rust, Java, plus repo memory notes about SDK parity.

### External references reviewed

- E2B use-case pages and docs index:
  - Coding agents
  - Computer use
  - Cloud browser and remote browser
  - GitHub Actions and CI-CD
- Daytona guides and broader docs surface:
  - AgentKit, Claude, Codex, Amp, Mastra, Letta, OpenAI Agents, OpenCode, OpenClaw
  - Data analysis and LangChain workflows
  - Reinforcement-learning guides
  - Sandboxes, preview, file system, git, PTY, SSH access, volumes, network limits, observability, runners

## AerolVM Capability Baseline

The current AerolVM SDK and docs clearly support these building blocks today:

- Sandbox lifecycle: create, get, list, start, stop, destroy, resize, update lifecycle.
- Runtime isolation: standard container runtime plus `gvisor` for stronger isolation.
- Execution modes: buffered `exec`, live `execStream`, PTY support, stdin, resize, signals, graceful close.
- Persistent processes: named sessions, multi-attach, output replay, session logs, session recordings.
- Files: upload and download through the toolbox API.
- External storage: S3, NFS, SSHFS, and `rclone`-backed mounts.
- Exposure: public sandbox URL plus per-port public routes.
- Access: per-sandbox SSH keys and an SSH gateway.
- Network restriction: full outbound block mode.
- Operations: health checks, reconcile, mount inspection, exposed-port metadata.

## Honest Positioning Constraints

To keep the use-cases page accurate, these limits should be called out explicitly:

- AerolVM does not currently publish first-class browser-desktop control APIs such as mouse, keyboard, screenshot, display, or recording services in the way Daytona documents them.
- AerolVM does not currently document a first-class snapshot, template catalog, or volume API comparable to Daytona or E2B reusable environments.
- AerolVM does not currently document Git, LSP, webhook, or observability APIs as dedicated top-level SDK services.
- Browser-agent and cloud-browser use cases are still possible, but they are mostly `Composed` or `Extended` because they rely on installing Playwright, Chromium, or a custom browser stack inside the sandbox.
- AerolVM does not currently advertise dedicated GPU selection, scheduler integration, or distributed-training primitives, so the strongest ML positioning today is CPU-friendly training, preprocessing, inference, packaging, and orchestration-backed experiments.

## Coverage Legend

| Label | Meaning |
|---|---|
| `Native` | Directly supported by current AerolVM SDKs and documented APIs. |
| `Composed` | Achievable by combining AerolVM primitives with additional software installed in the sandbox. |
| `Extended` | Feasible, but depends on adjacent tooling patterns that are not yet first-class in AerolVM. |

## Impact Scoring

Impact is scored out of `10` based on how strongly the use case matters in the current software landscape.

- `10/10`: Core modern platform pattern with clear market pull.
- `9/10`: High-leverage workflow that strongly improves product velocity or product capability.
- `8/10`: Valuable and common workflow with broad adoption potential.
- `7/10`: Useful niche or secondary workflow that matters for specific teams.
- `6/10` and below: More niche than core. These were generally excluded here.

## Recommended Information Architecture for the Docs Page

The public docs page should:

1. Explain the coverage legend first.
2. Anchor every workload in AerolVM primitives already present in the SDKs.
3. Include a short note that browser and desktop agent workflows are mostly composed today.
4. Include a separate machine-learning section instead of hiding ML workloads inside the AI-evaluation bucket.
5. Group use cases by outcome instead of by raw API feature.

## Use-Case Matrix

### 1. Infrastructure & Environment Provisioning

Implementation pattern:

1. Create sandbox with image, runtime, env, lifecycle, and optional mounts.
2. Stream bootstrap logs with `execStream`.
3. Expose service ports when browser access is needed.
4. Stop or destroy automatically when the environment is no longer active.

| # | Use case | Impact | Coverage | Why it matters | AerolVM building blocks |
|---:|---|---:|---|---|---|
| 1 | Branch preview environment for each pull request | 9/10 | `Native` | Makes every code change reviewable with real runtime behavior instead of screenshots and guesswork. | `create`, `execStream`, `exposePort`, `updateLifecycle` |
| 2 | Create your Supabase-ready dev stack in an isolated sandbox | 8/10 | `Composed` | Gives each engineer or feature branch a self-contained backend surface without polluting shared environments. | `create`, `uploadFile`, `execStream`, `exposePort`, `mounts` |
| 3 | Per-customer demo environment with seeded data | 8/10 | `Native` | Lets sales, support, and success teams demo realistic scenarios safely. | `create`, `env`, `exposePort`, `updateLifecycle` |
| 4 | Database migration rehearsal environment | 8/10 | `Native` | Reduces production migration risk by replaying changes in disposable infrastructure. | `create`, `mounts`, `exec`, `sessions` |
| 5 | Third-party integration test bed | 8/10 | `Native` | Isolates risky partner integrations and keeps secrets and failure states out of shared infra. | `create`, `env`, `networkBlockAll`, `exposePort` |
| 6 | One-click onboarding environment for new hires | 8/10 | `Native` | Shrinks time-to-first-commit and standardizes tool setup. | `create`, `uploadFile`, `sessions`, `ssh` |
| 7 | Sandbox-per-ticket backend replica | 8/10 | `Native` | Lets engineers and agents debug a task in isolation without resource contention. | `create`, `resize`, `updateLifecycle`, `exposePort` |
| 8 | Region-specific staging replica | 7/10 | `Composed` | Useful when teams need to validate data residency or regional configuration assumptions. | `create`, `env`, `mounts`, `exposePort` |
| 9 | Open source stack evaluation lab | 7/10 | `Composed` | Helps teams evaluate stacks quickly without touching laptops or shared servers. | `create`, `uploadFile`, `execStream`, `exposePort` |
| 10 | Secure contractor infrastructure workspace | 8/10 | `Native` | Gives external contributors a bounded workspace without broad host access. | `create`, `ssh`, `networkBlockAll`, `updateLifecycle` |

### 2. Remote Developer Workspaces

Implementation pattern:

1. Create an isolated sandbox per engineer, task, or incident.
2. Use SSH or persistent sessions for continuity.
3. Mount shared data only when needed.
4. Expose app or API ports for live previews.

| # | Use case | Impact | Coverage | Why it matters | AerolVM building blocks |
|---:|---|---:|---|---|---|
| 1 | Polyglot cloud devbox for app development | 8/10 | `Native` | Centralizes setup and gives every engineer a reproducible environment. | `create`, `ssh`, `uploadFile`, `downloadFile` |
| 2 | Persistent pair-programming shell | 8/10 | `Native` | Enables human-human or human-agent collaboration without losing terminal state. | `createSession`, `attachSession`, `sessionLog` |
| 3 | VS Code or JetBrains remote workspace over SSH | 9/10 | `Native` | Converts AerolVM into a remote IDE backend with minimal extra tooling. | `ssh`, `create`, `sessions`, `updateLifecycle` |
| 4 | Frontend live preview workspace | 8/10 | `Native` | Makes UI work easy to review from anywhere with safe isolated previews. | `execStream`, `exposePort`, `uploadFile` |
| 5 | Backend debugging environment with mounted fixtures | 8/10 | `Native` | Keeps messy repro work off production or shared staging. | `create`, `mounts`, `execStream`, `sessions` |
| 6 | Reproducible OSS contribution workspace | 7/10 | `Native` | Lowers contributor friction and avoids "works on my machine" drift. | `create`, `ssh`, `execStream`, `downloadFile` |
| 7 | Customer issue reproduction workspace | 9/10 | `Native` | High leverage for support and incident response because it isolates hard bugs quickly. | `create`, `env`, `uploadFile`, `sessionLog` |
| 8 | Workshop and classroom lab environment | 8/10 | `Native` | Simplifies training and education by avoiding laptop setup variance. | `create`, `updateLifecycle`, `uploadFile`, `exposePort` |
| 9 | Remote data cleanup workspace | 7/10 | `Native` | Useful for analysts or ops teams who need controlled access to mounted datasets. | `mounts`, `exec`, `downloadFile` |
| 10 | Secure vendor support workspace with limited lifetime | 8/10 | `Native` | Gives temporary access without handing over persistent infrastructure credentials. | `create`, `ssh`, `updateLifecycle`, `networkBlockAll` |

### 3. Coding Agents & Autonomous Engineering

Implementation pattern:

1. Start a sandbox per task, repo, or branch.
2. Upload or clone the target codebase into the sandbox.
3. Run the agent through `execStream` or a persistent session.
4. Pull out diffs, generated files, logs, or test artifacts.

| # | Use case | Impact | Coverage | Why it matters | AerolVM building blocks |
|---:|---|---:|---|---|---|
| 1 | Autonomous issue-to-PR coding agent | 10/10 | `Native` | One of the highest-value modern workloads for secure sandbox infrastructure. | `create`, `execStream`, `uploadFile`, `downloadFile`, `sessions` |
| 2 | Pull-request review and auto-fix agent | 9/10 | `Native` | Helps teams close feedback loops faster without granting agents host access. | `exec`, `execStream`, `sessionLog`, `downloadFile` |
| 3 | Test-writing and failing-test reproduction agent | 9/10 | `Native` | Great fit for isolated execution because tests often mutate environments heavily. | `uploadFile`, `execStream`, `sessions` |
| 4 | Dependency upgrade and compatibility agent | 9/10 | `Native` | Lets agents change packages, run builds, and validate results in a disposable environment. | `execStream`, `downloadFile`, `updateLifecycle` |
| 5 | Large-scale refactor or migration agent | 9/10 | `Native` | Long-lived sessions and streamed logs map well to iterative codebase-wide changes. | `sessions`, `uploadFile`, `downloadFile`, `execStream` |
| 6 | Documentation regeneration agent | 8/10 | `Native` | Useful for API docs, example updates, and release-note generation. | `exec`, `uploadFile`, `downloadFile`, `exposePort` |
| 7 | Multi-agent bug-fixer pipeline | 9/10 | `Composed` | High value pattern where specialized agents coordinate through files and sessions. | `create`, `sessions`, `sessionLog`, `downloadFile` |
| 8 | Long-running background coding worker | 9/10 | `Native` | Persistent sessions let agents survive reconnects and external orchestration restarts. | `createSession`, `attachSession`, `updateLifecycle` |
| 9 | Security patch verification agent | 9/10 | `Native` | Strong fit for `gvisor` and isolated execution of untrusted patches or tests. | `gvisor`, `networkBlockAll`, `execStream` |
| 10 | Multi-repo batch transformation agent | 8/10 | `Composed` | Useful for org-wide policy or API migrations, even if orchestration sits outside AerolVM. | `create`, `execStream`, `mounts`, `downloadFile` |

### 4. Browser Agents & Web Automation

Implementation pattern:

1. Install browser automation tooling in the sandbox image or bootstrap step.
2. Run browser tasks through `execStream` or persistent sessions.
3. Retrieve logs, screenshots, traces, and generated artifacts through files.
4. Expose app ports when the workload needs to drive a live preview.

| # | Use case | Impact | Coverage | Why it matters | AerolVM building blocks |
|---:|---|---:|---|---|---|
| 1 | Playwright or Cypress regression runner | 9/10 | `Composed` | Essential for modern UI verification without granting direct workstation access. | `create`, `execStream`, `uploadFile`, `downloadFile` |
| 2 | Web research agent in an isolated runtime | 8/10 | `Composed` | Keeps autonomous browsing separate from app infrastructure and developer laptops. | `create`, `execStream`, `downloadFile`, `networkBlockAll` |
| 3 | Form-filling and browser RPA worker | 8/10 | `Extended` | Valuable for internal workflows, but needs browser tooling beyond the AerolVM SDK itself. | `create`, `execStream`, `sessions`, `exposePort` |
| 4 | Checkout flow validator against preview URLs | 9/10 | `Composed` | Strong product QA use case for every commerce or signup-heavy app. | `exposePort`, `execStream`, `downloadFile` |
| 5 | Visual regression screenshot worker | 8/10 | `Composed` | Useful for catching UI drift and design regressions in generated apps. | `create`, `exec`, `downloadFile` |
| 6 | Lighthouse, SEO, and performance audit runner | 8/10 | `Composed` | Important for web teams that want repeatable measurements against preview apps. | `create`, `execStream`, `downloadFile` |
| 7 | Browser-assisted customer support reproducer | 8/10 | `Composed` | Lets support teams or agents replay issues safely in isolated environments. | `sessions`, `sessionLog`, `downloadFile`, `exposePort` |
| 8 | Internal dashboard automation over private data links | 8/10 | `Extended` | High value in enterprise workflows, but usually requires a custom private-access stack. | `mounts`, `networkBlockAll`, `execStream` |
| 9 | External site monitoring bot | 7/10 | `Composed` | Useful secondary workload for uptime and UX regression checks. | `create`, `exec`, `updateLifecycle` |
| 10 | Browser-agent loop for generated apps and previews | 9/10 | `Extended` | Very strong for AI app builders, but better when browser control becomes first-class. | `create`, `execStream`, `exposePort`, `downloadFile` |

Planning note:

- AerolVM should present these as browser automation or browser-agent patterns, not computer-use parity, unless first-class desktop APIs are added.

### 5. QA, CI/CD & Release Automation

Implementation pattern:

1. Create ephemeral execution environments per pipeline job.
2. Stream logs live so CI systems can surface progress.
3. Download artifacts and test outputs.
4. Destroy the sandbox after the run or stop it for later inspection.

| # | Use case | Impact | Coverage | Why it matters | AerolVM building blocks |
|---:|---|---:|---|---|---|
| 1 | Untrusted pull request validation sandbox | 9/10 | `Native` | A textbook use case for safer build and test infrastructure. | `gvisor`, `execStream`, `networkBlockAll` |
| 2 | Matrix test runners across multiple languages | 8/10 | `Native` | Lets teams parallelize test coverage across stacks without bespoke runners. | `create`, `execStream`, `resize` |
| 3 | Artifact build verification before release | 8/10 | `Native` | Ensures packages, binaries, and images actually build in a clean environment. | `exec`, `downloadFile`, `uploadFile` |
| 4 | Release smoke-test environment | 9/10 | `Native` | High leverage because it catches obvious runtime failures before user traffic does. | `create`, `exposePort`, `execStream` |
| 5 | Schema and migration validation before deploy | 8/10 | `Native` | Helps reduce one of the highest-risk classes of deployment failure. | `mounts`, `exec`, `sessionLog` |
| 6 | Contract tests against partner APIs | 8/10 | `Native` | Useful when partner integrations are brittle or rate-limited. | `create`, `env`, `exec`, `networkBlockAll` |
| 7 | Golden-path onboarding test runner | 7/10 | `Native` | Good for product quality even if it is less core than build verification. | `execStream`, `exposePort`, `downloadFile` |
| 8 | Long-running build log streaming worker | 8/10 | `Native` | Live logs are important for debuggability and agent observability. | `execStream`, `sessions`, `sessionLog` |
| 9 | Preview validation after every app build | 8/10 | `Native` | Strong bridge between CI and browser-facing review. | `exposePort`, `execStream`, `updateLifecycle` |
| 10 | Rollback rehearsal environment | 8/10 | `Native` | Lets teams validate recoverability instead of assuming rollback will work. | `create`, `exec`, `mounts`, `sessions` |

### 6. Data Engineering & Analytics

Implementation pattern:

1. Mount durable data or upload source files.
2. Run Python, shell, or custom binaries inside the sandbox.
3. Download transformed outputs or expose reports.
4. Tear down after the data job completes.

| # | Use case | Impact | Coverage | Why it matters | AerolVM building blocks |
|---:|---|---:|---|---|---|
| 1 | CSV and Parquet cleanup jobs | 8/10 | `Native` | Common operational workload that maps cleanly to isolated compute. | `uploadFile`, `downloadFile`, `exec` |
| 2 | Python analyst workspace for SQL and notebooks | 9/10 | `Native` | High leverage for data teams who need reproducible access to mounted datasets. | `create`, `mounts`, `sessions`, `ssh` |
| 3 | Automated report generation pipeline | 8/10 | `Native` | Useful for finance, ops, customer reports, and internal dashboards. | `exec`, `downloadFile`, `exposePort` |
| 4 | ETL from APIs into mounted storage | 8/10 | `Native` | Strong fit for scheduled or user-triggered integration jobs. | `mounts`, `execStream`, `networkBlockAll` |
| 5 | Data quality validation batch runner | 8/10 | `Native` | Improves trust in downstream analytics and model workflows. | `exec`, `downloadFile`, `sessionLog` |
| 6 | Customer-specific analytics environment | 8/10 | `Native` | Valuable for multi-tenant SaaS products that need hard isolation per account. | `create`, `mounts`, `updateLifecycle` |
| 7 | Document-to-JSON extraction workflow | 8/10 | `Native` | Common modern AI and data task that benefits from isolated execution. | `uploadFile`, `exec`, `downloadFile` |
| 8 | Chart and artifact generation service | 7/10 | `Native` | Useful as a product backend or internal reporting service. | `exec`, `downloadFile`, `exposePort` |
| 9 | Batch feature-engineering pipeline | 8/10 | `Native` | Supports ML workflows without requiring a heavy bespoke platform. | `create`, `mounts`, `execStream` |
| 10 | Notebook-replacement research runner | 7/10 | `Native` | Good for teams moving analysis out of ad hoc local notebooks. | `sessions`, `uploadFile`, `downloadFile` |

### 7. AI Evaluation & Model Ops

Implementation pattern:

1. Treat each sandbox as an isolated evaluation worker.
2. Run prompts, tool calls, and code generation inside the sandbox.
3. Pull logs and artifacts out for scoring.
4. Use `gvisor` or blocked egress for higher-trust-boundary use cases.

| # | Use case | Impact | Coverage | Why it matters | AerolVM building blocks |
|---:|---|---:|---|---|---|
| 1 | Prompt evaluation harness with reproducible runs | 9/10 | `Native` | Important for teams managing prompt quality over time. | `create`, `exec`, `downloadFile` |
| 2 | Tool-using agent evaluation runner | 9/10 | `Native` | Strong fit because agent tool execution naturally maps to sandbox execution. | `execStream`, `sessions`, `downloadFile` |
| 3 | Synthetic dataset generation pipeline | 8/10 | `Native` | Helpful for bootstrapping model training and eval corpora. | `create`, `exec`, `downloadFile`, `mounts` |
| 4 | RAG ingestion and re-index jobs | 8/10 | `Native` | Good fit for isolated ingestion, chunking, and index-building tasks. | `mounts`, `execStream`, `updateLifecycle` |
| 5 | Code interpreter backend for copilots | 9/10 | `Native` | A direct match for AerolVM's execution, files, and isolation model. | `exec`, `execStream`, `uploadFile`, `downloadFile` |
| 6 | Safe execution backend for LLM-generated code | 10/10 | `Native` | One of the clearest and strongest AerolVM value propositions. | `gvisor`, `networkBlockAll`, `execStream` |
| 7 | Multi-agent simulation environment | 8/10 | `Composed` | Useful for orchestration experiments even without a first-class multi-agent SDK. | `sessions`, `sessionLog`, `mounts`, `downloadFile` |
| 8 | Guardrail and safety-policy regression suite | 9/10 | `Native` | Useful for checking refusal, policy, and agent-boundary regressions over time. | `create`, `exec`, `downloadFile`, `sessionLog` |
| 9 | Auto-grading backend for coding education | 8/10 | `Native` | Highly practical for edtech products that execute untrusted student code. | `uploadFile`, `exec`, `downloadFile` |
| 10 | Model benchmark and regression runner | 8/10 | `Native` | Useful for comparing versions, prompts, and policies in controlled environments. | `create`, `execStream`, `downloadFile` |

### 8. Machine Learning Training & Inference

Implementation pattern:

1. Mount training data or upload curated datasets into the sandbox.
2. Run CPU-friendly training, tuning, or inference jobs inside isolated workers.
3. Stream logs from long-running experiments with `execStream` or sessions.
4. Export trained artifacts, packaged models, and evaluation outputs through files or registries.

| # | Use case | Impact | Coverage | Why it matters | AerolVM building blocks |
|---:|---|---:|---|---|---|
| 1 | Training-data preprocessing and feature engineering pipeline | 9/10 | `Native` | One of the most common ML workloads and a strong fit for mounted datasets plus isolated compute. | `create`, `mounts`, `execStream`, `downloadFile` |
| 2 | Classical ML model training on mounted datasets | 8/10 | `Composed` | Useful for tabular, ranking, forecasting, and smaller deep-learning workloads that do not need cluster primitives. | `create`, `mounts`, `execStream`, `updateLifecycle` |
| 3 | Hyperparameter sweep worker pool | 8/10 | `Composed` | Lets an external orchestrator fan out multiple isolated training runs safely. | `create`, `resize`, `execStream`, `downloadFile` |
| 4 | Batch inference and rescoring jobs | 9/10 | `Native` | Very practical for recommendation, fraud, scoring, and content classification systems. | `create`, `exec`, `mounts`, `downloadFile` |
| 5 | Small-model fine-tuning workspace | 8/10 | `Composed` | Good fit for lightweight fine-tuning and LoRA-style adaptation subject to available hardware. | `create`, `mounts`, `execStream`, `updateLifecycle` |
| 6 | Model distillation and quantization pipeline | 8/10 | `Composed` | Important for shipping smaller, cheaper models into production environments. | `create`, `execStream`, `downloadFile`, `uploadFile` |
| 7 | Experiment tracking and reproducibility box | 8/10 | `Composed` | Helps teams keep runs isolated and reproducible even when experiment tracking lives outside AerolVM. | `create`, `mounts`, `execStream`, `uploadFile` |
| 8 | Training-data validation and drift analysis | 8/10 | `Native` | Useful for catching stale or broken data before retraining or inference rollout. | `exec`, `mounts`, `downloadFile`, `sessionLog` |
| 9 | Model packaging and export service | 8/10 | `Native` | Valuable for converting trained artifacts into deployable packages, wheels, or images. | `exec`, `uploadFile`, `downloadFile`, `registry` |
| 10 | Lightweight model-serving sandbox for internal eval or staging | 8/10 | `Native` | Useful for testing model APIs and smoke-checking serving behavior before wider rollout. | `create`, `execStream`, `exposePort`, `updateLifecycle` |

Planning note:

- AerolVM's current public docs do not advertise dedicated GPU, scheduler, or distributed-training primitives, so the strongest ML positioning today is CPU-friendly training, preprocessing, batch inference, experiment orchestration, and model packaging.

### 9. Storage, Integration & Enterprise Data Access

Implementation pattern:

1. Keep credentials at the platform or host mount layer.
2. Present mounted data into the sandbox only where needed.
3. Run transformation or validation jobs in the sandbox.
4. Export only the required outputs.

| # | Use case | Impact | Coverage | Why it matters | AerolVM building blocks |
|---:|---|---:|---|---|---|
| 1 | S3-backed workspaces and artifact roots | 9/10 | `Native` | Durable object storage is one of the most common persistence patterns. | `mounts`, `exec`, `downloadFile` |
| 2 | NFS-backed media or asset processing | 8/10 | `Native` | Useful for teams with existing internal storage estates. | `mounts`, `execStream`, `sessions` |
| 3 | SSHFS access into private infrastructure | 8/10 | `Native` | Helps bridge existing internal systems into isolated compute. | `mounts`, `ssh`, `networkBlockAll` |
| 4 | `rclone` bridge to cloud storage or SaaS exports | 8/10 | `Native` | Broad integration surface without having to add separate platform APIs. | `mounts`, `exec`, `downloadFile` |
| 5 | Read-only partner data clean room | 9/10 | `Native` | Important for regulated or privacy-sensitive collaboration patterns. | `mounts`, `networkBlockAll`, `gvisor` |
| 6 | Backup verification sandbox | 8/10 | `Native` | Lets teams validate recoverability without touching production systems. | `mounts`, `exec`, `sessionLog` |
| 7 | Secure export or import transformation service | 8/10 | `Native` | Useful for one-off migrations and recurring enterprise data exchange. | `uploadFile`, `downloadFile`, `mounts` |
| 8 | Private registry image workflow | 8/10 | `Native` | Critical for enterprise adoption where public images are not acceptable. | `create`, `registry`, `execStream` |
| 9 | Multi-source content assembly pipeline | 7/10 | `Native` | Valuable for content processing and packaging workflows. | `uploadFile`, `mounts`, `downloadFile` |
| 10 | Shared workspace hydration from external storage | 8/10 | `Native` | Good fit for booting user or agent workspaces from durable data roots. | `mounts`, `create`, `updateLifecycle` |

### 10. Security, Compliance & Operations

Implementation pattern:

1. Prefer `gvisor` for untrusted-code workloads.
2. Use blocked egress where possible.
3. Capture session logs and recordings when auditability matters.
4. Use reconcile and health checks as operational recovery primitives.

| # | Use case | Impact | Coverage | Why it matters | AerolVM building blocks |
|---:|---|---:|---|---|---|
| 1 | Run untrusted code under `gvisor` | 10/10 | `Native` | Directly addresses one of the highest-risk patterns in modern AI systems. | `runtime`, `execStream` |
| 2 | Fully blocked egress sandboxes for containment | 9/10 | `Native` | Essential for high-trust-boundary execution and data-loss prevention. | `networkBlockAll`, `exec`, `sessions` |
| 3 | Suspicious script detonation lab | 9/10 | `Native` | Useful for malware analysis, security triage, and internal threat review. | `gvisor`, `networkBlockAll`, `sessionLog` |
| 4 | Incident-response reproduction workspace | 9/10 | `Native` | Helps teams debug failures without poking production state live. | `create`, `uploadFile`, `execStream` |
| 5 | Least-privilege contractor access environment | 8/10 | `Native` | Valuable for reducing blast radius while still enabling delivery work. | `ssh`, `updateLifecycle`, `networkBlockAll` |
| 6 | Session recording for audit evidence | 8/10 | `Native` | Important for operational accountability and regulated workflows. | `createSession`, `sessionRecording`, `sessionLog` |
| 7 | Network policy validation harness | 8/10 | `Native` | Helps teams confirm outbound restrictions work as expected. | `networkBlockAll`, `exec`, `exposePort` |
| 8 | Secret-boundary testing for generated code | 8/10 | `Native` | Strong AI safety and platform-security use case. | `mounts`, `gvisor`, `networkBlockAll` |
| 9 | Drift recovery after host or runtime mismatch | 7/10 | `Native` | Operationally useful when container state and control-plane state diverge. | `reconcile`, `health`, `list` |
| 10 | Secure evidence collection and export | 8/10 | `Native` | Useful for audits, incidents, and support escalations. | `downloadFile`, `sessionLog`, `sessionRecording` |

### 11. Customer-Facing Product Experiences

Implementation pattern:

1. Treat each user or request as an isolated sandbox-backed workload.
2. Run code or app processes inside the sandbox.
3. Surface results through files, streamed output, or preview URLs.
4. Stop or destroy the sandbox based on product lifecycle rules.

| # | Use case | Impact | Coverage | Why it matters | AerolVM building blocks |
|---:|---|---:|---|---|---|
| 1 | Embedded code runner inside a SaaS product | 10/10 | `Native` | One of the clearest product integrations for secure execution infrastructure. | `create`, `exec`, `downloadFile` |
| 2 | Interactive tutorial or lab backend | 9/10 | `Native` | Strong fit for education, docs, onboarding, and product-led growth. | `create`, `sessions`, `updateLifecycle`, `exposePort` |
| 3 | AI app builder runtime | 9/10 | `Native` | High-value modern product pattern that turns generated code into running previews. | `execStream`, `uploadFile`, `exposePort` |
| 4 | Live preview URLs for generated apps or APIs | 10/10 | `Native` | One of the most visible end-user outcomes AerolVM can enable today. | `exposePort`, `execStream`, `publicURL` |
| 5 | One-click user sandbox per workspace | 9/10 | `Native` | Ideal for multi-tenant products that need hard execution isolation. | `create`, `start`, `stop`, `destroy` |
| 6 | Multi-tenant job isolation layer | 9/10 | `Native` | Useful for platforms executing user code, user scripts, or per-customer jobs. | `create`, `updateLifecycle`, `networkBlockAll` |
| 7 | Background document or code conversion service | 8/10 | `Native` | Strong fit for products that transform user-uploaded content safely. | `uploadFile`, `exec`, `downloadFile` |
| 8 | Personalized demo environment for sales or support | 8/10 | `Native` | Helps teams show real workflows without polluting production. | `create`, `env`, `exposePort`, `updateLifecycle` |
| 9 | Self-service API playground with real execution | 8/10 | `Native` | Good fit for developer products that want live runnable examples. | `create`, `exec`, `sessions`, `exposePort` |
| 10 | Human-in-the-loop review workspace for generated changes | 8/10 | `Composed` | Useful when agents produce changes that humans need to inspect or approve. | `sessions`, `ssh`, `downloadFile`, `exposePort` |

## Category Prioritization

If the docs page needs a sharper narrative, prioritize these categories first:

1. Coding Agents & Autonomous Engineering
2. Customer-Facing Product Experiences
3. Security, Compliance & Operations
4. Infrastructure & Environment Provisioning
5. QA, CI/CD & Release Automation

If machine learning becomes a near-term product focus, elevate `Machine Learning Training & Inference` into the top five.

## Where AerolVM Is Already Strongest

- Safe code execution backends for AI products.
- Coding-agent runtimes with PTY, sessions, file transfer, and SSH.
- Preview-heavy developer workflows such as branch environments and app builders.
- ML preprocessing, batch inference, and model packaging on isolated datasets.
- External-storage-backed sandboxes for enterprise data movement.
- Secure, short-lived workspaces for debugging, support, and contractor access.

## Productization Opportunities Suggested by E2B and Daytona

These external references suggest the highest-leverage expansion areas for AerolVM:

1. First-class browser and desktop automation services.
2. Snapshot and template reuse workflows.
3. Built-in repo clone, Git helpers, and higher-level agent lifecycle primitives.
4. Observability, traces, events, and webhook delivery.
5. Stronger multi-tenant policy surfaces for orgs, quotas, and compliance.
6. Accelerator-aware ML primitives such as GPU selection, training templates, and job orchestration.

## Recommended Follow-on Docs Work

1. Add code examples that show an end-to-end coding-agent sandbox flow.
2. Add a browser-automation guide that is honest about `Composed` coverage.
3. Add a branch-preview guide that combines sandbox creation, file upload, and port exposure.
4. Add a secure-untrusted-code guide centered on `gvisor` and blocked egress.
5. Add a data-processing guide that combines mounts with sandbox execution.
6. Add a machine-learning guide that combines mounted datasets, long-running jobs, and model artifact export.

## Summary

AerolVM can already credibly support a broad modern use-case surface, especially where the workload is fundamentally about safe code execution, isolated environments, previews, files, sessions, mounted data, and small-to-medium ML workloads. The cleanest narrative is not "AerolVM does everything adjacent platforms do."

The stronger narrative is:

- AerolVM already covers the most important secure execution and agent-runtime patterns natively.
- AerolVM can already support a meaningful machine-learning story around preprocessing, inference, packaging, and CPU-friendly experimentation.
- AerolVM can cover browser and richer automation patterns compositionally today.
- The biggest future expansion areas are browser control, reusable prepared environments, and higher-level orchestration and observability.
