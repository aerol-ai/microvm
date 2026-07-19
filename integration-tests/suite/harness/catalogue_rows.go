package harness

func provRows() []CatalogueRow {
	return []CatalogueRow{
		rowNA("PROV-01", "Does a 3-node mixed cluster form?", catProv(), "", "members=3", scnMixed(), "UC-03"),
		rowNA("PROV-02", "Does the 10-node hetero cluster form?", catProv(), "", "members=10", scnHetero(), ""),
		rowNA("PROV-03", "Is a Raft leader elected?", catProv(), "", "leader present", scnBoth(), "UC-05"),
		rowNA("PROV-04", "Do heterogeneous node roles match the tfvars?", catProv(), "", "roles match", scnHetero(), "UC-04"),
		rowNA("PROV-05", "Does wildcard DNS resolve to the ingress?", catProv(), "", "A-record → ingress", scnBoth(), "UC-07"),
		rowNA("PROV-06", "Is the control-plane API reachable over HTTPS?", catProv(), "", "200 over TLS", scnBoth(), "UC-08"),
		rowNA("PROV-07", "Is the TLS chain valid (apex + wildcard)?", catProv(), "", "chain verifies", scnBoth(), "UC-09"),
		rowNA("PROV-08", "Is auth enforced (no PAT → 401)?", catProv(), "", "401", scnBoth(), "UC-10"),
		rowNA("PROV-09", "Does /v1/capacity report host capacity?", catProv(), "", "non-empty", scnBoth(), "UC-61"),
		rowNA("PROV-10", "Does admin/reconcile run clean?", catProv(), "", "no error", scnBoth(), "UC-63"),
		rowAll("PROV-11", "Are specialized runtimes advertised in gossip capacity?", catProv(), "", "each advertised", scnHetero(), "UC-87"),
		rowNA("PROV-12", "Does a second ingress node serve routes (HA ingress)?", catProv(), "", "both ingress answer", scnHetero(), ""),
		rowNA("PROV-13", "Is the persistent shared cert store reused (no re-issue)?", catProv(), "", "cert from store", scnBoth(), ""),
		rowNA("PROV-14", "Does the cluster survive a seed restart + rejoin?", catProv(), "", "members restored", scnHetero(), ""),
	}
}

func lifeRows() []CatalogueRow {
	var rows []CatalogueRow
	rows = append(rows, expandRT("LIFE", 1, 5, "Does create → running work?", catLife(), "", "status=running", scnBoth(),
		[]Runtime{RTContainerd, RTGvisor, RTWasm, RTIsolate, RTFirecracker},
		[]string{"UC-11", "UC-25", "UC-26", "UC-103", "UC-24"})...)
	rows = append(rows,
		row("LIFE-06", "Get sandbox by id", catLife(), "", "", scnBoth(), RTContainerd, "UC-12"),
		row("LIFE-07", "List includes the sandbox", catLife(), "", "", scnBoth(), RTContainerd, "UC-13"),
	)
	rows = append(rows, expandRT("LIFE", 8, 11, "Does stop → stopped work?", catLife(), "", "status=stopped", scnMixed(),
		[]Runtime{RTContainerd, RTGvisor, RTWasm, RTIsolate}, nil)...)
	rows = append(rows, row("LIFE-12", "Stop → stopped (firecracker)", catLife(), "", "status=stopped", scnHetero(), RTFirecracker, ""))
	rows = append(rows, expandRT("LIFE", 13, 16, "Does start (stopped) → running work?", catLife(), "", "running", scnMixed(),
		[]Runtime{RTContainerd, RTGvisor, RTWasm, RTIsolate}, []string{"UC-15", "", "", ""})...)
	rows = append(rows, row("LIFE-17", "Start stopped → running (firecracker)", catLife(), "", "running", scnHetero(), RTFirecracker, ""))
	rows = append(rows, expandRT("LIFE", 18, 21, "Does delete → 404 work?", catLife(), "", "404 after delete", scnMixed(),
		[]Runtime{RTContainerd, RTGvisor, RTWasm, RTIsolate}, []string{"UC-16", "", "", ""})...)
	rows = append(rows, row("LIFE-22", "Delete → 404 (firecracker)", catLife(), "", "404", scnHetero(), RTFirecracker, ""))
	rows = append(rows,
		row("LIFE-23", "Resize CPU/mem/disk", catLife(), "", "applied", scnBoth(), RTContainerd, "UC-18"),
		row("LIFE-24", "Resize with firecracker overlay disk", catLife(), "", "applied", scnHetero(), RTFirecracker, ""),
		row("LIFE-25", "Update lifecycle (idle auto-stop)", catLife(), "", "policy set", scnBoth(), RTContainerd, "UC-19"),
	)
	return rows
}

func rtRows() []CatalogueRow {
	return []CatalogueRow{
		row("RT-01", "Is containerd the default engine (no dockerd in path)?", catRT(), "", "engine=containerd", scnBoth(), RTContainerd, ""),
		row("RT-02", "Does gVisor run under a userspace kernel (runsc)?", catRT(), "", "runsc active", scnBoth(), RTGvisor, "UC-25"),
		row("RT-03", "Does the WASM resident host compile-once / instantiate-many?", catRT(), "", "1 compile, N instantiate", scnBoth(), RTWasm, ""),
		row("RT-04", "Does isolate run one workerd process per tenant group?", catRT(), "", "group reused", scnBoth(), RTIsolate, ""),
		row("RT-05", "Does Firecracker give a dedicated guest kernel per VM?", catRT(), "", "guest uname", scnHetero(), RTFirecracker, "UC-24"),
		rowNA("RT-06", "Is Kata correctly not-implemented (negative)?", catRT(), "", "clean 4xx", scnBoth(), "UC-27"),
		rowNA("RT-07", "Is an unspecified-runtime create honored, not forced to docker?", catRT(), "", "placed by default", scnHetero(), "UC-91"),
		rowAll("RT-08", "Does a runtime create place on a capability-matching worker?", catRT(), "", "correct worker", scnHetero(), "UC-90"),
		row("RT-09", "Does Firecracker cold-boot from a plain OCI image?", catRT(), "", "boots", scnHetero(), RTFirecracker, "UC-88"),
		row("RT-10", "Do Firecracker template clones have distinct kernel entropy?", catRT(), "", "unique entropy", scnHetero(), RTFirecracker, "UC-80"),
		row("RT-11", "Does isolate serve a fetch handler from an uploaded bundle?", catRT(), "", "body matches", scnBoth(), RTIsolate, "UC-103"),
	}
}

func execRows() []CatalogueRow {
	var rows []CatalogueRow
	rows = append(rows, expandRT("EXEC", 1, 5, "Does toolbox exec return output?", catExec(), "", "stdout matches", scnBoth(),
		[]Runtime{RTContainerd, RTGvisor, RTWasm, RTIsolate, RTFirecracker},
		[]string{"UC-39", "UC-44", "UC-44", "UC-44", "UC-44"})...)
	rows = append(rows,
		row("EXEC-06", "Does code-run (python interpreter) work?", catExec(), "", "result", scnBoth(), RTContainerd, ""),
		row("EXEC-07", "Does code-run (node interpreter) work?", catExec(), "", "result", scnBoth(), RTContainerd, ""),
		row("EXEC-08", "Interactive exec stream: stdin → stdout + exit code", catExec(), "", "streamed + code", scnBoth(), RTContainerd, "UC-68"),
		row("EXEC-09", "Exec with workdir + env", catExec(), "", "env honored", scnBoth(), RTContainerd, "UC-69"),
		row("EXEC-10", "Non-zero exit code propagates", catExec(), "", "code≠0 surfaced", scnBoth(), RTContainerd, ""),
		row("EXEC-11", "Large stdout streams without truncation", catExec(), "", "full bytes", scnBoth(), RTContainerd, ""),
		row("EXEC-12", "Long-running exec can be killed", catExec(), "", "terminated", scnBoth(), RTContainerd, ""),
		row("EXEC-13", "Isolate exec → fetch handler mapping", catExec(), "", "handler body", scnBoth(), RTIsolate, ""),
		row("EXEC-14", "WASM invoke via exec increments invoke metrics", catExec(), "", "invoke_total++", scnBoth(), RTWasm, ""),
		row("EXEC-15", "Exec succeeds under gVisor (syscall-filtered)", catExec(), "", "stdout matches", scnBoth(), RTGvisor, ""),
	)
	return rows
}

func fileRows() []CatalogueRow {
	return []CatalogueRow{
		row("FILE-01", "Upload a file into the sandbox", catFile(), "", "", scnBoth(), RTContainerd, "UC-40"),
		row("FILE-02", "Download a file; bytes round-trip", catFile(), "", "bytes equal", scnBoth(), RTContainerd, "UC-41"),
		row("FILE-03", "List files", catFile(), "", "listing", scnBoth(), RTContainerd, ""),
		row("FILE-04", "File info (stat)", catFile(), "", "metadata", scnBoth(), RTContainerd, ""),
		row("FILE-05", "Move / rename a file", catFile(), "", "moved", scnBoth(), RTContainerd, ""),
		row("FILE-06", "Search file contents", catFile(), "", "matches", scnBoth(), RTContainerd, ""),
		row("FILE-07", "Find files by name", catFile(), "", "matches", scnBoth(), RTContainerd, ""),
		row("FILE-08", "Git clone + status via toolbox git", catFile(), "", "repo present", scnBoth(), RTContainerd, ""),
		row("FILE-09", "Streaming upload with progress", catFile(), "", "completes", scnBoth(), RTContainerd, ""),
		row("FILE-10", "Streaming download with progress + abort", catFile(), "", "abort honored", scnBoth(), RTContainerd, ""),
		row("FILE-11", "Multi-file batch upload", catFile(), "", "all present", scnBoth(), RTContainerd, ""),
		row("FILE-12", "Large file (100 MB) round-trips", catFile(), "", "bytes equal", scnHetero(), RTContainerd, ""),
		row("FILE-13", "File ops work under gVisor", catFile(), "", "round-trip", scnBoth(), RTGvisor, ""),
	}
}

func sessRows() []CatalogueRow {
	return []CatalogueRow{
		row("SESS-01", "Create session + run command", catSess(), "", "output", scnBoth(), RTContainerd, "UC-42"),
		row("SESS-02", "Session lifecycle (list/get/signal/resize)", catSess(), "", "states", scnBoth(), RTContainerd, "UC-70"),
		row("SESS-03", "Session recording is downloadable", catSess(), "", "recording bytes", scnBoth(), RTContainerd, "UC-71"),
		row("SESS-04", "Sessions proxy streams", catSess(), "", "stream", scnBoth(), RTContainerd, "UC-45"),
		row("SESS-05", "Session replay after reattach", catSess(), "", "replay", scnBoth(), RTContainerd, ""),
		row("SESS-06", "Idempotent session by name", catSess(), "", "same session", scnBoth(), RTContainerd, ""),
		row("SESS-07", "PTY create + send input", catSess(), "", "echoed", scnBoth(), RTContainerd, ""),
		row("SESS-08", "PTY resize", catSess(), "", "resized", scnBoth(), RTContainerd, ""),
		row("SESS-09", "PTY kill + wait", catSess(), "", "exited", scnBoth(), RTContainerd, ""),
		row("SESS-10", "Async session with streamed logs", catSess(), "", "logs stream", scnBoth(), RTContainerd, ""),
	}
}

func netRows() []CatalogueRow {
	var rows []CatalogueRow
	rows = append(rows, expandRT("NET", 1, 5, "Expose port → preview URL", catNet(), "", "URL returned", scnBoth(),
		[]Runtime{RTContainerd, RTGvisor, RTWasm, RTIsolate, RTFirecracker},
		[]string{"UC-29", "UC-29", "UC-29", "UC-29", "UC-29"})...)
	rows = append(rows,
		row("NET-06", "Is the preview URL reachable over HTTPS after expose?", catNet(), "", "200", scnBoth(), RTContainerd, "UC-30"),
		row("NET-07", "Is expose_port idempotent (same URL)?", catNet(), "", "same URL", scnBoth(), RTContainerd, "UC-31"),
		row("NET-08", "Does unexpose remove the route?", catNet(), "", "route gone", scnBoth(), RTContainerd, "UC-33"),
		row("NET-09", "Is the default <id>.<domain> unreachable until expose?", catNet(), "", "not routable", scnBoth(), RTContainerd, "UC-32"),
		row("NET-10", "Private-by-default: exec works while private", catNet(), "", "no public URL, exec ok", scnBoth(), RTContainerd, "UC-97"),
		row("NET-11", "Raw TCP host-port reachable (L4)", catNet(), "", "TCP connect", scnBoth(), RTContainerd, "UC-34"),
		row("NET-12", "TLS-SNI expose (protocol=tls) — Postgres :5432", catNet(), "", "TLS wire", scnBoth(), RTContainerd, ""),
		row("NET-13", "Raw TCP expose (protocol=tcp) — Redis :6379", catNet(), "", "RESP reachable", scnBoth(), RTContainerd, ""),
		row("NET-14", "Raw TCP expose — SOCKS5 VPN :1080", catNet(), "", "proxy answers", scnBoth(), RTContainerd, ""),
		row("NET-15", "Mask request host (dev-server Host rewrite)", catNet(), "", "upstream sees rewrite", scnBoth(), RTContainerd, ""),
		row("NET-16", "Add custom domain → DNS instructions", catNet(), "", "CNAME record", scnBoth(), RTContainerd, "UC-35"),
		row("NET-17", "Custom domain reachable after CNAME", catNet(), "", "200", scnBoth(), RTContainerd, "UC-36"),
		rowNA("NET-18", "Ingress DNS target published", catNet(), "", "target present", scnBoth(), "UC-77"),
	)
	return rows
}

func egrRows() []CatalogueRow {
	return []CatalogueRow{
		row("EGR-01", "Allow-out CIDR is permitted", catEgr(), "", "reachable", scnBoth(), RTContainerd, ""),
		row("EGR-02", "Deny-out CIDR is blocked", catEgr(), "", "dropped", scnBoth(), RTContainerd, ""),
		row("EGR-03", "block-all drops real traffic", catEgr(), "", "no egress", scnBoth(), RTContainerd, "UC-98"),
		row("EGR-04", "Byte-in limit enforced (DROP on cross)", catEgr(), "", "capped", scnHetero(), RTContainerd, ""),
		row("EGR-05", "Byte-out limit enforced", catEgr(), "", "capped", scnHetero(), RTContainerd, ""),
		row("EGR-06", "Network usage counters returned", catEgr(), "", "counters", scnBoth(), RTContainerd, "UC-37"),
		row("EGR-07", "Network limits patch enforced", catEgr(), "", "applied", scnBoth(), RTContainerd, "UC-38"),
		row("EGR-08", "Isolate per-sandbox egress: allow vs block-all in one tenant", catEgr(), "", "200 vs 403", scnBoth(), RTIsolate, "UC-104"),
		row("EGR-09", "Isolate egress-pool exhaustion → EGRESS_DENY", catEgr(), "", "deny on exhaust", scnHetero(), RTIsolate, ""),
		row("EGR-10", "gVisor + block-all high-trust boundary", catEgr(), "", "contained", scnBoth(), RTGvisor, ""),
	}
}

func isoRows() []CatalogueRow {
	return []CatalogueRow{
		row("ISO-01", "gVisor kernel-probe: is the host kernel invisible (synthetic /proc)?", catISO(), "", "synthetic fields", scnBoth(), RTGvisor, ""),
		row("ISO-02", "Docker kernel-probe baseline: host kernel leaks (diff target)", catISO(), "", "real host fields", scnBoth(), RTContainerd, ""),
		row("ISO-03", "Firecracker: does uname show the guest kernel, not the host?", catISO(), "", "guest kernel", scnHetero(), RTFirecracker, ""),
		row("ISO-04", "Isolate: cross-tenant process boundary holds", catISO(), "", "separate processes", scnBoth(), RTIsolate, ""),
		row("ISO-05", "Are Linux capabilities dropped under gVisor (CapEff)?", catISO(), "", "reduced caps", scnBoth(), RTGvisor, ""),
		row("ISO-06", "secure-burner-browser: isolated Chromium desktop serves", catISO(), "", "noVNC 200", scnBoth(), RTGvisor, ""),
		row("ISO-07", "burner-minecraft: disposable desktop streams via noVNC", catISO(), "", "dashboard + noVNC", scnBoth(), RTContainerd, ""),
		row("ISO-08", "GPU + gVisor rejected (negative)", catISO(), "", "rejected", scnBoth(), RTGvisor, "UC-28"),
		row("ISO-09", "Snapshot-clone entropy uniqueness (no duplicate UUID)", catISO(), "", "unique", scnHetero(), RTFirecracker, ""),
		rowMultiRT("ISO-10", "Untrusted code cannot reach host filesystem", catISO(), "", "denied", scnHetero(), []Runtime{RTFirecracker, RTGvisor}, ""),
		rowMultiRT("ISO-11", "Untrusted code cannot reach host network (block-all)", catISO(), "", "denied", scnHetero(), []Runtime{RTFirecracker, RTGvisor}, ""),
	}
}

func snapRows() []CatalogueRow {
	return []CatalogueRow{
		row("SNAP-01", "Snapshot create", catSnap(), "", "snapshot id", scnBoth(), RTContainerd, "UC-20"),
		row("SNAP-02", "Register snapshot + create from it", catSnap(), "", "boots from snap", scnBoth(), RTContainerd, "UC-21"),
		row("SNAP-03", "Snapshot resume preserves in-sandbox state", catSnap(), "", "state intact", scnHetero(), RTContainerd, ""),
		row("SNAP-04", "Warm-pool hit (docker)", catSnap(), "", "pool hit metric", scnBoth(), RTContainerd, ""),
		row("SNAP-05", "Warm-pool hit (WASM resident)", catSnap(), "", "resident reuse", scnBoth(), RTWasm, ""),
		row("SNAP-06", "Warm-pool hit (isolate blank host)", catSnap(), "", "group reuse", scnBoth(), RTIsolate, ""),
		row("SNAP-07", "Warm-pool hit (Firecracker paused VMM)", catSnap(), "", "vmm acquire hit", scnHetero(), RTFirecracker, ""),
		rowAll("SNAP-08", "Cold vs warm create delta is measured", catSnap(), "", "delta reported", scnBoth(), ""),
		row("SNAP-09", "Template reuse skips OCI→ext4 build (fc)", catSnap(), "", "template hit", scnHetero(), RTFirecracker, ""),
		row("SNAP-10", "Create from a Daytona AI-agent snapshot (penify)", catSnap(), "", "boots", scnBoth(), RTContainerd, ""),
	}
}

func svcRows() []CatalogueRow {
	return []CatalogueRow{
		row("SVC-01", "Postgres 16 + row-level security boots (your-own-supabase)", catSVC(), "Database", "RLS query OK", scnBoth(), RTContainerd, ""),
		row("SVC-02", "Postgres exposed over TLS-SNI (:5432)", catSVC(), "Database", "psql over TLS", scnBoth(), RTContainerd, ""),
		row("SVC-03", "Postgres role DSNs (anon/authenticated/service_role) enforce RLS", catSVC(), "Database", "anon denied, svc allowed", scnBoth(), RTContainerd, ""),
		row("SVC-04", "Redis 7 + Upstash-compatible REST API (create-upstash-redis)", catSVC(), "Cache", "SET/GET via REST", scnBoth(), RTContainerd, ""),
		row("SVC-05", "Redis raw TCP (:6379) reachable", catSVC(), "Cache", "RESP round-trip", scnBoth(), RTContainerd, ""),
		row("SVC-06", "Temporal-clone workflow completes (Create-Your-Own-Temporal)", catSVC(), "Workflow/durable", "5-step done", scnBoth(), RTContainerd, ""),
		row("SVC-07", "Temporal workflow retries a failed activity", catSVC(), "Workflow/durable", "retry then success", scnBoth(), RTContainerd, ""),
		row("SVC-08", "Temporal durable state survives (host SQLite WAL)", catSVC(), "Workflow/durable", "state persisted", scnHetero(), RTContainerd, ""),
		row("SVC-09", "Temporal serverless vs durable modes both run", catSVC(), "Workflow/durable", "both modes", scnHetero(), RTContainerd, ""),
		row("SVC-10", "Hosted JupyterLab on a public URL (headless-jupyter)", catSVC(), "Notebook", "tokenized 200", scnBoth(), RTContainerd, ""),
		row("SVC-11", "DuckDB SQL-over-HTTP endpoint (duckdb-dataset-explorer)", catSVC(), "Analytics", "SQL answers", scnBoth(), RTContainerd, ""),
		row("SVC-12", "Deploy a GitHub app to a public URL (ai-app-hosting)", catSVC(), "Hosting", "app serves", scnBoth(), RTContainerd, ""),
		row("SVC-13", "Host an app on a custom domain (ai-app-hosting-2)", catSVC(), "Hosting", "custom-domain 200", scnHetero(), RTContainerd, ""),
		row("SVC-14", "SOCKS5 burner VPN (burner-vpn)", catSVC(), "VPN", "proxy works", scnBoth(), RTContainerd, ""),
		row("SVC-15", "EdTech coding-interview platform w/ nested sandboxes", catSVC(), "EdTech", "nested create", scnHetero(), RTContainerd, ""),
		row("SVC-16", "One-click per-user sandbox app", catSVC(), "EdTech", "user sandbox up", scnHetero(), RTContainerd, ""),
	}
}

func compRows() []CatalogueRow {
	return []CatalogueRow{
		row("COMP-01", "Parallel ML tuning fleet: 3 trainers (hyperparameter-tuning-farm)", catComp(), "ML fan-out", "3 accuracies", scnBoth(), RTContainerd, ""),
		row("COMP-02", "Fleet spin-up → crush job → teardown", catComp(), "ML fan-out", "all destroyed", scnBoth(), RTContainerd, ""),
		row("COMP-03", "Kaggle → Parquet ETL with Polars (kaggle-to-parquet)", catComp(), "Data ETL", "parquet emitted", scnBoth(), RTContainerd, ""),
		row("COMP-04", "DuckDB in-memory analytics over a dataset", catComp(), "Analytics", "query result", scnBoth(), RTContainerd, ""),
		row("COMP-05", "matplotlib chart artifacts (Daytona charts)", catComp(), "Code-interpreter", "PNGs returned", scnBoth(), RTContainerd, ""),
		row("COMP-06", "RandomForest training returns accuracy", catComp(), "ML fan-out", "accuracy", scnBoth(), RTContainerd, ""),
		row("COMP-07", "Parallel fan-out of N sandboxes (scale test)", catComp(), "ML fan-out", "N running", scnHetero(), RTContainerd, ""),
		rowAll("COMP-08", "CPU-bound benchmark per runtime (throughput)", catComp(), "Benchmark", "ops/s recorded", scnHetero(), ""),
		row("COMP-09", "Data download → process → download-back pipeline", catComp(), "Data ETL", "result bytes", scnBoth(), RTContainerd, ""),
		row("COMP-10", "FFmpeg-style transcode job (compute burst)", catComp(), "Media", "output file", scnHetero(), RTContainerd, ""),
	}
}

func aiRows() []CatalogueRow {
	return []CatalogueRow{
		row("AI-01", "claude-code generates a repo architecture doc (arch.md)", catAI(), "Repo agent", "arch.md non-empty", scnBoth(), RTContainerd, ""),
		row("AI-02", "claude-code PR-review auto-fix", catAI(), "Repo agent", "diff produced", scnHetero(), RTContainerd, ""),
		row("AI-03", "claude-code writes tests (bulk test generation)", catAI(), "Repo agent", "tests generated", scnHetero(), RTContainerd, ""),
		row("AI-04", "claude-code security-remediation pass", catAI(), "Repo agent", "fixes produced", scnHetero(), RTContainerd, ""),
		row("AI-05", "claude-code large-scale refactor", catAI(), "Repo agent", "refactor applied", scnHetero(), RTContainerd, ""),
		row("AI-06", "AI agent runs under gVisor (untrusted output isolated)", catAI(), "Security", "contained + output", scnHetero(), RTGvisor, ""),
		row("AI-07", "Penify AI-agent snapshot boots + runs (Daytona create-vm)", catAI(), "Hosted agent", "agent runs", scnBoth(), RTContainerd, ""),
		row("AI-08", "Hosted AI-agent-orchestrator app on custom domain", catAI(), "Hosted agent", "serves", scnHetero(), RTContainerd, ""),
		row("AI-09", "AI code-interpreter: generate + execute code", catAI(), "Code-interpreter", "code + result", scnBoth(), RTContainerd, ""),
		row("AI-10", "AI agent with docker-in-docker (penify image)", catAI(), "Hosted agent", "dind works", scnHetero(), RTContainerd, ""),
		row("AI-11", "AI agent long-running with idle-stop lifecycle", catAI(), "Hosted agent", "stops when idle", scnHetero(), RTContainerd, ""),
		rowMultiRT("AI-12", "Per-user AI agent sandbox at density", catAI(), "Density", "many tenants", scnHetero(), []Runtime{RTIsolate, RTContainerd}, ""),
	}
}

func mntRows() []CatalogueRow {
	return []CatalogueRow{
		row("MNT-01", "S3 mount readable inside sandbox", catMNT(), "S3", "object read", scnHetero(), RTContainerd, ""),
		row("MNT-02", "NFS mount read/write", catMNT(), "NFS", "round-trip", scnHetero(), RTContainerd, ""),
		row("MNT-03", "SSHFS mount read/write", catMNT(), "SSHFS", "round-trip", scnHetero(), RTContainerd, ""),
		row("MNT-04", "rclone mount readable", catMNT(), "rclone", "object read", scnHetero(), RTContainerd, ""),
		row("MNT-05", "Platform volume attach: write + read-back", catMNT(), "Platform volumes", "data returned", scnBoth(), RTContainerd, "UC-81"),
		row("MNT-06", "Volume persists across destroy; re-attach sees data", catMNT(), "Platform volumes", "persisted", scnBoth(), RTContainerd, "UC-82"),
		row("MNT-07", "Two sandboxes share one volume", catMNT(), "Platform volumes", "both read", scnBoth(), RTContainerd, "UC-83"),
		row("MNT-08", "Read-only volume rejects writes", catMNT(), "Platform volumes", "write denied", scnBoth(), RTContainerd, "UC-84"),
		row("MNT-09", "Volume subpath mount for multi-tenancy", catMNT(), "Platform volumes", "isolated paths", scnHetero(), RTContainerd, ""),
		row("MNT-10", "Platform volumes rejected on WASM (negative)", catMNT(), "Platform volumes", "rejected", scnBoth(), RTWasm, "UC-85"),
		row("MNT-11", "Platform volumes rejected on Firecracker (negative)", catMNT(), "Platform volumes", "rejected", scnHetero(), RTFirecracker, "UC-86"),
		row("MNT-12", "Mount list returned", catMNT(), "Platform volumes", "listing", scnBoth(), RTContainerd, "UC-66"),
		row("MNT-13", "Max 8 mounts/sandbox enforced", catMNT(), "Limits", "9th rejected", scnHetero(), RTContainerd, ""),
		row("MNT-14", "Sensitive mount target refused (/etc, /usr)", catMNT(), "Limits", "refused", scnHetero(), RTContainerd, ""),
	}
}

func haRows() []CatalogueRow {
	return []CatalogueRow{
		row("HA-01", "New sandbox gets a placement", catHA(), "", "placement id", scnBoth(), RTContainerd, "UC-53"),
		row("HA-02", "Non-owner request forwards to owner", catHA(), "", "correct answer", scnBoth(), RTContainerd, "UC-54"),
		row("HA-03", "Sandbox index consistent across nodes", catHA(), "", "consistent", scnBoth(), RTContainerd, "UC-55"),
		row("HA-04", "Drain node → sandboxes evacuate", catHA(), "", "evacuated", scnHetero(), RTContainerd, "UC-56"),
		row("HA-05", "Uncordon restores schedulability", catHA(), "", "schedulable", scnHetero(), RTContainerd, "UC-57"),
		row("HA-06", "Owner failover → replica serves", catHA(), "", "replica serves", scnHetero(), RTContainerd, "UC-58"),
		row("HA-07", "Recreate-via-failover preserves identity", catHA(), "", "same id", scnHetero(), RTContainerd, "UC-58b"),
		row("HA-08", "WASM live-migrate across nodes", catHA(), "", "migrated", scnHetero(), RTWasm, "UC-59"),
		row("HA-09", "WASM export/import round-trip", catHA(), "", "state restored", scnHetero(), RTWasm, ""),
		row("HA-10", "Orphan reclaim-local", catHA(), "", "reclaimed", scnHetero(), RTContainerd, "UC-60"),
		row("HA-11", "Delete-orphan", catHA(), "", "removed", scnHetero(), RTContainerd, ""),
		row("HA-12", "Cross-node SSH rejects a forged key", catHA(), "", "rejected", scnHetero(), RTContainerd, "UC-67"),
		row("HA-13", "Create through a non-worker ingress reaches a worker", catHA(), "", "placed", scnHetero(), RTContainerd, "UC-92"),
		row("HA-14", "FC template lifecycle through a non-FC entry node", catHA(), "", "works", scnHetero(), RTFirecracker, "UC-93"),
		rowAll("HA-15", "Placement spreads via power-of-two-choices", catHA(), "", "balanced", scnHetero(), ""),
		row("HA-16", "Leader change mid-flight doesn't drop a create", catHA(), "", "create survives", scnHetero(), RTContainerd, ""),
	}
}

func denRows() []CatalogueRow {
	return []CatalogueRow{
		row("DEN-01", "containerd density to rejection", catDEN(), "", "count@ceiling", scnBoth(), RTContainerd, "UC-95"),
		row("DEN-02", "gVisor density to rejection", catDEN(), "", "count@ceiling", scnHetero(), RTGvisor, ""),
		row("DEN-03", "WASM density to rejection", catDEN(), "", "count@ceiling", scnHetero(), RTWasm, ""),
		row("DEN-04", "isolate density per tenant group", catDEN(), "", "count@ceiling", scnHetero(), RTIsolate, ""),
		row("DEN-05", "Firecracker density to rejection", catDEN(), "", "count@ceiling", scnHetero(), RTFirecracker, ""),
		row("DEN-06", "Admission rejects over capacity (503)", catDEN(), "", "503", scnBoth(), RTContainerd, "UC-62"),
		rowNA("DEN-07", "Host pressure (cpu/mem/disk) reported per node", catDEN(), "", "metrics", scnBoth(), ""),
		row("DEN-08", "Density holds with byte-quota'd sandboxes", catDEN(), "", "count@ceiling", scnHetero(), RTContainerd, ""),
	}
}

func latRows() []CatalogueRow {
	return []CatalogueRow{
		row("LAT-01", "containerd create latency (p50/p90/p99)", catLAT(), "", "percentiles", scnBoth(), RTContainerd, "UC-94"),
		row("LAT-02", "gVisor create latency", catLAT(), "", "percentiles", scnBoth(), RTGvisor, ""),
		row("LAT-03", "WASM create latency (resident)", catLAT(), "", "percentiles", scnBoth(), RTWasm, ""),
		row("LAT-04", "isolate create latency (warm)", catLAT(), "", "percentiles", scnBoth(), RTIsolate, ""),
		row("LAT-05", "Firecracker create latency (warm pool)", catLAT(), "", "percentiles", scnHetero(), RTFirecracker, ""),
		row("LAT-06", "docker-cold vs warm delta", catLAT(), "", "delta", scnBoth(), RTContainerd, ""),
		row("LAT-07", "Sparse warm-path holds ≤30ms (docker)", catLAT(), "", "p50≤30ms", scnBoth(), RTContainerd, ""),
		row("LAT-08", "Burst warm-path under concurrency", catLAT(), "", "percentiles", scnHetero(), RTContainerd, ""),
		row("LAT-09", "Stage attribution: containerd (create/start/netrules)", catLAT(), "", "stage ms", scnBoth(), RTContainerd, ""),
		row("LAT-10", "Stage attribution: WASM (compile/instantiate)", catLAT(), "", "stage ms", scnBoth(), RTWasm, ""),
		row("LAT-11", "Stage attribution: Firecracker (spawn/load/resume/post_resume)", catLAT(), "", "stage ms", scnHetero(), RTFirecracker, ""),
		rowAll("LAT-12", "cluster_promote overhead measured", catLAT(), "", "promote ms", scnBoth(), ""),
	}
}

func slessRows() []CatalogueRow {
	return []CatalogueRow{
		row("SLESS-01", "Idle-stop after stopIfIdleFor", catSLESS(), "", "stopped", scnBoth(), RTContainerd, ""),
		row("SLESS-02", "Idle-destroy after destroyIfIdleFor", catSLESS(), "", "destroyed", scnBoth(), RTContainerd, ""),
		row("SLESS-03", "Scale-to-zero wake on HTTP (serverless)", catSLESS(), "", "wakes + serves", scnBoth(), RTContainerd, ""),
		row("SLESS-04", "Wake cold-start latency recorded", catSLESS(), "", "wake p50", scnHetero(), RTContainerd, ""),
		row("SLESS-05", "Wake circuit-breaker opens on repeated failure", catSLESS(), "", "circuit open", scnHetero(), RTContainerd, ""),
		row("SLESS-06", "stop-at-age enforced", catSLESS(), "", "stopped@age", scnHetero(), RTContainerd, ""),
		row("SLESS-07", "destroy-at-age enforced", catSLESS(), "", "destroyed@age", scnHetero(), RTContainerd, ""),
		row("SLESS-08", "ai-app-hosting-serverless scales to zero + wakes", catSLESS(), "", "wake serves", scnHetero(), RTContainerd, ""),
		row("SLESS-09", "burner-vpn-serverless scales to zero", catSLESS(), "", "wake serves", scnHetero(), RTContainerd, ""),
		rowNA("SLESS-10", "TTL-driven reaper terminates aged infra", catSLESS(), "", "reaped", scnBoth(), ""),
	}
}

func sshRows() []CatalogueRow {
	return []CatalogueRow{
		row("SSH-01", "Per-sandbox Ed25519 key returned on create", catSSH(), "", "key present", scnBoth(), RTContainerd, ""),
		row("SSH-02", "SSH connect with the per-sandbox key", catSSH(), "", "shell", scnBoth(), RTContainerd, "UC-43"),
		row("SSH-03", "SSH gateway listens on the ingress public host", catSSH(), "", "reachable", scnHetero(), RTContainerd, "UC-89"),
		row("SSH-04", "Forged key rejected cross-node", catSSH(), "", "rejected", scnHetero(), RTContainerd, "UC-67"),
		row("SSH-05", "SSH local port-forward works", catSSH(), "", "forwarded", scnHetero(), RTContainerd, ""),
		row("SSH-06", "SSH session attach/replay", catSSH(), "", "attached", scnHetero(), RTContainerd, ""),
	}
}

func tmplRows() []CatalogueRow {
	return []CatalogueRow{
		row("TMPL-01", "Build image from a Dockerfile", catTMPL(), "", "image built", scnBoth(), RTContainerd, "UC-46"),
		row("TMPL-02", "Rich Dockerfile builder (env/workdir/entrypoint/cmd/user/expose)", catTMPL(), "", "honored", scnBoth(), RTContainerd, "UC-76"),
		row("TMPL-03", "CreateWithImage graph", catTMPL(), "", "boots", scnBoth(), RTContainerd, "UC-74"),
		row("TMPL-04", "Declarative image (pipInstall/runCommands/env) — Daytona", catTMPL(), "", "snapshot built", scnBoth(), RTContainerd, ""),
		row("TMPL-05", "FC template create", catTMPL(), "", "template id", scnHetero(), RTFirecracker, "UC-47"),
		row("TMPL-06", "FC template list + get", catTMPL(), "", "present", scnHetero(), RTFirecracker, "UC-48"),
		row("TMPL-07", "FC template rebuild", catTMPL(), "", "rebuilt", scnHetero(), RTFirecracker, "UC-49"),
		row("TMPL-08", "FC template delete", catTMPL(), "", "deleted", scnHetero(), RTFirecracker, "UC-50"),
		row("TMPL-09", "WASM module register + list/get", catTMPL(), "", "present", scnBoth(), RTWasm, "UC-51"),
		row("TMPL-10", "WASM module push to registry", catTMPL(), "", "pushed", scnBoth(), RTWasm, "UC-52"),
		row("TMPL-11", "Isolate js-bundle CRUD (upload/list/get/delete)", catTMPL(), "", "round-trip", scnBoth(), RTIsolate, "UC-105"),
		row("TMPL-12", "Private registry auth (sealed creds)", catTMPL(), "", "pulls", scnHetero(), RTContainerd, ""),
		row("TMPL-13", "Image build graph → create in one flow", catTMPL(), "", "boots", scnBoth(), RTContainerd, ""),
	}
}

func facRows() []CatalogueRow {
	return []CatalogueRow{
		row("FAC-01", "Daytona SDK: create-vm from snapshot", catFAC(), "", "created", scnBoth(), RTContainerd, ""),
		row("FAC-02", "Daytona: exec-command + codeRun", catFAC(), "", "output", scnBoth(), RTContainerd, ""),
		row("FAC-03", "Daytona: full session lifecycle (create/get/exec/logs/delete)", catFAC(), "", "states", scnBoth(), RTContainerd, ""),
		row("FAC-04", "Daytona: file-operations (list/create/upload/search/replace/download)", catFAC(), "", "all ok", scnBoth(), RTContainerd, ""),
		row("FAC-05", "Daytona: streaming upload/download + progress + abort", catFAC(), "", "completes", scnBoth(), RTContainerd, ""),
		row("FAC-06", "Daytona: PTY (create/input/resize/kill/wait)", catFAC(), "", "interactive", scnBoth(), RTContainerd, ""),
		row("FAC-07", "Daytona: volumes multi-mount + subpath", catFAC(), "", "shared", scnHetero(), RTContainerd, ""),
		row("FAC-08", "Daytona: lifecycle state machine + setLabels", catFAC(), "", "labeled", scnBoth(), RTContainerd, ""),
		row("FAC-09", "Daytona: region us + eu snapshots", catFAC(), "", "both regions", scnHetero(), RTContainerd, ""),
		row("FAC-10", "Daytona: declarative image with resources", catFAC(), "", "built", scnBoth(), RTContainerd, ""),
		row("FAC-11", "Daytona: git-lsp (clone + LSP symbols/completions)", catFAC(), "", "symbols", scnBoth(), RTContainerd, ""),
		row("FAC-12", "Daytona: network-settings (blockAll / allowList)", catFAC(), "", "enforced", scnBoth(), RTContainerd, ""),
		row("FAC-13", "Daytona: auto-delete / auto-archive intervals", catFAC(), "", "applied", scnBoth(), RTContainerd, ""),
		row("FAC-14", "Daytona: pagination (sandbox + snapshot lists)", catFAC(), "", "pages", scnBoth(), RTContainerd, ""),
		row("FAC-15", "E2B facade: exec + files round-trip (compat)", catFAC(), "", "compat", scnHetero(), RTContainerd, ""),
	}
}

func regRows() []CatalogueRow {
	return []CatalogueRow{
		row("REG-01", "Region us snapshot + create", catREG(), "", "created", scnHetero(), RTContainerd, ""),
		row("REG-02", "Region eu snapshot + create", catREG(), "", "created", scnHetero(), RTContainerd, ""),
		row("REG-03", "arm64 Firecracker host boots a VM (optional 12th node)", catREG(), "", "boots", scnHetero(), RTFirecracker, ""),
		row("REG-04", "Foreign-arch snapshot rejected on arm64 cluster", catREG(), "", "rejected", scnHetero(), RTFirecracker, "UC-79"),
		rowNA("REG-05", "Foreign-arch snapshot rejected (offline guard)", catREG(), "", "rejected", scnHetero(), "UC-78"),
	}
}

func gpuRows() []CatalogueRow {
	return []CatalogueRow{
		row("GPU-01", "GPU sandbox request honored (if GPU host present)", catGPU(), "", "gpu visible", scnHetero(), RTContainerd, ""),
		row("GPU-02", "GPU + gVisor rejected (negative)", catGPU(), "", "rejected", scnBoth(), RTGvisor, "UC-28"),
		row("GPU-03", "Specific GPU device-ids honored", catGPU(), "", "mapped", scnHetero(), RTContainerd, ""),
	}
}

func obsRows() []CatalogueRow {
	return []CatalogueRow{
		rowNA("OBS-01", "/v1/metrics scrape returns output", catOBS(), "", "text", scnBoth(), "UC-64"),
		rowNA("OBS-02", "Grafana reachable + Prometheus datasource healthy", catOBS(), "", "200", scnBoth(), "UC-106"),
		rowNA("OBS-03", "All sandboxd nodes are up in Prometheus", catOBS(), "", "up==N", scnBoth(), "UC-107"),
		rowNA("OBS-04", "Create-funnel metrics populate under load", catOBS(), "", "series move", scnBoth(), ""),
		row("OBS-05", "Per-runtime WASM invoke metrics increment", catOBS(), "", "invoke_total", scnBoth(), RTWasm, ""),
		rowMultiRT("OBS-06", "Warm-pool hit metrics (docker/vmm) increment", catOBS(), "", "hit_total", scnBoth(), []Runtime{RTContainerd, RTFirecracker}, ""),
		rowNA("OBS-07", "Raft/gossip/lease metrics live", catOBS(), "", "series", scnBoth(), ""),
		rowNA("OBS-08", "Host-pressure metrics track density", catOBS(), "", "rises", scnBoth(), ""),
		rowNA("OBS-09", "Ingress/Caddy admin metrics live", catOBS(), "", "series", scnBoth(), ""),
		rowNA("OBS-10", "Dashboard snapshot captured to reports/obs", catOBS(), "", "PNG saved", scnHetero(), ""),
	}
}

func idemRows() []CatalogueRow {
	return []CatalogueRow{
		row("IDEM-01", "create-with-id idempotent under retry", catIDEM(), "", "one sandbox", scnBoth(), RTContainerd, "UC-17"),
		row("IDEM-02", "Concurrent duplicate create (5×)", catIDEM(), "", "one wins, no leak", scnBoth(), RTContainerd, "UC-65"),
		row("IDEM-03", "expose-port idempotent (same URL)", catIDEM(), "", "same URL", scnBoth(), RTContainerd, "UC-31"),
		row("IDEM-04", "custom-domain add idempotent", catIDEM(), "", "no dup", scnHetero(), RTContainerd, ""),
		row("IDEM-05", "sandboxd restart reconcile survives", catIDEM(), "", "state intact", scnHetero(), RTContainerd, "UC-100"),
		row("IDEM-06", "containerd restart: shims survive + events resubscribe", catIDEM(), "", "shims alive", scnHetero(), RTContainerd, "UC-101"),
		row("IDEM-07", "dockerd coexistence: AEROLVM-USER jump survives restart", catIDEM(), "", "jump intact", scnHetero(), RTContainerd, "UC-102"),
		row("IDEM-08", "Neighbor isolation on same bridge", catIDEM(), "", "blocked", scnHetero(), RTContainerd, "UC-99"),
		row("IDEM-09", "Host-port pool: no leak on retry / PK conflict", catIDEM(), "", "pool stable", scnBoth(), RTContainerd, ""),
		row("IDEM-10", "Snapshot register idempotent", catIDEM(), "", "one row", scnBoth(), RTContainerd, ""),
	}
}
