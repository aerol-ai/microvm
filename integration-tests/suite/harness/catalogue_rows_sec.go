package harness

// Secrets, audit and the enterprise posture — the catalogue rows for
// plans/integration-test-security.md's UC-110..UC-169.
//
// Kept in its own file because the SEC block is a whole programme rather than
// an increment to an existing category, and because catalogue_rows.go is
// already the longest file in the package.
//
// Every row references a use case. A catalogue row with no UCRef is a
// question nobody has agreed to answer; for this block, all sixty have tests,
// so leaving one unreferenced would be a bookkeeping slip rather than an
// honest gap.

func catSEC() string { return "Secrets, audit & enterprise posture" }

func secRows() []CatalogueRow {
	return []CatalogueRow{
		// A. Sealing and fan-out.
		rowAll("SEC-01", "Are credentials opaque by default, and does reading them leave exactly one audit record?", catSEC(), "Sealing", "one secret_open, no plaintext", scnBoth(), "UC-110"),
		rowAll("SEC-02", "Does an HA create reach failover_ready with a holder set larger than the owner alone?", catSEC(), "Fan-out", "≥2 holders", scnBoth(), "UC-111"),
		rowAll("SEC-03", "Is the sealed row actually ON every recipient and on nobody else?", catSEC(), "Fan-out", "peer HEAD 200/404", scnBoth(), "UC-112"),
		rowAll("SEC-04", "Does observing the sealed state change it?", catSEC(), "Fan-out", "generation stable", scnBoth(), "UC-113"),
		rowAll("SEC-05", "Is a caller on the internal port without a peer certificate refused?", catSEC(), "Authz", "403/401", scnBoth(), "UC-114"),
		rowAll("SEC-06", "Is a zero-ACK HA create retracted, leaving no orphan?", catSEC(), "Fan-out", "no orphan row", scnBoth(), "UC-115"),
		rowAll("SEC-07", "Does the recipient-set size track the backup-count knob, capped at the cluster?", catSEC(), "Fan-out", "tracks + capped", scnBoth(), "UC-116"),

		// B. Cross-node failover open — the critical path.
		rowAll("SEC-08", "After the owner dies, does the sandbox recreate on a recipient AND still have working credentials?", catSEC(), "Failover", "secret readable in-guest", scnBoth(), "UC-117"),
		rowAll("SEC-09", "Does the sealed env survive every restore path, on every runtime?", catSEC(), "Failover", "env intact", scnBoth(), "UC-118"),
		rowAll("SEC-10", "Does a non-recipient owner fail legibly instead of booting empty?", catSEC(), "Failover", "loud, not empty", scnBoth(), "UC-119"),
		rowAll("SEC-11", "Killed mid-fan-out: recreates or fails loudly, never half-sealed?", catSEC(), "Failover", "never half-sealed", scnBoth(), "UC-120"),

		// C. Reseal on membership change.
		rowAll("SEC-12", "Does a membership change reseal, and does the generation then STOP moving?", catSEC(), "Reseal", "advances once", scnBoth(), "UC-121"),
		rowAll("SEC-13", "Does draining a recipient reseal to a replacement at a new generation?", catSEC(), "Reseal", "new gen, new set", scnBoth(), "UC-122"),
		rowAll("SEC-14", "Can a retired recipient still open, and is its tomb swept?", catSEC(), "Reseal", "fail closed + swept", scnBoth(), "UC-123"),
		rowAll("SEC-15", "Do two concurrent reseal triggers converge on one generation?", catSEC(), "Reseal", "one winner", scnBoth(), "UC-124"),
		rowAll("SEC-16", "Does a whole-cluster restart restore holder counts under the enterprise posture?", catSEC(), "Reseal", "not stuck false", scnBoth(), "UC-125"),

		// D. Env sealing and the API contract.
		rowAll("SEC-17", "Do Get AND List omit env by default?", catSEC(), "Env", "omitted in both", scnBoth(), "UC-126"),
		rowAll("SEC-18", "Does include_env return env and audit exactly once, naming the actor?", catSEC(), "Env", "one record, named", scnBoth(), "UC-127"),
		rowAll("SEC-19", "Is env absent from the Raft placement spec replicated to every voter?", catSEC(), "Env", "absent", scnBoth(), "UC-128"),
		rowAll("SEC-20", "Is there plaintext env on disk, and does the sealed row survive an update?", catSEC(), "Env", "no plaintext", scnBoth(), "UC-129"),
		rowAll("SEC-21", "Does a corrupted sealed env fail loud rather than boot empty?", catSEC(), "Env", "loud", scnBoth(), "UC-130"),

		// E. Audit chain, read API, fan-out.
		rowAll("SEC-22", "Does the audit chain verify on a live node after real work?", catSEC(), "Audit chain", "ok + records grew", scnBoth(), "UC-131"),
		rowAll("SEC-23", "Does a hand-edited line fail verification and name the break?", catSEC(), "Audit chain", "detected + named", scnBoth(), "UC-132"),
		rowAll("SEC-24", "Does an audit read fan out to peers?", catSEC(), "Audit read", "≥2 answered", scnBoth(), "UC-133"),
		rowAll("SEC-25", "With a node down, is coverage honest or the answer silently short?", catSEC(), "Audit read", "partial + missing", scnBoth(), "UC-134"),
		rowAll("SEC-26", "Does the evidence survive the owner's death?", catSEC(), "Audit read", "history complete", scnBoth(), "UC-135"),
		rowAll("SEC-27", "Is post-delete history readable and scoped to its incarnation?", catSEC(), "Audit read", "no cross-incarnation leak", scnBoth(), "UC-136"),
		rowAll("SEC-28", "Does index-off return the same events as index-on?", catSEC(), "Audit read", "parity", scnBoth(), "UC-137"),
		rowAll("SEC-29", "Does pagination walk a history with no duplicates and no gaps?", catSEC(), "Audit read", "exact set", scnBoth(), "UC-138"),

		// F. Export connectors and witness.
		rowAll("SEC-30", "Does the file backend write chained records?", catSEC(), "Export", "chained JSONL", scnBoth(), "UC-139"),
		rowAll("SEC-31", "Does the s3 backend write objects that reconstruct the chain?", catSEC(), "Export", "objects land", scnBoth(), "UC-140"),
		rowAll("SEC-32", "Does the webhook backend deliver records the receiver accepts?", catSEC(), "Export", "0 rejected", scnBoth(), "UC-141"),
		rowAll("SEC-33", "Does a failing sink get retried until every record lands?", catSEC(), "Export", "at-least-once", scnBoth(), "UC-142"),
		rowAll("SEC-34", "Do chain heads reach the witness, with receipts on disk and the gauge at 1?", catSEC(), "Witness", "head + receipt", scnBoth(), "UC-143"),
		rowAll("SEC-35", "Does a witness disagreement refuse an enterprise boot?", catSEC(), "Witness", "fail closed", scnBoth(), "UC-144"),
		rowAll("SEC-36", "Does the ingest endpoint require a token, and is it loopback-only?", catSEC(), "Ingest", "loopback + tokened", scnBoth(), "UC-145"),
		rowAll("SEC-37", "Does retention prune HOLD while export lags, then verify across the checkpoint?", catSEC(), "Retention", "gate holds", scnBoth(), "UC-145b"),

		// G. Quota, rate limits, overflow.
		rowAll("SEC-38", "Does the per-identity audit limit return Retry-After and then recover?", catSEC(), "Limits", "429 + recovery", scnBoth(), "UC-146"),
		rowAll("SEC-39", "Is the peer ceiling a separate budget from the operator limit?", catSEC(), "Limits", "operator unaffected", scnBoth(), "UC-147"),
		rowAll("SEC-40", "Does an overflow gap marker record HOW MUCH was dropped?", catSEC(), "Overflow", "dropped>0", scnBoth(), "UC-148"),
		rowAll("SEC-41", "Does the spill policy leave no gap at all?", catSEC(), "Overflow", "no marker", scnBoth(), "UC-149"),
		rowAll("SEC-42", "Does egress attribution name the right sandbox?", catSEC(), "Egress", "right sandbox", scnBoth(), "UC-150"),

		// H. Cluster mTLS and authz.
		rowAll("SEC-43", "Does every node carry DNS:node:<id>, with ca.key only on the seed?", catSEC(), "mTLS", "scoped + seed-only", scnBoth(), "UC-151"),
		rowAll("SEC-44", "Is a plaintext call to the internal port refused?", catSEC(), "mTLS", "refused", scnBoth(), "UC-152"),
		rowAll("SEC-45", "Is a self-signed cert carrying a valid node SAN rejected?", catSEC(), "mTLS", "rejected", scnBoth(), "UC-153"),
		rowAll("SEC-46", "Do operator routes take the PAT while internal mTLS routes refuse it?", catSEC(), "Authz", "both halves", scnBoth(), "UC-154"),
		rowAll("SEC-47", "Is a removed peer's certificate actually revoked?", catSEC(), "mTLS", "revoked", scnBoth(), "UC-155"),

		// I. Enterprise profile.
		rowAll("SEC-48", "Does every forbidden enterprise config refuse the boot WITH its documented message?", catSEC(), "Enterprise", "14 rows refuse", scnBoth(), "UC-156"),
		rowAll("SEC-49", "Does a CA signing key in the daemon TLS dir refuse an enterprise boot?", catSEC(), "Enterprise", "refuses", scnBoth(), "UC-157"),
		rowAll("SEC-50", "Does an on-node-only exporter refuse an enterprise boot?", catSEC(), "Enterprise", "refuses", scnBoth(), "UC-158"),
		rowAll("SEC-51", "Does the node rejoin cleanly after EVERY boot-gate row?", catSEC(), "Enterprise", "no degraded fleet", scnBoth(), "UC-159"),

		// J. Storage retirement and fleet-scale reads.
		rowAll("SEC-52", "Does draining a worker raise a storage-retirement obligation that can be discharged?", catSEC(), "Retirement", "raised + attested", scnBoth(), "UC-160"),
		rowAll("SEC-53", "Do fleet-scale reads stay paged with an advancing cursor?", catSEC(), "Scale", "bounded", scnBoth(), "UC-161"),
		rowAll("SEC-54", "Does the Terraform ingress gate still match the daemon's constant?", catSEC(), "Scale", "no drift", scnBoth(), "UC-162"),

		// K. Isolate jail under enterprise.
		rowAll("SEC-55", "Is workerd jailed (non-root, chroot, seccomp, pid cap) WHILE serving?", catSEC(), "Isolate jail", "all four + serving", scnBoth(), "UC-163"),
		rowAll("SEC-56", "Does per-sandbox egress attribution hold under the jail?", catSEC(), "Isolate jail", "per-sandbox", scnBoth(), "UC-164"),

		// L. Non-regression.
		rowAll("SEC-57", "Did the security branch slow the DEFAULT create path?", catSEC(), "Latency", "p50 +10% / p99 +20%", scnMixed(), "UC-165"),
		rowAll("SEC-58", "What does an HA create cost, including the first call and the KMS wrap?", catSEC(), "Latency", "reported separately", scnMixed(), "UC-166"),

		// M. Surfaces the first F-table missed.
		rowAll("SEC-59", "Does reconcile reclaim a leaked workerd group?", catSEC(), "Reconcile", "reclaimed", scnBoth(), "UC-167"),
		rowAll("SEC-60", "Does the js-bundle list declare a peer it could not reach?", catSEC(), "Reconcile", "declared", scnBoth(), "UC-168"),
		rowAll("SEC-61", "Is the canary anywhere on any node, in any encoding?", catSEC(), "Leak sweep", "zero hits", scnBoth(), "UC-169"),
	}
}
