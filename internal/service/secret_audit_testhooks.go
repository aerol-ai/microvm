package service

// Test hooks for packages that exercise the audit read path over HTTP and
// cannot reach the package-private admission state. Not for production use.

// HoldSecretAuditQuerySlotsForTest occupies every local audit read slot so a
// caller can observe the fail-fast busy path. The returned func releases them.
func HoldSecretAuditQuerySlotsForTest() (release func()) {
	held := cap(secretAuditLocalQuerySlots)
	for range held {
		secretAuditLocalQuerySlots <- struct{}{}
	}
	return func() {
		for range held {
			<-secretAuditLocalQuerySlots
		}
	}
}

// HoldSecretAuditVerifyForTest makes VerifySecretAuditChain report busy until
// the returned func runs.
func HoldSecretAuditVerifyForTest() (release func()) {
	secretAuditVerifyMu.Lock()
	return secretAuditVerifyMu.Unlock
}
