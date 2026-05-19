package service

import (
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestSandboxMatchesTagsAllMustMatch pins the AND semantics:
// every key in the filter must equal the sandbox's Tags entry for that key.
// A control plane that scopes by both user_id AND project_id must not get a
// row back where only user_id matched — otherwise cross-project listings
// leak data.
func TestSandboxMatchesTagsAllMustMatch(t *testing.T) {
	sb := &models.Sandbox{Tags: map[string]string{"user_id": "alice", "project_id": "p1"}}
	if !sandboxMatchesTags(sb, map[string]string{"user_id": "alice"}) {
		t.Fatal("single-key match should pass")
	}
	if !sandboxMatchesTags(sb, map[string]string{"user_id": "alice", "project_id": "p1"}) {
		t.Fatal("both-key match should pass")
	}
	if sandboxMatchesTags(sb, map[string]string{"user_id": "alice", "project_id": "p2"}) {
		t.Fatal("project_id mismatch must fail the whole filter")
	}
	if sandboxMatchesTags(sb, map[string]string{"user_id": "bob"}) {
		t.Fatal("user_id mismatch must fail")
	}
}

// TestSandboxMatchesTagsMissingTag pins that a filter key the sandbox doesn't
// carry at all is treated as a mismatch — the lookup returns zero string,
// which doesn't equal the wanted value. Without this, a sandbox with no tags
// would match every filter that doesn't have an empty-string value.
func TestSandboxMatchesTagsMissingTag(t *testing.T) {
	sb := &models.Sandbox{Tags: map[string]string{"user_id": "alice"}}
	if sandboxMatchesTags(sb, map[string]string{"project_id": "p1"}) {
		t.Fatal("missing tag key must fail the filter")
	}
	// Nil-tag sandbox: same rule, no entry == no match.
	naked := &models.Sandbox{}
	if sandboxMatchesTags(naked, map[string]string{"user_id": "alice"}) {
		t.Fatal("sandbox with no tags must not match a non-empty filter")
	}
}
