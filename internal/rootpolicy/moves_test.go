package rootpolicy

import (
	"testing"
)

// TestCheckRestorePath (M1 PR 13): a restored container's checkpoint is its
// own staged folder in the moves folder, and nothing else runsc would read
// as root.
func TestCheckRestorePath(t *testing.T) {
	p := testPolicy()
	own := testMoves + "/in/" + testID
	for _, tc := range []struct {
		name, id, dir string
		rule          Rule
	}{
		{"its own staged checkpoint", testID, own, ""},
		{"another sandbox's staged checkpoint", testID, testMoves + "/in/sb-2", RuleCheckpoint},
		{"its checkpoint on the source side", testID, testMoves + "/out/" + testID, RuleCheckpoint},
		{"the moves folder itself", testID, testMoves, RuleCheckpoint},
		{"the staged side's folder", testID, testMoves + "/in", RuleCheckpoint},
		{"a folder below its own", testID, own + "/x", RuleCheckpoint},
		{"climbing out with ..", testID, testMoves + "/in/../../../etc", RuleCheckpoint},
		{"its own, with ..", testID, testMoves + "/out/../in/" + testID, RuleCheckpoint},
		{"outside the moves folder", testID, "/etc", RuleCheckpoint},
		{"relative", testID, "moves/in/" + testID, RuleCheckpoint},
		// With no container to bind it to, the moves folder bounds it.
		{"no container: anywhere in the moves folder", "", testMoves + "/in/sb-2", ""},
		{"no container: outside the moves folder", "", "/etc", RuleCheckpoint},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := RuleOf(CheckRestorePath(p, tc.id, tc.dir)); got != tc.rule {
				t.Fatalf("rule %q, want %q", got, tc.rule)
			}
		})
	}
	if got := MoveFolder(p, MovesOut, testID); got != testMoves+"/out/"+testID {
		t.Fatalf("MoveFolder = %q", got)
	}
}

// TestRestoreAnnotationNamesItsOwnCheckpoint: the gate's spec check binds
// the restore annotation to the container the spec is for.
func TestRestoreAnnotationNamesItsOwnCheckpoint(t *testing.T) {
	p := testPolicy()
	for _, tc := range []struct {
		name, dir string
		rule      Rule
	}{
		{"its own", testMoves + "/in/" + testID, ""},
		{"another sandbox's", testMoves + "/in/sb-2", RuleCheckpoint},
		{"the source side", testMoves + "/out/" + testID, RuleCheckpoint},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := gvisorSpec(t)
			s.Annotations[RestoreAnnotation] = tc.dir
			if got := RuleOf(CheckSpec(p, testID, s)); got != tc.rule {
				t.Fatalf("rule %q, want %q", got, tc.rule)
			}
		})
	}
}

func TestCheckMoveBundleSize(t *testing.T) {
	for _, tc := range []struct {
		n, max int64
		rule   Rule
	}{
		{0, 1 << 30, ""},
		{1 << 30, 1 << 30, ""},
		{1<<30 + 1, 1 << 30, RuleMoveBundle},
		{1, 0, RuleMoveBundle},
	} {
		if got := RuleOf(CheckMoveBundleSize(tc.n, tc.max)); got != tc.rule {
			t.Errorf("CheckMoveBundleSize(%d, %d) rule %q, want %q", tc.n, tc.max, got, tc.rule)
		}
	}
}
