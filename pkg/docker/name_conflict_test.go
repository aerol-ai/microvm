package docker

import (
	"errors"
	"testing"
)

// Docker's 409 "name is already in use" on a container create reads as
// ErrSandboxContainerExists (as containerd's AlreadyExists does), keeping
// the original text; any other error is left alone.
func TestNameConflictAsExists(t *testing.T) {
	conflict := errors.New(`docker API POST /containers/create failed with status 409: {"message":"Conflict. The container name \"/sb-2fc2accde1299111\" is already in use by container \"706e3dd9\". You have to remove (or rename) that container to be able to reuse that name."}`)
	for _, tc := range []struct {
		name   string
		err    error
		exists bool
	}{
		{"name conflict", conflict, true},
		{"other 409", errors.New("docker API POST /containers/create failed with status 409: conflict: unable to find a free port"), false},
		{"not a 409", errors.New("docker API POST /containers/create failed with status 500: is already in use"), false},
		{"cancelled", errors.New(`Post "http://docker/containers/create?name=sb-1": context canceled`), false},
		{"nil", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := nameConflictAsExists(tc.err)
			if errors.Is(got, ErrSandboxContainerExists) != tc.exists {
				t.Fatalf("nameConflictAsExists(%v) = %v; exists %v, want %v", tc.err, got, !tc.exists, tc.exists)
			}
			if tc.err != nil && !errors.Is(got, tc.err) {
				t.Fatalf("the original error must stay in the chain: %v", got)
			}
			if tc.err == nil && got != nil {
				t.Fatalf("nil in, %v out", got)
			}
		})
	}
}
