package daemon

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// itestStaticValidator is TEST-ONLY scaffolding (see SB_ITEST_IDENTITY_FILE in
// daemon.Run). It resolves a bearer token to an owner-scoped Identity from a
// static map so the integration harness can drive real cross-tenant scoping.
// It is NOT the managed identity feature and must never be wired in production.
type itestStaticValidator struct{ tokens map[string]string }

func (v itestStaticValidator) Validate(_ context.Context, token string) (controlplane.Identity, error) {
	owner, ok := v.tokens[strings.TrimSpace(token)]
	if !ok || strings.TrimSpace(owner) == "" {
		return controlplane.Identity{}, controlplane.ErrTokenRejected
	}
	return controlplane.Identity{ExternalID: "itest:" + owner, OwnerRef: owner}, nil
}

// loadITestIdentityFile parses a token->owner map. Each non-empty, non-comment
// line is "<token> <owner_ref>". Whitespace-trimmed; "#" starts a comment.
func loadITestIdentityFile(path string) (map[string]string, error) {
	f, err := os.Open(path) //nolint:gosec // operator-supplied test config path
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tokens := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("itest identity line %q: want '<token> <owner_ref>'", line)
		}
		tokens[fields[0]] = fields[1]
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(tokens) == 0 {
		return nil, fmt.Errorf("itest identity file %q has no entries", path)
	}
	return tokens, nil
}
