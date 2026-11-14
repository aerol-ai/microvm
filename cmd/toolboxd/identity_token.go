package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// The sandbox's cloud identity token (plans/sandbox-cloud-identity.md D1.7).
// sandboxd signs a short-lived OIDC token and pushes it here; toolboxd
// writes it where the sandbox's AEROLVM_IDENTITY_TOKEN_FILE (and the AWS
// and Azure variables) point, and the cloud SDKs read it from there.
//
// The route is under /admin: every tenant-facing toolbox proxy (v1, the
// Daytona facade) refuses /admin paths, so only sandboxd reaches it, with
// the sandbox's toolbox token (security point 5). toolboxd never verifies
// the token: it cannot, and a forged one could only fail at the cloud.
// Nothing here logs the token or echoes it back.

// identityTokenDir and identityTokenName are cloudidentity.TokenDir and the
// file in it (TestIdentityTokenPathMatchesIssuer pins them). A var so tests
// write under a temp dir.
var identityTokenDir = "/run/aerolvm/identity"

const identityTokenName = "token"

// maxIdentityTokenBody bounds the push body; a token is a few KB.
const maxIdentityTokenBody = 32 << 10

func (s *server) handleIdentityToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxIdentityTokenBody)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	token := strings.TrimSpace(body.Token)
	if !compactJWT(token) {
		writeError(w, http.StatusBadRequest, "token must be a compact JWT")
		return
	}
	if err := writeIdentityToken(identityTokenDir, token); err != nil {
		// The error names paths and syscalls only, never the token.
		s.logger.Error("identity token not written; cloud SDKs keep the previous token", "error", err)
		writeError(w, http.StatusInternalServerError, "identity token not written")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// compactJWT reports whether token has a JWT's shape: three non-empty
// base64url segments. It keeps junk out of the file, nothing more.
func compactJWT(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for i := 0; i < len(p); i++ {
			c := p[i]
			if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
				return false
			}
		}
	}
	return true
}

// writeIdentityToken replaces the token file atomically: a temp file in the
// same folder, synced, renamed over the old one. A reader (an SDK
// refreshing credentials) sees the old token or the new one, never half of
// either. The file is 0644 in a 0755 folder: every process in the sandbox
// may read it, the same as the env that names it, and none but toolboxd
// (root) can replace it. No trailing newline: some SDKs send the file's
// bytes as they are.
func writeIdentityToken(dir, token string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("identity token folder: %w", err)
	}
	// MkdirAll keeps an existing folder's mode, and the umask trims a new
	// one's; set it explicitly.
	if err := os.Chmod(dir, 0o755); err != nil {
		return fmt.Errorf("identity token folder: %w", err)
	}
	f, err := os.CreateTemp(dir, ".token-*")
	if err != nil {
		return fmt.Errorf("identity token temp file: %w", err)
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	_, werr := f.WriteString(token)
	if werr == nil {
		werr = f.Chmod(0o644)
	}
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return fmt.Errorf("identity token temp file: %w", werr)
	}
	if err := os.Rename(tmp, filepath.Join(dir, identityTokenName)); err != nil {
		return fmt.Errorf("identity token rename: %w", err)
	}
	ok = true
	// Make the rename durable; a failure here leaves a correct file that a
	// crash could lose, which the next push repairs.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
