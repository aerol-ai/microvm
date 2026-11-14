package main

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cloudidentity"
)

const testJWT = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiJ0ZWFtOnA6cm9sZTpkZXBsb3kifQ.c2lnbmF0dXJl"

func withIdentityTokenDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "run", "aerolvm", "identity")
	prev := identityTokenDir
	identityTokenDir = dir
	t.Cleanup(func() { identityTokenDir = prev })
	return dir
}

// The env sandboxd sets and the file toolboxd writes must be the same path.
func TestIdentityTokenPathMatchesIssuer(t *testing.T) {
	if got := filepath.Join(identityTokenDir, identityTokenName); got != cloudidentity.TokenFile {
		t.Fatalf("toolboxd writes %s, sandboxd points the SDKs at %s", got, cloudidentity.TokenFile)
	}
}

func TestIdentityTokenPushWritesTheFileAtomically(t *testing.T) {
	dir := withIdentityTokenDir(t)
	h := authedRoutes(newDaytonaTestServer(t))
	put := func(body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodPut, "/admin/identity/token", strings.NewReader(body)))
		return rr
	}
	if rr := put(`{"token":"` + testJWT + `"}`); rr.Code != http.StatusNoContent || rr.Body.Len() != 0 {
		t.Fatalf("push = %d %q", rr.Code, rr.Body.String())
	}
	path := filepath.Join(dir, identityTokenName)
	got, err := os.ReadFile(path)
	if err != nil || string(got) != testJWT {
		t.Fatalf("token file = %q %v (no trailing newline, exactly the token)", got, err)
	}
	for p, want := range map[string]os.FileMode{path: 0o644, dir: 0o755} {
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm() != want {
			t.Fatalf("%s mode = %v %v, want %v", p, st.Mode().Perm(), err, want)
		}
	}
	// A refresh replaces it and leaves no temp file behind.
	next := strings.Replace(testJWT, "c2lnbmF0dXJl", "bmV4dA", 1)
	if rr := put(`{"token":" ` + next + ` "}`); rr.Code != http.StatusNoContent {
		t.Fatalf("refresh = %d", rr.Code)
	}
	if got, _ := os.ReadFile(path); string(got) != next {
		t.Fatalf("after refresh = %q", got)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("folder holds %d entries, want only the token", len(entries))
	}
	// A folder an image created with a tight mode is opened up for readers.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if rr := put(`{"token":"` + testJWT + `"}`); rr.Code != http.StatusNoContent {
		t.Fatalf("push into a 0700 folder = %d", rr.Code)
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o755 {
		t.Fatalf("folder mode = %v", st.Mode().Perm())
	}
}

func TestIdentityTokenPushRefusesBadInput(t *testing.T) {
	dir := withIdentityTokenDir(t)
	h := authedRoutes(newDaytonaTestServer(t))
	for name, body := range map[string]string{
		"bad json":       `{bad`,
		"empty":          `{}`,
		"two segments":   `{"token":"a.b"}`,
		"empty segment":  `{"token":"a..c"}`,
		"not base64url":  `{"token":"a.b+c.d"}`,
		"too big":        `{"token":"` + strings.Repeat("a", maxIdentityTokenBody) + `"}`,
		"newline inside": `{"token":"a.b\nx.c"}`,
	} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodPut, "/admin/identity/token", strings.NewReader(body)))
		if rr.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, rr.Code)
		}
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("a refused push created the folder")
	}
}

// Security point 5: only the holder of the toolbox token may push.
func TestIdentityTokenPushNeedsTheToolboxToken(t *testing.T) {
	withIdentityTokenDir(t)
	srv := newDaytonaTestServer(t)
	srv.authToken = "real-token"
	h := srv.routes()
	for _, auth := range []string{"", "Bearer wrong", "real-token"} {
		req := httptest.NewRequest(http.MethodPut, "/admin/identity/token", strings.NewReader(`{"token":"`+testJWT+`"}`))
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code == http.StatusNoContent {
			t.Fatalf("Authorization %q pushed a token", auth)
		}
	}
	req := httptest.NewRequest(http.MethodPut, "/admin/identity/token", strings.NewReader(`{"token":"`+testJWT+`"}`))
	req.Header.Set("Authorization", "Bearer real-token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("the toolbox token = %d", rr.Code)
	}
	// GET and POST are not the push route.
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		req := httptest.NewRequest(method, "/admin/identity/token", nil)
		req.Header.Set("Authorization", "Bearer real-token")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("%s = %d, want 404", method, rr.Code)
		}
	}
}

// A write failure answers 500 without the token, and logs without it.
func TestIdentityTokenWriteFailureNeverEchoesTheToken(t *testing.T) {
	parent := t.TempDir()
	blocker := filepath.Join(parent, "identity")
	if err := os.WriteFile(blocker, []byte("a file, not a folder"), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := identityTokenDir
	identityTokenDir = blocker
	t.Cleanup(func() { identityTokenDir = prev })
	var logs bytes.Buffer
	srv := newDaytonaTestServer(t)
	srv.logger = slog.New(slog.NewTextHandler(&logs, nil))
	h := authedRoutes(srv)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPut, "/admin/identity/token", strings.NewReader(`{"token":"`+testJWT+`"}`)))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("push into a file = %d", rr.Code)
	}
	if strings.Contains(rr.Body.String(), testJWT) || strings.Contains(logs.String(), testJWT) {
		t.Fatal("the token leaked into the answer or the log")
	}
}

func TestWriteIdentityTokenErrors(t *testing.T) {
	dir := t.TempDir()
	// The rename target is a folder: the rename fails and the temp file is
	// removed.
	if err := os.Mkdir(filepath.Join(dir, identityTokenName), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, identityTokenName, "x"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeIdentityToken(dir, testJWT); err == nil || !strings.Contains(err.Error(), "rename") {
		t.Fatalf("rename onto a folder = %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("a failed write left %d entries", len(entries))
	}
}
