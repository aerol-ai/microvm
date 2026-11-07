package v1

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/nodeupgrade"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// launchHost is the machine as the node upgrade routes see it: systemd-run
// is recorded, never run.
type launchHost struct {
	*nodeupgrade.SystemHost
	mu       sync.Mutex
	launches [][]string
	fail     error
}

func (h *launchHost) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.launches = append(h.launches, append([]string{name}, args...))
	return nil, h.fail
}

func (h *launchHost) UnitActive(context.Context, string) bool { return true }

// nodeUpgradeMux serves the real v1 routes as an admin, on a node with the
// given cluster and remote-upgrade settings.
func nodeUpgradeMux(t *testing.T, clusterMode, remote bool) (*http.ServeMux, *nodeupgrade.Local, *launchHost) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{EnableCluster: clusterMode, RemoteUpgrade: remote}, logger, nil, nil, nil, nil, nil, nil, nil)
	host := &launchHost{SystemHost: &nodeupgrade.SystemHost{}}
	l := &nodeupgrade.Local{
		StateDir:       filepath.Join(t.TempDir(), "upgrade"),
		Host:           host,
		Binary:         func() (string, error) { return "/usr/local/bin/sandboxd", nil },
		RunningVersion: "v0.6.12",
	}
	svc.AttachNodeUpgrades(l)
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{Service: svc, Logger: logger, Auth: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := controlplane.ContextWithAccess(r.Context(), controlplane.Access{Fleet: true})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}})
	return mux, l, host
}

func sendBody(mux http.Handler, method, path, body string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rr
}

func upgradeErr(t *testing.T, rr *httptest.ResponseRecorder) upgradewire.ErrorResponse {
	t.Helper()
	var e upgradewire.ErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &e); err != nil {
		t.Fatalf("not an upgrade error body: %d %q", rr.Code, rr.Body.String())
	}
	return e
}

func hexSum(b string) string {
	s := sha256.Sum256([]byte(b))
	return hex.EncodeToString(s[:])
}

func platformAsset(name string) string { return name + "_" + runtime.GOOS + "_" + runtime.GOARCH }

// In cluster mode every single-node route answers 409 and names the
// rollout command.
func TestNodeUpgradeRoutesRefuseInClusterMode(t *testing.T) {
	mux, _, host := nodeUpgradeMux(t, true, true)
	file := upgradewire.NodeUpgradeFilesPath + "/" + hexSum("x")
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, upgradewire.NodeUpgradePath},
		{http.MethodGet, upgradewire.NodeUpgradePath},
		{http.MethodPut, file},
		{http.MethodHead, file},
	} {
		rr := sendBody(mux, tc.method, tc.path, "{}")
		if rr.Code != http.StatusConflict {
			t.Fatalf("%s %s = %d", tc.method, tc.path, rr.Code)
		}
		if e := upgradeErr(t, rr); e.Error != upgradewire.ErrCodeClusterMode || !strings.Contains(e.Hint, "aerolvm upgrade apply") {
			t.Fatalf("%s %s = %+v", tc.method, tc.path, e)
		}
	}
	if len(host.launches) != 0 {
		t.Fatal("a cluster node launched an upgrade")
	}
}

// SB_REMOTE_UPGRADE=false refuses every route that changes the node; the
// status read still works.
func TestNodeUpgradeRoutesRespectRemoteUpgradeOff(t *testing.T) {
	mux, _, _ := nodeUpgradeMux(t, false, false)
	file := upgradewire.NodeUpgradeFilesPath + "/" + hexSum("x")
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, upgradewire.NodeUpgradePath},
		{http.MethodPut, file},
		{http.MethodHead, file},
	} {
		rr := sendBody(mux, tc.method, tc.path, "{}")
		if e := upgradeErr(t, rr); rr.Code != http.StatusForbidden || e.Error != upgradewire.ErrCodeRemoteUpgradeDisabled || !strings.Contains(e.Hint, "sudo sandboxd upgrade node") {
			t.Fatalf("%s %s = %d %+v", tc.method, tc.path, rr.Code, e)
		}
	}
	if rr := sendBody(mux, http.MethodGet, upgradewire.NodeUpgradePath, ""); rr.Code != http.StatusNotFound || upgradeErr(t, rr).Error != "not_found" {
		t.Fatalf("GET with remote upgrade off = %d %s", rr.Code, rr.Body.String())
	}
}

func TestNodeUpgradeUploadThenStart(t *testing.T) {
	mux, _, host := nodeUpgradeMux(t, false, true)
	sandboxd, toolboxd := "sandboxd v0.6.13", "toolboxd v0.6.13"
	filePath := func(s string) string { return upgradewire.NodeUpgradeFilesPath + "/" + s }

	for _, tc := range []struct {
		name, method, path, body string
		code                     int
		errCode                  string
	}{
		{"bad name", http.MethodPut, filePath("ABC"), "x", http.StatusBadRequest, "invalid_request"},
		{"head bad name", http.MethodHead, filePath("abc"), "", http.StatusBadRequest, ""},
		{"wrong body", http.MethodPut, filePath(hexSum(sandboxd)), "something else", http.StatusBadRequest, upgradewire.ErrCodeHashMismatch},
		{"head missing", http.MethodHead, filePath(hexSum(sandboxd)), "", http.StatusNotFound, ""},
		{"put", http.MethodPut, filePath(hexSum(sandboxd)), sandboxd, http.StatusCreated, ""},
		{"put again", http.MethodPut, filePath(hexSum(sandboxd)), sandboxd, http.StatusOK, ""},
		{"head present", http.MethodHead, filePath(hexSum(sandboxd)), "", http.StatusOK, ""},
		{"get before any op", http.MethodGet, upgradewire.NodeUpgradePath, "", http.StatusNotFound, "not_found"},
		{"bad json", http.MethodPost, upgradewire.NodeUpgradePath, "{", http.StatusBadRequest, "invalid_request"},
		{"bad version", http.MethodPost, upgradewire.NodeUpgradePath, `{"version":"../x","files":{}}`, http.StatusBadRequest, "invalid_request"},
	} {
		rr := sendBody(mux, tc.method, tc.path, tc.body)
		if rr.Code != tc.code {
			t.Fatalf("%s: %d %s", tc.name, rr.Code, rr.Body.String())
		}
		if tc.errCode != "" {
			if e := upgradeErr(t, rr); e.Error != tc.errCode {
				t.Fatalf("%s: %+v", tc.name, e)
			}
		}
	}

	files := map[string]string{platformAsset("sandboxd"): hexSum(sandboxd), platformAsset("toolboxd"): hexSum(toolboxd)}
	post := func(version string) *httptest.ResponseRecorder {
		b, _ := json.Marshal(upgradewire.NodeUpgradeRequest{Version: version, Files: files, Source: upgradewire.SourceUpload})
		return sendBody(mux, http.MethodPost, upgradewire.NodeUpgradePath, string(b))
	}
	// The version the node runs: 200, nothing launched.
	if rr := post("v0.6.12"); rr.Code != http.StatusOK || len(host.launches) != 0 {
		t.Fatalf("same version = %d %s", rr.Code, rr.Body.String())
	}
	// toolboxd was never uploaded.
	if rr := post("v0.6.13"); rr.Code != http.StatusConflict || upgradeErr(t, rr).Error != upgradewire.ErrCodeFilesMissing ||
		!strings.Contains(upgradeErr(t, rr).Reason, platformAsset("toolboxd")) {
		t.Fatalf("missing toolboxd = %d %s", rr.Code, rr.Body.String())
	}
	if rr := sendBody(mux, http.MethodPut, filePath(hexSum(toolboxd)), toolboxd); rr.Code != http.StatusCreated {
		t.Fatal(rr.Body.String())
	}
	rr := post("v0.6.13")
	var op upgradewire.NodeUpgradeResponse
	if rr.Code != http.StatusAccepted || json.Unmarshal(rr.Body.Bytes(), &op) != nil || op.State != upgradewire.NodeOpPending || op.Op == "" {
		t.Fatalf("start = %d %s", rr.Code, rr.Body.String())
	}
	if len(host.launches) != 1 || host.launches[0][0] != "systemd-run" || !strings.Contains(strings.Join(host.launches[0], " "), "--from") {
		t.Fatalf("launches = %q", host.launches)
	}
	// A retry is the same op; another version is refused while it runs.
	var again upgradewire.NodeUpgradeResponse
	if rr := post("v0.6.13"); rr.Code != http.StatusAccepted || json.Unmarshal(rr.Body.Bytes(), &again) != nil || again.Op != op.Op {
		t.Fatalf("retry = %d %s", rr.Code, rr.Body.String())
	}
	if rr := post("v0.6.14"); rr.Code != http.StatusConflict || upgradeErr(t, rr).Error != upgradewire.ErrCodeUpgradeRunning {
		t.Fatalf("other version = %d %s", rr.Code, rr.Body.String())
	}
	var got upgradewire.NodeUpgradeResponse
	if rr := sendBody(mux, http.MethodGet, upgradewire.NodeUpgradePath, ""); rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &got) != nil || got.Op != op.Op {
		t.Fatalf("status = %d %s", rr.Code, rr.Body.String())
	}
	// While it runs, even the version the node runs now is refused.
	if rr := post("v0.6.12"); rr.Code != http.StatusConflict || len(host.launches) != 1 {
		t.Fatalf("same version while busy = %d %s", rr.Code, rr.Body.String())
	}
}

func TestNodeUpgradeRouteFailures(t *testing.T) {
	t.Run("upload too large", func(t *testing.T) {
		mux, _, _ := nodeUpgradeMux(t, false, true)
		old := maxNodeUpgradeFile
		maxNodeUpgradeFile = 4
		t.Cleanup(func() { maxNodeUpgradeFile = old })
		path := upgradewire.NodeUpgradeFilesPath + "/" + hexSum("too big")
		if rr := sendBody(mux, http.MethodPut, path, "too big"); rr.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("declared length = %d", rr.Code)
		}
		// No declared length: the body is cut while it streams.
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, path, io.MultiReader(strings.NewReader("too big")))
		req.ContentLength = -1
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("streamed = %d %s", rr.Code, rr.Body.String())
		}
	})
	t.Run("store unwritable", func(t *testing.T) {
		mux, l, _ := nodeUpgradeMux(t, false, true)
		if err := os.WriteFile(filepath.Dir(l.StateDir)+"/upgrade", []byte("a file, not a directory"), 0o600); err != nil {
			t.Fatal(err)
		}
		if rr := sendBody(mux, http.MethodPut, upgradewire.NodeUpgradeFilesPath+"/"+hexSum("x"), "x"); rr.Code != http.StatusInternalServerError {
			t.Fatalf("put = %d %s", rr.Code, rr.Body.String())
		}
	})
	t.Run("launch fails", func(t *testing.T) {
		mux, _, host := nodeUpgradeMux(t, false, true)
		host.fail = errors.New("exit status 1")
		b, _ := json.Marshal(upgradewire.NodeUpgradeRequest{Version: "v0.6.11", Rollback: true})
		if rr := sendBody(mux, http.MethodPost, upgradewire.NodeUpgradePath, string(b)); rr.Code != http.StatusInternalServerError ||
			!strings.Contains(upgradeErr(t, rr).Reason, "systemd-run") {
			t.Fatalf("launch failure = %d %s", rr.Code, rr.Body.String())
		}
	})
}
