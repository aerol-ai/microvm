package wasm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// TestDriverWasip1HTTPServeWhileWorkPreopen proves the §"/work + listen" fix:
// a guest can hold the /work dir preopen (fd 3) AND a wasip1 HTTP listener at the
// same time. Because wazero appends the listener after dir preopens, it lands at
// fd 4; the engine injects AEROL_WASM_LISTEN_FD so the guest accepts on the right
// fd. A successful /work read over HTTP confirms both halves work concurrently —
// if the injected fd disagreed with where the listener actually landed, the guest
// would Accept on the /work directory fd and this request would fail loudly.
func TestDriverWasip1HTTPServeWhileWorkPreopen(t *testing.T) {
	modPath := filepath.Join("..", "..", "..", "pkg", "wasm", "testdata", "wasip1-http.wasm")
	if st, err := os.Stat(modPath); err != nil || st.Size() == 0 {
		t.Skip("wasip1-http.wasm testdata missing")
	}
	absMod, err := filepath.Abs(modPath)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	runDir := filepath.Join(os.TempDir(), "aw-http-work")
	t.Cleanup(func() { _ = os.RemoveAll(runDir) })

	sup := newInProcessSupervisor()
	t.Cleanup(func() {
		for id := range sup.workers {
			_ = sup.Stop(id)
		}
	})

	driver := New(Config{RunDir: runDir, ModulesDir: dir, DefaultMemoryMB: 64}, nil)
	driver.SetModuleResolver(fakeResolver{path: absMod, digest: "wasip1-http"})
	driver.SetWorkerSupervisor(sup)

	ctx := context.Background()
	sandboxID := "sb-http-work"
	createReq := models.CreateSandboxRequest{
		Image:            "wasip1-http.wasm",
		ContainerCommand: []string{"wasi", "http"},
	}
	if _, err := driver.Create(ctx, createReq, sandboxID, "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Plant a file in the sandbox's /work host dir, then expose HTTP. The single
	// /work preopen pushes the listener to fd 3+1 = 4.
	const want = "hello from /work\n"
	if err := os.WriteFile(filepath.Join(driver.sandboxDir(sandboxID), "greeting.txt"), []byte(want), 0o600); err != nil {
		t.Fatalf("plant /work file: %v", err)
	}

	if err := driver.SyncGuestListenPorts(ctx, sandboxID, []int{8080}); err != nil {
		t.Fatalf("SyncGuestListenPorts: %v", err)
	}
	inst, err := driver.instance(sandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if inst.resolvedListenPort <= 0 {
		t.Fatalf("resolved listen port = %d", inst.resolvedListenPort)
	}

	wc := driver.newWorkerClient(inst.socketPath)
	req, err := http.NewRequest(http.MethodGet, "http://guest/?workfile=greeting.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if err := wc.ProxyHTTP(sandboxID, 0, rec, req); err != nil {
		t.Fatalf("ProxyHTTP: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != want {
		t.Fatalf("/work read over HTTP = %q, want %q", got, want)
	}
}

// TestListenerFDMath pins the fd the engine reports to AerolVM-aware guests:
// stdio (0–2), then one dir fd per preopen, then the listener.
func TestListenerFDMath(t *testing.T) {
	cases := []struct {
		preopens int
		want     int
	}{
		{preopens: 0, want: 3},
		{preopens: 1, want: 4},
		{preopens: 3, want: 6},
	}
	for _, tc := range cases {
		caps := wasmengine.Capabilities{WASIListenPort: 0}
		for i := 0; i < tc.preopens; i++ {
			caps.Preopens = append(caps.Preopens, wasmengine.Preopen{GuestPath: "/p", HostPath: "/tmp"})
		}
		if got := wasmengine.ListenerFD(caps); got != tc.want {
			t.Fatalf("ListenerFD(%d preopens) = %d, want %d", tc.preopens, got, tc.want)
		}
	}
}
