package firecracker

import (
	"context"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// A start from a stopped sandbox's snapshot whose first vsock connection is
// torn. Live (M2 spike SP-A, 2026-11-26, m8i.xlarge with nested
// virtualization): the guest accepted the host's first connection after the
// resume, then reset it while handling Firecracker's vsock transport reset,
// so the handshake read EOF; the same snapshot tore the first connection of
// every new VMM, so retrying the whole start never helped (24 of 60
// pause/resume cycles lost). The model: every VMM restored from this
// snapshot loses its first connection; a second one on the same VMM works.

// tearFirstConnPerVMM hands back a torn connection on the first dial after
// each LoadSnapshot, and the fixture's healthy connections after that.
type tearFirstConnPerVMM struct {
	inner *fakeVsockDialer
	mu    sync.Mutex
	loads int
	torn  map[int]bool
	tears int
	arm   bool
}

type tornVsockConn struct{}

func (tornVsockConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (tornVsockConn) Write(p []byte) (int, error) { return len(p), nil }
func (tornVsockConn) Close() error                { return nil }

func (d *tearFirstConnPerVMM) loaded() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.loads++
	return nil
}

func (d *tearFirstConnPerVMM) Dial(ctx context.Context, socketPath string, cid, port uint32) (io.ReadWriteCloser, error) {
	d.mu.Lock()
	if d.arm && !d.torn[d.loads] {
		d.torn[d.loads] = true
		d.tears++
		d.mu.Unlock()
		return tornVsockConn{}, nil
	}
	d.mu.Unlock()
	return d.inner.Dial(ctx, socketPath, cid, port)
}

func TestStartFromSandboxSnapshot_RedialsATornFirstConnection(t *testing.T) {
	f := newDriverFixture(t)
	ctx := context.Background()
	dialer := &tearFirstConnPerVMM{inner: f.vsock, torn: map[int]bool{}}
	f.client.loadSnapshotHook = dialer.loaded
	f.driver.SetVsockDialer(dialer)

	if _, err := f.driver.Create(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, DiskGB: 1, OverlaySizeGB: 1,
	}, "sb-torn", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := f.driver.Stop(ctx, "sb-torn"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	dialer.mu.Lock()
	dialer.arm = true
	dialer.mu.Unlock()

	// Before the redial this failed with "vsock handshake: vsock read: EOF",
	// and so did every retry of the start.
	st, err := f.driver.StartWithIdentity(ctx, "sb-torn", "sb-torn", "tok")
	if err != nil {
		t.Fatalf("Start after a torn first connection: %v", err)
	}
	if st.Status != models.SandboxStatusStarted {
		t.Fatalf("status = %q, want started", st.Status)
	}
	if dialer.tears != 1 {
		t.Fatalf("torn connections = %d, want 1 (one per restored VMM)", dialer.tears)
	}
	// The redial is the only extra dial: the handshake's second dial, then
	// post_resume, thaw and adopt as before.
	pings := 0
	for _, w := range f.vsock.snapshotWrites() {
		if strings.Contains(string(w), `"op":"ping"`) {
			pings++
		}
	}
	if pings != 2 {
		t.Fatalf("pings on healthy connections = %d, want 2 (Create's and the redialed Start's)", pings)
	}
}
