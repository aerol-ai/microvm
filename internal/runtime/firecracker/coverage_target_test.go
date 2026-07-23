package firecracker

import (
	"context"
	"testing"
	"time"
)

// TestColdBootInjectFiles_Exported covers the exported wrapper ColdBootInjectFiles
// which was previously 0% (only the private coldBootInjectFiles was exercised).
func TestColdBootInjectFiles_Exported(t *testing.T) {
	slot := &TapSlot{GuestIP: "10.0.0.2", HostIP: "10.0.0.1", CIDR: "10.0.0.0/30"}

	// With a non-empty binary path we should get 3 inject files.
	files := ColdBootInjectFiles("/opt/toolboxd", "my-token", slot)
	if len(files) != 3 {
		t.Fatalf("want 3 files, got %d: %+v", len(files), files)
	}

	// Without a binary path the exported function returns nil too.
	nilFiles := ColdBootInjectFiles("", "tok", nil)
	if nilFiles != nil {
		t.Fatalf("ColdBootInjectFiles with empty binary should return nil, got %+v", nilFiles)
	}
}

// TestApplyEgressPolicy_NotImplemented and TestClearEgressPolicy_NotImplemented
// confirm that both methods return a methodNotImplemented error (0% before this).
func TestApplyEgressPolicy_NotImplemented(t *testing.T) {
	d := New(Config{}, nil)
	err := d.ApplyEgressPolicy("10.0.0.1", []string{"8.8.8.8"}, nil)
	if err == nil {
		t.Fatal("ApplyEgressPolicy should return an error (not implemented)")
	}
}

func TestClearEgressPolicy_NotImplemented(t *testing.T) {
	d := New(Config{}, nil)
	err := d.ClearEgressPolicy("10.0.0.1", nil, []string{"10.0.0.0/8"})
	if err == nil {
		t.Fatal("ClearEgressPolicy should return an error (not implemented)")
	}
}

// TestWarmHandle_SetTapOwner covers the setTapOwner helper (0% before this).
// We build a minimal warmHandle directly since it is a package-private type.
func TestWarmHandle_SetTapOwner(t *testing.T) {
	vmmHandle := &fakeVMM{runDir: t.TempDir()}
	wh := &warmHandle{
		handle:   vmmHandle,
		slotID:   "slot-001",
		tapName:  "fctap0",
		tapOwner: "slot-001",
	}

	wh.setTapOwner("sb-abc")

	wh.ownerMu.Lock()
	got := wh.tapOwner
	wh.ownerMu.Unlock()

	if got != "sb-abc" {
		t.Fatalf("tapOwner = %q, want sb-abc", got)
	}
}

// TestWarmHandle_ShutdownWithNilDriver exercises the shutdown path when driver
// fields are nil (setTapOwner + Shutdown were 0%).
func TestWarmHandle_ShutdownWithNilDriver(t *testing.T) {
	vmmHandle := &fakeVMM{runDir: t.TempDir()}
	wh := &warmHandle{
		handle:   vmmHandle,
		driver:   nil, // nil driver: no rss/tap cleanup branches
		slotID:   "slot-x",
		tapOwner: "slot-x",
	}
	// Should not panic even with a nil driver.
	_ = wh.Shutdown(context.Background(), time.Second)
}

// TestHandlePID_HandleRunDir_HandleStderrTail cover the thin wrapper methods on
// VMMHandle which were at 66% (only one branch exercised). We use the fakeVMM
// which satisfies VMMHandle.
func TestHandlePID_HandleRunDir_HandleStderrTail(t *testing.T) {
	dir := t.TempDir()
	vmm := &fakeVMM{runDir: dir, pid: 42}

	if vmm.Pid() != 42 {
		t.Fatalf("Pid() = %d, want 42", vmm.Pid())
	}
	if vmm.RunDir() != dir {
		t.Fatalf("RunDir() = %q, want %q", vmm.RunDir(), dir)
	}
	// StderrTail on a brand-new fakeVMM has no data; just confirm no panic.
	_ = vmm.StderrTail()
}

// TestHandlePID_NilHandle etc. cover the nil-guard branches in the package-level
// handle* wrappers (the second branch that was previously uncovered).
func TestHandlePID_NilHandle(t *testing.T) {
	if got := handlePID(nil); got != 0 {
		t.Fatalf("handlePID(nil) = %d, want 0", got)
	}
	if got := handlePID(&fakeVMM{pid: 7}); got != 7 {
		t.Fatalf("handlePID(vmm) = %d, want 7", got)
	}
}

func TestHandleRunDir_NilHandle(t *testing.T) {
	if got := handleRunDir(nil); got != "" {
		t.Fatalf("handleRunDir(nil) = %q, want empty", got)
	}
	dir := t.TempDir()
	if got := handleRunDir(&fakeVMM{runDir: dir}); got != dir {
		t.Fatalf("handleRunDir(vmm) = %q, want %q", got, dir)
	}
}

func TestHandleStderrTail_NilHandle(t *testing.T) {
	if got := handleStderrTail(nil); got != "" {
		t.Fatalf("handleStderrTail(nil) = %q, want empty", got)
	}
	vmm := &fakeVMM{stderrTl: "panic: out of memory"}
	if got := handleStderrTail(vmm); got != "panic: out of memory" {
		t.Fatalf("handleStderrTail(vmm) = %q", got)
	}
}

// TestToolboxNetworkEnv_NilSlot / TestToolboxNetworkPayload_NilSlot cover the
// ok==false path in guestNetworkConfig (was at 75% — nil-slot branch missing).
func TestToolboxNetworkEnv_NilSlot(t *testing.T) {
	if got := toolboxNetworkEnv(nil); got != "" {
		t.Fatalf("toolboxNetworkEnv(nil) = %q, want empty", got)
	}
	emptySlot := &TapSlot{}
	if got := toolboxNetworkEnv(emptySlot); got != "" {
		t.Fatalf("toolboxNetworkEnv(empty) = %q, want empty", got)
	}
}

func TestToolboxNetworkPayload_NilSlot(t *testing.T) {
	if got := toolboxNetworkPayload(nil); got != nil {
		t.Fatalf("toolboxNetworkPayload(nil) = %v, want nil", got)
	}
	// Happy-path: non-nil slot returns a map.
	slot := &TapSlot{GuestIP: "10.0.0.2", HostIP: "10.0.0.1", CIDR: "10.0.0.0/30"}
	got := toolboxNetworkPayload(slot)
	if got == nil {
		t.Fatal("toolboxNetworkPayload(slot) = nil, want non-nil map")
	}
}

func TestGuestNetworkConfig_InvalidCIDR(t *testing.T) {
	// CIDR with a bad mask string should return ok=false.
	slot := &TapSlot{GuestIP: "10.0.0.2", HostIP: "10.0.0.1", CIDR: "invalid"}
	if _, ok := guestNetworkConfig(slot); ok {
		t.Fatal("guestNetworkConfig with invalid CIDR should return ok=false")
	}
}

// TestRequireKernelVMGenID_NoKernel tests the early-exit when no kernel image is
// configured (the first if block at 58.8% gap).
func TestRequireKernelVMGenID_NoKernel(t *testing.T) {
	d := New(Config{}, nil)
	err := d.requireKernelVMGenID()
	if err == nil {
		t.Fatal("requireKernelVMGenID with no kernel should error")
	}
}

// TestRequireKernelVMGenID_NoConfigFile tests the "no config file found" path.
func TestRequireKernelVMGenID_NoConfigFile(t *testing.T) {
	d := New(Config{KernelImage: t.TempDir() + "/vmlinux"}, nil)
	err := d.requireKernelVMGenID()
	if err == nil {
		t.Fatal("requireKernelVMGenID with missing kernel config should error")
	}
}
