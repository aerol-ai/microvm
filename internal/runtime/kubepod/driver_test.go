package kubepod

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	sbruntime "github.com/aerol-ai/microvm/internal/runtime"
	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

const (
	testNS = "aerolvm-sandboxes"
	testID = "sb-0011223344556677"
	// podURL is the path of testID's pod, for failure rules.
	podURL = "GET /api/v1/namespaces/" + testNS + "/pods/" + testID
)

var testReq = models.CreateSandboxRequest{Image: "alpine:3.20", CPU: 1, MemoryMB: 256}

// podOf is a running sandbox pod of id that worker made, put straight into
// the fake (not through the driver).
func podOf(worker, id string) *Pod {
	return &Pod{Metadata: ObjectMeta{
		Name: podName(id), Namespace: testNS,
		Labels:      map[string]string{LabelComponent: componentSandbox, LabelWorker: worker},
		Annotations: map[string]string{AnnotationSandboxID: id},
	}, Status: &PodStatus{Phase: PhaseRunning, PodIP: "10.244.9.9"}}
}

func withPhase(p *Pod, phase string) *Pod {
	p.Status = &PodStatus{Phase: phase}
	return p
}

// keepSpec puts testID's spec in the driver's folder, as a create does.
func keepSpec(t *testing.T, d *Driver, id string) {
	t.Helper()
	p, err := d.renderPod(testReq, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.specs.put(p); err != nil {
		t.Fatal(err)
	}
}

func hasSpec(d *Driver, id string) bool {
	kept, _ := d.specs.has(podName(id))
	return kept
}

func mustCreate(t *testing.T, d *Driver) *models.SandboxRuntimeState {
	t.Helper()
	st, err := d.Create(context.Background(), testReq, testID, "tok", nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return st
}

func TestCreateRunsPod(t *testing.T) {
	f := newFakeAPI(t)
	f.setToken("sa-token")
	f.setKubelet(runningKubelet)
	d := newTestDriver(t, f, nil)
	st, err := d.Create(context.Background(), testReq, testID, "tok-NEVER-IN-A-SPEC", nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if st.SandboxID != testID || st.ContainerID != testID || st.Status != models.SandboxStatusStarted || st.ContainerIP == "" || st.StartedAt.IsZero() {
		t.Fatalf("state = %+v", st)
	}
	if n := f.count("POST "); n != 1 {
		t.Errorf("creates = %d, want 1", n)
	}
	stored, _ := json.Marshal(f.get(testNS, testID))
	kept, err := os.ReadFile(d.specs.path(testID))
	if err != nil {
		t.Fatalf("spec not kept: %v", err)
	}
	for what, raw := range map[string][]byte{"the stored pod": stored, "the kept spec": kept} {
		if strings.Contains(string(raw), "tok-NEVER-IN-A-SPEC") {
			t.Errorf("%s holds the toolbox token", what)
		}
	}
}

func TestCreateRefusesBeforeAnyCall(t *testing.T) {
	f := newFakeAPI(t)
	d := newTestDriver(t, f, nil)
	cases := []struct {
		name  string
		id    string
		req   models.CreateSandboxRequest
		binds []mounts.ContainerBind
		want  error
	}{
		{"bad id", "../etc", testReq, nil, nil},
		{"host mounts", testID, testReq, []mounts.ContainerBind{{}}, ErrHostMountsNotSupported},
		{"env", testID, models.CreateSandboxRequest{Image: "alpine", Env: map[string]string{"A": "b"}}, nil, ErrEnvNotSupported},
	}
	for _, tc := range cases {
		_, err := d.Create(context.Background(), tc.req, tc.id, "tok", tc.binds)
		if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
			t.Errorf("%s: Create = %v, want %v", tc.name, err, tc.want)
		}
	}
	if n := f.count(""); n != 0 {
		t.Errorf("refused creates made %d API calls", n)
	}
}

func TestCreateDuplicateOnThisWorker(t *testing.T) {
	f := newFakeAPI(t)
	f.setKubelet(runningKubelet)
	d := newTestDriver(t, f, nil)
	mustCreate(t, d)
	_, err := d.Create(context.Background(), testReq, testID, "tok", nil)
	if !errors.Is(err, dockerpkg.ErrSandboxContainerExists) {
		t.Fatalf("second create = %v, want ErrSandboxContainerExists", err)
	}
	if n := f.count("POST "); n != 1 {
		t.Errorf("creates = %d, want 1: a kept spec answers without a call", n)
	}
}

func TestCreateNameTaken(t *testing.T) {
	now := time.Now()
	stopping := podOf("worker-0", testID)
	stopping.Metadata.DeletionTimestamp = &now
	cases := []struct {
		name     string
		existing *Pod
		failGet  int
		want     error
		text     string
		keepSpec bool
	}{
		{"this worker's live pod, spec lost", podOf("worker-0", testID), 0, dockerpkg.ErrSandboxContainerExists, "already exists", true},
		{"another worker's pod", podOf("worker-7", testID), 0, ErrOldPodPresent, "worker-7", false},
		{"this worker's pod still stopping", stopping, 0, ErrOldPodPresent, "still stopping", false},
		{"another sandbox's name", podOf("worker-0", "sb-ffffffffffffffff"), 0, nil, "held by sandbox", false},
		{"gone before it was read", podOf("worker-0", testID), 404, ErrOldPodPresent, "went away", false},
		{"cannot be read", podOf("worker-0", testID), 500, nil, "500", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAPI(t)
			f.setGoneAfter(-1) // a stopping pod stays until someone removes it
			d := newTestDriver(t, f, nil)
			p := *tc.existing
			p.Metadata.Name = testID
			f.put(&p)
			if tc.failGet != 0 {
				f.setFail(podURL, tc.failGet, false)
			}
			_, err := d.Create(context.Background(), testReq, testID, "tok", nil)
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) || !strings.Contains(err.Error(), tc.text) {
				t.Fatalf("Create = %v, want %v with %q", err, tc.want, tc.text)
			}
			if got := hasSpec(d, testID); got != tc.keepSpec {
				t.Errorf("spec kept = %v, want %v", got, tc.keepSpec)
			}
			if dc := f.deleteCalls(); len(dc) != 0 {
				t.Errorf("the existing pod was deleted: %v", dc)
			}
		})
	}
}

func TestCreateFailsAndCleansUp(t *testing.T) {
	waiting := func(container, reason string) func(*Pod) {
		return func(p *Pod) {
			p.Status = &PodStatus{Phase: PhasePending, ContainerStatuses: []ContainerStatus{{
				Name: container, State: ContainerState{Waiting: &StateWaiting{Reason: reason, Message: "detail"}},
			}}}
		}
	}
	short := 50 * time.Millisecond
	cases := []struct {
		name    string
		kubelet func(*Pod)
		start   time.Duration
		text    string
	}{
		{"image pull fails", waiting(sandboxContainer, "ImagePullBackOff"), 0, "cannot start: ImagePullBackOff: detail"},
		{"bad image name", waiting(sandboxContainer, "InvalidImageName"), 0, "InvalidImageName"},
		{"init container fails", func(p *Pod) {
			p.Status = &PodStatus{Phase: PhaseFailed, InitContainerStatuses: []ContainerStatus{{
				Name: initContainer, State: ContainerState{Terminated: &StateTerminated{ExitCode: 1, Reason: "Error", Message: "no space"}},
			}}}
		}, 0, "ended before it was ready: container toolbox-install: exit 1 Error no space"},
		{"pod ends with no container reason", func(p *Pod) {
			p.Status = &PodStatus{Phase: PhaseSucceeded, Reason: "Evicted"}
		}, 0, "Succeeded Evicted"},
		{"never scheduled", func(p *Pod) {
			p.Status = &PodStatus{Phase: PhasePending, Conditions: []PodCondition{{Type: "PodScheduled", Status: "False", Reason: "Unschedulable", Message: "0/3 nodes"}}}
		}, short, "not scheduled: Unschedulable: 0/3 nodes"},
		{"still creating", waiting(sandboxContainer, "ContainerCreating"), short, "sandbox: ContainerCreating"},
		{"running, no address", func(p *Pod) { p.Status = &PodStatus{Phase: PhaseRunning} }, short, "no address yet"},
		{"no status", func(p *Pod) { p.Status = nil }, short, "no status yet"},
		{"deleted while starting", func(p *Pod) {
			now := time.Now()
			p.Metadata.DeletionTimestamp = &now
		}, 0, "being deleted"},
		{"replaced while starting", func(p *Pod) { p.Metadata.UID = "uid-other" }, 0, "replaced"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAPI(t)
			f.setKubelet(tc.kubelet)
			d := newTestDriver(t, f, func(c *Config) {
				if tc.start > 0 {
					c.StartTimeout = tc.start
				}
			})
			_, err := d.Create(context.Background(), testReq, testID, "tok", nil)
			if err == nil || !strings.Contains(err.Error(), tc.text) {
				t.Fatalf("Create = %v, want an error with %q", err, tc.text)
			}
			if hasSpec(d, testID) {
				t.Error("a failed create kept its spec")
			}
			if dc := f.deleteCalls(); len(dc) != 1 || dc[0].grace != 1 || dc[0].uid != "uid-1" {
				t.Errorf("deletes = %+v, want one by UID with grace 1", dc)
			}
		})
	}
}

func TestCreateAPIErrors(t *testing.T) {
	t.Run("create refused", func(t *testing.T) {
		f := newFakeAPI(t)
		f.setFail("POST ", 500, false)
		d := newTestDriver(t, f, nil)
		if _, err := d.Create(context.Background(), testReq, testID, "tok", nil); err == nil || !strings.Contains(err.Error(), "500") {
			t.Fatalf("Create = %v, want the 500", err)
		}
		if hasSpec(d, testID) {
			t.Error("a refused create kept its spec")
		}
	})
	t.Run("pod deleted by someone else while it starts", func(t *testing.T) {
		f := newFakeAPI(t)
		d := newTestDriver(t, f, nil)
		f.setFail(podURL, 404, false)
		if _, err := d.Create(context.Background(), testReq, testID, "tok", nil); err == nil || !strings.Contains(err.Error(), "deleted while it started") {
			t.Fatalf("Create = %v, want deleted while it started", err)
		}
	})
	t.Run("one failed read does not fail the create", func(t *testing.T) {
		f := newFakeAPI(t)
		f.setKubelet(runningKubelet)
		f.setFail(podURL, 503, true)
		d := newTestDriver(t, f, nil)
		if _, err := d.Create(context.Background(), testReq, testID, "tok", nil); err != nil {
			t.Fatalf("Create after one failed read: %v", err)
		}
	})
	t.Run("spec folder not writable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root writes anywhere")
		}
		f := newFakeAPI(t)
		d := newTestDriver(t, f, nil)
		if err := os.Chmod(d.cfg.SpecDir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(d.cfg.SpecDir, 0o700) })
		if _, err := d.Create(context.Background(), testReq, testID, "tok", nil); err == nil || !strings.Contains(err.Error(), "keep spec") {
			t.Fatalf("Create = %v, want a keep spec error", err)
		}
		if n := f.count(""); n != 0 {
			t.Errorf("calls = %d, want none", n)
		}
	})
}

func TestCreateCallerContextEnds(t *testing.T) {
	f := newFakeAPI(t)
	d := newTestDriver(t, f, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err := d.Create(ctx, testReq, testID, "tok", nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Create = %v, want the caller's deadline", err)
	}
	// The undo ran on a context of its own, after the caller's ended.
	if dc := f.deleteCalls(); len(dc) != 1 {
		t.Errorf("deletes = %+v, want the pod deleted", dc)
	}
}

func TestStop(t *testing.T) {
	t.Run("deletes and waits until gone", func(t *testing.T) {
		f := newFakeAPI(t)
		f.setKubelet(runningKubelet)
		f.setGoneAfter(3)
		d := newTestDriver(t, f, nil)
		mustCreate(t, d)
		if err := d.Stop(context.Background(), testID); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		if f.get(testNS, testID) != nil {
			t.Error("Stop returned before the pod was gone")
		}
		if dc := f.deleteCalls(); len(dc) != 1 || dc[0].grace != 10 || dc[0].uid != "uid-1" {
			t.Errorf("deletes = %+v, want one by UID with the stop grace", dc)
		}
		if !hasSpec(d, testID) {
			t.Error("Stop forgot the spec Start needs")
		}
		if err := d.Stop(context.Background(), testID); err != nil {
			t.Errorf("second Stop = %v, want nil", err)
		}
	})
	t.Run("node cannot be reached", func(t *testing.T) {
		f := newFakeAPI(t)
		f.setGoneAfter(-1)
		d := newTestDriver(t, f, func(c *Config) { c.StopTimeout = 30 * time.Millisecond })
		f.put(podOf("worker-0", testID))
		if err := d.Stop(context.Background(), testID); err == nil || !strings.Contains(err.Error(), "still stopping") {
			t.Fatalf("Stop = %v, want still stopping", err)
		}
	})
	t.Run("another worker's pod is left alone", func(t *testing.T) {
		f := newFakeAPI(t)
		d := newTestDriver(t, f, nil)
		f.put(podOf("worker-7", testID))
		if err := d.Stop(context.Background(), testID); err != nil || len(f.deleteCalls()) != 0 {
			t.Fatalf("Stop = %v, deletes %v", err, f.deleteCalls())
		}
	})
	t.Run("failed delete", func(t *testing.T) {
		f := newFakeAPI(t)
		d := newTestDriver(t, f, nil)
		f.put(podOf("worker-0", testID))
		f.setFail("DELETE ", 500, false)
		if err := d.Stop(context.Background(), testID); err == nil || !strings.Contains(err.Error(), "500") {
			t.Errorf("Stop = %v, want the delete's 500", err)
		}
	})
	t.Run("failed read", func(t *testing.T) {
		f := newFakeAPI(t)
		d := newTestDriver(t, f, nil)
		f.setFail("GET ", 500, false)
		if err := d.Stop(context.Background(), testID); err == nil {
			t.Error("Stop with a failed read: want an error")
		}
	})
	t.Run("a replaced pod counts as gone", func(t *testing.T) {
		f := newFakeAPI(t)
		f.setGoneAfter(-1)
		d := newTestDriver(t, f, nil)
		f.put(podOf("worker-0", testID)) // uid-1
		stale := &Pod{Metadata: ObjectMeta{Name: testID, UID: "uid-stale"}}
		if err := d.deleteAndWait(context.Background(), stale, time.Second); err != nil {
			t.Fatalf("delete of a replaced pod = %v, want nil", err)
		}
		if f.get(testNS, testID).Metadata.DeletionTimestamp != nil {
			t.Error("the newer pod was deleted")
		}
	})
}

func TestWaitGone(t *testing.T) {
	f := newFakeAPI(t)
	f.setGoneAfter(-1)
	d := newTestDriver(t, f, nil)
	f.put(podOf("worker-0", testID)) // uid-1
	if err := d.waitGone(context.Background(), testID, "uid-old", time.Second); err != nil {
		t.Fatalf("waitGone for a replaced pod = %v, want nil", err)
	}
	f.setFail("GET ", 500, false)
	if err := d.waitGone(context.Background(), testID, "uid-1", 20*time.Millisecond); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("waitGone with failing reads = %v, want the read error named", err)
	}
}

func TestStart(t *testing.T) {
	t.Run("after a stop it makes the pod again", func(t *testing.T) {
		f := newFakeAPI(t)
		f.setKubelet(runningKubelet)
		d := newTestDriver(t, f, nil)
		mustCreate(t, d)
		if err := d.Stop(context.Background(), testID); err != nil {
			t.Fatal(err)
		}
		st, err := d.Start(context.Background(), testID)
		if err != nil || st.Status != models.SandboxStatusStarted || st.ContainerIP == "" {
			t.Fatalf("Start = %+v, %v", st, err)
		}
		if p := f.get(testNS, testID); p == nil || p.Metadata.UID != "uid-2" {
			t.Fatalf("pod after start = %+v, want a new one", p)
		}
		// Start again: the pod runs, so nothing is made.
		if _, err := d.Start(context.Background(), testID); err != nil || f.count("POST ") != 2 {
			t.Fatalf("second Start = %v with %d creates, want no new create", err, f.count("POST "))
		}
	})
	t.Run("a start after a worker upgrade gets the new toolboxd", func(t *testing.T) {
		f := newFakeAPI(t)
		f.setKubelet(runningKubelet)
		old := newTestDriver(t, f, nil)
		mustCreate(t, old)
		if err := old.Stop(context.Background(), testID); err != nil {
			t.Fatal(err)
		}
		// The upgraded worker: same spec folder, new toolbox image.
		upgraded := newTestDriver(t, f, func(c *Config) {
			c.SpecDir = old.cfg.SpecDir
			c.ToolboxImage = "ghcr.io/aerol-ai/aerolvm:next"
			c.ToolboxPath = "/toolboxd"
		})
		if _, err := upgraded.Start(context.Background(), testID); err != nil {
			t.Fatal(err)
		}
		ic := f.get(testNS, testID).Spec.InitContainers[0]
		if ic.Image != "ghcr.io/aerol-ai/aerolvm:next" || ic.Command[0] != "/toolboxd" {
			t.Fatalf("init container = %s %v, want the upgraded worker's toolbox", ic.Image, ic.Command)
		}
		if c := f.get(testNS, testID).Spec.Containers[0]; c.Image != testReq.Image {
			t.Fatalf("sandbox image = %s: the sandbox's own image must not change", c.Image)
		}
	})
	t.Run("an ended pod is replaced", func(t *testing.T) {
		f := newFakeAPI(t)
		f.setGoneAfter(2)
		d := newTestDriver(t, f, nil)
		keepSpec(t, d, testID)
		f.put(withPhase(podOf("worker-0", testID), PhaseFailed)) // uid-1
		f.setKubelet(func(p *Pod) {
			if p.Metadata.UID != "uid-1" {
				runningKubelet(p)
			}
		})
		st, err := d.Start(context.Background(), testID)
		if err != nil || st.ContainerIP == "" {
			t.Fatalf("Start = %+v, %v", st, err)
		}
		if dc := f.deleteCalls(); len(dc) != 1 || dc[0].uid != "uid-1" {
			t.Errorf("deletes = %+v, want the ended pod deleted by UID", dc)
		}
	})
	t.Run("a stopping pod is waited for", func(t *testing.T) {
		f := newFakeAPI(t)
		f.setKubelet(runningKubelet)
		f.setGoneAfter(3)
		d := newTestDriver(t, f, nil)
		mustCreate(t, d)
		if err := d.client.DeletePod(context.Background(), testNS, testID, "", 0); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Start(context.Background(), testID); err != nil {
			t.Fatalf("Start: %v", err)
		}
		dc := f.deleteCalls()
		if len(dc) != 1 || dc[0].grace != 1 {
			t.Errorf("deletes = %+v: want only the first (grace raised from 0 to 1); a stopping pod is not deleted again", dc)
		}
	})
	t.Run("refusals", func(t *testing.T) {
		f := newFakeAPI(t)
		d := newTestDriver(t, f, nil)
		if _, err := d.Start(context.Background(), testID); !errors.Is(err, sbruntime.ErrInstanceNotFound) {
			t.Errorf("Start with no pod and no spec = %v, want ErrInstanceNotFound", err)
		}
		f.put(podOf("worker-7", testID))
		if _, err := d.Start(context.Background(), testID); !errors.Is(err, ErrOldPodPresent) {
			t.Errorf("Start over another worker's pod = %v, want ErrOldPodPresent", err)
		}
		f.setFail("GET ", 500, false)
		if _, err := d.Start(context.Background(), testID); err == nil || errors.Is(err, sbruntime.ErrInstanceNotFound) {
			t.Errorf("Start with a failed read = %v, want that error", err)
		}
	})
	t.Run("the new pod does not run", func(t *testing.T) {
		f := newFakeAPI(t)
		f.setKubelet(func(p *Pod) { p.Status = &PodStatus{Phase: PhaseFailed} })
		d := newTestDriver(t, f, nil)
		keepSpec(t, d, testID)
		if _, err := d.Start(context.Background(), testID); err == nil {
			t.Fatal("Start of a pod that fails: want an error")
		}
		if !hasSpec(d, testID) {
			t.Error("a failed start forgot the stopped sandbox's spec")
		}
		if dc := f.deleteCalls(); len(dc) != 1 {
			t.Errorf("deletes = %+v, want the failed pod deleted", dc)
		}
	})
	t.Run("create refused", func(t *testing.T) {
		f := newFakeAPI(t)
		d := newTestDriver(t, f, nil)
		keepSpec(t, d, testID)
		f.setFail("POST ", 500, false)
		if _, err := d.Start(context.Background(), testID); err == nil || !strings.Contains(err.Error(), "500") {
			t.Fatalf("Start = %v, want the 500", err)
		}
	})
	t.Run("pod came back while starting", func(t *testing.T) {
		f := newFakeAPI(t)
		d := newTestDriver(t, f, nil)
		keepSpec(t, d, testID)
		// The first read finds nothing; then the create meets a pod.
		f.put(podOf("worker-0", testID))
		f.setFail("GET ", 404, true)
		if _, err := d.Start(context.Background(), testID); !errors.Is(err, ErrOldPodPresent) {
			t.Fatalf("Start = %v, want ErrOldPodPresent", err)
		}
	})
	t.Run("ended pod cannot be deleted", func(t *testing.T) {
		f := newFakeAPI(t)
		d := newTestDriver(t, f, nil)
		f.put(withPhase(podOf("worker-0", testID), PhaseFailed))
		f.setFail("DELETE ", 500, false)
		if _, err := d.Start(context.Background(), testID); err == nil || !strings.Contains(err.Error(), "500") {
			t.Fatalf("Start = %v, want the delete's 500", err)
		}
	})
	t.Run("ended pod never goes", func(t *testing.T) {
		f := newFakeAPI(t)
		f.setGoneAfter(-1)
		d := newTestDriver(t, f, func(c *Config) { c.StopTimeout = 20 * time.Millisecond })
		f.put(withPhase(podOf("worker-0", testID), PhaseFailed))
		if _, err := d.Start(context.Background(), testID); err == nil || !strings.Contains(err.Error(), "still stopping") {
			t.Fatalf("Start = %v, want still stopping", err)
		}
	})
	t.Run("kept spec unreadable", func(t *testing.T) {
		f := newFakeAPI(t)
		d := newTestDriver(t, f, nil)
		if err := os.WriteFile(d.specs.path(testID), []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Start(context.Background(), testID); err == nil || !strings.Contains(err.Error(), "kept spec") {
			t.Fatalf("Start = %v, want the spec error", err)
		}
	})
}

func TestDestroy(t *testing.T) {
	if err := newTestDriver(t, newFakeAPI(t), nil).Destroy(context.Background(), nil); err != nil {
		t.Fatalf("Destroy(nil) = %v", err)
	}
	t.Run("deletes, waits and forgets", func(t *testing.T) {
		f := newFakeAPI(t)
		f.setKubelet(runningKubelet)
		f.setGoneAfter(2)
		d := newTestDriver(t, f, nil)
		st := mustCreate(t, d)
		if err := d.Destroy(context.Background(), &models.Sandbox{ID: testID, ContainerID: st.ContainerID}); err != nil {
			t.Fatalf("Destroy: %v", err)
		}
		if f.get(testNS, testID) != nil {
			t.Error("pod still there")
		}
		if hasSpec(d, testID) {
			t.Error("spec still kept")
		}
		if dc := f.deleteCalls(); len(dc) != 1 || dc[0].grace != 1 {
			t.Errorf("deletes = %+v, want grace 1", dc)
		}
		// Again, by sandbox ID alone: converges.
		if err := d.Destroy(context.Background(), &models.Sandbox{ID: testID}); err != nil {
			t.Errorf("second Destroy = %v", err)
		}
	})
	t.Run("another worker's pod stays", func(t *testing.T) {
		f := newFakeAPI(t)
		d := newTestDriver(t, f, nil)
		keepSpec(t, d, testID)
		f.put(podOf("worker-7", testID))
		if err := d.Destroy(context.Background(), &models.Sandbox{ID: testID}); err != nil {
			t.Fatal(err)
		}
		if f.get(testNS, testID) == nil || len(f.deleteCalls()) != 0 {
			t.Error("Destroy deleted another worker's pod")
		}
		if hasSpec(d, testID) {
			t.Error("spec still kept")
		}
	})
	t.Run("a pod that never goes keeps the spec", func(t *testing.T) {
		f := newFakeAPI(t)
		f.setGoneAfter(-1)
		d := newTestDriver(t, f, func(c *Config) { c.StopTimeout = 20 * time.Millisecond })
		keepSpec(t, d, testID)
		f.put(podOf("worker-0", testID))
		if err := d.Destroy(context.Background(), &models.Sandbox{ID: testID}); err == nil {
			t.Fatal("Destroy of a pod that never goes: want an error")
		}
		if !hasSpec(d, testID) {
			t.Error("a failed destroy forgot the spec; a retry could not find it")
		}
	})
	t.Run("failed read", func(t *testing.T) {
		f := newFakeAPI(t)
		d := newTestDriver(t, f, nil)
		keepSpec(t, d, testID)
		f.setFail("GET ", 500, false)
		if err := d.Destroy(context.Background(), &models.Sandbox{ID: testID}); err == nil || !hasSpec(d, testID) {
			t.Errorf("Destroy with a failed read = %v (spec kept %v), want an error and the spec kept", err, hasSpec(d, testID))
		}
	})
}

func TestInspect(t *testing.T) {
	now := time.Now()
	stopping := podOf("worker-0", testID)
	stopping.Metadata.DeletionTimestamp = &now
	cases := []struct {
		name   string
		pod    *Pod
		spec   bool
		status models.SandboxStatus
		ip     bool
		gone   bool
	}{
		{"running", podOf("worker-0", testID), false, models.SandboxStatusStarted, true, false},
		{"pending", withPhase(podOf("worker-0", testID), PhasePending), false, models.SandboxStatusStarted, false, false},
		{"no status", &Pod{Metadata: podOf("worker-0", testID).Metadata}, false, models.SandboxStatusStarted, false, false},
		{"node lost", withPhase(podOf("worker-0", testID), "Unknown"), false, models.SandboxStatusStarted, false, false},
		{"ended", withPhase(podOf("worker-0", testID), PhaseSucceeded), false, models.SandboxStatusStopped, false, false},
		{"stopping, still running", stopping, false, models.SandboxStatusStarted, true, false},
		{"stopped: spec, no pod", nil, true, models.SandboxStatusStopped, false, false},
		{"gone: no spec, no pod", nil, false, "", false, true},
		{"another worker's pod, no spec", podOf("worker-7", testID), false, "", false, true},
		{"another worker's pod, spec", podOf("worker-7", testID), true, models.SandboxStatusStopped, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAPI(t)
			f.setGoneAfter(-1) // a stopping pod stays until someone removes it
			d := newTestDriver(t, f, nil)
			if tc.pod != nil {
				f.put(tc.pod)
			}
			if tc.spec {
				keepSpec(t, d, testID)
			}
			st, err := d.Inspect(context.Background(), testID)
			if got := sbruntime.InstanceGone(st, err); got != tc.gone {
				t.Fatalf("Inspect = %+v, %v: gone = %v, want %v", st, err, got, tc.gone)
			}
			if tc.gone {
				return
			}
			if err != nil || st.Status != tc.status || (st.ContainerIP != "") != tc.ip || st.SandboxID != testID || st.ContainerID != testID {
				t.Fatalf("Inspect = %+v, %v; want %s, ip %v", st, err, tc.status, tc.ip)
			}
		})
	}
	t.Run("API down is unknown, not gone", func(t *testing.T) {
		f := newFakeAPI(t)
		d := newTestDriver(t, f, nil)
		f.setFail("GET ", 500, false)
		st, err := d.Inspect(context.Background(), testID)
		if err == nil || sbruntime.InstanceGone(st, err) {
			t.Fatalf("Inspect = %v, %v: want an unknown answer", st, err)
		}
	})
	t.Run("kept spec unreadable is unknown, not gone", func(t *testing.T) {
		f := newFakeAPI(t)
		d := newTestDriver(t, f, nil)
		if err := os.WriteFile(d.specs.path(testID), []byte("nope"), 0o600); err != nil {
			t.Fatal(err)
		}
		if st, err := d.Inspect(context.Background(), testID); err == nil || sbruntime.InstanceGone(st, err) {
			t.Fatalf("Inspect = %v, want an unknown answer", err)
		}
	})
}

func TestListManaged(t *testing.T) {
	f := newFakeAPI(t)
	d := newTestDriver(t, f, nil)
	// More than one page of this worker's running pods.
	for i := 0; i < listPageSize+5; i++ {
		f.put(podOf("worker-0", fmt.Sprintf("sb-%016x", i)))
	}
	f.put(withPhase(podOf("worker-0", "sb-e000000000000000"), PhaseFailed))
	f.put(podOf("worker-7", "sb-7000000000000000"))
	keepSpec(t, d, "sb-5000000000000000")
	// A kept spec whose pod runs is listed once, as running.
	keepSpec(t, d, "sb-0000000000000001")

	got, err := d.ListManaged(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := listPageSize + 5 + 2; len(got) != want {
		t.Fatalf("listed %d, want %d", len(got), want)
	}
	if got["sb-7000000000000000"] != nil {
		t.Error("listed another worker's pod")
	}
	if got["sb-e000000000000000"].Status != models.SandboxStatusStopped || got["sb-5000000000000000"].Status != models.SandboxStatusStopped {
		t.Error("an ended pod and a kept spec with no pod must be stopped")
	}
	if got["sb-0000000000000001"].Status != models.SandboxStatusStarted {
		t.Error("a running pod with a kept spec must be started")
	}
	if n := f.count("GET /api/v1/namespaces/" + testNS + "/pods"); n != 2 {
		t.Errorf("list calls = %d, want 2 pages", n)
	}

	if err := os.WriteFile(d.specs.path("sb-bad"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ListManaged(context.Background()); err == nil {
		t.Error("ListManaged with an unreadable spec: want an error")
	}
	f.setFail("GET ", 403, false)
	if _, err := d.ListManaged(context.Background()); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("ListManaged = %v, want the 403", err)
	}
}

func TestPingAndRefusedCalls(t *testing.T) {
	f := newFakeAPI(t)
	d := newTestDriver(t, f, nil)
	if err := d.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	f.setFail("GET ", 403, false)
	if err := d.Ping(context.Background()); err == nil {
		t.Error("Ping without the list right: want an error")
	}
	if _, err := d.CreateSnapshot(context.Background(), testID, "img"); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Errorf("CreateSnapshot = %v", err)
	}
	if err := d.Resize(context.Background(), testID, models.ResizeSandboxRequest{}); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Errorf("Resize = %v", err)
	}
	if err := d.RemoveImage(context.Background(), "alpine"); err != nil {
		t.Errorf("RemoveImage = %v", err)
	}
}

func TestParallelCreates(t *testing.T) {
	f := newFakeAPI(t)
	f.setKubelet(runningKubelet)
	d := newTestDriver(t, f, nil)
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := 0; i < 20; i++ {
		id := fmt.Sprintf("sb-%016x", i)
		// Two creates per ID: one makes the pod, the other is a duplicate.
		for j := 0; j < 2; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := d.Create(context.Background(), testReq, id, "tok", nil)
				if err != nil && !errors.Is(err, dockerpkg.ErrSandboxContainerExists) {
					errs <- err
				}
			}()
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	got, err := d.ListManaged(context.Background())
	if err != nil || len(got) != 20 {
		t.Fatalf("ListManaged = %d, %v; want 20", len(got), err)
	}
	for id, st := range got {
		if st.Status != models.SandboxStatusStarted {
			t.Errorf("%s = %s", id, st.Status)
		}
		if !hasSpec(d, id) {
			t.Errorf("%s lost its spec to the duplicate create", id)
		}
	}
	if n := f.count("POST "); n < 20 || n > 40 {
		t.Errorf("creates = %d", n)
	}
}
