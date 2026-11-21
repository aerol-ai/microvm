package mounts

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts/adapters"
)

func TestConsumerArgv(t *testing.T) {
	c := Consumer{UID: 61000, GID: 61001}
	for _, tc := range []struct {
		name string
		t    models.MountType
		in   []string
		want []string
	}{
		{"s3", models.MountTypeS3, []string{"mount-s3", "--foreground", "--", "bucket", "/m"},
			[]string{"mount-s3", "--foreground", "--allow-other", "--uid", "61000", "--gid", "61001", "--dir-mode", "0700", "--file-mode", "0600", "--", "bucket", "/m"}},
		{"rclone", models.MountTypeRclone, []string{"rclone", "mount", "--config", "c", "--", "remote:", "/m"},
			[]string{"rclone", "mount", "--config", "c", "--allow-other", "--uid=61000", "--gid=61001", "--umask=077", "--", "remote:", "/m"}},
		{"no separator", models.MountTypeRclone, []string{"rclone", "mount"},
			[]string{"rclone", "mount", "--allow-other", "--uid=61000", "--gid=61001", "--umask=077"}},
		{"sshfs checks on the server", models.MountTypeSSHFS, []string{"sshfs", "-o", "allow_other", "--", "h:/", "/m"},
			[]string{"sshfs", "-o", "allow_other", "--", "h:/", "/m"}},
		{"nfs is a kernel mount", models.MountTypeNFS, []string{"mount", "-t", "nfs"}, []string{"mount", "-t", "nfs"}},
	} {
		if got := consumerArgv(tc.t, slices.Clone(tc.in), c); !slices.Equal(got, tc.want) {
			t.Fatalf("%s: argv = %v\nwant %v", tc.name, got, tc.want)
		}
	}
}

func TestWithConsumer(t *testing.T) {
	if _, ok := consumerFrom(nil); ok {
		t.Fatal("consumer without a context")
	}
	if _, ok := consumerFrom(WithConsumer(context.Background(), Consumer{})); ok {
		t.Fatal("a root or empty consumer was recorded")
	}
	c, ok := consumerFrom(WithConsumer(context.Background(), Consumer{UID: 5, GID: 6}))
	if !ok || c != (Consumer{UID: 5, GID: 6}) {
		t.Fatalf("consumer = %+v, %v", c, ok)
	}
}

// recordArgvAdapter's mount writes its argv to a file, so a test can see what the
// manager ran.
type recordArgvAdapter struct{ out string }

func (a recordArgvAdapter) Build(_ string, _ int, _ models.MountSpec, hostTarget, _ string) (adapters.Plan, error) {
	return adapters.Plan{
		Argv:          []string{"sh", "-c", `printf '%s\n' "$@" > "$0"`, a.out, "--", "bucket", hostTarget},
		IsKernelMount: true,
	}, nil
}

// A WASM sandbox's mounts start with its worker's uid let in.
func TestMountAllAppliesConsumer(t *testing.T) {
	out := filepath.Join(t.TempDir(), "argv")
	m := newTestManager(t, map[models.MountType]adapters.Adapter{models.MountTypeS3: recordArgvAdapter{out: out}})
	spec := models.MountSpec{Type: models.MountTypeS3, Source: "s3://bucket", Target: "/data"}
	ctx := WithConsumer(context.Background(), Consumer{UID: 61000, GID: 61000})
	if _, err := m.MountAll(ctx, "sb-consumer", []models.MountSpec{spec}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(raw); !strings.Contains(got, "--allow-other\n--uid\n61000\n") {
		t.Fatalf("mount argv = %q", got)
	}
	_ = m.UnmountAll("sb-consumer")
}

// Item 2: a mount started for root only is marked so (RootOnly), and one
// started for the consumer is not.
func TestMountRootOnlyBinds(t *testing.T) {
	out := filepath.Join(t.TempDir(), "argv")
	m := newTestManager(t, map[models.MountType]adapters.Adapter{models.MountTypeS3: recordArgvAdapter{out: out}})
	spec := []models.MountSpec{{Type: models.MountTypeS3, Source: "s3://bucket", Target: "/data"}}
	binds, err := m.MountAll(context.Background(), "sb-root-only", spec)
	if err != nil || len(binds) != 1 || !binds[0].RootOnly || !m.HostBindsFor("sb-root-only")[0].RootOnly {
		t.Fatalf("mount without a consumer = %+v, %v: want RootOnly", binds, err)
	}
	binds, err = m.MountAll(WithConsumer(context.Background(), Consumer{UID: 61000, GID: 61000}), "sb-consumer-2", spec)
	if err != nil || binds[0].RootOnly || m.HostBindsFor("sb-consumer-2")[0].RootOnly {
		t.Fatalf("mount for a consumer = %+v, %v", binds, err)
	}
	if fuseForRootOnly(models.MountTypeSSHFS) || fuseForRootOnly(models.MountTypeNFS) || !fuseForRootOnly(models.MountTypeRclone) {
		t.Fatal("root-only types")
	}
	_ = m.UnmountAll("sb-root-only")
	_ = m.UnmountAll("sb-consumer-2")
}

// Item 2: after an upgrade a helper is taken over as it runs, never
// restarted: one started before consumers existed is adopted with its bare
// command line and marked RootOnly; one started for the consumer is adopted
// as it is.
func TestReestablishAdoptsBothHelperKinds(t *testing.T) {
	proc := t.TempDir()
	withProcRoot(t, proc)
	prevProbe := waitForMountProbe
	waitForMountProbe = func(string, time.Duration, <-chan struct{}) error { return nil }
	t.Cleanup(func() { waitForMountProbe = prevProbe })
	withProbeMount(t, func(string) mountProbe { return mountLive })
	recordGroupKills(t)
	spec := []models.MountSpec{{Type: models.MountTypeS3, Source: "s3://b", Target: "/data"}}
	consumer := Consumer{UID: 61000, GID: 61000}
	for i, tc := range []struct {
		name         string
		withConsumer bool
		rootOnly     bool
	}{
		{"started before the upgrade", false, true},
		{"started for the consumer", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sandboxID := fmt.Sprintf("sb-kind-%d", i)
			pid := 5000 + i
			m := newTestManager(t, map[models.MountType]adapters.Adapter{models.MountTypeS3: liveFUSEAdapter{}})
			hostPath := m.hostPath(sandboxID, 0)
			if err := os.MkdirAll(hostPath, 0o700); err != nil {
				t.Fatal(err)
			}
			plan, _ := liveFUSEAdapter{}.Build(sandboxID, 0, spec[0], hostPath, m.credDir)
			argv := plan.Argv
			if tc.withConsumer {
				argv = consumerArgv(models.MountTypeS3, slices.Clone(plan.Argv), consumer)
			}
			fakeProc(t, proc, pid, argv...)
			live := newFakeLive(pid, 0)
			prevOpen := openHelperProcess
			openHelperProcess = func(gotPID int, got []string) (liveProcess, error) {
				if gotPID != pid || !slices.Equal(got, argv) {
					return nil, errProcessGone
				}
				return live, nil
			}
			t.Cleanup(func() { openHelperProcess = prevOpen })
			if err := m.Reestablish(WithConsumer(t.Context(), consumer), sandboxID, spec); err != nil {
				t.Fatalf("Reestablish: %v", err)
			}
			m.mu.Lock()
			st := m.state[sandboxID][0]
			m.mu.Unlock()
			if st.proc != live || st.cmd != nil {
				t.Fatalf("state = %+v: the running helper was not taken over", st)
			}
			if got := m.HostBindsFor(sandboxID)[0].RootOnly; got != tc.rootOnly {
				t.Fatalf("RootOnly = %v, want %v", got, tc.rootOnly)
			}
			if !slices.Equal(st.plan.Argv, argv) {
				t.Fatalf("plan = %v, want the helper's own %v", st.plan.Argv, argv)
			}
		})
	}
}
