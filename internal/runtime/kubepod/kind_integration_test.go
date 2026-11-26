//go:build integration

package kubepod

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	sbruntime "github.com/aerol-ai/microvm/internal/runtime"
	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestKindDriver runs the driver against a real API server, from inside an
// unprivileged pod (Pod Security "restricted") whose service account has
// only pods create, delete, get, list and watch in a sandbox namespace with
// Pod Security "baseline". integration-tests/k8s/kubepod-driver.sh builds
// the images, starts that pod on a kind cluster and sets the env below; the
// test is skipped anywhere else.
func TestKindDriver(t *testing.T) {
	if os.Getenv("AEROL_KUBEPOD_KIND") != "1" {
		t.Skip("runs inside a kind pod; see integration-tests/k8s/kubepod-driver.sh")
	}
	env := func(k string) string {
		v := os.Getenv(k)
		if v == "" {
			t.Fatalf("%s is not set", k)
		}
		return v
	}
	client, err := InClusterClient()
	if err != nil {
		t.Fatal(err)
	}
	ns := env("AEROL_KUBEPOD_NAMESPACE")
	d, err := New(Config{
		Namespace:      ns,
		WorkerID:       env("AEROL_KUBEPOD_WORKER"),
		RuntimeClasses: map[string]string{models.RuntimeDocker: env("AEROL_KUBEPOD_CLASS")},
		ToolboxImage:   env("AEROL_KUBEPOD_TOOLBOX_IMAGE"),
		ToolboxPath:    env("AEROL_KUBEPOD_TOOLBOX_PATH"),
		SpecDir:        t.TempDir(),
		StartTimeout:   2 * time.Minute,
		StopTimeout:    time.Minute,
		StopGrace:      2 * time.Second,
	}, client, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	step := func(name string, fn func() error) {
		t.Helper()
		start := time.Now()
		if err := fn(); err != nil {
			t.Fatalf("FAIL %s: %v", name, err)
		}
		t.Logf("PASS %s (%s)", name, time.Since(start).Round(time.Millisecond))
	}

	step("ping: the five-verb Role may list pods", func() error { return d.Ping(ctx) })

	raw := make([]byte, 8)
	_, _ = rand.Read(raw)
	id := "sb-" + hex.EncodeToString(raw)
	const token = "tok-kind-never-in-a-spec"
	req := models.CreateSandboxRequest{Image: env("AEROL_KUBEPOD_IMAGE"), CPU: 0.25, MemoryMB: 128, DiskGB: 1}
	var st *models.SandboxRuntimeState
	step("create: the pod runs with an address", func() (err error) {
		st, err = d.Create(ctx, req, id, token, nil)
		if err == nil && (st.ContainerIP == "" || st.Status != models.SandboxStatusStarted) {
			err = fmt.Errorf("state %+v", st)
		}
		return err
	})
	t.Cleanup(func() { _ = d.Destroy(context.Background(), &models.Sandbox{ID: id}) })

	step("the stored pod holds no token and the expected shape", func() error {
		p, err := client.GetPod(ctx, ns, id)
		if err != nil {
			return err
		}
		b, _ := json.Marshal(p)
		switch {
		case strings.Contains(string(b), token):
			return errors.New("the pod holds the toolbox token")
		case p.Spec.RuntimeClassName != env("AEROL_KUBEPOD_CLASS"):
			return fmt.Errorf("runtimeClassName %q", p.Spec.RuntimeClassName)
		case p.Spec.AutomountServiceAccountToken == nil || *p.Spec.AutomountServiceAccountToken:
			return errors.New("service account token mounted")
		}
		return nil
	})

	health := func(ip string) error {
		url := "http://" + net.JoinHostPort(ip, strconv.Itoa(defaultToolboxPort)) + "/health"
		var last error
		for i := 0; i < 30; i++ {
			resp, err := http.Get(url)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return nil
				}
				err = fmt.Errorf("status %d", resp.StatusCode)
			}
			last = err
			time.Sleep(500 * time.Millisecond)
		}
		return fmt.Errorf("%s: %w", url, last)
	}
	step("toolboxd (PID 1, copied by the init container) answers /health", func() error { return health(st.ContainerIP) })

	step("a second create is a duplicate", func() error {
		_, err := d.Create(ctx, req, id, token, nil)
		if !errors.Is(err, dockerpkg.ErrSandboxContainerExists) {
			return fmt.Errorf("got %v", err)
		}
		return nil
	})

	step("inspect and list see it", func() error {
		got, err := d.Inspect(ctx, id)
		if err != nil || got.Status != models.SandboxStatusStarted {
			return fmt.Errorf("inspect %+v, %v", got, err)
		}
		all, err := d.ListManaged(ctx)
		if err != nil || all[id] == nil {
			return fmt.Errorf("list has %d, %v", len(all), err)
		}
		return nil
	})

	step("stop deletes the pod and waits until it is gone", func() error {
		if err := d.Stop(ctx, id); err != nil {
			return err
		}
		if _, err := client.GetPod(ctx, ns, id); !isNotFound(err) {
			return fmt.Errorf("pod after stop: %v", err)
		}
		got, err := d.Inspect(ctx, id)
		if err != nil || got.Status != models.SandboxStatusStopped {
			return fmt.Errorf("inspect after stop %+v, %v", got, err)
		}
		return nil
	})

	step("start makes the pod again from the kept spec", func() error {
		got, err := d.Start(ctx, id)
		if err != nil {
			return err
		}
		return health(got.ContainerIP)
	})

	step("destroy removes the pod and the spec", func() error {
		if err := d.Destroy(ctx, &models.Sandbox{ID: id}); err != nil {
			return err
		}
		got, err := d.Inspect(ctx, id)
		if !sbruntime.InstanceGone(got, err) {
			return fmt.Errorf("inspect after destroy %+v, %v", got, err)
		}
		return nil
	})
}
